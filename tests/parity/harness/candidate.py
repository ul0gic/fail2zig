# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Actual Zig component adapters; no daemon/enforcement or modeled candidate results."""

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import signal
import subprocess
import tempfile

try:
    from .contract import load_json
except ImportError:  # unittest discovery with the harness directory on sys.path
    from contract import load_json


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _execute(command, work, timeout=5, build=False):
    """Bound children, output files and environment; outer runner supplies namespaces."""
    work = Path(work)
    output_limit = 4 * 1024 * 1024 if build else 1024 * 1024

    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (int(timeout) + 1,) * 2)
        file_limit = 128 * 1024 * 1024 if build else output_limit
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit,) * 2)
        if not build:
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))

    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(work),
           "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
           "ZIG_GLOBAL_CACHE_DIR": str(work / "zig-global-cache"),
           "ZIG_LOCAL_CACHE_DIR": str(work / "zig-local-cache")}
    with tempfile.TemporaryFile(dir=work) as out, tempfile.TemporaryFile(dir=work) as err:
        process = subprocess.Popen(command, cwd=work, env=env, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, start_new_session=True,
                                   preexec_fn=limits)
        status = "ok"
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            status = "timeout"
        finally:
            # Also terminate a descendant that outlives a successfully exited worker.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        out.seek(0, os.SEEK_END)
        out_size = out.tell()
        err.seek(0, os.SEEK_END)
        err_size = err.tell()
        out.seek(0)
        err.seek(0)
        raw = {"stdout": out.read(output_limit).decode("utf-8", errors="replace"),
               "stderr": err.read(output_limit).decode("utf-8", errors="replace"),
               "returncode": process.returncode}
        # A worker can ignore a short write and exit zero at RLIMIT_FSIZE. Reaching
        # the cap is therefore an error even when its output is exactly cap-sized.
        if out_size >= output_limit or err_size >= output_limit:
            status = "output_limit"
        if status == "ok" and process.returncode != 0:
            status = "error"
        return status, raw


def prepare(context):
    """Build probes serially before isolation; remap each returned entry's path only."""
    root, work = Path(context["root"]).resolve(), Path(context["work"]).resolve()
    work.mkdir(parents=True, exist_ok=True)
    binaries_dir = work / "binaries"
    binaries_dir.mkdir(exist_ok=True)
    zig = shutil.which("zig")
    if zig is None:
        raise RuntimeError("Zig compiler unavailable; candidate cannot be prepared")
    status, version = _execute([zig, "version"], work, build=True)
    if status != "ok":
        raise RuntimeError(f"Zig version failed: {version}")
    common_inputs = sorted(root.glob("shared/**/*.zig"))
    core_inputs = sorted(root.glob("engine/core/*.zig")) + common_inputs
    definitions = {
        "config": (["--dep", "fail2ban_config", f"-Mroot={root / 'tests/parity/config_probe.zig'}",
                    f"-Mfail2ban_config={root / 'engine/config/fail2ban.zig'}"],
                   [root / "tests/parity/config_probe.zig", root / "engine/config/fail2ban.zig"]),
        "effective_config": (["--dep", "engine",
                              f"-Mroot={root / 'tests/parity/harness/effective_config_probe.zig'}",
                              "--dep", "shared", f"-Mengine={root / 'engine/main.zig'}",
                              f"-Mshared={root / 'shared/root.zig'}"],
                             [root / "tests/parity/harness/effective_config_probe.zig"]
                             + sorted(root.glob("engine/**/*.zig")) + common_inputs),
        "ssh_log": (["--dep", "engine", f"-Mroot={root / 'tests/parity/harness/ssh_log_probe.zig'}",
                     "--dep", "shared", f"-Mengine={root / 'engine/main.zig'}",
                     f"-Mshared={root / 'shared/root.zig'}"],
                    [root / "tests/parity/harness/ssh_log_probe.zig"]
                    + sorted(root.glob("engine/**/*.zig")) + common_inputs),
        "tickets": (["--dep", "state", "--dep", "shared",
                     f"-Mroot={root / 'tests/parity/time_probe.zig'}", "--dep", "shared",
                     f"-Mstate={root / 'engine/core/state.zig'}", f"-Mshared={root / 'shared/root.zig'}"],
                    [root / "tests/parity/time_probe.zig"] + core_inputs),
        "persistence": (["--dep", "persist", "--dep", "shared",
                         f"-Mroot={root / 'tests/parity/harness/persistence_probe.zig'}", "--dep", "shared",
                         f"-Mpersist={root / 'engine/core/persist.zig'}", f"-Mshared={root / 'shared/root.zig'}"],
                        [root / "tests/parity/harness/persistence_probe.zig"] + core_inputs),
    }
    result = {"toolchain": {"zig_version": version["stdout"].strip(), "zig_path": zig,
                            "zig_sha256": _digest(zig), "adapter_sha256": _digest(Path(__file__))}}
    for kind, (modules, inputs) in definitions.items():
        binary = binaries_dir / f"candidate-{kind}"
        command = [zig, "build-exe", "-O", "ReleaseSafe", *modules, f"-femit-bin={binary}"]
        # Pin inputs before and after compilation, including conservative transitive supersets.
        hashes = {str(path.relative_to(root)): _digest(path) for path in inputs}
        status, raw = _execute(command, work, timeout=180, build=True)
        if status != "ok":
            raise RuntimeError(f"candidate {kind} build {status}: {raw}")
        if hashes != {str(path.relative_to(root)): _digest(path) for path in inputs}:
            raise RuntimeError(f"candidate {kind} sources changed while building")
        result[kind] = {"path": str(binary), "sha256": _digest(binary), "command": command,
                        "input_hashes": hashes, "raw": raw, "scope": "production component only"}
    return result


def _result(status, observations=None, raw=None, **details):
    return {"status": status, "observations": observations or [],
            "raw": raw or {"stdout": "", "stderr": "", "returncode": None},
            "details": {"scope": "production component only; no daemon, ingestion or enforcement", **details}}


def _integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def _validate_ticket(value, persistence=False):
    keys = {"pending_retry", "pending_last_time", "threshold_reached"}
    if persistence:
        keys |= {"attempt_count", "ban_count", "ban_expiry"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("invalid ticket observation fields")
    if not _integer(value["pending_retry"], 0, 2 ** 32 - 1) or type(value["threshold_reached"]) is not bool:
        raise ValueError("invalid ticket observation types")
    for key in ("pending_last_time", "ban_expiry") if persistence else ("pending_last_time",):
        if value[key] is not None and not _integer(value[key], -(2 ** 63), 2 ** 63 - 1):
            raise ValueError("invalid ticket timestamp type")
    if persistence and not all(_integer(value[key], 0, 2 ** 32 - 1) for key in ("attempt_count", "ban_count")):
        raise ValueError("invalid persistence counter type")


def run_case(case, context):
    kind = case.get("kind")
    if kind not in ("config", "effective_config", "ssh_log", "tickets", "persistence"):
        return _result("unsupported", reason=f"candidate adapter has no {kind!r} capability")
    inputs = case.get("input", {})
    if not isinstance(inputs, dict):
        return _result("error", reason="case input must be an object")
    if kind in ("config", "effective_config") and (inputs.get("section", "probe") != "probe" or inputs.get("option", "maxretry") != "maxretry"):
        return _result("unsupported", reason="config component probe observes only probe.maxretry")
    if kind == "ssh_log":
        line = inputs.get("line")
        ordinary = (r"(?:[A-Za-z0-9 :T+_.-]+ )?sshd(?:-session)?\[[0-9]{1,8}\]: "
                    r"(?:Failed password for (?:invalid user )?fixture-user from 192\.0\.2\.10 port [0-9]{1,5} ssh2"
                    r"|Accepted publickey for fixture-user from 192\.0\.2\.10 port [0-9]{1,5} ssh2: [A-Za-z0-9:+/_=. -]+)")
        if not isinstance(line, str) or not 1 <= len(line) <= 1024 or re.fullmatch(ordinary, line) is None:
            return _result("unsupported", reason="SSH matcher probe requires one bounded ordinary record sanitized to fixture-user/192.0.2.10")
    if kind in ("tickets", "persistence"):
        events = inputs.get("events")
        if (not _integer(inputs.get("findtime"), 1, 3600)
                or not _integer(inputs.get("maxretry"), 1, 1024)
                or not isinstance(events, list) or not 1 <= len(events) <= 256
                or not all(_integer(value, -(2 ** 60), 2 ** 60) for value in events)):
            return _result("unsupported", reason="outside integer component probe bounds")
    try:
        metadata = context["binaries"][kind]
        binary = Path(metadata["path"])
        if _digest(binary) != metadata["sha256"]:
            return _result("error", reason="candidate binary hash mismatch")
        case_work = Path(tempfile.mkdtemp(prefix=f"candidate-{kind}-", dir=context["work"]))
        if kind in ("config", "effective_config"):
            files = inputs.get("files")
            if not isinstance(files, dict) or len(files) > 64:
                return _result("error", reason="config files must be a bounded object")
            if sum(len(value.encode()) for value in files.values() if isinstance(value, str)) > 256 * 1024:
                return _result("error", reason="config fixture exceeds byte limit")
            for name, content in files.items():
                if not isinstance(name, str) or not isinstance(content, str):
                    return _result("error", reason="config file names and contents must be strings")
                relative = PurePosixPath(name)
                if relative.is_absolute() or ".." in relative.parts or not relative.parts or "\x00" in name:
                    return _result("error", reason="config filename escapes private fixture")
                path = case_work / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            command = [str(binary), str(case_work)]
            if kind == "effective_config":
                command.append(str(case_work / "imported.toml"))
        elif kind == "ssh_log":
            command = [str(binary), inputs["line"]]
        else:
            arguments = [str(inputs["findtime"]), str(inputs["maxretry"]), ",".join(map(str, inputs["events"]))]
            command = [str(binary), *([str(case_work / "state.bin")] if kind == "persistence" else []), *arguments]
        status, raw = _execute(command, case_work)
        details = {"binary_sha256": metadata["sha256"], "command": command}
        if kind in ("tickets", "persistence"):
            details.update(clock="explicit integer event timestamps; now is not used by StateTracker",
                           native_config_supported_threshold=inputs["maxretry"] <= 128)
        if status == "output_limit":
            return _result("error", raw=raw, output_limit_reached=True,
                           captured_output_limit_bytes=1024 * 1024, **details)
        if status != "ok":
            return _result(status, raw=raw, **details)
        decoded = load_json(raw["stdout"])
        if not isinstance(decoded, dict):
            raise ValueError("candidate probe result must be an object")
        if kind in ("config", "effective_config"):
            if set(decoded) != {"value", "warnings"} or not (decoded["value"] is None or isinstance(decoded["value"], str)):
                raise ValueError("invalid config probe result")
            if not _integer(decoded["warnings"], 0, 2 ** 64 - 1):
                raise ValueError("invalid config warning counter")
            observations = [{"event": "config", "sequence": 0, "values": {"value": decoded["value"]}}]
            details["warnings"] = decoded["warnings"]
            if kind == "effective_config":
                details.update(observation_layer="production importConfig + Config.loadFile + resolveJail",
                               value_representation="production effective u32 maxretry rendered as decimal",
                               imported_config_sha256=_digest(case_work / "imported.toml"))
        elif kind == "ssh_log":
            if (set(decoded) != {"identity", "result"}
                    or not (decoded["identity"] is None or isinstance(decoded["identity"], str))
                    or decoded["result"] not in ("matched", "ignored")
                    or (decoded["identity"] is None) != (decoded["result"] == "ignored")):
                raise ValueError("invalid native SSH matcher result")
            observations = [{"event": "match", "sequence": 0, "values": decoded}]
            details.update(observation_layer="production stripSyslogPrefix + builtin sshd pattern matcher",
                           timestamps_compared=False)
        elif kind == "tickets":
            trace = decoded.get("trace")
            if set(decoded) != {"trace"} or not isinstance(trace, list) or len(trace) != len(inputs["events"]):
                raise ValueError("invalid ticket trace shape")
            for value in trace:
                _validate_ticket(value)
            observations = [{"event": "ticket", "sequence": index, "values": value} for index, value in enumerate(trace)]
        else:
            if set(decoded) != {"persisted", "restored"}:
                raise ValueError("invalid persistence probe result")
            for value in decoded.values():
                _validate_ticket(value, persistence=True)
            observations = [{"event": event, "sequence": index, "values": decoded[event]}
                            for index, event in enumerate(("persisted", "restored"))]
            details.update(candidate_only=True, restart_scope="tracker destroyed then recreated in same process",
                           state_sha256=_digest(case_work / "state.bin"))
        return _result("ok", observations, raw, **details)
    except (OSError, ValueError, TypeError, KeyError) as error:
        return _result("error", raw=locals().get("raw"), reason=f"{type(error).__name__}: {error}")
