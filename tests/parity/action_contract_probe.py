#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Original in-memory action recorders driven by pinned reference dispatch methods.

Run using unshare --user --map-root-user --net and Python -I -B.
No configured/custom action module is loaded; the reference action classes are
imported. No command, daemon or thread starts, and no external effect occurs.
This is a reference contract probe, not an executor.
"""

import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import platform
import sys
import tempfile
import threading
from types import SimpleNamespace

REFERENCE_COMMIT = "f60978618a101427b06924fc932b44350fec2b63"
REFERENCE_PYTHON_MANIFEST = "441290735615a4f70dd72df993fe94e4a3f261bf5646a64573e1d1d7eaa6187e"
ROOT = Path(__file__).resolve().parents[2]
EVENT_TIME = 1_800_000_000
SUBJECT = "192.0.2.40"


def source_hashes(reference):
    return {p.relative_to(reference).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((reference / "fail2ban").rglob("*.py"))}


def checkout_identity(root):
    """Read HEAD metadata only; no git process or index mutation."""
    metadata = root / ".git"
    if metadata.is_file():
        text = metadata.read_text().strip()
        if not text.startswith("gitdir: "):
            raise ValueError("unrecognized git metadata")
        metadata = (root / text[8:]).resolve()
    head = (metadata / "HEAD").read_text().strip()
    if not head.startswith("ref: "):
        return "detached", head
    name = head[5:]
    if not name.startswith("refs/") or ".." in Path(name).parts:
        raise ValueError("invalid HEAD reference")
    loose = metadata / name
    if loose.exists():
        return name.removeprefix("refs/heads/"), loose.read_text().strip()
    for line in (metadata / "packed-refs").read_text().splitlines():
        if line and not line.startswith(("#", "^")):
            commit, ref = line.split(" ", 1)
            if ref == name:
                return name.removeprefix("refs/heads/"), commit
    raise ValueError("HEAD reference missing")


def check_reference(reference):
    if checkout_identity(reference)[1] != REFERENCE_COMMIT:
        raise ValueError("reference HEAD differs from pinned commit")
    hashes = source_hashes(reference)
    digest = hashlib.sha256(json.dumps(hashes, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    if digest != REFERENCE_PYTHON_MANIFEST:
        raise ValueError("reference Python sources differ from pinned manifest")
    return hashes


def isolation_record():
    uid_map = Path("/proc/self/uid_map").read_text().strip()
    ranges = [list(map(int, line.split())) for line in uid_map.splitlines()]
    interfaces = sorted(line.split(":", 1)[0].strip()
                        for line in Path("/proc/net/dev").read_text().splitlines()[2:])
    if len(ranges) != 1 or ranges[0][0] != 0 or ranges[0][2] != 1 or interfaces != ["lo"]:
        raise ValueError("run in disposable user/network namespaces with --map-root-user")
    return {"uid_map": uid_map, "interfaces": interfaces,
            "user_namespace": os.readlink("/proc/self/ns/user"),
            "network_namespace": os.readlink("/proc/self/ns/net"),
            "filesystem_isolated": False}


def run_contracts(reference):
    denied = []

    def forbid_external(event, _args):
        if event.startswith("subprocess.") or event in {
            "os.system", "os.posix_spawn", "os.fork", "os.forkpty", "socket.__new__"
        }:
            denied.append(event)
            raise RuntimeError("contract probe forbids external execution/network")

    sys.addaudithook(forbid_external)
    sys.path.insert(0, str(reference))
    from fail2ban.server.actions import Actions
    from fail2ban.server.action import ActionBase
    from fail2ban.server.ipdns import IPAddr
    from fail2ban.server.mytime import MyTime
    from fail2ban.server.observer import Observers
    from fail2ban.server.ticket import BanTicket
    from fail2ban.server.utils import Utils

    def forbidden_helper(*_args, **_kwargs):
        denied.append("reference command/module helper")
        raise RuntimeError("contract probe never loads action modules or commands")

    Utils.executeCmd = forbidden_helper
    Utils.load_python_module = forbidden_helper
    if Observers.Main is not None:
        raise RuntimeError("probe requires no observer thread")
    error_events = []

    class ErrorCapture(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.ERROR:
                error_events.append({"level": record.levelname,
                                     "message": record.getMessage()})

    logging.getLogger("fail2ban").addHandler(ErrorCapture())
    logging.getLogger("fail2ban").propagate = False
    logging.getLogger("fail2ban").setLevel(logging.ERROR)

    class Recorder(ActionBase):
        def __init__(self, jail, name, calls, effects, contexts, *, fail=None,
                     norestored=False, prolongable=False, mutate=False):
            super().__init__(jail, name)
            self.calls, self.effects, self.contexts = calls, effects, contexts
            self.fail = fail or {}
            self.norestored = norestored
            self.supports_prolong = prolongable
            self.mutate = mutate
            self.effects[name] = set()

        @property
        def _prolongable(self):
            return self.supports_prolong

        def record(self, verb, info=None):
            self.calls.append(self._name + ":" + verb)
            if info is not None:
                # Select data-only fields; never evaluate DNS/history/service accessors.
                context = {k: info[k] for k in ("time", "bantime", "failures", "restored")}
                context.update(fid=str(info["fid"]), ip=str(info["ip"]))
                self.contexts.append({"action": self._name, "verb": verb, **context})
            failure = self.fail.get(verb)
            if failure == "before":
                raise RuntimeError("original recorder failure before fake effect")
            if failure == "false":
                return False
            if info is not None and verb == "ban":
                self.effects[self._name].add(str(info["fid"]))
            elif info is not None and verb == "unban":
                self.effects[self._name].discard(str(info["fid"]))
            if self.mutate and info is not None:
                info["ip"] = "192.0.2.99"
            if failure == "after":
                raise RuntimeError("original recorder failure after fake effect")
            return None

        def start(self):
            return self.record("start")

        def stop(self):
            return self.record("stop")

        def ban(self, info):
            return self.record("ban", info)

        def unban(self, info):
            return self.record("unban", info)

        def prolong(self, info):
            return self.record("prolong", info)

    class FlushRecorder(Recorder):
        def flush(self):
            self.calls.append(self._name + ":flush")
            self.effects[self._name].clear()
            return True

    def fixture(specs):
        MyTime.setTime(EVENT_TIME)
        calls, contexts, effects = [], [], {}
        jail = SimpleNamespace(name="synthetic-jail", database=None)
        manager = Actions(jail)
        jail.actions = manager
        manager.setBanTime(60)
        for name, options in specs:
            options = dict(options)
            cls = FlushRecorder if options.pop("flush", False) else Recorder
            # Intentional test seam: bypass Actions.add and every extension loader.
            manager._actions[name] = cls(jail, name, calls, effects, contexts, **options)
        return manager, calls, effects, contexts

    def ticket(restored=False, time=EVENT_TIME):
        item = BanTicket(IPAddr(SUBJECT), time, data={"failures": 3, "matches": ["synthetic denial"]})
        item.setBanTime(60)
        item.restored = restored
        return item

    def current(manager):
        return sorted(str(ip) for ip in manager.getBanList())

    def ban(manager, item):
        return manager._Actions__checkBan([item])

    def pair(**first):
        return [("first", first), ("second", {})]

    results = []

    def case(case_id, requirements, specs, exercise, expected_error_prefixes=()):
        error_events.clear()
        manager, calls, effects, contexts = fixture(specs)
        checks = []

        def check(name, observed, expected):
            checks.append({"name": name, "observed": observed, "expected": expected,
                           "equal": observed == expected})

        exercise(manager, calls, effects, contexts, check)
        check("error_event_count", len(error_events), len(expected_error_prefixes))
        check("error_levels", [event["level"] for event in error_events],
              ["ERROR"] * len(expected_error_prefixes))
        check("error_message_prefixes",
              [event["message"].startswith(prefix)
               for event, prefix in zip(error_events, expected_error_prefixes)],
              [True] * len(expected_error_prefixes))
        results.append({"id": case_id, "requirement_ids": requirements,
                        "fixture": {"time": EVENT_TIME, "subject": SUBJECT,
                                    "actions": [{"name": n, **o} for n, o in specs]},
                        "checks": checks, "calls": calls, "contexts": contexts,
                        "error_events": error_events.copy(),
                        "expected_error_prefixes": list(expected_error_prefixes),
                        "fake_observed_effects": {n: sorted(v) for n, v in effects.items()},
                        "result": "equal" if all(c["equal"] for c in checks) else "mismatch"})

    def start_stop(m, calls, effects, contexts, check):
        m.active = False
        Actions.run(m)  # synchronous call: loop is skipped, no thread is started
        check("order", calls, ["first:start", "second:start", "second:stop", "first:stop"])
        check("actions_removed", len(m), 0)

    case("parity-act-start-stop", ["ACT-03-START", "ACT-03-FLUSH"], pair(), start_stop)
    case("parity-act-start-failure-continues", ["ACT-04-MULTI", "ACT-08-PARTIAL"],
         pair(fail={"start": "before"}), start_stop, ("Failed to start jail",))

    def ordinary(m, calls, effects, contexts, check):
        item = ticket()
        check("admitted", ban(m, item), 1)
        check("calls", calls, ["first:ban", "second:ban"])
        check("legacy_banned_flag", item.banned, 8)
        check("legacy_list", current(m), [SUBJECT])
        check("fake_realized_first", sorted(effects["first"]), [SUBJECT])
        check("fake_realized_second", sorted(effects["second"]), [SUBJECT])

    case("parity-act-ordered-ban", ["ACT-04-MULTI", "ACT-03-TAGS"], pair(), ordinary)

    def partial(first_present):
        def exercise(m, calls, effects, contexts, check):
            item = ticket()
            check("admitted", ban(m, item), 1)
            check("calls", calls, ["first:ban", "second:ban"])
            check("legacy_banned_flag_despite_result", item.banned, 8)
            check("legacy_list", current(m), [SUBJECT])
            check("fake_realized_first", sorted(effects["first"]), [SUBJECT] if first_present else [])
            check("fake_realized_second", sorted(effects["second"]), [SUBJECT])
        return exercise

    for mode in ("before", "after", "false"):
        case("parity-act-ban-" + mode, ["ACT-08-PARTIAL", "ACT-04-MULTI"],
             pair(fail={"ban": mode}), partial(mode == "after"),
             ("Failed to execute ban jail",) if mode != "false" else ())

    def restored(m, calls, effects, contexts, check):
        item = ticket(restored=True)
        check("admitted", ban(m, item), 1)
        check("ban_skipped_only_first", calls.copy(), ["second:ban"])
        check("restore_context", contexts[0]["restored"], 1)
        check("unban_result", m.removeBannedIP(IPAddr(SUBJECT), db=False), 1)
        check("unban_has_no_restore_skip", calls, ["second:ban", "first:unban", "second:unban"])
        check("legacy_empty", current(m), [])

    case("parity-act-restored-policy", ["ACT-03-RESTORED", "ACT-03-FLUSH"],
         pair(norestored=True), restored)

    def prolong(restored_value=False, absent=False):
        def exercise(m, calls, effects, contexts, check):
            item = ticket(restored=restored_value)
            if not absent:
                ban(m, item)
            calls.clear()
            item.setBanTime(120)
            m._prolongBan(item)
            check("prolong_calls", calls, [] if absent or restored_value else ["first:prolong"])
            check("legacy_list", current(m), [] if absent else [SUBJECT])
        return exercise

    for name, is_restored, absent in [("selected", False, False), ("restored", True, False),
                                      ("absent", False, True)]:
        case("parity-act-prolong-" + name, ["ACT-03-PROLONG", "ACT-03-RESTORED"],
             pair(prolongable=True, norestored=True), prolong(is_restored, absent))

    def unban_failure(m, calls, effects, contexts, check):
        ban(m, ticket())
        calls.clear()
        check("unban_result", m.removeBannedIP(IPAddr(SUBJECT), db=False), 1)
        check("unban_continues", calls, ["first:unban", "second:unban"])
        check("legacy_empty_despite_failure", current(m), [])
        check("first_effect_still_present", sorted(effects["first"]), [SUBJECT])
        check("second_effect_removed", sorted(effects["second"]), [])

    case("parity-act-unban-failure", ["ACT-08-PARTIAL", "ACT-04-MULTI"],
         pair(fail={"unban": "before"}), unban_failure,
         ("Failed to execute unban jail",))

    def reban(failing):
        def exercise(m, calls, effects, contexts, check):
            item = ticket()
            ban(m, item)
            calls.clear()
            if failing:
                m._actions["first"].fail["ban"] = "before"
            check("reban_result", m._Actions__reBan(item), 0 if failing else 1)
            # Recorder inherits ActionBase.reban, which delegates to ban.
            check("reban_dispatch", calls, ["first:ban"] if failing else ["first:ban", "second:ban"])
            check("legacy_ticket_retained", current(m), [SUBJECT])
        return exercise

    case("parity-act-reban-base", ["ACT-06-PYTHON", "ACT-03-PROLONG"], pair(), reban(False))
    case("parity-act-reban-failure-stops", ["ACT-08-PARTIAL", "ACT-03-PROLONG"],
         pair(), reban(True), ("Failed to execute reban jail",))

    def context_reset(m, calls, effects, contexts, check):
        ban(m, ticket())
        check("separate_action_context", [c["ip"] for c in contexts], [SUBJECT, SUBJECT])
        check("failure_metadata", [c["failures"] for c in contexts], [3, 3])
        check("ticket_time", [c["time"] for c in contexts], [EVENT_TIME, EVENT_TIME])

    case("parity-act-context-reset", ["ACT-03-TAGS", "ACT-04-MULTI"], pair(mutate=True), context_reset)

    def flush(m, calls, effects, contexts, check):
        ban(m, ticket())
        calls.clear()
        check("flush_ticket_count", m.removeBannedIP(None, db=False), 1)
        check("flush_and_fallback", calls, ["first:flush", "second:unban"])
        check("legacy_empty", current(m), [])
        check("fake_effects_empty", {n: sorted(v) for n, v in effects.items()}, {"first": [], "second": []})

    case("parity-act-flush-fallback", ["ACT-03-FLUSH"], pair(flush=True), flush)

    def expiry(m, calls, effects, contexts, check):
        ban(m, ticket())
        calls.clear()
        MyTime.setTime(EVENT_TIME + 60)
        check("at_end", m._Actions__checkUnBan(maxCount=10), 0)
        check("no_calls_at_end", calls.copy(), [])
        MyTime.setTime(EVENT_TIME + 61)
        check("past_end", m._Actions__checkUnBan(maxCount=10), 1)
        check("ordered_unban", calls, ["first:unban", "second:unban"])
        check("legacy_empty", current(m), [])

    case("parity-act-expiry-boundary", ["POL-02-B", "ACT-03-FLUSH"], pair(), expiry)
    MyTime.setTime(None)
    if denied:
        raise RuntimeError("reference attempted forbidden external operation: " + repr(denied))
    if threading.active_count() != 1:
        raise RuntimeError("unexpected thread started during synchronous probe")
    return results, denied


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reference = args.reference.resolve()
    output = args.output.resolve()
    if output.is_relative_to(reference) or output.is_relative_to(ROOT):
        parser.error("write generated report outside source checkouts")
    isolation = isolation_record()
    initial_hashes = check_reference(reference)
    test_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    sys.dont_write_bytecode = True
    with tempfile.TemporaryDirectory(prefix="f2z-action-contract-") as cache:
        # Prevent loading unrelated preexisting reference bytecode as well as writes.
        sys.pycache_prefix = cache
        cases, denied = run_contracts(reference)
    if check_reference(reference) != initial_hashes:
        raise RuntimeError("reference changed while running probe")
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != test_hash:
        raise RuntimeError("probe changed while running")
    branch, head = checkout_identity(ROOT)
    report = {"schema_version": 1, "scope": "P0 D2 in-memory pinned-reference action contract; no candidate executor validation",
              "reference_commit": REFERENCE_COMMIT, "reference_python_sources": initial_hashes,
              "reference_python_manifest_sha256": REFERENCE_PYTHON_MANIFEST,
              "test_sha256": test_hash, "candidate_branch": branch, "candidate_head": head,
              "python_version": sys.version, "kernel": platform.release(), "isolation": isolation,
              "external_operations_attempted": denied, "cases": cases,
              "expectation_review": [{"field": "Ticket.banned", "initial_expected": True,
                                      "observed": 8,
                                      "source": "fail2ban/server/ticket.py:169",
                                      "resolution": "Getter returns BANNED bitmask 0x08; compare exact reference value rather than assume a boolean."}],
              "harness_adjustments": ["Expiry dispatcher is supplied maxCount=10, as the reference Actions.run caller supplies a numeric limit; omitted private-method default None is not the live call contract."],
              "equal": sum(c["result"] == "equal" for c in cases),
              "mismatches": sum(c["result"] != "equal" for c in cases),
              "limits": ["Original Recorder/FlushRecorder objects only; Actions.add and module loading bypassed.",
                         "Private dispatcher entrypoints are pinned test seams, not a public ABI.",
                         "No threads, subprocess commands, DNS, providers, firewall, database or real effects.",
                         "Fake effects are test ground truth; action return values do not establish production realization.",
                         "ERROR counts, levels and message prefixes are checked; complete log formatting, tracebacks and other levels are not certified.",
                         "No privileged executor, queue persistence, process-tree cancellation, reconciliation or throughput implementation.",
                         "User/network namespaces do not isolate host filesystem; reference Python manifest is checked before and after."]}
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['equal']} action contracts equal; {report['mismatches']} mismatches; {output}")
    return 1 if report["mismatches"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"action contract probe could not complete: {error}", file=sys.stderr)
        raise SystemExit(2)
