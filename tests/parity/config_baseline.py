#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Compare real configuration readers using original, synthetic fixtures."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

REFERENCE_COMMIT = "f60978618a101427b06924fc932b44350fec2b63"
ROOT = Path(__file__).resolve().parents[2]
CASES = [
    ("parity-cfg-001", None, "2", {
        "jail.conf": "[probe]\nmaxretry = 2\n",
    }),
    ("parity-cfg-002", "SYS-026", "7", {
        "jail.conf": "[probe]\nmaxretry = 2\n",
        "jail.d/20-package.conf": "[probe]\nmaxretry = 3\n",
        "jail.local": "[probe]\nmaxretry = 7\n",
    }),
    ("parity-cfg-003", "SYS-026", "9", {
        "jail.conf": "[probe]\nmaxretry = 2\n",
        "jail.local": "[probe]\nmaxretry = 7\n",
        "jail.d/90-operator.local": "[probe]\nmaxretry = 9\n",
    }),
    ("parity-cfg-004", "SYS-027", "2", {
        "jail.conf": "[INCLUDES]\nbefore = common.conf\n[probe]\nenabled = true\n",
        "common.conf": "[probe]\nmaxretry = 2\n",
    }),
    ("parity-cfg-005", "SYS-027", "9", {
        "jail.conf": "[INCLUDES]\nafter = override.conf\n[probe]\nmaxretry = 2\n",
        "override.conf": "[probe]\nmaxretry = 9\n",
    }),
    ("parity-cfg-006", None, "4", {
        "jail.conf": "[DEFAULT]\nretrybase = 4\n[probe]\nmaxretry = %(retrybase)s\n",
    }),
]

# Only the reference's configuration reader runs: no server, filters, or actions.
REFERENCE_PROBE = """
import json, sys
sys.path.insert(0, sys.argv[1])
from fail2ban.client.configreader import ConfigReaderUnshared
reader = ConfigReaderUnshared(basedir=sys.argv[2])
if not reader.read('jail'):
    raise RuntimeError('reference could not read fixture')
print(json.dumps({'value': reader.get('probe', 'maxretry', fallback=None)}))
"""


def run(args, *, cwd=None, timeout=30):
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(args, cwd=cwd, env=env, check=True, text=True,
                          capture_output=True, timeout=timeout).stdout.strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare(reference, candidate):
    return reference["value"] == candidate["value"]


def decode_probe(output):
    result = json.loads(output)
    if not isinstance(result, dict) or "value" not in result:
        raise ValueError("probe response must be an object containing value")
    if result["value"] is not None and not isinstance(result["value"], str):
        raise ValueError("probe value must be a string or null")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reference = args.reference.resolve()
    commit = run(["git", "rev-parse", "HEAD"], cwd=reference)
    if commit != REFERENCE_COMMIT:
        raise RuntimeError(f"reference commit mismatch: {commit}")
    run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=reference)
    extra_sources = run(["git", "ls-files", "--others", "--exclude-standard"], cwd=reference)
    if extra_sources:
        raise RuntimeError("reference checkout contains untracked files")
    # An intentionally wrong result must be detected before collecting evidence.
    if compare({"value": "2"}, {"value": "3"}):
        raise RuntimeError("comparison failed its mismatch control")
    if not compare({"value": "2"}, {"value": "2"}):
        raise RuntimeError("comparison failed its equality control")

    source_paths = ["engine/config/fail2ban.zig", "tests/parity/config_probe.zig",
                    "tests/parity/config_baseline.py"]
    source_hashes = {name: digest(ROOT / name) for name in source_paths}
    report = {
        "schema_version": 1,
        "scope": "P0 config reader comparison only; not G0/G1 completion or certification",
        "reference_commit": commit,
        "candidate_branch": run(["git", "branch", "--show-current"], cwd=ROOT),
        "candidate_head": run(["git", "rev-parse", "HEAD"], cwd=ROOT),
        "candidate_sources": source_hashes,
        "zig_version": run(["zig", "version"]),
        "python_version": sys.version,
        "kernel": platform.release(),
        "comparison_controls": "passed",
        "cases": [],
    }
    with tempfile.TemporaryDirectory(prefix="f2z-parity-config-") as temporary:
        work = Path(temporary)
        binary = work / "config-probe"
        run(["zig", "build-exe", "-O", "ReleaseSafe", "--dep", "fail2ban_config",
             f"-Mroot={ROOT / 'tests/parity/config_probe.zig'}",
             f"-Mfail2ban_config={ROOT / 'engine/config/fail2ban.zig'}",
             f"-femit-bin={binary}"], cwd=ROOT, timeout=180)
        report["probe_sha256"] = digest(binary)
        for case_id, issue, expected_reference, files in CASES:
            fixture = work / case_id
            for name, content in files.items():
                path = fixture / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            observed_reference = decode_probe(run([
                sys.executable, "-I", "-B", "-X", f"pycache_prefix={work / 'bytecode'}",
                "-c", REFERENCE_PROBE, str(reference), str(fixture)]))
            if observed_reference["value"] != expected_reference:
                raise RuntimeError(f"{case_id}: reference behavior changed: {observed_reference}")
            observed_candidate = decode_probe(run([str(binary), str(fixture)]))
            report["cases"].append({
                "id": case_id, "requirement": "CFG-01", "issue": issue,
                "fixture_files": files, "reference": observed_reference,
                "candidate": observed_candidate,
                "result": "equal" if compare(observed_reference, observed_candidate) else "mismatch",
            })
    if any(digest(ROOT / name) != value for name, value in source_hashes.items()):
        raise RuntimeError("candidate sources changed during comparison")
    if run(["git", "rev-parse", "HEAD"], cwd=reference) != REFERENCE_COMMIT:
        raise RuntimeError("reference revision changed during comparison")
    run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=reference)
    report["equal"] = sum(case["result"] == "equal" for case in report["cases"])
    report["mismatches"] = len(report["cases"]) - report["equal"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['equal']} equal; {report['mismatches']} mismatches; {args.output}")
    return 1 if report["mismatches"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"comparison error: {error}", file=sys.stderr)
        sys.exit(2)
