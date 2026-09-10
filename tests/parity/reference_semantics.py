#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Probe pinned reference filter semantics with original, ordinary synthetic records.

Run in a disposable user/network namespace. This tests compatibility contracts,
not the candidate implementation. No jail thread, daemon or action is started.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile


REFERENCE_COMMIT = "f60978618a101427b06924fc932b44350fec2b63"
ROOT = Path(__file__).resolve().parents[2]
EVENT_TIME = 1_800_000_000

# Each subprocess has fresh isolated imports. Resource controls are a prototype:
# the timeout control waits for a signal; it does not exercise pathological regex.
WORKER = r'''
import json, resource, signal, sys
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
request = json.loads(sys.stdin.read(4097))
if request['operation'] == 'timeout_control':
    print('deadline-control-ready', file=sys.stderr, flush=True)
    signal.pause()
if request['operation'] == 'failure_control':
    raise RuntimeError('intentional ordinary worker failure control')
sys.path.insert(0, sys.argv[1])
from fail2ban.server.failregex import FailRegex, RegexException
from fail2ban.server.filter import Filter
from fail2ban.server.ipdns import IPAddr

def identity(value):
    return {'value': str(value), 'family': value.familyStr,
            'prefix_length': value.plen if value.familyStr else None,
            'raw_identity': value.family == IPAddr.CIDR_RAW}

try:
    if request['operation'] == 'regex':
        matcher = FailRegex(request['pattern'], useDns='no')
        matcher.search([('', '', request['line'])])
        result = {'matched': matcher.hasMatched(), 'captures': {}}
        if result['matched']:
            result['captures'] = {
                key: value for key, value in matcher.getGroups().items()
                if value is not None
            }
    else:
        matcher = Filter(None, useDns='raw')
        if request.get('prefix'):
            matcher.prefRegex = request['prefix']
        matcher.addFailRegex(request['pattern'])
        failures = matcher.findFailure(('', '', request['line']), request['time'])
        result = {'tickets': []}
        for regex_index, fail_id, timestamp, data in failures:
            item = {'identity': identity(fail_id), 'time': timestamp,
                    'regex_index': regex_index}
            if data.get('ip') is not None:
                item['address'] = identity(data['ip'])
            result['tickets'].append(item)
    print(json.dumps({'status': 'ok', 'result': result}))
except RegexException:
    print(json.dumps({'status': 'invalid_regex'}))
'''


def ticket(value, family, raw=False, address=None, prefix=None):
    if prefix is None and family is not None:
        prefix = int(value.split("/")[1]) if "/" in value else 32 if family == "inet4" else 128
    result = {"identity": {"value": value, "family": family, "raw_identity": raw,
                           "prefix_length": prefix},
              "time": EVENT_TIME, "regex_index": 0}
    if address is not None:
        result["address"] = {"value": address, "family": "inet4", "raw_identity": False,
                             "prefix_length": 32}
    return {"status": "ok", "result": {"tickets": [result]}}


CASES = [
    ("parity-flt-capture-positive", "FLT-04-CAPTURE", {
        "operation": "regex",
        "pattern": r"^account <F-USER>[a-z]+</F-USER> confirms (?P=user) source <ADDR> port <F-PORT/>$",
        "line": "account alice confirms alice source 192.0.2.10 port https",
    }, {"status": "ok", "result": {"matched": True, "captures": {
        "user": "alice", "ip4": "192.0.2.10", "fport": "https"}}}),
    ("parity-flt-capture-negative", "FLT-03-RE", {
        "operation": "regex",
        "pattern": r"^account <F-USER>[a-z]+</F-USER> confirms (?P=user) source <ADDR>$",
        "line": "account alice confirms bob source 192.0.2.10",
    }, {"status": "ok", "result": {"matched": False, "captures": {}}}),
    ("parity-flt-flags-lookahead", "FLT-03-RE", {
        "operation": "regex",
        "pattern": r"^(?i:notice) (?=source )source <ADDR>$",
        "line": "NOTICE source 2001:db8::10",
    }, {"status": "ok", "result": {"matched": True,
        "captures": {"ip6": "2001:db8::10"}}}),
    ("parity-flt-raw-identity", "FLT-04-RAWID", {
        "operation": "filter", "pattern": r"^account <F-ID>\w+</F-ID> denied$",
        "line": "account alice denied",
    }, ticket("alice", None, raw=True)),
    ("parity-flt-identity-and-address", "FLT-04-RAWID", {
        "operation": "filter",
        "pattern": r"^account <F-ID>\w+</F-ID> source <ADDR> denied$",
        "line": "account alice source 192.0.2.10 denied",
    }, ticket("alice", None, raw=True, address="192.0.2.10")),
    ("parity-flt-raw-negative", "FLT-04-RAWID", {
        "operation": "filter", "pattern": r"^account <F-ID>\w+</F-ID> denied$",
        "line": "account alice accepted",
    }, {"status": "ok", "result": {"tickets": []}}),
    ("parity-flt-cidr4-network", "FLT-03-SUBNET", {
        "operation": "filter", "pattern": r"^network <SUBNET> denied$",
        "line": "network 192.0.2.129/24 denied",
    }, ticket("192.0.2.0/24", "inet4")),
    ("parity-flt-cidr6-network", "FLT-03-SUBNET", {
        "operation": "filter", "pattern": r"^network <SUBNET> denied$",
        "line": "network 2001:db8::1234/64 denied",
    }, ticket("2001:db8::/64", "inet6")),
    ("parity-flt-cidr-host-boundary", "FLT-03-SUBNET", {
        "operation": "filter", "pattern": r"^network <SUBNET> denied$",
        "line": "network 192.0.2.10/32 denied",
    }, ticket("192.0.2.10", "inet4")),
    ("parity-flt-cidr-zero-boundary", "FLT-03-SUBNET", {
        "operation": "filter", "pattern": r"^network <SUBNET> denied$",
        "line": "network 192.0.2.10/0 denied",
    }, ticket("0.0.0.0", "inet4", prefix=0)),
    ("parity-flt-cidr-zero-host-distinct", "FLT-03-SUBNET", {
        "operation": "filter", "pattern": r"^network <SUBNET> denied$",
        "line": "network 0.0.0.0/32 denied",
    }, ticket("0.0.0.0", "inet4", prefix=32)),
    ("parity-flt-prefix-identity", "FLT-04-PREFIX", {
        "operation": "filter",
        "prefix": r"^source <ADDR> <F-CONTENT>.*</F-CONTENT>$",
        "pattern": r"^account <F-ID>\w+</F-ID> denied$",
        "line": "source 192.0.2.10 account alice denied",
    }, ticket("alice", None, raw=True, address="192.0.2.10")),
    ("parity-flt-invalid-regex", "FLT-03-RE", {
        "operation": "regex", "pattern": "[", "line": "ordinary record",
    }, {"status": "invalid_regex"}),
    ("parity-worker-failure-control", "D1", {
        "operation": "failure_control",
    }, {"status": "worker_error"}),
    ("parity-worker-deadline-control", "D1", {
        "operation": "timeout_control",
    }, {"status": "deadline_exceeded"}),
]


def command(args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True,
                          text=True, timeout=15).stdout.strip()


def check_reference(reference):
    commit = command(["git", "rev-parse", "HEAD"], reference)
    if commit != REFERENCE_COMMIT:
        raise RuntimeError(f"reference commit mismatch: {commit}")
    command(["git", "diff", "--exit-code", "HEAD", "--"], reference)
    if command(["git", "ls-files", "--others", "--exclude-standard"], reference):
        raise RuntimeError("reference checkout has untracked files")


def hashes(reference):
    return {path.relative_to(reference).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((reference / "fail2ban").rglob("*.py"))}


def probe(reference, work, request):
    request = dict(request, time=EVENT_TIME)
    payload = json.dumps(request)
    if len(payload.encode()) > 4096:
        raise ValueError("synthetic fixture exceeds input contract")
    timeout = 0.5 if request["operation"] == "timeout_control" else 10
    args = [sys.executable, "-I", "-B", "-X", f"pycache_prefix={work / 'bytecode'}",
            "-c", WORKER, str(reference)]
    try:
        result = subprocess.run(args, input=payload, capture_output=True,
                                text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        # subprocess.run kills and reaps this worker before returning the error.
        stderr = error.stderr or b""
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        status = "deadline_exceeded"
        if request["operation"] == "timeout_control" and "deadline-control-ready" not in stderr:
            status = "worker_startup_deadline"
        return {"status": status}, {"deadline_seconds": timeout, "stderr": stderr}
    evidence = {"returncode": result.returncode, "stdout": result.stdout,
                "stderr": result.stderr, "deadline_seconds": timeout}
    if result.returncode:
        if (request["operation"] == "failure_control"
                and "intentional ordinary worker failure control" not in result.stderr):
            return {"status": "unexpected_worker_error"}, evidence
        return {"status": "worker_error"}, evidence
    observed = json.loads(result.stdout)
    if not isinstance(observed, dict) or "status" not in observed:
        raise ValueError("malformed worker response")
    return observed, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reference = args.reference.resolve()
    check_reference(reference)
    source_hashes = hashes(reference)
    test_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    # Outcome categories must never collapse into an ordinary clean no-match.
    no_match = {"status": "ok", "result": {"matched": False, "captures": {}}}
    if any(no_match == {"status": status} for status in
           ("worker_error", "deadline_exceeded", "invalid_regex")):
        raise RuntimeError("failure/no-match distinction control failed")
    report = {
        "schema_version": 1,
        "scope": "P0 D1/D3 reference-only contract prototype; no candidate parity certification",
        "reference_commit": REFERENCE_COMMIT,
        "reference_python_sources": source_hashes,
        "test_sha256": test_hash,
        "candidate_branch": command(["git", "branch", "--show-current"], ROOT),
        "candidate_head": command(["git", "rev-parse", "HEAD"], ROOT),
        "python_version": sys.version,
        "kernel": platform.release(),
        "event_time": EVENT_TIME,
        "expectation_review": [{
            "case": "parity-flt-cidr-zero-boundary",
            "initial_expected_display": "0.0.0.0/0",
            "initial_observed_display": "0.0.0.0",
            "disposition": "Reference source review confirmed zero-prefix display omission; preserve prefix_length independently and compare /0 versus /32.",
            "source": "fail2ban/server/ipdns.py:559",
        }],
        "limits": [
            "Original small synthetic records only; no daemon, action, DNS or network requests.",
            "Timeout uses signal.pause control, not pathological matching or exhaustion.",
            "Process CPU/address-space limits are configured, not exhaustion-tested.",
            "Known small worker output only; this is not a general bounded-output supervisor.",
            "No worker child-process cancellation, state recovery or throughput claim.",
            "Outer user/network namespace isolation must be supplied by the caller.",
        ],
        "cases": [],
    }
    with tempfile.TemporaryDirectory(prefix="f2z-reference-semantics-") as temporary:
        for case_id, requirement, request, expected in CASES:
            observed, evidence = probe(reference, Path(temporary), request)
            report["cases"].append({
                "id": case_id, "requirement": requirement, "fixture": request,
                "expected": expected, "observed": observed, "worker": evidence,
                "result": "equal" if observed == expected else "mismatch",
            })
    check_reference(reference)
    if source_hashes != hashes(reference):
        raise RuntimeError("reference sources changed during probe")
    if test_hash != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise RuntimeError("contract test changed during probe")
    report["equal"] = sum(case["result"] == "equal" for case in report["cases"])
    report["mismatches"] = len(report["cases"]) - report["equal"]
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['equal']} reference contracts equal; {report['mismatches']} mismatches; {args.output}")
    return 1 if report["mismatches"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"reference semantics error: {error}", file=sys.stderr)
        sys.exit(2)
