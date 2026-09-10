#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""D4 clock/ticket contracts using real pinned reference code and an optional prebuilt candidate probe."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REFERENCE_COMMIT = "f60978618a101427b06924fc932b44350fec2b63"
NOW = 1_800_000_000
WORKER = r'''
import json, logging, resource, sys
from types import SimpleNamespace
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
request = json.loads(sys.stdin.read(16385))
sys.path.insert(0, sys.argv[1])
from fail2ban.server.filter import Filter
from fail2ban.server.failmanager import FailManager, FailManagerEmpty
from fail2ban.server.ticket import FailTicket
from fail2ban.server.ipdns import IPAddr
from fail2ban.server.mytime import MyTime
from fail2ban.server.observer import ObserverThread, Observers
MyTime.setTime(request['now'])
if Observers.Main is not None:
    raise RuntimeError('unexpected running observer')
errors = []
class ErrorCollector(logging.Handler):
    def emit(self, record):
        errors.append(record.getMessage())
error_collector = ErrorCollector(level=logging.ERROR)
logging.getLogger().addHandler(error_collector)
address = IPAddr('192.0.2.10')

def pending(manager):
    # Read-only inspection of the pinned object's retained ticket, not a replacement algorithm.
    item = manager._FailManager__failList.get(address)
    return {'pending_retry': manager.getFailCount()[1],
            'pending_last_time': item.getTime() if item is not None else None}

def make_filter():
    item = Filter(None, useDns='raw')
    item.ignoreSelf = False  # Avoid self-address discovery; ignore behavior is out of scope.
    item.setFindTime(request['findtime'])
    item.setMaxRetry(1024)  # No action or jail ticket dispatch in these filter fixtures.
    item.addFailRegex(r'^synthetic failure from <ADDR>$')
    item.inOperation = request['live']
    return item

if request['operation'] == 'filter':
    line = ('', '', 'synthetic failure from 192.0.2.10')
    matcher = make_filter()
    parsed = matcher.processLine(line, request['event'])
    stored = make_filter()
    stored.processLineAndAdd(line, request['event'])
    if stored._errors:
        raise RuntimeError('reference suppressed a filter processing error')
    result = {'matched': bool(parsed), 'parsed_time': parsed[0][2] if parsed else None,
              'stored_time': pending(stored.failManager)['pending_last_time'],
              'pending_retry': pending(stored.failManager)['pending_retry']}
elif request['operation'] in ('manager', 'cleanup'):
    manager = FailManager()
    manager.setMaxTime(request['findtime'])
    manager.setMaxRetry(request['maxretry'])
    trace = []
    for event in request['events']:
        item = FailTicket(address, event, matches=['original synthetic record'], data={'failures': 1})
        manager.addFailure(item)
        reached = False
        try:
            manager.toBan(address)  # Ticket extraction only; no actions or real ban.
            reached = True
        except FailManagerEmpty:
            pass
        trace.append(dict(pending(manager), threshold_reached=reached))
    if request['operation'] == 'cleanup':
        manager.cleanup(request['cleanup_time'])
        result = pending(manager)
    else:
        result = {'trace': trace}
elif request['operation'] == 'history_weight':
    manager = FailManager()
    manager.setMaxRetry(100)
    item = FailTicket(address, request['event'], data={'failures': 1})
    manager.addFailure(item)
    history = SimpleNamespace(getBan=lambda ip, jail: [
        (request['history_count'], request['history_time'], 60)])
    jail = SimpleNamespace(isAlive=lambda: True, getBanTimeExtra=lambda key: True,
                           name='synthetic', database=history,
                           filter=SimpleNamespace(failManager=manager))
    # Real observer calculation invoked synchronously; no ObserverThread is started.
    ObserverThread.failureFound(None, jail, item)
    result = dict(pending(manager), ticket_ban_count=item.getBanCount())
else:
    raise RuntimeError('unknown fixture operation')
if errors:
    raise RuntimeError('reference logged processing errors: ' + repr(errors))
print(json.dumps({'status': 'ok', 'result': result}))
'''


def filter_case(case_id, live, offset, parsed_offset, stored_offset):
    event = NOW + offset
    expected = {'matched': parsed_offset is not None,
                'parsed_time': NOW + parsed_offset if parsed_offset is not None else None,
                'stored_time': NOW + stored_offset if stored_offset is not None else None,
                'pending_retry': int(stored_offset is not None)}
    return (case_id, 'TIME-01', {'operation': 'filter', 'live': live, 'event': event,
                               'findtime': 600}, expected, False)


CASES = [
    filter_case('parity-time-startup-old', False, -601, None, None),
    filter_case('parity-time-startup-equality', False, -600, -600, -600),
    filter_case('parity-time-startup-inside', False, -599, -599, -599),
    filter_case('parity-time-live-past-61', True, -61, 0, 0),
    filter_case('parity-time-live-past-60', True, -60, -60, -60),
    filter_case('parity-time-live-past-fraction', True, -60.9, -60.9, -60.9),
    filter_case('parity-time-live-future-60', True, 60, 60, 0),
    filter_case('parity-time-live-future-fraction', True, 60.9, 60.9, 0),
    filter_case('parity-time-live-future-61', True, 61, 0, 0),
    filter_case('parity-time-startup-future', False, 61, 61, 0),
]


def manager_case(case_id, offsets, retries, times, threshold=None, maxretry=10):
    trace = [{'pending_retry': retry,
              'pending_last_time': NOW + time if time is not None else None,
              'threshold_reached': index == threshold}
             for index, (retry, time) in enumerate(zip(retries, times))]
    return (case_id, 'POL-01', {'operation': 'manager', 'events': [NOW + x for x in offsets],
                               'findtime': 600, 'maxretry': maxretry}, {'trace': trace}, True)


CASES += [
    manager_case('parity-ticket-burst', [0, 1, 2], [1, 2, 3], [0, 1, 2]),
    manager_case('parity-ticket-window-equality', [0, 600], [1, 2], [0, 600]),
    manager_case('parity-ticket-rate-retention', [0, 1, 2, 601], [1, 2, 3, 4], [0, 1, 2, 601]),
    manager_case('parity-ticket-rate-threshold', [0, 1, 2, 601], [1, 2, 3, 0],
                 [0, 1, 2, None], threshold=3, maxretry=4),
    manager_case('parity-ticket-rate-decay', [0, 1, 2, 900], [1, 2, 3, 3], [0, 1, 2, 900]),
    manager_case('parity-ticket-out-of-order', [100, 0], [1, 2], [100, 100]),
    manager_case('parity-ticket-129-threshold', [0] * 129, list(range(1, 129)) + [0],
                 [0] * 128 + [None], threshold=128, maxretry=129),
]
for offset, expected in ((599, {'pending_retry': 1, 'pending_last_time': NOW}),
                         (600, {'pending_retry': 0, 'pending_last_time': None}),
                         (601, {'pending_retry': 0, 'pending_last_time': None})):
    CASES.append((f'parity-ticket-cleanup-{offset}', 'POL-01',
                  {'operation': 'cleanup', 'findtime': 600, 'maxretry': 1000,
                   'events': [NOW], 'cleanup_time': NOW + offset}, expected, False))
for count, event, weight, stored_count in ((1, NOW, 2, 1), (2, NOW, 3, 2),
                                          (2, NOW - 100, 1, 0)):
    CASES.append((f'parity-ticket-history-{count}-{event - NOW}', 'POL-03',
                  {'operation': 'history_weight', 'history_count': count,
                   'history_time': NOW - 100, 'event': event},
                  {'pending_retry': weight, 'pending_last_time': event,
                   'ticket_ban_count': stored_count}, False))


def run(args, *, cwd=None, payload=None, timeout=15):
    result = subprocess.run(args, cwd=cwd, input=payload, text=True, capture_output=True,
                            timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}): {args[0]}: {result.stderr[:4096]}')
    return result.stdout.strip(), result.stderr


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference_check(reference):
    commit, _ = run(['git', 'rev-parse', 'HEAD'], cwd=reference)
    if commit != REFERENCE_COMMIT:
        raise RuntimeError('reference commit mismatch')
    run(['git', 'diff', '--exit-code', 'HEAD', '--'], cwd=reference)
    untracked, _ = run(['git', 'ls-files', '--others', '--exclude-standard'], cwd=reference)
    if untracked:
        raise RuntimeError('reference contains untracked files')


def validate_result(value):
    if not isinstance(value, dict):
        raise RuntimeError('malformed probe JSON object')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--candidate-probe', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    reference = args.reference.resolve()
    reference_check(reference)
    reference_hashes = {p.relative_to(reference).as_posix(): sha(p)
                        for p in sorted((reference / 'fail2ban').rglob('*.py'))}
    owned = ['tests/parity/time_baseline.py', 'tests/parity/time_probe.zig']
    candidate_sources = ['engine/core/state.zig', 'shared/root.zig', 'shared/types.zig',
                         'shared/protocol.zig']
    source_hashes = {p: sha(ROOT / p) for p in owned + candidate_sources}
    candidate = args.candidate_probe.resolve() if args.candidate_probe else None
    candidate_hash = sha(candidate) if candidate else None
    report = {'schema_version': 1, 'reference_commit': REFERENCE_COMMIT,
              'scope': 'P0 D4 reference clock/ticket contracts; optional real StateTracker comparison only',
              'reference_python_sources': reference_hashes, 'sources': source_hashes,
              'candidate_probe_sha256': candidate_hash,
              'candidate_branch': run(['git', 'branch', '--show-current'], cwd=ROOT)[0],
              'candidate_head': run(['git', 'rev-parse', 'HEAD'], cwd=ROOT)[0],
              'python_version': sys.version, 'kernel': platform.release(),
              'clock': {'source': 'MyTime.setTime', 'now': NOW},
              'namespaces': {name: os.readlink(f'/proc/self/ns/{name}') for name in ('user', 'net')},
              'limits': [
                  'No builds performed by this runner; optional candidate executable is caller supplied.',
                  'Caller must establish supplied executable provenance from recorded source hashes; binary hashing alone does not prove its build inputs.',
                  'Filter timestamp fixtures call real processLine/processLineAndAdd with an explicit parsed date; no date-pattern parsing is tested.',
                  'Candidate comparison exercises StateTracker directly, not private daemon lineCallback or real ingestion.',
                  'Manager fixtures explicitly omit periodic cleanup unless marked cleanup; traces are API semantics, not end-to-end scheduling.',
                  'History weighting invokes real ObserverThread.failureFound synchronously with synthetic history/jail collaborators; no SQLite or async queue proof.',
                  'No daemon, firewall, action, source file monitoring, DNS or network request; self-ignore discovery explicitly disabled.',
                  'Small bounded fixtures and worker resource limits only; no exhaustion, throughput or supervisor certification.',
              ], 'cases': []}
    with tempfile.TemporaryDirectory(prefix='f2z-time-contract-') as temporary:
        for case_id, requirement, request, expected, comparable in CASES:
            request = dict(request, now=NOW)
            payload = json.dumps(request)
            if len(payload.encode()) > 16384:
                raise RuntimeError('fixture exceeds worker input contract')
            stdout, stderr = run([sys.executable, '-I', '-B', '-X',
                                  f'pycache_prefix={temporary}/bytecode', '-c', WORKER, str(reference)],
                                 payload=payload)
            response = validate_result(json.loads(stdout))
            if response.get('status') != 'ok' or not isinstance(response.get('result'), dict):
                raise RuntimeError('malformed reference response')
            observed = response['result']
            item = {'id': case_id, 'requirement': requirement, 'fixture': request,
                    'expected_reference': expected, 'reference': observed,
                    'reference_stderr': stderr,
                    'reference_result': 'equal' if observed == expected else 'mismatch',
                    'candidate_comparison': 'not_run' if comparable else 'reference_only'}
            if candidate and comparable:
                output, candidate_stderr = run([str(candidate), str(request['findtime']),
                                                str(request['maxretry']),
                                                ','.join(map(str, request['events']))])
                actual = validate_result(json.loads(output))
                if not isinstance(actual.get('trace'), list):
                    raise RuntimeError('malformed candidate trace')
                item.update(candidate=actual, candidate_stderr=candidate_stderr,
                            candidate_comparison='equal' if observed == actual else 'mismatch')
            report['cases'].append(item)
    reference_check(reference)
    if reference_hashes != {p.relative_to(reference).as_posix(): sha(p)
                            for p in sorted((reference / 'fail2ban').rglob('*.py'))}:
        raise RuntimeError('reference source changed during run')
    if any(sha(ROOT / p) != h for p, h in source_hashes.items()):
        raise RuntimeError('probe/candidate source changed during run')
    if candidate and sha(candidate) != candidate_hash:
        raise RuntimeError('candidate probe changed during run')
    report['reference_equal'] = sum(x['reference_result'] == 'equal' for x in report['cases'])
    report['reference_mismatches'] = len(report['cases']) - report['reference_equal']
    report['candidate_equal'] = sum(x['candidate_comparison'] == 'equal' for x in report['cases'])
    report['candidate_mismatches'] = sum(x['candidate_comparison'] == 'mismatch' for x in report['cases'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['reference_equal']} reference contracts equal; {report['reference_mismatches']} reference mismatches; "
          f"{report['candidate_equal']} candidate equal; {report['candidate_mismatches']} candidate mismatches; {args.output}")
    return 1 if report['reference_mismatches'] or report['candidate_mismatches'] else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'time comparison error: {error}', file=sys.stderr)
        sys.exit(2)
