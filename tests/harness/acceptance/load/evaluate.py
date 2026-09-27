#!/usr/bin/env python3
"""Evaluate existing B5 evidence; no daemon control and no product imports."""
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import sqlite3

PERMANENT = '198.19.9.9'
HOT = '198.18.250.1'


class SafetyFailure(ValueError):
    """A measured protection failure, rather than missing evidence."""


def field(value, name):
    found = []
    def visit(obj):
        if isinstance(obj, dict):
            for key, item in obj.items():
                if key == name:
                    found.append(item)
                elif isinstance(item, (dict, list)):
                    visit(item)
        elif isinstance(obj, list):
            for item in obj:
                visit(item)
    visit(value)
    if len(found) != 1 or found[0] is None:
        raise ValueError(f'missing/ambiguous status field: {name}')
    return found[0]


def status(obj):
    values = {k: field(obj, k) for k in ('committed_records', 'active_bans',
              'pending_bans', 'overdue_removals', 'overdue_bookkeeping',
              'knowledge', 'protection', 'storage', 'cause')}
    for key in ('committed_records', 'active_bans', 'pending_bans',
                'overdue_removals', 'overdue_bookkeeping'):
        if type(values[key]) is not int or values[key] < 0:
            raise ValueError(f'invalid status field: {key}')
    if values['storage'] == 'intervention':
        raise SafetyFailure('storage intervention')
    return values


def inventory(path):
    lines = path.read_text().splitlines()
    if not lines or not re.fullmatch(r'now_ms \d+', lines[0]):
        raise ValueError(f'incomplete oracle sample: {path}')
    if not lines[-1].startswith('summary '):
        raise ValueError(f'missing oracle summary: {path}')
    addresses = []
    for line in lines:
        if line.startswith('elem '):
            match = re.match(r'elem ([0-9.]+)/32\b', line)
            if not match:
                raise ValueError(f'unexpected element: {line}')
            addresses.append(match[1])
    start = int(lines[0].split()[1]) / 1000
    finishes = []
    for line in lines:
        if line.startswith('set '):
            m = re.search(r'dump_start_ms=(\d+) dump_latency_ms=(\d+)', line)
            if not m:
                raise ValueError('missing kernel dump timing')
            finishes.append((int(m[1])+int(m[2]))/1000)
    if set(addresses) and not finishes:
        raise ValueError('missing timing for observed kernel elements')
    return start, max([start]+finishes), set(addresses)


def sample(work, path, raw_status):
    work = Path(work)
    values = status(json.loads(raw_status))
    _, _, addresses = inventory(Path(path))
    if values['overdue_removals']:
        raise ValueError('overdue blocking removals reported')
    allowed = set()
    for name in ('portsentry.log', 'perm.log'):
        for line in (work / name).read_text().splitlines():
            match = re.match(r'\S+ Scan from: \[([0-9.]+)\]', line)
            if not match:
                raise ValueError('malformed generated input')
            allowed.add(match[1])
    foreign = addresses - allowed
    if foreign:
        raise ValueError(f'unexpected blocked subjects: {sorted(foreign)}')
    marker = work / 'permanent-seen'
    if marker.exists() and PERMANENT not in addresses:
        raise ValueError('permanent baseline disappeared during load')
    if PERMANENT in addresses and not marker.exists():
        marker.write_text('observed\n')


def metadata(args):
    work, binary, rate, load, hot, drain, bantime, clk = args
    values = [float(x) for x in (rate, load, hot, drain, bantime, clk)]
    if any(not math.isfinite(x) or x <= 0 for x in values):
        raise ValueError('all workload values must be finite and positive')
    rate, load, hot, drain, bantime, clk = values
    if not (0.1 <= rate <= 10 and 1 <= load <= 1800 and 0.1 <= hot <= 10
            and 1 <= drain <= 900 and 1 <= bantime <= 3600 and 1 <= clk <= 100000):
        raise ValueError('workload overrides exceed bounded driver range')
    if any(v != int(v) for v in (load, drain, bantime, clk)):
        raise ValueError('durations and CLK_TCK must be integral')
    if rate * load >= 50000:
        raise ValueError('workload would wrap distinct generator addresses')
    result = dict(zip(('rate', 'load_s', 'hot_s', 'drain_s', 'bantime', 'clk_tck'), values))
    result['source_checkpoint_records'] = 2
    result['binary'] = binary
    result['sha256'] = hashlib.file_digest(open(binary, 'rb'), 'sha256').hexdigest()
    result['qualification'] = ('acceptance' if values[:5] == [3, 1800, 2, 900, 600]
                               else 'plumbing-only')
    Path(work, 'run.json').write_text(json.dumps(result, indent=2) + '\n')


def evaluate(work):
    work = Path(work)
    result = {'result': 'incomplete', 'failures': [], 'limitations': [
        'First-observed kernel latency is an upper bound; previous absent sample bounds installation below.',
        'Only first installation per distinct subject is measured; hot refresh deadlines need separate evidence.',
        'No TCP probes in this source driver; kernel observations alone do not prove packet-path behavior.'
    ]}
    try:
        meta = json.loads((work / 'run.json').read_text())
        result.update(qualification=meta['qualification'], sha256=meta['sha256'])
        gaps = meta.get('historical_evidence_gaps', [])
        result['acceptance_complete'] = meta['qualification'] == 'acceptance' and not bool(gaps)
        result['limitations'].extend(gaps)
        if gaps:
            result['execution'] = 'historical-replay'
        appended = {}
        records = 0
        for name in ('portsentry.log', 'perm.log'):
            for line in (work / name).read_text().splitlines():
                match = re.match(r'(\S+) Scan from: \[([0-9.]+)\]', line)
                if not match:
                    raise ValueError('malformed generated input')
                stamp = datetime.datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
                appended.setdefault(match[2], stamp)
                records += 1
        if not appended or PERMANENT not in appended or HOT not in appended:
            raise ValueError('missing original B5 workload sources')
        samples = []
        for line in (work / 'samples.log').read_text().splitlines():
            head, separator, raw = line.partition('|')
            if not separator:
                raise ValueError('missing sample status')
            parts = head.split()
            row = dict(item.split('=', 1) for item in parts[1:])
            sample = {key: int(row[key]) for key in ('cpu', 'rss_kb', 'db', 'wal', 'elems', 'lines')}
            sample['t'] = float(parts[0])
            sample.update(status(json.loads(raw)))
            samples.append(sample)
        files = sorted((work / 'kernel').glob('[0-9]*.txt'))
        if len(samples) < 2 or len(files) != len(samples):
            raise ValueError('missing sample/oracle evidence')
        first, lower, previous = {}, {}, None
        foreign = set()
        permanent_seen = False
        permanent_lost = False
        for path in files:
            stamp, finish, addresses = inventory(path)
            foreign.update(addresses - appended.keys())
            if permanent_seen and PERMANENT not in addresses:
                permanent_lost = True
            if PERMANENT in addresses:
                permanent_seen = True
            if previous is not None and stamp <= previous:
                raise ValueError('non-increasing oracle timestamps')
            for address in addresses & appended.keys():
                if address not in first:
                    first[address] = finish
                    lower[address] = max(0, (previous if previous is not None else appended[address]) - appended[address])
            previous = stamp
        failures = result['failures']
        missing = sorted(appended.keys() - first.keys())
        if missing:
            failures.append(f'{len(missing)} subjects never observed in kernel')
        if foreign:
            failures.append(f'unexpected blocked subjects: {sorted(foreign)}')
        if permanent_lost:
            failures.append('permanent baseline disappeared during load')
        if any(row['overdue_removals'] for row in samples):
            failures.append('overdue blocking removals reported')
        if 'intervention' in (work / 'daemon.log').read_text():
            failures.append('daemon logged intervention')
        upper_values = sorted(first[ip] - appended[ip] for ip in first)
        lower_values = sorted(lower.values())
        if not upper_values or upper_values[0] < 0:
            raise ValueError('missing/invalid latency samples')
        rank = min(len(upper_values) - 1, int(.95 * len(upper_values)))
        result.update(subjects=len(appended), records=records, source_checkpoint_records=2, missing=missing,
                      latency_p95_lower_s=lower_values[rank], latency_p95_upper_s=upper_values[rank],
                      latency_max_upper_s=upper_values[-1],
                      max_source_lag_records=max(row['lines'] + 2 - row['committed_records'] for row in samples),
                      max_pending_bans=max(row['pending_bans'] for row in samples),
                      final_pending_bans=samples[-1]['pending_bans'],
                      max_overdue_removals=max(row['overdue_removals'] for row in samples),
                      final_overdue_removals=samples[-1]['overdue_removals'],
                      max_overdue_bookkeeping=max(row['overdue_bookkeeping'] for row in samples),
                      final_overdue_bookkeeping=samples[-1]['overdue_bookkeeping'],
                      max_rss_bytes=max(row['rss_kb'] * 1024 for row in samples),
                      max_db_wal_bytes=max(row['db'] + row['wal'] for row in samples))
        if result['max_rss_bytes'] > 150 * 1024 * 1024:
            failures.append('RSS exceeds 150 MiB')
        if result['max_db_wal_bytes'] > 272 * 1024 * 1024:
            failures.append('DB plus WAL exceeds 272 MiB')
        full = meta['qualification'] == 'acceptance'
        if full and lower_values[rank] > 5:
            failures.append('BUG-079: p95 enforcement latency exceeds 5 seconds')
        elif full and upper_values[rank] > 5:
            result['limitations'].append('Sampling straddles p95=5s; cannot establish pass or fail for latency.')
        final = status(json.loads((work / 'status-final.json').read_text()))
        _, _, running = inventory(files[-1])
        if full:
            if (final['storage'], final['knowledge'], final['protection']) != ('healthy', 'fresh', 'active'):
                failures.append('final status is not healthy/fresh/active')
            if running != {PERMANENT}:
                failures.append('ordinary subjects not drained or permanent baseline missing')
            result['final_input_commit_delta'] = records + 2 - final['committed_records']
            if final['pending_bans'] or final['overdue_bookkeeping'] or final['overdue_removals']:
                failures.append('final lifecycle work has not drained')
        with sqlite3.connect((work / 'state/fail2zig.sqlite').as_uri() + '?mode=ro', uri=True) as db:
            ordinary_retry = db.execute("SELECT count(*) FROM retry_states WHERE jail='portsentry'").fetchone()[0]
            permanent_retry = db.execute("SELECT count(*) FROM retry_states WHERE jail='perm'").fetchone()[0]
        result.update(ordinary_retry_final=ordinary_retry, permanent_retry_final=permanent_retry)
        if meta['qualification'] == 'acceptance' and ordinary_retry != 0:
            failures.append('ordinary retry states have not drained')
        _, _, after_stop = inventory(work / 'kernel-after-stop.txt')
        if after_stop:
            failures.append('owned kernel elements remain after stop')
        tail = [row for row in samples if row['t'] >= samples[-1]['t'] - 120]
        settled = (len(tail) > 1 and all(row['elems'] == 1 and row['active_bans'] == 1
                   and row['lines'] + 2 == row['committed_records'] and row['pending_bans'] == 0
                   and row['overdue_removals'] == 0 and row['overdue_bookkeeping'] == 0
                   and row['storage'] == 'healthy' for row in tail))
        result['settled_idle_cpu_percent'] = ((tail[-1]['cpu'] - tail[0]['cpu']) * 100 /
                   meta['clk_tck'] / (tail[-1]['t'] - tail[0]['t'])) if settled else None
        # Original driver does not independently prove stable load plateau or
        # each hot-subject renewal. Never convert their absence into acceptance.
        result['plateau_verified'] = False
        result['hot_renewal_verified'] = False
        if full:
            result['acceptance_complete'] = False
            result['limitations'].append('Load plateau and hot renewal require retained independent review; not automated here.')
        result['result'] = ('fail' if failures else 'incomplete' if full or gaps else 'plumbing-pass')
    except SafetyFailure as exc:
        result['acceptance_complete'] = False
        result['result'] = 'fail'
        result['failures'].append(str(exc))
    except (OSError, ValueError, KeyError, IndexError, TypeError, ZeroDivisionError, sqlite3.Error) as exc:
        result['acceptance_complete'] = False
        result['result'] = 'fail' if result['failures'] else 'incomplete'
        result['failures'].append(str(exc))
    (work / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['result'] in ('pass', 'plumbing-pass') else 1


if __name__ == '__main__':
    try:
        mode, *args = sys.argv[1:]
        if mode == 'metadata':
            metadata(args)
        elif mode == 'status':
            status(json.load(sys.stdin))
        elif mode == 'sample' and len(args) == 2:
            sample(args[0], args[1], sys.stdin.read())
        elif mode == 'failed' and len(args) == 2:
            path = Path(args[0], 'summary.json')
            result = json.loads(path.read_text()) if path.exists() else {'result': 'incomplete', 'failures': []}
            result['failures'].append('driver or cleanup exited with code ' + args[1])
            result['result'] = 'fail'
            path.write_text(json.dumps(result, indent=2) + '\n')
        elif mode == 'evaluate' and len(args) == 1:
            sys.exit(evaluate(args[0]))
        else:
            raise ValueError('usage: evaluate.py metadata ... | status | evaluate WORK')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'evidence failure: {exc}', file=sys.stderr)
        sys.exit(1)
