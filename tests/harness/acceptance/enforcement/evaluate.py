#!/usr/bin/env python3
"""Existing B1 kernel/latency/health observations turned into a failure exit."""
import datetime
import json
import re
from pathlib import Path
import sys


def value(obj, key):
    found = []
    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == key:
                    found.append(v)
                elif isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(obj)
    if len(found) != 1 or found[0] is None:
        raise ValueError(f'missing/ambiguous status field {key}')
    return found[0]


def inventory(path):
    lines = path.read_text().splitlines()
    if not lines or not re.fullmatch(r'now_ms \d+', lines[0]) or not lines[-1].startswith('summary '):
        raise ValueError('incomplete kernel sample: ' + str(path))
    elems = set()
    for line in lines:
        if line.startswith('elem '):
            m = re.match(r'elem ([0-9.]+)/32\b', line)
            if not m:
                raise ValueError('unexpected kernel element: ' + line)
            elems.add(m[1])
    start = int(lines[0].split()[1]) / 1000
    finishes = []
    for line in lines:
        if line.startswith('set '):
            m = re.search(r'dump_start_ms=(\d+) dump_latency_ms=(\d+)', line)
            if not m:
                raise ValueError('missing kernel dump timing')
            finishes.append((int(m[1])+int(m[2]))/1000)
    if elems and not finishes:
        raise ValueError('missing timing for observed kernel elements')
    return start, max([start]+finishes), elems


def sample(work, path):
    stamp, _, elems = inventory(path)
    status = json.loads((work/'status.json').read_text())
    if value(status, 'storage') != 'healthy':
        raise ValueError('storage not healthy')
    knowledge = value(status, 'knowledge')
    protection = value(status, 'protection')
    if protection != 'active':
        raise ValueError('protection not active')
    if knowledge != 'fresh':
        raise ValueError('kernel knowledge not fresh')
    with (work/'health.jsonl').open('a') as f:
        f.write(json.dumps({'t':stamp,'knowledge':knowledge,'protection':protection,'elements':len(elems)})+'\n')


def evaluate(work):
    failures = []
    result = {'result':'incomplete','failures':failures,
              'latency_measurement':'first observed presence upper bound, preceding absence lower bound'}
    try:
        append = {}
        for line in (work/'portsentry.log').read_text().splitlines():
            m = re.match(r'(\S+) Scan from: \[([0-9.]+)\]', line)
            if not m:
                raise ValueError('invalid workload record')
            append[m[2]] = datetime.datetime.strptime(m[1],'%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
        expected = {f'198.18.0.{i}' for i in range(1,211)}
        if set(append) != expected:
            raise ValueError('workload did not produce exactly original 210 subjects')
        first, lower, previous, last = {}, {}, None, set()
        files = sorted((work/'kernel').glob('[0-9]*.txt'))
        health = (work/'health.jsonl').read_text().splitlines()
        if not files or len(files) != len(health):
            raise ValueError('missing kernel/health evidence')
        for path, health_line in zip(files, health):
            stamp, finish, last = inventory(path)
            observation = json.loads(health_line)
            if (not isinstance(observation, dict) or
                    observation.get('knowledge') != 'fresh' or
                    observation.get('protection') != 'active' or
                    observation.get('elements') != len(last) or
                    not isinstance(observation.get('t'), (int, float)) or
                    abs(observation['t'] - stamp) > 0.001):
                failures.append('kernel/health sample mismatch')
            if previous is not None and stamp <= previous:
                raise ValueError('non-increasing sample clock')
            if last - expected:
                failures.append('unexpected blocked subjects')
            for ip in last & expected:
                if ip not in first:
                    first[ip] = finish-append[ip]
                    lower[ip] = max(0,(previous if previous is not None else append[ip])-append[ip])
            previous = stamp
        if last != expected or len(first) != 210:
            failures.append('all 210 bans not present at settled observation')
        if not first or min(first.values()) < 0:
            raise ValueError('invalid first-install latency')
        upper_max, lower_max = max(first.values()), max(lower.values())
        result.update(subjects_seen=len(first), latency_max_lower_s=lower_max, latency_max_upper_s=upper_max)
        if lower_max > 10:
            failures.append('maximum append-to-kernel latency exceeds 10 seconds')
        elif upper_max > 10:
            result['uncertainty'] = 'sampling straddles 10-second acceptance boundary'
        if not (work/'tcp.log').read_text().strip():
            raise ValueError('no blocked TCP probe after observed installation')
        _, _, after = inventory(work/'kernel-after-stop.txt')
        if after:
            failures.append('owned elements remain after stop')
        result['result'] = 'fail' if failures else 'incomplete' if upper_max > 10 else 'pass'
    except (ValueError, OSError, KeyError, TypeError) as e:
        failures.append(str(e))
    (work/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return 0 if result['result']=='pass' else 1


if __name__=='__main__':
    try:
        mode, root, *args = sys.argv[1:]
        work=Path(root)
        if mode=='sample' and len(args)==1:
            sample(work,Path(args[0]))
        elif mode=='evaluate' and not args:
            sys.exit(evaluate(work))
        elif mode=='failed' and len(args)==1:
            p=work/'summary.json'
            result=json.loads(p.read_text()) if p.exists() else {'failures':[]}
            result['result']='fail'; result['failures'].append('driver/cleanup exit '+args[0])
            p.write_text(json.dumps(result,indent=2)+'\n')
        else:
            raise ValueError('unknown evaluator invocation')
    except (ValueError,OSError,KeyError,TypeError) as e:
        print(str(e),file=sys.stderr); sys.exit(1)
