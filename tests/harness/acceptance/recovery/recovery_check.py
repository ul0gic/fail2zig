#!/usr/bin/env python3
"""Assertions extracted from the B2/B3/B8 evidence checks; harness-only SQLite."""
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

db, mode, *args = sys.argv[1:]

def require(value, message):
    if not value:
        raise SystemExit(message)

def connect(write=False):
    return sqlite3.connect(Path(db).as_uri() + ('?mode=rw' if write else '?mode=ro'), uri=True)

def rows(sql):
    with connect() as c:
        return [list(row) for row in c.execute(sql)]

def owners():
    return rows('SELECT hex(scope_key),jail,lease_kind,deadline_us FROM effect_owners ORDER BY 1,2')

def cursors():
    return rows('SELECT jail,source,hex(cursor) FROM source_cursors ORDER BY jail,source')

def kernel(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        if not line.startswith('elem '):
            continue
        words = line.split()
        key = words[1]
        require(key not in result, 'duplicate kernel subject ' + key)
        deadline = re.search(r'\bdeadline_ms=(\d+)\b', line)
        require(deadline is not None, 'missing finite kernel deadline')
        result[key] = int(deadline.group(1))
    return result

if mode == 'status':
    data = json.loads(Path(args[0]).read_text())
    require(data.get('storage') == 'healthy', 'storage is not healthy')
    require(data.get('protection') == 'active', 'protection is not active')
elif mode == 'count':
    okay = len(kernel(args[0])) == int(args[1])
    if len(args) > 2 and args[2] == 'quiet':
        sys.exit(0 if okay else 1)
    require(okay, 'kernel count mismatch')
elif mode == 'deadlines':
    before, after = kernel(args[0]), kernel(args[1])
    require(before.keys() == after.keys(), 'kernel subject set changed')
    tolerance = int(args[2])
    require(0 <= tolerance <= 1000, 'invalid deadline tolerance')
    require(all(abs(before[k] - after[k]) <= tolerance for k in before), 'kernel deadlines changed')
elif mode == 'snapshot':
    files = {p: [os.stat(p).st_dev, os.stat(p).st_ino, os.stat(p).st_size] for p in args[1:]}
    Path(args[0]).write_text(json.dumps(dict(owners=owners(), cursors=cursors(), files=files), sort_keys=True))
elif mode == 'continuity':
    saved = json.loads(Path(args[0]).read_text())
    require(set(saved['files']) == set(args[1:]), 'source paths changed')
    for p in args[1:]:
        s = os.stat(p)
        require([s.st_dev, s.st_ino, s.st_size] == saved['files'][p], 'source identity/size changed')
    require(cursors() == saved['cursors'], 'source cursors changed before restart')
elif mode == 'owners':
    require(owners() == json.loads(Path(args[0]).read_text())['owners'], 'owners/deadlines changed')
elif mode == 'repaired':
    saved = json.loads(Path(args[0]).read_text())
    require(owners() == saved['owners'], 'repair changed owners/deadlines')
    before = {(j, s): c for j, s, c in saved['cursors']}
    after = {(j, s): c for j, s, c in cursors()}
    require(before.keys() == after.keys(), 'repair changed source membership')
    affected = [k for k in before if k[0] == 'portsentry']
    require(len(affected) == 1, 'fixture must have one repair source')
    require(before[affected[0]] != after[affected[0]], 'repair did not change truncated cursor')
    require(all(before[k] == after[k] for k in before if k != affected[0]), 'repair changed unrelated cursor')
    untouched = [v for k, v in before.items() if k[0] == 'sshd']
    require(len(untouched) == 1 and json.loads(bytes.fromhex(untouched[0]))['offset'] > 0, 'unaffected source was not ingested')
    require(rows('SELECT count(*) FROM source_repairs') == [[1]], 'repair receipt count mismatch')
    s = os.stat(args[1])
    require([s.st_dev, s.st_ino] == saved['files'][args[1]][:2], 'repair source inode changed')
elif mode == 'dump':
    with connect() as c:
        for line in c.iterdump():
            print(line)
elif mode == 'drift':
    with connect(True) as c:
        c.execute('UPDATE effect_owner_live SET live=live+5 WHERE id=1')
elif mode == 'counter':
    expected = int(args[0])
    actual = rows('SELECT live,mismatch_streak FROM effect_owner_live WHERE id=1')
    count = rows('SELECT count(*) FROM effect_owners WHERE lease_kind<>0')[0][0]
    require(actual == [[count, expected]], 'counter recount/streak mismatch')
    log = Path(args[1]).read_text()
    if expected == 0:
        require('live-owner counter' not in log, 'clean startup incorrectly warned')
    else:
        severity = 'warning' if expected == 1 else 'error'
        require(any(severity in line and 'live-owner counter' in line for line in log.splitlines()), 'counter severity missing')
        if expected == 2:
            require('again (2 consecutive startups)' in log, 'repeated warning not persisted')
else:
    raise SystemExit('unknown assertion mode')
