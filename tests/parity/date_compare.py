#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original date formats and mixed trajectories through actual reference/candidate APIs.

This component test does not claim daemon integration or selected-platform qualification.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

LINES = [
    '2026-01-01T00:00:00.125Z neutral', 'Jan  1 00:00:01 neutral',
    '[1767225602.125] neutral', 'Dec 31 23:59:59 neutral',
    '01/01/26 00:00:01 neutral', '[01/Jan/2026:00:00:01 +0000] neutral',
    '01/01/2026:00:00:01 neutral', '01-01-2026 00:00:01.125 neutral',
    '00:00:01 neutral', '<01/01/26@00:00:01> neutral', '260101 00:00:01 neutral',
    'Jan 01, 2026 12:00:01 AM neutral', 'Jan-01-26 00:00:01 neutral',
    '20260101T000001 neutral', 'UTC Jan 01 00:00:01 2026 neutral',
    '+00:00 Jan 01 00:00:01 2026 neutral', '@400000006955b90100000000 neutral',
    'neutral only', 'prefix 2026-01-01 00:00:01 neutral',
    'x Jan 01 00:00:01 y 2026-01-01 00:00:02 neutral',
]
CUSTOM = [
    ('%Y-%m-%dT%H:%M:%S.%f%z', '2026-01-01T00:00:00.125+0000'),
    ('%Y-%m-%d %H:%M:%S %Exz', '2026-01-01 00:00:00 CET+0100'),
    ('%Y-%m-%d %H:%M:%S %Z', '2026-01-01 00:00:00 NPT'),
    ('%y-%m-%d %H:%M:%S', '99-01-01 00:00:00'),
    ('%Y %j %H:%M:%S', '2024 060 00:00:00'),
    ('%Y %U %w %H:%M:%S', '2026 01 1 00:00:00'),
    ('%Y %W %w %H:%M:%S', '2026 01 1 00:00:00'),
    ('%H:%M:%S', '23:59:59'), ('%b %d %H:%M:%S', 'Dec 31 23:59:59'),
    ('%Y-%m-%d %I:%M:%S %p', '2026-01-01 12:00:01 PM'),
    ('%Y-%m-%d %I:%M:%S %p', '2026-01-01 12:00:01 AM'),
    ('%Y-%m-%d %H:%M:%S', '2026-02-29 00:00:00'),
    ('%Y-%m-%d %H:%M:%S', '2024-02-29 00:00:00'),
    ('LEPOCH', '1767225600123456'), ('EPOCH', '1767225600.125'),
    ('^EPOCH', '[1767225600.125]'), ('TAI64N', '@400000006955b90000000000'),
    ('{^LN-BEG}%Y-%m-%d', '[2026-01-01] neutral'),
    ('**%Y-%m-%d**', 'x2026-01-01z neutral'),
    ('^prefix {DATE} suffix$', 'prefix 2026-01-01 00:00:01 suffix'),
    ('^prefix {EPOCH} suffix$', 'prefix 1767225600.125 suffix'),
    ('%Y-%m-%d %H:%M:%S (?P<f>neutral)', '2026-01-01 00:00:01 neutral'),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    commit = subprocess.check_output(['git','-C',str(args.reference),'rev-parse','HEAD'],text=True).strip()
    if commit != 'f60978618a101427b06924fc932b44350fec2b63':
        raise SystemExit('wrong reference commit')
    os.environ['TZ'] = 'UTC'
    time.tzset()
    sys.path.insert(0,str(args.reference))
    from fail2ban.server.datedetector import DateDetector
    from fail2ban.server.mytime import MyTime
    path = Path(__file__).resolve().parents[2] / 'engine/compat/date_time.py'
    spec = importlib.util.spec_from_file_location('f2z_date_compare',path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    now = 1767225603
    MyTime.setTime(now)
    results = []

    def compare(reference,candidate,line,context):
        expected = reference.getTime(line)
        result,context = candidate.process(line,now=now,usage_time=time.time(),context=context)
        expected = None if expected is None else [expected[0],expected[1].group(1),list(expected[1].span(1))]
        observed = None if result is None or result.effective is None else [result.effective,result.text,[result.start,result.end]]
        return dict(line=line,expected=expected,observed=observed,equal=expected==observed),context

    reference = DateDetector()
    reference.default_tz = 'UTC'
    candidate = module.DateDetector(reference_year=2026,default_tz='UTC')
    context = None
    for index,line in enumerate(LINES*3):
        row,context = compare(reference,candidate,line,context)
        row['id'] = 'mixed-trajectory:'+str(index)
        results.append(row)
        # Force an actual JSON checkpoint/restore boundary between every record.
        context = json.loads(json.dumps(context,allow_nan=False))
    # Original mixed-position collisions: a leading date competes with a second
    # differently formatted date inside neutral message text; retained template
    # selection history matters across this sequence.
    collision_lines=[]
    formatted=[line.removesuffix(' neutral') for line in LINES if line.endswith(' neutral')]
    for index,line in enumerate(formatted):
        alternate=formatted[(index+5)%len(formatted)]
        collision_lines.extend([
            'prefix '+line+' neutral',
            line+' neutral later '+alternate,
            'prefix '+line+' neutral later '+alternate,
            '['+line+'] neutral',
        ])
    collision_lines += [
        '2026-02-29 00:00:01 neutral later 2026-01-01 00:00:02',
        '2024-02-29 00:00:01 neutral',
        '2026-01-01T01:00:00.125+01:00 neutral',
        '2026-01-01T00:00:00,125Z neutral',
        'Jan 01 2026 00:00:01 neutral',
        'Thu Jan 01 00:00:01 2026 neutral',
        '2026/01/01 00:00:01 neutral',
        '2026.01.01 00:00:01 neutral',
    ]
    for index,line in enumerate(collision_lines):
        row,context = compare(reference,candidate,line,context)
        row['id']='position-collision:'+str(index)
        results.append(row)
        context=json.loads(json.dumps(context,allow_nan=False))
    for index,(pattern,line) in enumerate(CUSTOM):
        reference = DateDetector()
        reference.default_tz = 'UTC'
        reference.appendTemplate(pattern)
        candidate = module.DateDetector([pattern],reference_year=2026,default_tz='UTC')
        row,_ = compare(reference,candidate,line,None)
        row['id'] = 'explicit-pattern:'+str(index)
        row['pattern'] = pattern
        results.append(row)
    receipt = dict(scope='date component APIs only; not daemon/full profile acceptance',
                   reference_commit=commit,
                   candidate_source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                   profile_sha256=hashlib.sha256(path.with_name('date_profile.json').read_bytes()).hexdigest(),
                   cases=results,equal=sum(row['equal'] for row in results),
                   mismatches=sum(not row['equal'] for row in results))
    args.output.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({key:value for key,value in receipt.items() if key!='cases'}))
    return bool(receipt['mismatches'])


if __name__ == '__main__':
    raise SystemExit(main())
