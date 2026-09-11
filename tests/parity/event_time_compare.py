#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original bounded fixtures comparing actual time/duration candidate APIs to the reference.

This is a component check, not evidence that the daemon uses these APIs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference', required=True, type=Path)
    ap.add_argument('--candidate', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    commit = subprocess.check_output(['git', '-C', str(args.reference), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != 'f60978618a101427b06924fc932b44350fec2b63':
        raise SystemExit('wrong reference commit')
    sys.path.insert(0, str(args.reference))
    from fail2ban.server.mytime import MyTime
    from fail2ban.server.filter import Filter
    observations = []

    def candidate(*params):
        return json.loads(subprocess.check_output([str(args.candidate), *map(str, params)], timeout=3, text=True))

    for text in ['1d12h', '1hour+30min', '1year-6mo', '1.5 min', '(2+3)*60', '2**3**2', '-2**2', '7//2', '7%3', '2h**2']:
        expected = MyTime.str2seconds(text)
        observed = candidate('duration', text)['seconds']
        observations.append(dict(id='duration:'+text, expected=expected, observed=observed, equal=expected == observed))
    now = 1800000000.25
    MyTime.setTime(now)
    for mode, stamp in [('startup',now-600.001), ('startup',now-600), ('startup',now-599.999), ('live',now-60.999), ('live',now-61), ('live',now+60.999), ('live',now+61), ('replay',now-601.125)]:
        item = Filter(None, useDns='raw')
        item.ignoreSelf = False
        item.setFindTime(600)
        item.setMaxRetry(1024)
        item.addFailRegex(r'^synthetic failure from <ADDR>$')
        item.inOperation = mode == 'live'
        item.checkFindTime = mode != 'replay'
        matches = item.processLine(('', '', 'synthetic failure from 192.0.2.10'), stamp)
        expected = matches[0][2] if matches else None
        observed = candidate('normalize', mode, now, 600, stamp)
        observed_time = observed['parsed_time'] if observed['disposition'] == 'accepted' else None
        observations.append(dict(id=f'time:{mode}:{stamp}', expected=expected, observed=observed_time, equal=expected == observed_time))
    result = dict(reference_commit=commit, candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest(), scope='actual component APIs; not daemon integration or full SYS-032 acceptance', cases=observations, equal=sum(x['equal'] for x in observations), mismatches=sum(not x['equal'] for x in observations))
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'cases'}))
    return bool(result['mismatches'])


if __name__ == '__main__':
    raise SystemExit(main())
