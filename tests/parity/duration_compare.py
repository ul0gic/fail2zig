#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded original numeric inputs through reference and candidate duration parsers."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    commit=subprocess.check_output(['git','-C',str(args.reference),'rev-parse','HEAD'],text=True).strip()
    if commit!='f60978618a101427b06924fc932b44350fec2b63':
        raise SystemExit('wrong reference commit')
    sys.path.insert(0,str(args.reference))
    from fail2ban.server.mytime import MyTime
    path=Path(__file__).resolve().parents[2]/'engine/compat/duration.py'
    spec=importlib.util.spec_from_file_location('f2z_duration_compare',path)
    candidate=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=candidate
    spec.loader.exec_module(candidate)
    cases=['1d12h','1hour+30min','1year-6mo','1.5 min','(2+3)*60','2**3**2','-2**2','7//2','7%3','2h**2',
           '1e3','1e+3','1e-3','0x10','0xff','0b10','1_000','2**-2','1m/2','1h30.5m','9007199254740993',
           '18446744073709551615','-1','-2','1/0','4 << 2','-7%3','-7//3']
    rows=[]
    for text in cases:
        def observe(function):
            try:
                value=function(text)
                # JSON keeps integer strings lossless in evidence too.
                return {'kind':type(value).__name__,'value':repr(value)}
            except Exception as exc:
                return {'error':type(exc).__name__}
        expected=observe(MyTime.str2seconds)
        observed=observe(candidate.expression)
        rows.append(dict(input=text,expected=expected,observed=observed,equal=expected==observed))
    result=dict(scope='numeric duration component; arbitrary executable expressions intentionally rejected, bounded budgets, no daemon integration',reference_commit=commit,candidate_source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=rows,equal=sum(r['equal'] for r in rows),mismatches=sum(not r['equal'] for r in rows))
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
    return bool(result['mismatches'])


if __name__=='__main__':
    raise SystemExit(main())
