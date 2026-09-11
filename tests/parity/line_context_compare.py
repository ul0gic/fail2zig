#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original line trajectories through native context and actual reference Filter."""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import re
import subprocess
import sys


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference',type=Path,required=True)
    ap.add_argument('--candidate',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    commit=subprocess.check_output(['git','-C',str(args.reference),'rev-parse','HEAD'],text=True).strip()
    if commit!='f60978618a101427b06924fc932b44350fec2b63': raise SystemExit('wrong reference commit')
    sys.path.insert(0,str(args.reference))
    from fail2ban.server.filter import Filter
    from fail2ban.server.mytime import MyTime
    logging.disable(logging.CRITICAL)
    class Detector:
        row=None
        def matchTime(self,line):
            expression=(r'(never)?' if self.row['start']==-1 else r'()') if self.row['kind']=='optional_empty' else r'\[([^]]*)\]'
            return (None if self.row['kind']=='missing' else re.search(expression,line),None)
        def getTime(self,text,match):
            return (self.row['value'],None) if self.row['kind']=='parsed' else None
    def tuple_dict(value):
        return dict(zip(('prefix','time','suffix'),value)) if value is not None else None
    rows=[]
    for mode in ('startup','live','replay'):
        for max_lines in (1,2,5):
            reference=Filter(None)
            reference.dateDetector=detector=Detector()
            reference.setMaxLines(max_lines)
            reference.setFindTime(600)
            reference.checkFindTime=mode!='replay'
            reference.inOperation=mode=='live'
            captured=[]
            actual_find=reference.findFailure
            def recording_find(parts,date,noDate=False):
                captured.append((parts,date,noDate))
                return actual_find(parts,date,noDate=noDate)
            reference.findFailure=recording_find
            inputs=[]
            expected=[]
            for index,(kind,value,now) in enumerate([
                ('missing',None,1000),('optional_empty',None,1000),
                ('parsed',999.125,1000),('missing',None,1000),('invalid',None,1000),
                ('optional_empty',None,1000),('missing',None,1060),
                ('parsed',1.25,1060),('missing',None,1060),
                ('parsed',1121.125,1060),('missing',None,1060),
                ('parsed',0.0,1060),('optional_empty',None,1060),
                ('invalid',None,1060),('parsed',1000.0,1060),
                ('missing',None,1060),('parsed',1000.125,1060),
                ('invalid',None,1060),('parsed',460.0,1060),
                ('parsed',459.999,1060),('missing',None,1060)]):
                line=f'é[{value if kind=="parsed" else "bad"}] neutral {index} Ω' if kind in ('parsed','invalid') else f'neutral follow {index}'
                match=re.search(r'\[([^]]*)\]',line) if kind in ('parsed','invalid') else None
                row=dict(line=line,kind=kind,value=value,start=match.start(1) if match else 0,end=match.end(1) if match else 0,now=now,mode=mode)
                if kind=='optional_empty' and index in (1,12): row.update(start=-1,end=-1)
                detector.row=row
                MyTime.setTime(now)
                before=len(captured)
                reference.processLine(line)
                appended=len(captured)!=before
                last=captured[-1] if appended else None
                inputs.append(row)
                expected.append(dict(last_date=reference._Filter__lastDate,last_time_text=reference._Filter__lastTimeText,
                    buffer=[tuple_dict(t) for t in reference._Filter__lineBuffer],
                    processed=tuple_dict(captured[-1][0]) if captured else None,
                    appended=appended,no_date=last[2] if last else None,date=last[1] if last else None))
            observed=json.loads(subprocess.check_output([str(args.candidate),json.dumps(dict(max_lines=max_lines,rows=inputs))],text=True))
            for index,(want,got) in enumerate(zip(expected,observed)):
                rows.append(dict(mode=mode,max_lines=max_lines,index=index,input=inputs[index],expected=want,observed=got,equal=want==got))
    MyTime.setTime(None)
    source=Path(__file__).resolve().parents[2]/'engine/core/line_context.zig'
    result=dict(scope='pre-matching tuple/time-text/maxlines context; actual Filter with no failregex; not P3 matching or daemon qualification',reference_commit=commit,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
        cases=rows,equal=sum(r['equal'] for r in rows),mismatches=sum(not r['equal'] for r in rows))
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
    return bool(result['mismatches'])


if __name__=='__main__':
    raise SystemExit(main())
