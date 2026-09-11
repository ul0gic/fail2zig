#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original per-file EOF/tail/restart trajectories, no matching or actions."""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference',type=Path,required=True)
    ap.add_argument('--candidate',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    commit=subprocess.check_output(['git','-C',str(args.reference),'rev-parse','HEAD'],text=True).strip()
    if commit!='f60978618a101427b06924fc932b44350fec2b63': raise SystemExit('wrong reference commit')
    sys.path.insert(0,str(args.reference))
    from fail2ban.server.filter import FileFilter
    logging.disable(logging.CRITICAL)
    rows=[]
    with tempfile.TemporaryDirectory(prefix='f2z-original-file-mode-') as directory:
        for name,initial,tail,pos in [('empty-head','',False,None),('complete-head','one\n',False,None),('partial-head','partial',False,None),('empty-tail','',True,None),('complete-tail','one\n',True,None),('restored-at-eof','one\n',False,4),('restored-before-line','one\ntwo\n',False,4),('append-during-ack','one\n',False,None)]:
            path=Path(directory)/name;path.write_text(initial)
            reference=FileFilter(SimpleNamespace(name='original-eof',database=None));reference.active=True;reference.idle=False
            events=[]
            pending_append=name=='append-during-ack'
            def record(line,date=None):
                nonlocal pending_append
                events.append(dict(line=line,live=bool(reference.inOperation)))
                if pending_append:
                    pending_append=False
                    with path.open('a') as stream:stream.write('during acknowledgement\n')
            reference.processLineAndAdd=record
            reference.addLogPath(str(path),tail=tail,autoSeek=False);log=reference.getLog(str(path))
            if pos is not None:log.setPos(pos)
            expected=[]
            for stage in ('first','append'):
                if stage=='append':
                    with path.open('a') as stream:stream.write('later\n')
                before=bool(log.inOperation);reference.getFailures(str(path))
                expected.append(dict(stage=stage,before=before,after=bool(log.inOperation),position=log.getPos(),events=events[:]))
                events.clear()
            path.write_text(initial)
            command=[str(args.candidate),str(path),str(int(tail)),str(pos) if pos is not None else 'none']
            if name=='append-during-ack':command.append('append-during-ack')
            observed=json.loads(subprocess.check_output(command,text=True))
            rows.append(dict(case=name,expected=expected,observed=observed,equal=expected==observed))
    source=Path(__file__).resolve().parents[2]/'engine/core/durable_file_source.zig'
    result=dict(scope='actual source EOF lifecycle observations; original records and recorder callback; no matching/tickets/actions',reference_commit=commit,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest(),cases=rows,
        equal=sum(r['equal'] for r in rows),mismatches=sum(not r['equal'] for r in rows))
    args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
    return bool(result['mismatches'])
if __name__=='__main__':raise SystemExit(main())
