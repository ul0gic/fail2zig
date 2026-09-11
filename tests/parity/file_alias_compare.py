#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original local hardlink fixtures through candidate FileSet and reference FileFilter."""
import argparse
import hashlib
import json
import logging
import os
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
    with tempfile.TemporaryDirectory(prefix='f2z-original-hardlink-pairs-') as directory:
        a=Path(directory)/'a.log';b=Path(directory)/'b.log'
        a.write_text('original neutral record\n');os.link(a,b)
        for selection in ('explicit','glob','overlapping-glob'):
            reference=FileFilter(SimpleNamespace(name='original-hardlinks',database=None))
            reference.active=True;reference.idle=False
            messages=[]
            reference.processLineAndAdd=lambda line,date=None:messages.append(line)
            paths=[a,b] if selection!='overlapping-glob' else [a,b,a,b]
            for path in paths: reference.addLogPath(str(path),autoSeek=False)
            for path in reference.getLogPaths(): reference.getFailures(path)
            expected=dict(configured_sources=len(reference.getLogPaths()),records=messages,positions=[reference.getLog(str(path)).getPos() for path in (a,b)])
            specs=[str(a),str(b)] if selection=='explicit' else [str(Path(directory)/'*.log')]*(2 if selection=='overlapping-glob' else 1)
            observed=json.loads(subprocess.check_output([str(args.candidate),*specs],text=True))
            rows.append(dict(selection=selection,same_inode=a.stat().st_ino==b.stat().st_ino,expected=expected,observed=observed,equal=expected==observed))
    source=Path(__file__).resolve().parents[2]/'engine/core/durable_file_source.zig'
    result=dict(scope='actual configured hardlink aliases and duplicate path registration; original benign records; no matching/tickets/actions',reference_commit=commit,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest(),cases=rows,
        equal=sum(r['equal'] for r in rows),mismatches=sum(not r['equal'] for r in rows))
    args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
    return bool(result['mismatches'])
if __name__=='__main__': raise SystemExit(main())
