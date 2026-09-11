#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Actual reference startup loop and candidate session on one private journal.

Only the pre-matching callback is observed. No upstream test body, filter matching,
firewall action, live journal, real service or database of the reference is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import types
from unittest.mock import patch


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--journal',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--encoding',default='utf-8')
    args=parser.parse_args()
    commit=subprocess.check_output(['git','-C',str(args.reference),'rev-parse','HEAD'],text=True).strip()
    if commit!='f60978618a101427b06924fc932b44350fec2b63': raise SystemExit('wrong reference commit')
    sys.path.insert(0,str(args.reference))
    from fail2ban.server import filtersystemd as reference
    from systemd import journal
    rows=[]
    cases=[('ordinary-startup',1730000005.,600.,None,[]),
           ('approximate-now',1730000000.5,600.,None,[]),
           ('old-window',1730001000.,600.,None,[]),
           ('zero-window',1730000005.,0.,None,[]),
           ('fractional-window',1730000000.5,.75,None,[]),
           ('legacy-before',1730000005.,600.,1729999999.,[]),
           ('legacy-exact',1730000005.,600.,1730000000.123456,[]),
           ('legacy-after',1730000005.,600.,1730000001.,[]),
           ('selected',1730000005.,600.,None,['SYSLOG_IDENTIFIER=example']),
           ('empty-selected',1730000005.,600.,None,['SYSLOG_IDENTIFIER=no-original-record']),
           ('source-time',1730000005.,600.,None,['SYSLOG_IDENTIFIER=source-time'])]
    for name,now,findtime,legacy,matches in cases:
        values=[]
        state=types.SimpleNamespace(active=True,idle=False,sleeptime=0,ticks=0,inOperation=False,jailName='original-fixture')
        actual=journal.Reader(files=[str(args.journal)],flags=0)
        for match in matches: actual.add_match(match)
        class Reader:
            reading=False
            current=None
            def seek_tail(self): return actual.seek_tail()
            def seek_realtime(self,time):
                self.reading=True
                return actual.seek_realtime(time)
            def get_previous(self): return actual.get_previous()
            def get_next(self):
                entry=actual.get_next()
                if self.reading:
                    self.current=entry
                    if not entry: state.active=False
                return entry
            def wait(self,_): return journal.APPEND
        reader=Reader()
        state._FilterSystemd__journal=reader
        state.getJournalMatch=lambda:matches
        state.getFindTime=lambda:findtime
        state.getLogEncoding=lambda:args.encoding
        state.getJrnEntTime=lambda entry:reference.FilterSystemd.getJrnEntTime(state,entry)
        state.formatJournalEntry=lambda entry:reference.FilterSystemd.formatJournalEntry(state,entry)
        state.seekToTime=lambda value:reference.FilterSystemd.seekToTime(state,value)
        state.inOperationMode=lambda:reference.FilterSystemd.inOperationMode(state)
        state.jail=types.SimpleNamespace(database=types.SimpleNamespace(getJournalPos=lambda jail,name:legacy) if legacy is not None else None)
        state._pendDBUpdates={}
        state._nextUpdateTM=now+1000
        state._updateDBPending=lambda:state._pendDBUpdates.clear()
        state.performSvc=lambda:None
        state.done=lambda:None
        def fail(*args): raise RuntimeError('unexpected reference loop failure: '+repr(args))
        state.commonError=fail
        def observed(line,time):
            if len(values)>=64: raise RuntimeError('reference record budget')
            values.append(dict(cursor=reader.current['__CURSOR'].decode() if isinstance(reader.current['__CURSOR'],bytes) else reader.current['__CURSOR'],mode='live' if state.inOperation else 'startup',time_text=line[1],message=line[2],timestamp_bits=struct.pack('>d',time).hex()))
        state.processLineAndAdd=observed
        try:
            with patch.object(reference.MyTime,'time',return_value=now),patch.object(reference.Utils,'wait_for',side_effect=lambda predicate,*args:predicate()):
                reference.FilterSystemd.run(state)
        finally: actual.close()
        expected=dict(records=values,in_operation=state.inOperation)
        process=subprocess.run([str(args.candidate),str(args.journal),repr(now),repr(findtime),'none' if legacy is None else repr(legacy),*matches],check=True,text=True,capture_output=True,timeout=20,env=dict(os.environ,F2Z_JOURNAL_PROBE_ENCODING=args.encoding))
        observed=json.loads(process.stdout)
        rows.append(dict(id=name,now=now,findtime=findtime,legacy_position=legacy,matches=matches,expected=expected,observed=observed,agreement=expected==observed))
    result=dict(scope='actual reference startup loop and actual private candidate session before matching; no actions',reference_commit=commit,
                candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest(),journal_sha256=hashlib.sha256(args.journal.read_bytes()).hexdigest(),
                encoding=args.encoding,cases=rows,case_count=len(rows),agreements=sum(row['agreement'] for row in rows))
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(f"{result['agreements']}/{result['case_count']} journal session agreements")
    return result['agreements']!=result['case_count']

if __name__=='__main__': raise SystemExit(main())
