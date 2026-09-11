#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original JailReader/source-plan comparisons; command data and inert receiver only."""
import argparse, hashlib, json, subprocess, sys, tempfile, tomllib
from pathlib import Path
REFERENCE = r'''
import json,sys
sys.path.insert(0,sys.argv[1])
from fail2ban.client.jailreader import JailReader
from fail2ban.server.transmitter import Transmitter
r=JailReader('probe',basedir=sys.argv[2]);r.read();r.getOptions()
# Original paths are not opened: an explicit deterministic discovery seam.
r._glob = lambda path: [path] if path else []
JailReader._glob = staticmethod(r._glob)
stream=r.convert(allow_no_files=True)
keys=json.loads(sys.argv[3]);combined=r.getCombined()
values={key:combined[key] for key in keys if key in combined}
class Receiver:
 def addLogPath(self,*args): pass
 def getLogPath(self,*args): return []
t=Transmitter(Receiver())
paths=[row[3:] for row in stream if row[:3]==['set','probe','addlogpath']]
invalid=any(t.proceed(['set','probe','addlogpath',*row])[0] for row in paths)
matches=[]
for row in stream:
 if row[:3]==['set','probe','addjournalmatch']:
  if matches:matches.append('+')
  matches.extend(row[3:])
print(json.dumps({'values':values,'paths':paths,'invalid_start':invalid,'matches':matches}))
'''
CASES=[
 ('absent','',None),('empty','logpath=\n',None),
 ('default-head','logpath=/original/log\n',None),
 ('explicit-modes','logpath=/original/one HeAd\n /original/two TAIL\n',None),
 ('space-path','logpath=/original/with space tail\n',None),
 ('space-no-mode','logpath=/original/with space\n',None),
 ('bad-mode','logpath=/original/log sideways\n',None),
 ('systemd-ignores-mode','backend=systemd\nlogpath=/original/log sideways\n',None),
 ('filter-derived','filter=original\n','[Definition]\njournalmatch=UNIT=one\n FIELD="two words"\ndatepattern=EPOCH\nmaxlines=3\nusedns=no\n'),
 ('explicit-overrides','filter=original\njournalmatch=\ndatepattern=TAI64N\nmaxlines=2\nusedns=warn\n','[Definition]\njournalmatch=UNIT=one\ndatepattern=EPOCH\nmaxlines=3\nusedns=no\n'),
 ('typed-fallback','maxlines=bad\nignoreself=bad\nskip_if_nologs=bad\nsystemd_if_nologs=bad\n',None),
 ('auto-file','filter=original\n','[Definition]\njournalmatch=K=<logtype>\n[Init]\nlogtype=journal\n'),
 ('auto-journal','filter=original\nbackend=systemd\n','[Definition]\njournalmatch=K=<logtype>\n'),
 ('auto-raw-case','filter=original\nbackend=SYSTEMD\n','[Definition]\njournalmatch=K=<logtype>\n'),
 ('selector-logtype','filter=original[logtype=custom]\n','[Definition]\njournalmatch=K=<logtype>\n'),
 ('definition-logtype','filter=original\n','[Definition]\nlogtype=manual\njournalmatch=K=<logtype>\n'),
 ('known-datepattern','filter=original\ndatepattern=%(known/datepattern)s EPOCH\n','[Definition]\ndatepattern=TAI64N\n'),
 ('known-open-option','filter=original\nignorecommand=%(known/custom)s <ip>\n','[Definition]\ncustom=/original/helper\n'),
 ('final-jail-substitution','filter=original\ndatepattern=EPOCH\n','[Definition]\ndatepattern=TAI64N\njournalmatch=FORMAT=%(datepattern)s\n'),
 ('resolved-percent-filter','filter=original\n','[Definition]\ndatepattern=%%Y-%%m-%%d\n'),
 ('reader-builtins','ignorecommand=%(fail2ban_confpath)s/original <ip>\n',None),
 ('empty-ignore','ignoreip=\nignorecache=\nignorecommand=\nignoreself=no\n',None),
]
KEYS=['backend','logpath','journalmatch','datepattern','maxlines','logencoding','logtimezone','skip_if_nologs','systemd_if_nologs','ignoreip','ignoreself','ignorecache','ignorecommand','usedns']
def option_value(option):
 r=option['reader']
 if r is None:raise ValueError(option)
 if r['presence']=='absent' and option['derived_filter_asset'] is None and 'null_value' in r['value']:return False,None
 value=r['value'];return True,next(iter(value.values())) if 'null_value' not in value else None

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('reference','candidate','probe','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();reference=a.reference.resolve();candidate=a.candidate.resolve()
 commit=subprocess.check_output(['git','-C',str(reference),'rev-parse','HEAD'],text=True).strip()
 if commit!='f60978618a101427b06924fc932b44350fec2b63':raise ValueError('wrong reference')
 subprocess.run(['git','-C',str(reference),'diff','--exit-code','HEAD','--'],check=True,capture_output=True)
 rows=[]
 for name,body,asset in CASES:
  with tempfile.TemporaryDirectory(prefix='f2z-source-plan-original-') as tmp:
   root=Path(tmp);(root/'jail.conf').write_text('[probe]\nenabled=true\n'+body)
   if asset:(root/'filter.d').mkdir();(root/'filter.d/original.conf').write_text(asset)
   ref=subprocess.run([sys.executable,'-B','-c',REFERENCE,str(reference),tmp,json.dumps(KEYS)],capture_output=True,text=True,check=True,timeout=10)
   out=root/'prepared.toml';proc=subprocess.run([str(candidate),'--import-config',tmp,'--import-output',str(out)],capture_output=True,text=True,timeout=10)
   if not out.exists():raise ValueError(proc.stderr)
   manifest=json.loads(tomllib.loads(out.read_text())['global']['compatibility_manifest']);plan=manifest['source_plans'][0]
   observed=json.loads(subprocess.check_output([str(a.probe.resolve()),str(out)],text=True,stderr=subprocess.PIPE))[0]
   values={}
   for key in KEYS:
    present,value=option_value(plan.get(key,plan['ignore'].get(key)))
    if present:values[key]=int(value) if key=='maxlines' and value is not None else value
   paths=[] if values['backend'].startswith('systemd') else [[v['pattern'],v['start_spelling']] for v in plan['paths'] if v['pattern']]
   actual={'values':values,'paths':paths,'invalid_start':bool(observed['path_error']) if paths else False,'matches':observed['matches']}
   wanted=json.loads(ref.stdout);rows.append({'id':name,'input':body,'filter':asset,'reference':wanted,'candidate':actual,'equal':wanted==actual})
 root=Path(__file__).resolve().parents[3]
 paths=['engine/config/source_plan.zig','engine/config/filter_context.zig','engine/config/migration.zig','engine/config/fail2ban.zig','tests/parity/harness/p2_source_plan_compare.py','tests/parity/harness/p2_source_plan_probe.zig']
 report={'schema_version':1,'scope':'Prepared reader values, path tokens and inert head/tail admission, journal match tokenization; no daemon or G2 admission','reference_commit':commit,'candidate_binary_sha256':hashlib.sha256(candidate.read_bytes()).hexdigest(),'probe_sha256':hashlib.sha256(a.probe.read_bytes()).hexdigest(),'source_hashes':{path:hashlib.sha256((root/path).read_bytes()).hexdigest() for path in paths},'reference_source_hashes':{path:hashlib.sha256((reference/path).read_bytes()).hexdigest() for path in ['fail2ban/client/jailreader.py','fail2ban/client/filterreader.py','fail2ban/client/configreader.py','fail2ban/client/configparserinc.py','fail2ban/helpers.py','fail2ban/server/transmitter.py']},'cases':rows,'agreements':sum(r['equal'] for r in rows),'total':len(rows)}
 a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'agreements':report['agreements'],'total':report['total']}));return int(report['agreements']!=report['total'])
if __name__=='__main__':raise SystemExit(main())
