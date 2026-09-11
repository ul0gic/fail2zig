#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Original benign P2 source-configuration differential cases; no action execution.

Requires a prebuilt p2_config_probe and pinned reference tree; compilation stays with
our serialized build coordinator. All cases call the actual configuration readers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

CASES = [
    ("known", "jail", "probe", "v", {"jail.conf": "[probe]\nv=base\n", "jail.local": "[probe]\nv=%(known/v)s-local\n"}),
    ("default-context", "jail", "probe", "v", {"jail.conf": "[DEFAULT]\nx=base\nv=%(x)s\n[probe]\nx=local\n"}),
    ("cross-section", "jail", "probe", "v", {"jail.conf": "[Other]\nx=other\n[probe]\nv=%(Other/x)s %(__name__)s\n"}),
    ("lower-cross-section", "jail", "probe", "v", {"jail.conf": "[other]\nx=other\n[probe]\nv=%(other/x)s %(__name__)s\n"}),
    ("escaped-percent", "jail", "probe", "v", {"jail.conf": "[probe]\nx=100%%\nv=%(x)s\n"}),
    ("empty", "jail", "probe", "v", {"jail.conf": "[probe]\nv=\n"}),
    ("missing", "jail", "probe", "v", {"jail.conf": "[probe]\nx=x\n"}),
    ("include-local-only", "jail", "probe", "v", {"jail.conf": "[INCLUDES]\nbefore=extra.conf\n[probe]\nx=x\n", "extra.local": "[probe]\nv=local\n"}),
    ("include-after-local", "jail", "probe", "v", {"jail.conf": "[INCLUDES]\nafter=extra.conf\n[probe]\nv=base\n", "extra.conf": "[probe]\nv=conf\n", "extra.local": "[probe]\nv=local\n"}),
    ("nested-relative", "jail", "probe", "v", {"jail.conf": "[INCLUDES]\nbefore=sub/extra.conf\n", "sub/extra.conf": "[INCLUDES]\nafter=last.conf\n", "sub/last.conf": "[probe]\nv=nested\n"}),
    ("case-and-comment", "jail", "probe", "v", {"jail.conf": "[probe]\nV=ok ; comment\n"}),
    ("conditional", "filter.d/custom", "Init", "v?family=inet6", {"filter.d/custom.conf": "[Init]\nv=base\n[Init?family=inet6]\nv=other\n"}),
    ("self-cycle", "jail", "probe", "v", {"jail.conf": "[DEFAULT]\nv=base\n[probe]\nv=%(v)s\n"}),
    ("missing-substitution", "jail", "probe", "v", {"jail.conf": "[probe]\nv=%(absent)s\n"}),
]
for hops in (9,10,11):
    for terminal in ('literal','100%%'):
        body='[probe]\n'+''.join(f'v{i}=%(v{i+1})s\n' for i in range(hops))+f'v{hops}={terminal}\n'
        CASES.append((f'depth-{hops}-{terminal}', 'jail','probe','v0',{'jail.conf':body}))
ASSET_CASES = [
    ("embedded-tag-name", "custom", "failregex", "[Definition]\nfailregex=<pre<suffix>>\n[Init]\nsuffix=fix\nprefix=ordinary\n", {}),
    ("init-tag", "custom", "failregex", "[Definition]\nfailregex=<prefix> <HOST>\n[Init]\nprefix=normal\n", {}),
    ("init-override", "custom[prefix=custom]", "failregex", "[Definition]\nfailregex=<prefix> <HOST>\n[Init]\nprefix=normal\n", {"prefix":"custom"}),
    ("init-known", "custom[prefix=custom]", "failregex", "[Definition]\nfailregex=<known/prefix> <prefix> <HOST>\n[Init]\nprefix=normal\n", {"prefix":"custom"}),
    ("percent-precedence", "custom[prefix=custom]", "failregex", "[Definition]\nprefix=normal\nfailregex=%(prefix)s <HOST>\n", {"prefix":"custom"}),
    ("nested-tags", "custom", "failregex", "[Definition]\nfailregex=<outer> <HOST>\n[Init]\nouter=<inner>\ninner=normal\n", {}),
    ("conditional-init-override", "custom[mode=custom]", "mode?family=inet6", "[Definition]\nfailregex=<HOST>\n[Init]\nmode=base\n[Init?family=inet6]\nmode=special\n", {"mode":"custom"}),
    ("init-empty", "custom[prefix=]", "failregex", "[Definition]\nfailregex=<prefix> <HOST>\n[Init]\nprefix=normal\n", {"prefix":""}),
]
ASSET_REFERENCE = '''import json,sys
sys.path.insert(0,sys.argv[1])
from fail2ban.client.filterreader import FilterReader
p=FilterReader('custom','probe',json.loads(sys.argv[3]),basedir=sys.argv[2]);p.read();p.getOptions({})
try:
 value=p.getCombined().get(sys.argv[4]);print(json.dumps({'value':value,'failure':None}))
except Exception as e: print(json.dumps({'value':None,'failure':type(e).__name__}))
'''
REFERENCE = '''import json,sys
sys.path.insert(0,sys.argv[1])
from fail2ban.client.configreader import ConfigReaderUnshared
p=ConfigReaderUnshared(basedir=sys.argv[2]);p.read(sys.argv[3])
try: print(json.dumps({'value':p.get(sys.argv[4],sys.argv[5],fallback=None),'failure':None}))
except Exception as e: print(json.dumps({'value':None,'failure':type(e).__name__}))
'''
ERRORS = {"InterpolationDepthError": "InterpolationCycle", "InterpolationMissingOptionError": "InterpolationMissingOption", "InterpolationSyntaxError": "InterpolationUnterminated"}

SELECTOR_CASES = [
    "first[a=' one ',b=two][a=last,\nx?family=inet6=value]\nsecond[port='80,443']",
    "first[a=1]\nsecond",
    "first[empty=,x=' comma, bracket] '][key=2]",
    "first[]",
    "first[x=one][x=two]",
    "first[x=1] second[y=2]",
    "first[x='a\nb']\nsecond",
]
SELECTOR_REFERENCE = r"""
import json,sys
sys.path.insert(0,sys.argv[1])
from fail2ban.helpers import extractOptions,splitWithOptions
result=[]
for raw in splitWithOptions(sys.argv[2]):
    name,parameters=extractOptions(raw.strip())
    result.append({'name':name,'parameters':[{'name':key,'value':value} for key,value in parameters.items()]})
print(json.dumps(result))
"""

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    reference = args.reference.resolve()
    commit = subprocess.check_output(['git','-C',str(reference),'rev-parse','HEAD'],text=True).strip()
    if commit != 'f60978618a101427b06924fc932b44350fec2b63':
        raise ValueError('wrong reference commit')
    subprocess.run(['git','-C',str(reference),'diff','--exit-code','HEAD','--'],check=True,capture_output=True)
    rows=[]
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    for name,stem,section,option,files in CASES:
        with tempfile.TemporaryDirectory(prefix='f2z-p2-config-') as tmp:
            for path,data in files.items():
                target=Path(tmp)/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(data)
            ref=json.loads(subprocess.check_output([sys.executable,'-c',REFERENCE,str(reference),tmp,stem,section,option],env=env,text=True,timeout=10))
            candidate=json.loads(subprocess.check_output([str(args.probe.resolve()),tmp,stem,section,option],env=env,text=True,timeout=10))
            normalized={**ref,'failure':ERRORS.get(ref['failure'],ref['failure'])}
            rows.append({'id':name,'reference':ref,'candidate':candidate,'equal':normalized==candidate,'input':files})
    for name,selector,key,source,parameters in ASSET_CASES:
        with tempfile.TemporaryDirectory(prefix='f2z-p2-asset-') as tmp:
            target=Path(tmp)/'filter.d/custom.conf';target.parent.mkdir();target.write_text(source)
            ref=json.loads(subprocess.check_output([sys.executable,'-c',ASSET_REFERENCE,str(reference),tmp,json.dumps(parameters),key],env=env,text=True,timeout=10))
            candidate=json.loads(subprocess.check_output([str(args.probe.resolve()),'asset',tmp,'filter.d',selector,key,''],env=env,text=True,timeout=10))
            rows.append({'id':name,'reference':ref,'candidate':candidate,'equal':ref==candidate,'input':source,'parameters':parameters})
    for index,selection in enumerate(SELECTOR_CASES):
        ref=json.loads(subprocess.check_output([sys.executable,'-B','-c',SELECTOR_REFERENCE,str(reference),selection],env=env,text=True,timeout=10))
        candidate=json.loads(subprocess.check_output([str(args.probe.resolve()),'selectors',selection],env=env,text=True,timeout=10))
        rows.append({'id':f'original-selector-{index}','reference':ref,'candidate':candidate,'equal':ref==candidate,'input':selection})
    root=Path(__file__).resolve().parents[3]
    inputs=['engine/config/fail2ban.zig','tests/parity/harness/p2_config_probe.zig','tests/parity/harness/p2_config_compare.py']
    reference_inputs=['fail2ban/client/configparserinc.py','fail2ban/client/configreader.py','fail2ban/client/filterreader.py','fail2ban/helpers.py']
    report={'candidate_source_hashes':{path:hashlib.sha256((root/path).read_bytes()).hexdigest() for path in inputs},'reference_source_hashes':{path:hashlib.sha256((reference/path).read_bytes()).hexdigest() for path in reference_inputs},'schema_version':1,'reference_commit':commit,'probe_sha256':hashlib.sha256(args.probe.read_bytes()).hexdigest(),'cases':rows,'agreements':sum(r['equal'] for r in rows),'total':len(rows)}
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'agreements':report['agreements'],'total':report['total']}))
    return 0 if all(r['equal'] for r in rows) else 1
if __name__=='__main__':
    raise SystemExit(main())
