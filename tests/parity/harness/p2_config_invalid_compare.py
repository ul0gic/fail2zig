#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original INI lexical acceptance/rejection observations; no runtime actions."""
import argparse,hashlib,json,platform,re,subprocess,sys,tempfile
from pathlib import Path
REFERENCE=r'''
import json,sys
sys.path.insert(0,sys.argv[1])
from fail2ban.client.configparserinc import SafeConfigParserWithIncludes
p=SafeConfigParserWithIncludes()
try:
 p.read(sys.argv[2]);value=p.get(sys.argv[3],sys.argv[4],fallback=None)
 print(json.dumps({'accepted':True,'value':value,'error':None}))
except Exception as e:print(json.dumps({'accepted':False,'value':None,'error':type(e).__name__}))
'''
CASES=[
 ('duplicate-key','[probe]\nv=one\nv=two\n','probe'),
 ('duplicate-section','[probe]\nv=one\n[probe]\nv=two\n','probe'),
 ('outside-section','v=one\n','probe'),
 ('valueless-key','[probe]\nv\n','probe'),
 ('empty-key','[probe]\n=one\n','probe'),
 ('empty-section','[]\nv=one\n',''),
 ('unclosed-section','[probe\nv=one\n','probe'),
 ('trailing-section-text','[probe] original text\nv=one\n','probe'),
 ('spaced-section','[ probe ]\nv=one\n',' probe '),
 ('semicolon-without-space','[probe]\nv=one;two\n','probe'),
 ('semicolon-with-space','[probe]\nv=one ;two\n','probe'),
 ('inline-hash','[probe]\nv=one #two\n','probe'),
 ('comment-continuation','[probe]\nv=one\n # original comment\n two\n','probe'),
 ('blank-continuation','[probe]\nv=one\n\n two\n','probe'),
 ('greedy-header','[nested]suffix] original\nv=one\n','nested]suffix'),
 ('comment-header-bracket','[probe] ; ignored ]\nv=one\n','probe'),
 ('comment-removes-closing','[probe ; ignored ]\nv=one\n','probe'),
 ('colon-value','[probe]\nv: one:two\n','probe'),
]
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for arg in ('reference','probe','output'):p.add_argument('--'+arg,type=Path,required=True)
 p.add_argument('--source-profile',choices=['upstream1.1.1','upstream1.1.0'],default='upstream1.1.1')
 a=p.parse_args();reference=a.reference.resolve()
 commit=subprocess.check_output(['git','-C',str(reference),'rev-parse','HEAD'],text=True).strip()
 expected={'upstream1.1.1':'f60978618a101427b06924fc932b44350fec2b63','upstream1.1.0':'61799e15e1dd4389dea0cc7595da0a287835a177'}[a.source_profile]
 if commit!=expected:raise ValueError('wrong reference')
 subprocess.run(['git','-C',str(reference),'diff','--exit-code','HEAD','--'],check=True,capture_output=True)
 rows=[]
 for name,data,section in CASES:
  with tempfile.TemporaryDirectory(prefix='f2z-p2-original-lexical-') as tmp:
   path=Path(tmp)/'jail.conf';path.write_text(data)
   wanted=json.loads(subprocess.check_output([sys.executable,'-B','-c',REFERENCE,str(reference),str(path),section,'v'],text=True,timeout=10))
   result=subprocess.run([str(a.probe.resolve()),tmp,'jail',section,'v'],capture_output=True,text=True,timeout=10)
   if result.returncode:
    error=re.search(r'error: ([A-Za-z0-9_]+)',result.stderr)
    actual={'accepted':False,'value':None,'error':error.group(1) if error else 'unclassified'}
   else:
    value=json.loads(result.stdout);actual={'accepted':value['failure'] is None,'value':value['value'],'error':value['failure']}
   equal=actual['accepted']==wanted['accepted'] and actual['value']==wanted['value']
   rows.append({'id':name,'input':data,'section':section,'reference':wanted,'candidate':actual,'equal_outcome':equal})
 root=Path(__file__).resolve().parents[3]
 report={'schema_version':1,'scope':'Lexical acceptance/value outcomes with original error names retained; error vocabulary is not asserted identical','source_profile':a.source_profile,'execution_environment':{'python':sys.version,'platform':platform.platform()},'selected_distro_runtime_certified':False,'reference_commit':commit,'probe_sha256':hashlib.sha256(a.probe.read_bytes()).hexdigest(),'source_hashes':{x:hashlib.sha256((root/x).read_bytes()).hexdigest() for x in ['engine/config/fail2ban.zig','tests/parity/harness/p2_config_probe.zig','tests/parity/harness/p2_config_invalid_compare.py']},'reference_source_sha256':hashlib.sha256((reference/'fail2ban/client/configparserinc.py').read_bytes()).hexdigest(),'cases':rows,'agreements':sum(x['equal_outcome'] for x in rows),'total':len(rows)}
 a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'agreements':report['agreements'],'total':report['total']}));return int(report['agreements']!=report['total'])
if __name__=='__main__':raise SystemExit(main())
