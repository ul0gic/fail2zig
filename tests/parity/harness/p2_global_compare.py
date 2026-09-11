#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original global-reader fixtures versus actual production migration metadata.

Preparation only: never executes filters, actions, stock tests or daemon commands.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

REFERENCE = r'''
import json,sys
sys.path.insert(0,sys.argv[1])
from fail2ban.client.fail2banreader import Fail2banReader
reader=Fail2banReader(basedir=sys.argv[2]);reader.read()
early=reader.getEarlyOptions()
reader.getOptions()
# convert returns command data; no transmitter/server executes that data.
global_options={row[1]:row[2] for row in reader.convert()}
print(json.dumps({'early':early,'global':global_options}))
'''
CASES = [
 ('missing-source', {}),
 ('missing-definition', {'fail2ban.conf':'# Original empty configuration\n'}),
 ('empty-definition', {'fail2ban.conf':'[Definition]\n'}),
 ('layered-empty', {'fail2ban.conf':'[INCLUDES]\nbefore=common.conf\n[Definition]\nlogtarget=base\n',
     'common.conf':'[Definition]\nsyslogsocket=auto\n',
     'fail2ban.d/10-package.conf':'[Definition]\nlogtarget=package\n',
     'fail2ban.local':'[Definition]\nlogtarget=operator\n',
     'fail2ban.d/90-final.local':'[Definition]\nlogtarget=\n'}),
 ('typed-thread', {'fail2ban.conf':'[Definition]\ndbmaxmatches=1_024\nallowipv6=no\ndbfile=None\ndbpurgeage=2d\n[Thread]\nstacksize=8192\n'}),
 ('empty-thread', {'fail2ban.conf':'[Definition]\n[Thread]\n'}),
 ('invalid-integers', {'fail2ban.conf':'[Definition]\ndbmaxmatches=bad\n[Thread]\nstacksize=bad\n'}),
 ('unicode-integer', {'fail2ban.conf':'[Definition]\ndbmaxmatches=١٢\n'}),
 ('explicit-empty-and-open', {'fail2ban.conf':'[Definition]\ndbfile=\nallowipv6=\n[PrivateExtension]\ncustom=original-value\n'}),
 ('consuming-interpolation', {'fail2ban.conf':'[DEFAULT]\nbase=STDERR\n[Definition]\nlogtarget=%(base)s\nbase=SYSLOG\n'}),
]


def normalized(manifest):
    result = {'early':{}, 'global':{}}
    thread = {}
    for row in manifest['global']['reader_observations']:
        if row['reader_entry'] == 'omitted':
            continue
        if row['reader_entry'] != 'emitted':
            raise ValueError('unexpected invalid reader observation')
        tagged = row['value']['value']
        if 'string' in tagged: value = tagged['string']
        elif 'integer' in tagged: value = int(tagged['integer'])
        elif 'null_value' in tagged: value = None
        else: raise ValueError('unexpected typed observation')
        target = thread if row['phase'] == 'thread' else result[row['phase']]
        target[row['option']] = value
    if thread:
        result['global']['thread'] = thread
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    reference=args.reference.resolve();candidate=args.candidate.resolve()
    commit=subprocess.check_output(['git','-C',str(reference),'rev-parse','HEAD'],text=True).strip()
    if commit != 'f60978618a101427b06924fc932b44350fec2b63':raise ValueError('wrong reference commit')
    subprocess.run(['git','-C',str(reference),'diff','--exit-code','HEAD','--'],check=True,capture_output=True)
    rows=[]
    for name,files in CASES:
        with tempfile.TemporaryDirectory(prefix='f2z-p2-global-original-') as directory:
            root=Path(directory)
            (root/'jail.conf').write_text('[sshd]\nenabled=true\n')
            for path,data in files.items():
                target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(data)
            ref=subprocess.run([sys.executable,'-B','-c',REFERENCE,str(reference),directory],capture_output=True,text=True,timeout=10,check=True)
            output=root/'prepared.toml'
            cand=subprocess.run([str(candidate),'--import-config',directory,'--import-output',str(output)],capture_output=True,text=True,timeout=10)
            if cand.returncode not in (0,1) or not output.exists():raise ValueError(f'{name}: preparation failed {cand.stderr}')
            manifest=json.loads(tomllib.loads(output.read_text())['global']['compatibility_manifest'])
            actual=normalized(manifest);wanted=json.loads(ref.stdout)
            rows.append({'id':name,'input':files,'reference':wanted,'candidate':actual,'equal':wanted==actual,
                         'candidate_exit':cand.returncode,'manifest_sha256':hashlib.sha256(manifest_json(manifest)).hexdigest()})
    root=Path(__file__).resolve().parents[3]
    paths=['engine/config/fail2ban.zig','engine/config/migration.zig','engine/config/native.zig','engine/config/source_plan.zig','engine/config/filter_context.zig','tests/parity/harness/p2_global_compare.py']
    refpaths=['fail2ban/client/fail2banreader.py','fail2ban/client/configreader.py','fail2ban/client/configparserinc.py','fail2ban/helpers.py']
    report={'schema_version':1,'scope':'Actual early/global/Thread reader values versus prepared migration metadata; no runtime setter execution or full CFG03 certification',
            'reference_commit':commit,'candidate_binary_sha256':hashlib.sha256(candidate.read_bytes()).hexdigest(),
            'candidate_source_hashes':{p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths},
            'reference_source_hashes':{p:hashlib.sha256((reference/p).read_bytes()).hexdigest() for p in refpaths},
            'cases':rows,'agreements':sum(row['equal'] for row in rows),'total':len(rows)}
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'agreements':report['agreements'],'total':report['total']}))
    return 0 if report['agreements']==report['total'] else 1


def manifest_json(manifest):
    return json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()

if __name__=='__main__':raise SystemExit(main())
