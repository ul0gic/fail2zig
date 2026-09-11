#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original controlled backend factories and no-log selections; no live sources/actions."""
import argparse
import hashlib
import itertools
import json
import logging
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference',type=Path,required=True)
    ap.add_argument('--candidate',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    commit=subprocess.check_output(['git','-C',str(args.reference),'rev-parse','HEAD'],text=True).strip()
    if commit!='f60978618a101427b06924fc932b44350fec2b63':
        raise SystemExit('wrong reference commit')
    sys.path.insert(0,str(args.reference))
    from fail2ban.server.jail import Jail
    from fail2ban.client.jailreader import JailReader
    logging.disable(logging.CRITICAL)
    rows=[]
    def candidate(*values):
        return json.loads(subprocess.check_output([str(args.candidate),*map(str,values)],text=True))
    names=('auto','pyinotify','polling','systemd','AUTO','POLLING','unknown')
    for name,outcomes in itertools.product(names,itertools.product('sme',repeat=3)):
        outcomes=''.join(outcomes)
        jail=object.__new__(Jail)
        jail._Jail__name='original-policy'
        attempted=[]
        for index,backend in enumerate(('pyinotify','polling','systemd')):
            def initialize(index=index,backend=backend,**kwargs):
                attempted.append(backend)
                if outcomes[index]=='m': raise ImportError('original controlled missing dependency')
                if outcomes[index]=='e': raise OSError('original controlled initialization error')
            setattr(jail,'_init'+backend.capitalize(),initialize)
        with patch('fail2ban.server.jail.Actions',lambda _:object()):
            try:
                expected={'backend':jail._setBackend(name),'attempts':attempted}
            except (ValueError,RuntimeError,OSError) as error:
                expected={'failure':{ValueError:'UnknownBackend',RuntimeError:'NoAvailableBackend',OSError:'InitializationFailed'}[type(error)],'attempts':attempted}
        observed=candidate('select',name,outcomes)
        rows.append(dict(kind='backend',input=[name,outcomes],expected=expected,observed=observed,equal=expected==observed))
    for name in ('auto','auto[journalflags=1]','AUTO','polling','systemd','systemd[journalflags=1]','SYSTEMD'):
        for present,found,journal,skip,local,global_,allow in itertools.product((False,True),repeat=7):
            if not present and found: continue
            options={'backend':name,'skip_if_nologs':skip,'systemd_if_nologs':local}
            if present: options['logpath']='original-neutral.log'
            if journal: options['journalmatch']=''
            reader=JailReader('original-policy')
            reader._JailReader__opts=options
            with patch.object(JailReader,'_glob',return_value=['original-neutral.log'] if found else []):
                try:
                    stream=reader.convert(allow_no_files=allow,systemd_if_nologs=global_)
                    expected={'disposition':'skip','backend':name} if stream[0][0]=='config-error' else {'disposition':'admit','backend':stream[0][2]}
                except ValueError:
                    expected={'disposition':'missing_logs','backend':name}
            inputs=[int(v) for v in (present,found,journal,skip,local,global_,allow)]
            observed=candidate('prepare',name,*inputs)
            rows.append(dict(kind='no-log',input=[name,*inputs],expected=expected,observed=observed,equal=expected==observed))
    source=Path(__file__).resolve().parents[2]/'engine/core/source_policy.zig'
    result=dict(scope='native backend/no-log policy and controlled reference factories; no platform qualification or live backend creation',reference_commit=commit,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
        cases=rows,equal=sum(r['equal'] for r in rows),mismatches=sum(not r['equal'] for r in rows))
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
    return bool(result['mismatches'])


if __name__=='__main__':
    raise SystemExit(main())
