#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original ActionInfo/tag formatting fixtures; no upstream action bodies execute."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    commit=subprocess.check_output(['git','-C',str(args.reference),'rev-parse','HEAD'],text=True).strip()
    if commit!='f60978618a101427b06924fc932b44350fec2b63':
        raise SystemExit('wrong reference commit')
    sys.path.insert(0,str(args.reference))
    from fail2ban.server.actions import Actions
    from fail2ban.server.filter import Filter
    from fail2ban.server.action import CommandAction
    from fail2ban.server.ticket import FailTicket
    from fail2ban.server.ipdns import DNSUtils
    path=Path(__file__).resolve().parents[2]/'engine/compat/action_info.py'
    spec=importlib.util.spec_from_file_location('f2z_action_info_compare',path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    rows=[]
    def record(name,expected,observed):
        rows.append(dict(id=name,expected=expected,observed=observed,equal=expected==observed))
    for address in ('192.0.2.1','2001:db8::1'):
        data={'user':"O'Brien",'fport':'22','fid':'neutral-id'}
        ticket=FailTicket(address,1000.125,matches=['neutral first','neutral second'],data=data)
        ticket.setAttempt(3)
        ticket.setBanCount(2)
        jail=SimpleNamespace(name='neutral',database=None,
            actions=SimpleNamespace(getBanTime=lambda:60,banManager=SimpleNamespace(size=lambda:4,getBanTotal=lambda:5)),
            filter=SimpleNamespace(failManager=SimpleNamespace(size=lambda:6,getFailTotal=lambda:7)))
        reference=Actions.ActionInfo(ticket,jail)
        candidate=module.ActionInfo(dict(id=address,attempts=3,time=1000.125,ban_count=2,
                                         matches=['neutral first','neutral second'],data=data,repr=repr(ticket)),
                                    jail={'name':'neutral','ban_time':60,'banned':4,'banned_total':5,'found':6,'found_total':7},
                                    resolver=SimpleNamespace(reverse=lambda address,now:dict(name='neutral.test',error=None)))
        with patch.object(DNSUtils,'ipToName',return_value='neutral.test'):
            for key in module.ActionInfo.KEYS:
                if key=='F-*':
                    # The reference adds internal ticket fields to its data dict.
                    continue
                record('field:'+address+':'+key,str(reference[key]),str(candidate[key]))
            for index,template in enumerate(['<ip>|<family>|<ip-rev>','<fid>|<time>|<failures>',
                                            '<jail.name>:<bantime>:<bancount>',
                                            'record "<F-USER>" "<matches>"',
                                            '<F-ID>:<F-PORT>:<F-MISSING>',
                                            '<unknown>|<sp>|<br>',
                                            '<ip>:<F-USER>:<ip-host>']):
                record('expansion:'+address+':'+str(index),CommandAction.replaceDynamicTags(template,reference),module.expand_dynamic(template,candidate))
    ignore_path=path.with_name('ignore_dns.py')
    ignore_spec=importlib.util.spec_from_file_location('f2z_ignore_for_tags',ignore_path)
    ignore=importlib.util.module_from_spec(ignore_spec)
    sys.modules[ignore_spec.name]=ignore
    ignore_spec.loader.exec_module(ignore)
    reference=Filter(None,useDns='no')
    reference.ignoreSelf=False
    reference.ignoreCache={'key':'<ip>:<F-USER>','max-count':'10','max-time':'10'}
    reference.ignoreCommand='original-recorder <ip> <F-USER>'
    reference_commands=[]
    candidate_commands=[]
    now=[100]
    status=[0]
    def reference_execute(command,**kwargs):
        reference_commands.append(command)
        return status[0] in (0,1),status[0]
    def candidate_execute(value,values):
        expanded=module.expand_dynamic('original-recorder <ip> <F-USER>',values['info'])
        candidate_commands.append(expanded)
        return {'ignore':status[0]==0,'error':None if status[0] in (0,1) else 'command-exit-error'}
    policy=ignore.IgnorePolicy(ignore_self=False,
        cache_key=lambda value,values:module.cache_key('<ip>:<F-USER>',values['info']),
        cache_count=10,cache_time=10,command=candidate_execute)
    with patch.object(CommandAction,'executeCmd',side_effect=reference_execute),patch('fail2ban.server.utils.time.time',side_effect=lambda:now[0]):
        for stamp,code in [(100,0),(109,1),(110,1),(111,0),(120,2),(130,0)]:
            now[0],status[0]=stamp,code
            ticket=FailTicket('192.0.2.1',stamp,data={'user':'neutral'})
            info=module.ActionInfo({'id':'192.0.2.1','data':{'user':'neutral'}},now=stamp)
            expected=reference.inIgnoreIPList(ticket,False)
            observed=policy.check('192.0.2.1',now=stamp,cache_values={'info':info}).ignored
            record('ignorecommand-cache:'+str(stamp),[expected,len(reference_commands)],[observed,len(candidate_commands)])
        record('ignorecommand-expanded-trace',reference_commands,candidate_commands)
    receipt=dict(scope='ActionInfo snapshot fields, dynamic expansion, and ignorecommand/cache recorders; no upstream command execution',reference_commit=commit,candidate_source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),ignore_source_sha256=hashlib.sha256(ignore_path.read_bytes()).hexdigest(),cases=rows,equal=sum(row['equal'] for row in rows),mismatches=sum(not row['equal'] for row in rows))
    args.output.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({k:v for k,v in receipt.items() if k!='cases'}))
    return bool(receipt['mismatches'])


if __name__=='__main__':
    raise SystemExit(main())
