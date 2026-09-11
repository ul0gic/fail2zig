#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original configured ignore/cache trajectories; reference commands only recorded."""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    commit=subprocess.check_output(['git','-C',str(args.reference),'rev-parse','HEAD'],text=True).strip()
    if commit!='f60978618a101427b06924fc932b44350fec2b63':raise SystemExit('wrong reference commit')
    sys.path.insert(0,str(args.reference))
    from fail2ban.helpers import extractOptions
    from fail2ban.server.filter import Filter
    from fail2ban.server.action import CommandAction
    from fail2ban.server.ticket import FailTicket
    from fail2ban.server.ipdns import DNSUtils,IPAddr
    from fail2ban.server.utils import Utils
    Cache=Utils.Cache
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'engine/compat'))
    import ignore_adapter as candidate
    logging.disable(logging.CRITICAL)
    rows=[]
    def record(name,expected,observed):rows.append(dict(id=name,expected=expected,observed=observed,equal=expected==observed))
    for value in ['', 'key=<ip>','key="<ip>,<F-USER>",max-count=2,max-time=1h','key=a][key=b,max-time=10s','key=a,key=b,','extra=value,key=<ip>','key=','key =a','key="oops','bad','key=a]junk','key="a" ,max-count=2',',','  ', 'key= a b ']:
        try:expected=extractOptions('cache['+value+']')[1]
        except ValueError:expected='invalid'
        try:observed=candidate.parse_ignorecache(value)
        except ValueError:observed='invalid'
        record('cache-parse:'+value,expected,observed)
    for manual in (False,True):
        config={'ignoreself':False,'allowipv6':'no','usedns':'no','ignorecache':'key=<ip>:<F-USER>,max-count=2,max-time=10','ignorecommand':'original-recorder <ip> <F-USER>'}
        reference=Filter(None,useDns='no');reference.ignoreSelf=False
        reference.ignoreCache=extractOptions('cache['+config['ignorecache']+']')[1];reference.ignoreCommand=config['ignorecommand']
        reference_calls=[];candidate_calls=[];status=[0];clock=[100]
        def reference_command(command,**kwargs):reference_calls.append(command);return status[0] in (0,1),status[0]
        def candidate_command(command,**kwargs):candidate_calls.append(command);return {'ignore':status[0]==0,'error':None if status[0] in (0,1) else 'command-exit-error'}
        instance=candidate.Adapter(config,'original-profile',trusted_command=candidate.TrustedCommand(config['ignorecommand'],'original-profile'),command_runner=candidate_command)
        state=None;shared=None
        with patch.object(CommandAction,'executeCmd',side_effect=reference_command),patch('fail2ban.server.utils.time.time',side_effect=lambda:clock[0]):
            for stamp,code in [(100,0),(109,1),(110,1),(111,0),(120,2),(130,0)]:
                clock[0],status[0]=stamp,code
                ticket=FailTicket('192.0.2.1',stamp,data={'user':'neutral'})
                expected=reference.inIgnoreIPList('192.0.2.1' if manual else ticket,False)
                result=instance.stage('192.0.2.1',now=stamp,snapshot=state,shared_snapshot=shared,ticket=None if manual else {'id':'192.0.2.1','data':{'user':'neutral'}})
                state=result['snapshot'];shared=result['shared_snapshot']
                record('manual-'+str(manual)+':'+str(stamp),[expected,len(reference_calls)],[result['decisions'][0]['ignored'],len(candidate_calls)])
            record('command-trace:'+str(manual),reference_calls,candidate_calls)
    # Real Filter cache-first path with controlled self-interface reads. No
    # upstream command or test body runs; shared cache sizes are unchanged.
    reference=Filter(None,useDns='no');reference.ignoreSelf=True;reference.ignoreCache={'key':'<ip>','max-time':'1000'}
    reference_reads=[];candidate_reads=[];clock=[100]
    def ref_interfaces():reference_reads.append(clock[0]);return {IPAddr('192.0.2.8')}
    def local_interfaces():candidate_reads.append(clock[0]);return {'192.0.2.8'}
    def lookup(kind,name,**kwargs):return {'addresses':[],'error':None} if kind=='forward' else {'name':'original.test','error':None}
    instance=candidate.Adapter({'ignorecache':'key=<ip>,max-time=1000','allowipv6':'no'},'original-profile',interfaces=local_interfaces,lookup=lookup)
    state=None;shared=None
    with patch.object(DNSUtils,'CACHE_nameToIp',Cache(maxCount=1000,maxTime=300)),patch.object(DNSUtils,'CACHE_ipToName',Cache(maxCount=1000,maxTime=300)),patch.object(DNSUtils,'getNetIntrfIPs',side_effect=ref_interfaces),patch.object(DNSUtils,'getSelfNames',return_value=set()),patch('fail2ban.server.utils.time.time',side_effect=lambda:clock[0]),patch.object(candidate.policy.socket,'gethostname',return_value='original'):
        for stamp in (100,401,1100):
            clock[0]=stamp
            expected=reference.inIgnoreIPList('192.0.2.8',False)
            result=instance.stage('192.0.2.8',now=stamp,snapshot=state,shared_snapshot=shared);state=result['snapshot'];shared=result['shared_snapshot']
            record('cache-before-self:'+str(stamp),[expected,reference_reads[:]], [result['decisions'][0]['ignored'],candidate_reads[:]])
    reference.ignoreCache=None
    reference_reads.clear();candidate_reads.clear();clock[0]=100
    instance=candidate.Adapter({'allowipv6':'no'},'original-profile',interfaces=local_interfaces,lookup=lookup)
    cache=Cache(maxCount=1000,maxTime=300)
    with patch.object(DNSUtils,'CACHE_nameToIp',cache),patch.object(DNSUtils,'getNetIntrfIPs',side_effect=ref_interfaces),patch.object(DNSUtils,'getSelfNames',return_value=set()),patch('fail2ban.server.utils.time.time',side_effect=lambda:clock[0]),patch.object(candidate.policy.socket,'gethostname',return_value='original'):
        reference.inIgnoreIPList('192.0.2.8',False)
        first=instance.stage('192.0.2.8',now=100)
        staged_cache=candidate.policy.Cache();candidate.cache_restore(staged_cache,'forward',first['shared_snapshot']['forward'])
        for index in range(1000):
            cache.set('pressure-'+str(index)+'.test',set())
            staged_cache.set('pressure-'+str(index)+'.test',{'addresses':set(),'error':None,'cache_hit':False},100)
        first['shared_snapshot']['forward']=candidate.cache_export(staged_cache,'forward')
        expected=reference.inIgnoreIPList('192.0.2.8',False)
        observed=instance.stage('192.0.2.8',now=100,snapshot=first['snapshot'],shared_snapshot=first['shared_snapshot'])
        record('shared-forward-cache-self-eviction',[expected,len(reference_reads)],[observed['decisions'][0]['ignored'],len(candidate_reads)])
    # Near-capacity pressure evicts the IPv6 marker from the same FIFO as DNS.
    # Populate benign cached answers, never contact a resolver/network.
    reference_probes=[];candidate_probes=[];clock=[100]
    def support_ref():reference_probes.append(clock[0]);return True
    def support_candidate():candidate_probes.append(clock[0]);return True
    instance=candidate.Adapter({'ignoreself':False,'allowipv6':'auto','usedns':'yes'},'original-profile',ipv6_probe=support_candidate,lookup=lambda *args,**kwargs:{'addresses':[],'error':None})
    first=instance.stage('first.test',now=100);state=first['snapshot'];shared=first['shared_snapshot']
    cache=Cache(maxCount=1000,maxTime=300)
    with patch.object(DNSUtils,'CACHE_nameToIp',cache),patch.object(DNSUtils,'_IPv6IsAllowed',None),patch.object(DNSUtils,'_IPv6IsSupportedBySystem',side_effect=support_ref),patch('fail2ban.server.utils.time.time',side_effect=lambda:clock[0]):
        DNSUtils.IPv6IsAllowed();cache.set('first.test',set())
        for index in range(999):cache.set('original-'+str(index)+'.test',set())
        staged_cache=candidate.policy.Cache()
        candidate.cache_restore(staged_cache,'forward',shared['forward'])
        for index in range(999):staged_cache.set('original-'+str(index)+'.test',{'addresses':set(),'error':None,'cache_hit':False},100)
        shared['forward']=candidate.cache_export(staged_cache,'forward')
        DNSUtils.IPv6IsAllowed()
        result=instance.stage('after-pressure.test',now=100,snapshot=state,shared_snapshot=shared)
        record('shared-forward-cache-ipv6-eviction',len(reference_probes),len(candidate_probes))
        record('shared-forward-cache-capacity',1000,len(result['shared_snapshot']['forward']))
    # Two independent jails consume one explicit process cache snapshot.
    references=[Filter(None,useDns='no'),Filter(None,useDns='no')]
    for ref in references:ref.ignoreSelf=True
    reference_reads=[];candidate_reads=[];clock=[100]
    def reference_interfaces():reference_reads.append(clock[0]);return {IPAddr('192.0.2.8')}
    def candidate_interfaces():candidate_reads.append(clock[0]);return {'192.0.2.8'}
    adapters=[candidate.Adapter({'allowipv6':'no','ignoreip':items},'original-profile',interfaces=candidate_interfaces,lookup=lookup) for items in ([],['192.0.2.9'])]
    states=[None,None];shared=None
    cache=Cache(maxCount=1000,maxTime=300)
    with patch.object(DNSUtils,'CACHE_nameToIp',cache),patch.object(DNSUtils,'CACHE_ipToName',Cache(maxCount=1000,maxTime=300)),patch.object(DNSUtils,'getNetIntrfIPs',side_effect=reference_interfaces),patch.object(DNSUtils,'getSelfNames',return_value=set()),patch('fail2ban.server.utils.time.time',side_effect=lambda:clock[0]),patch.object(candidate.policy.socket,'gethostname',return_value='original'):
        for jail_index,stamp in ((0,100),(1,101),(0,102)):
            clock[0]=stamp
            expected=references[jail_index].inIgnoreIPList('192.0.2.8',False)
            result=adapters[jail_index].stage('192.0.2.8',now=stamp,snapshot=states[jail_index],shared_snapshot=shared)
            states[jail_index],shared=result['snapshot'],result['shared_snapshot']
            record('cross-jail-self:'+str(stamp),[expected,reference_reads[:]], [result['decisions'][0]['ignored'],candidate_reads[:]])
        staged_cache=candidate.policy.Cache();candidate.cache_restore(staged_cache,'forward',shared['forward'])
        for index in range(1000):
            name='cross-pressure-'+str(index)+'.test'
            cache.set(name,set());staged_cache.set(name,{'addresses':set(),'error':None,'cache_hit':False},102)
        shared['forward']=candidate.cache_export(staged_cache,'forward')
        clock[0]=103
        expected=references[1].inIgnoreIPList('192.0.2.8',False)
        result=adapters[1].stage('192.0.2.8',now=103,snapshot=states[1],shared_snapshot=shared)
        record('cross-jail-self-eviction',[expected,reference_reads[:]], [result['decisions'][0]['ignored'],candidate_reads[:]])
    path=Path(candidate.__file__)
    result=dict(scope='configured ignore composition, original command recorders, cache-first and shared-cache pressure; no matcher/actions/network',reference_commit=commit,
        component_sha256={name:hashlib.sha256(path.with_name(name).read_bytes()).hexdigest() for name in ('ignore_adapter.py','ignore_dns.py','action_info.py','duration.py')},cases=rows,
        equal=sum(r['equal'] for r in rows),mismatches=sum(not r['equal'] for r in rows))
    args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
    return bool(result['mismatches'])
if __name__=='__main__':raise SystemExit(main())
