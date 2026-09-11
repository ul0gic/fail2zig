#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original address/ignore/DNS fixtures with recorded local dependency answers only."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
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
    from fail2ban.server.filter import Filter
    from fail2ban.server.ipdns import DNSUtils,IPAddr,FileIPAddrSet,getfqdn
    from fail2ban.server.mytime import MyTime
    from fail2ban.server.utils import Utils
    path=Path(__file__).resolve().parents[2]/'engine/compat/ignore_dns.py'
    spec=importlib.util.spec_from_file_location('f2z_ignore_compare',path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    rows=[]
    def record(name,expected,observed):
        rows.append(dict(id=name,expected=expected,observed=observed,equal=expected==observed))
    # Any unresolved ignore entry gets a controlled empty answer in network cases.
    with patch.object(DNSUtils,'dnsToIp',return_value=set()):
        for entries in [[],['192.0.2.1'],['192.0.2.0/24'],['0.0.0.0/0'],['2001:db8::/32'],['::/0'],['::ffff:192.0.2.1'],['::ffff:192.0.2.1/128']]:
            reference=Filter(None,useDns='no')
            reference.ignoreSelf=False
            for entry in entries:
                reference.addIgnoreIP(entry)
            candidate=module.IgnorePolicy(entries,ignore_self=False)
            for address in ['192.0.2.1','192.0.2.2','198.51.100.1','2001:db8::1','2001:db9::1','::ffff:192.0.2.1']:
                record('network:'+','.join(entries)+':'+address,reference.inIgnoreIPList(address,False),candidate.check(address,now=100).ignored)
    now=[100.0]
    reference_calls=[]
    candidate_calls=[]
    def addresses(name):
        return ['192.0.2.1','2001:db8::1'] if name=='neutral.test' else []
    def reference_lookup(name,port,family,kind,protocol):
        reference_calls.append((name,family))
        values=addresses(name)
        if not values:
            raise socket.gaierror('original controlled missing answer')
        return [(family,socket.SOCK_STREAM,socket.IPPROTO_TCP,'',(value,0)) for value in values if (':' in value)==(family==socket.AF_INET6)]
    def candidate_lookup(kind,name,**kwargs):
        candidate_calls.append((kind,name))
        return dict(addresses=addresses(name),error=None if addresses(name) else 'gaierror')
    DNSUtils.CACHE_nameToIp.clear()
    resolver=module.Resolver(candidate_lookup)
    with patch('socket.getaddrinfo',reference_lookup),patch.object(DNSUtils,'IPv6IsAllowed',return_value=True),patch('fail2ban.server.utils.time.time',side_effect=lambda:now[0]):
        for mode in ['yes','warn','no']:
            for address in ['neutral.test','missing.test','192.0.2.1','[2001:db8::1]']:
                expected=sorted(str(ip) for ip in DNSUtils.textToIp(address,mode))
                observed=sorted(ip.text for ip in resolver.text_to_identity(address,mode,now[0])['identities'])
                record('dns:'+mode+':'+address,expected,observed)
        before_reference=len(reference_calls)
        before_candidate=len(candidate_calls)
        now[0]=399
        DNSUtils.dnsToIp('neutral.test');resolver.forward('neutral.test',now[0])
        record('dns-cache-before-expiry',[0,0],[len(reference_calls)-before_reference,len(candidate_calls)-before_candidate])
        now[0]=400
        DNSUtils.dnsToIp('neutral.test');resolver.forward('neutral.test',now[0])
        record('dns-cache-at-expiry',[2,1],[len(reference_calls)-before_reference,len(candidate_calls)-before_candidate])
        reference_cache=Utils.Cache(maxCount=2,maxTime=10)
        candidate_cache=module.Cache(2,10)
        for action,key,value,stamp in [('set','a',False,500),('get','a',None,509),('get','a',None,510),('set','a',1,511),('set','b',2,512),('get','a',None,513),('set','c',3,514),('get','a',None,514),('get','b',None,514)]:
            now[0]=stamp
            if action=='set':
                reference_cache.set(key,value);candidate_cache.set(key,value,stamp)
            else:
                record(f'cache:{key}:{stamp}',reference_cache.get(key),candidate_cache.get(key,stamp))
    with tempfile.TemporaryDirectory(prefix='f2z-original-ignore-') as directory:
        file_path=Path(directory)/'ignore.txt'
        file_path.write_text('192.0.2.1, 2001:db8::/32 # neutral entries\n')
        reference_file=FileIPAddrSet(str(file_path))
        candidate_file=module.FileIgnoreSet('file:'+str(file_path))
        for stamp in (100,101,102):
            MyTime.setTime(stamp)
            if stamp==101:
                file_path.write_text('198.51.100.1\n')
            for address in ('192.0.2.1','2001:db8::1','198.51.100.1'):
                record(f'file:{stamp}:{address}',IPAddr(address) in reference_file,candidate_file.contains(module.identity(address),stamp)[0])
        MyTime.setTime(104)
        file_path.unlink()
        record('file:last-good-on-missing',IPAddr('198.51.100.1') in reference_file,candidate_file.contains(module.identity('198.51.100.1'),104)[0])
    # Exercise the actual bounded resolver process using local localhost/NSS only.
    record('bounded-localhost-fqdn',getfqdn('localhost'),module.bounded_resolve('fqdn','localhost')['name'])
    hostname_calls=[]
    def hostname_lookup(kind,name,**kwargs):
        hostname_calls.append((kind,name))
        return {'name':'neutral.example','error':None}
    names=module.Resolver(hostname_lookup)
    with patch('socket.gethostname',return_value='neutral'),patch('fail2ban.server.ipdns.getfqdn',return_value='neutral.example'),patch('fail2ban.server.utils.time.time',side_effect=lambda:now[0]):
        DNSUtils.CACHE_ipToName.clear()
        now[0]=700
        for fqdn in (False,True):
            record('hostname:'+str(fqdn),DNSUtils.getHostname(fqdn),names.hostname(fqdn,700)['name'])
        names.hostname(True,999)
        record('hostname-cache-before-expiry',1,len(hostname_calls))
        names.hostname(True,1000)
        record('hostname-cache-at-expiry',2,len(hostname_calls))
    # Interface enumeration reads local kernel metadata, without hostname resolution.
    expected_interfaces={str(value) for value in DNSUtils.getNetIntrfIPs()}
    observed_interfaces={value.text for value in module.local_interface_identities()}
    # Do not retain private interface addresses in the public comparison receipt.
    record('local-interface-enumeration',True,expected_interfaces==observed_interfaces)
    receipt=dict(scope='component address/network/DNS and cache comparisons; controlled DNS answers plus local localhost/NSS; no firewall actions; daemon integration not certified',reference_commit=commit,candidate_source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=rows,equal=sum(row['equal'] for row in rows),mismatches=sum(not row['equal'] for row in rows))
    args.output.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({k:v for k,v in receipt.items() if k!='cases'}))
    return bool(receipt['mismatches'])


if __name__=='__main__':
    raise SystemExit(main())
