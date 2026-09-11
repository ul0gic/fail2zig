# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Configured, staged ignore/DNS policy over explicit identities and ticket snapshots.

The caller atomically publishes both returned snapshots with its record transaction.
The per-jail version-2 snapshot contains ignore-cache/file state; shared_snapshot
version 1 contains process-wide DNS, interface, self and IPv6 caches. All jails
in the same explicit runtime profile/global IPv6 policy pass the same committed
shared snapshot, protected by the caller's shared revision/CAS. Omitting it
starts an empty process cache; never omit it merely because a jail is new.
Discarding a proposal publishes neither cache. Dependency implementations and
locale/platform identity belong in the explicit profile supplied at admission.
This component
does not match logs, create tickets, activate imported commands or alter firewalls.
External dependencies are explicit and must honor the supplied timeout.
"""
from dataclasses import dataclass
import hashlib
import errno
import ipaddress
import json
import math
import re
import socket
import time
from pathlib import Path

import action_info


class ExternalWorkBudget(ValueError):
    """A staged dependency count or deadline exhausted its admitted budget."""
import duration
import ignore_dns as policy

MAX_SNAPSHOT = 4 * 1024 * 1024
MARKERS={'self-ips':('self','ips'),'interfaces':('netintrf','ips'),'ipv6':('self','ipv6-allowed'),'self-names':('self','dns')}


def parse_ignorecache(text):
    """Bounded parameter-list syntax used by the reference ignorecache setter."""
    if not isinstance(text,str) or len(text)>65536:raise ValueError('invalid ignorecache text')
    result={};position=0
    name_pattern=re.compile(r'[\w.\-]+(?:\?[\w.\-]+=[\w.\-]+)?=')
    while position<len(text):
        while position<len(text) and text[position].isspace():position+=1
        if position==len(text):break
        if text[position]==',' and not text[position+1:].strip():break
        match=name_pattern.match(text,position)
        if match is None:raise ValueError('invalid ignorecache parameter')
        name=match[0][:-1];position=match.end()
        if position<len(text) and text[position] in ('"',"'"):
            quote=text[position];end=text.find(quote,position+1)
            if end<0:
                start=position
                while position<len(text) and text[position] not in ',]':position+=1
                value=text[start:position]
            else:
                value=text[position+1:end];position=end+1
        else:
            start=position
            while position<len(text) and text[position] not in ',]':position+=1
            value=text[start:position]
        result[name]=value.strip()
        if len(result)>256:raise ValueError('ignorecache parameter budget')
        if position==len(text):break
        if text[position]==',':position+=1;continue
        if text[position]==']':
            position+=1
            while position<len(text) and text[position].isspace():position+=1
            if position<len(text) and text[position]=='[':position+=1;continue
        raise ValueError('invalid ignorecache separator')
    return result


def from_plan(plan):
    """Normalize a prepared IgnorePlan while its owner retains raw provenance."""
    expected={'schema_version','admission','jail','ignoreip','ignoreself','usedns','ignorecache','ignorecommand','allowipv6','diagnostics'}
    if not isinstance(plan,dict) or set(plan)!=expected or type(plan['schema_version']) is not int or plan['schema_version']!=1 or plan['admission']!='prepared-only':raise ValueError('invalid ignore plan')
    if not isinstance(plan['jail'],str) or not plan['jail'] or len(plan['jail'])>4096:raise ValueError('invalid jail identity')
    if not isinstance(plan['diagnostics'],list) or plan['diagnostics']:raise ValueError('ignore plan contains fatal diagnostics')
    absent=object()
    def option(envelope):
        if not isinstance(envelope,dict) or set(envelope)!={'reader','error_name','derived_filter_asset'} or envelope['error_name'] is not None:raise ValueError('invalid prepared ignore option')
        reader=envelope['reader']
        if reader is None:return absent
        fields={'presence','resolution','value_type','raw','value','origin','default_identity'}
        if not isinstance(reader,dict) or set(reader)!=fields or reader['presence'] not in ('absent','explicit','derived') or reader['resolution'] not in ('resolved','reference_fallback') or reader['value_type'] not in ('string','boolean'):raise ValueError('invalid ignore reader envelope')
        value=reader['value']
        if not isinstance(value,dict) or len(value)!=1:raise ValueError('invalid ignore reader value')
        if 'null_value' in value and value['null_value']=={}:
            return absent if reader['presence']=='absent' else None
        if 'string' in value and isinstance(value['string'],str):return value['string']
        if 'boolean' in value and type(value['boolean']) is bool:return value['boolean']
        raise ValueError('invalid ignore reader value type')
    result={}
    for name in ('ignoreip','ignoreself','usedns','ignorecache','ignorecommand'):
        value=option(plan[name])
        if value is absent:continue
        if name=='ignoreself':
            if value is not None and type(value) is not bool:raise ValueError('invalid typed ignoreself')
            value=False if value is None else value
        elif name=='ignoreip' and value is None:value=[]
        elif name=='ignorecommand' and value is None:value=''
        elif name=='ignorecache':value=parse_ignorecache(value)
        result[name]=value
    ipv6=plan['allowipv6']
    if not isinstance(ipv6,dict) or set(ipv6)!={'option','policy','adapter_value'}:raise ValueError('invalid IPv6 plan')
    option(ipv6['option'])
    mapping={'automatic':'auto','enabled':'yes','disabled':'no'}
    if ipv6['policy'] not in mapping or ipv6['adapter_value']!=mapping[ipv6['policy']]:raise ValueError('invalid IPv6 plan policy')
    result['allowipv6']=ipv6['adapter_value']
    return result


def finite(value):
    if type(value) not in (int,float) or not math.isfinite(value):
        raise ValueError('nonfinite policy value')
    return value


def identity_json(value):
    return {'kind':value.kind,'text':value.text,'prefix':value.prefix}


def identity_restore(value):
    if not isinstance(value,dict) or set(value)!={'kind','text','prefix'}:
        raise ValueError('invalid identity snapshot')
    kind,text,prefix=value['kind'],value['text'],value['prefix']
    if not isinstance(text,str): raise ValueError('invalid identity text')
    if kind in ('ipv4','ipv6'):
        if type(prefix) is not int: raise ValueError('invalid identity prefix')
        result=policy.identity(text+'/'+str(prefix))
    else:
        result=policy.identity(text,raw=kind=='raw')
    if identity_json(result)!=value: raise ValueError('noncanonical identity snapshot')
    return result


def identities_json(values):
    return sorted((identity_json(value) for value in values),key=lambda v:(v['kind'],v['text'],v['prefix'] or 0))


def identities_restore(values):
    if not isinstance(values,list) or len(values)>100000: raise ValueError('identity snapshot budget')
    result={identity_restore(value) for value in values}
    if len(result)!=len(values): raise ValueError('duplicate identity snapshot')
    return result


def cache_export(cache,kind):
    result=[]
    for key,(value,expiry) in cache.items.items():
        finite(expiry)
        marker=next((name for name,item in MARKERS.items() if key==item),None)
        if marker:
            key={'marker':marker}
            if marker in ('self-ips','interfaces'):value=identities_json(value)
            elif marker=='self-names':value=sorted(value)
        elif kind=='forward':
            value=dict(value,addresses=identities_json(value['addresses']))
        if isinstance(key,tuple): key={'hostname':key[1]}
        result.append([key,value,expiry])
    return result


def cache_restore(cache,kind,entries):
    if not isinstance(entries,list) or len(entries)>cache.max_count: raise ValueError('cache snapshot budget')
    for entry in entries:
        if not isinstance(entry,list) or len(entry)!=3: raise ValueError('invalid cache entry')
        key,value,expiry=entry
        finite(expiry)
        marker=None
        if isinstance(key,dict):
            if set(key)=={'marker'} and isinstance(key['marker'],str) and key['marker'] in MARKERS:
                marker=key['marker']
                if kind!=('reverse' if marker=='self-names' else 'forward'):raise ValueError('wrong shared-cache marker')
                key=MARKERS[marker]
            else:
                if kind!='reverse' or set(key)!={'hostname'} or type(key['hostname']) is not bool: raise ValueError('invalid cache key')
                key=('hostname',key['hostname'])
        elif not isinstance(key,str) or len(key)>65536: raise ValueError('invalid cache key')
        if key in cache.items: raise ValueError('duplicate cache key')
        if marker:
            if marker in ('self-ips','interfaces'):value=identities_restore(value)
            elif marker=='ipv6':
                if type(value) is not bool:raise ValueError('invalid IPv6 cache marker')
            else:
                if not isinstance(value,list) or len(value)>3 or any(not isinstance(v,str) or len(v)>4096 for v in value) or len(set(value))!=len(value):raise ValueError('invalid self-name cache marker')
                value=set(value)
        elif kind=='ignore':
            if type(value) is not bool: raise ValueError('invalid ignore cache result')
        else:
            fields={'addresses','error','cache_hit'} if kind=='forward' else {'name','error','cache_hit'}
            if not isinstance(value,dict) or set(value)!=fields or type(value['cache_hit']) is not bool: raise ValueError('invalid resolver cache result')
            if value['error'] is not None and (not isinstance(value['error'],str) or len(value['error'])>4096): raise ValueError('invalid resolver error')
            if kind=='forward':
                value=dict(value,addresses=identities_restore(value['addresses']))
                if any(v.address is None for v in value['addresses']):raise ValueError('non-address in DNS cache')
            elif value['name'] is not None and (not isinstance(value['name'],str) or len(value['name'])>4096): raise ValueError('invalid resolver name')
        cache.items[key]=(value,expiry)


def system_ipv6_support():
    """Bounded local capability observation, without outgoing connections."""
    if not socket.has_ipv6:return False
    try:
        with open('/proc/sys/net/ipv6/conf/all/disable_ipv6','rb') as stream:
            return not int(stream.read(32))
    except (OSError,ValueError):
        pass
    probe=None
    try:
        probe=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
        probe.bind(('',0))
        return True
    except OSError as error:
        if error.errno is not None and (error.errno<0 or error.errno in (errno.EADDRNOTAVAIL,errno.EAFNOSUPPORT)):return False
        if error.errno in (errno.EADDRINUSE,errno.EACCES):return True
        return None
    finally:
        if probe is not None:probe.close()


@dataclass(frozen=True)
class TrustedCommand:
    template: str
    profile: str


class Adapter:
    def __init__(self,effective,profile,*,lookup=policy.bounded_resolve,
                 interfaces=policy.local_interface_identities,ipv6_probe=system_ipv6_support,
                 trusted_command=None,command_runner=policy.bounded_command,
                 deadline=2.0,max_external_calls=32):
        if not isinstance(effective,dict) or set(effective)-{'ignoreip','ignoreself','usedns','ignorecache','ignorecommand','allowipv6'}:
            raise ValueError('invalid effective ignore options')
        if not isinstance(profile,str) or not profile or len(profile)>4096: raise ValueError('invalid profile binding')
        config={'ignoreip':[],'ignoreself':True,'usedns':'warn','ignorecache':None,'ignorecommand':'','allowipv6':'auto',**effective}
        entries=config['ignoreip']
        if isinstance(entries,str): entries=[entry for entry in re.split(r'[,\s]+',entries) if entry]
        if not isinstance(entries,list) or len(entries)>100000 or any(not isinstance(v,str) or len(v)>4096 for v in entries): raise ValueError('invalid ignoreip')
        config['ignoreip']=list(entries)
        if type(config['ignoreself']) is not bool or not isinstance(config['usedns'],str) or len(config['usedns'])>128: raise ValueError('invalid effective policy option')
        if config['allowipv6'] not in ('auto','yes','no') or type(config['allowipv6']) is not str: raise ValueError('invalid allowipv6 policy')
        if not isinstance(config['ignorecommand'],str) or len(config['ignorecommand'])>65536: raise ValueError('invalid ignore command')
        if config['ignorecommand']:
            if not isinstance(trusted_command,TrustedCommand) or trusted_command.template!=config['ignorecommand'] or trusted_command.profile!=profile:
                raise ValueError('ignore command requires explicit profile-bound admission')
        self.cache_key=None;self.cache_count=100;self.cache_time=300
        cache=config['ignorecache']
        if isinstance(cache,str):cache=parse_ignorecache(cache);config['ignorecache']=cache
        if cache:
            if not isinstance(cache,dict) or len(cache)>256 or not isinstance(cache.get('key'),str): raise ValueError('invalid ignorecache declaration')
            self.cache_key=cache['key']
            if len(self.cache_key)>65536: raise ValueError('ignore cache key budget')
            count=cache.get('max-count',100)
            if type(count) not in (str,int): raise ValueError('invalid ignore cache count')
            self.cache_count=int(count)
            self.cache_time=duration.expression(cache.get('max-time',300))
            policy.Cache(self.cache_count,self.cache_time)
        elif cache not in (None,{},''): raise ValueError('invalid empty ignorecache declaration')
        if not 0<finite(deadline)<=30 or type(max_external_calls) is not int or not 1<=max_external_calls<=1000: raise ValueError('invalid external work budget')
        encoded=json.dumps(config,sort_keys=True,separators=(',',':'),allow_nan=False)
        if len(encoded.encode())>MAX_SNAPSHOT: raise ValueError('ignore configuration budget')
        self.config=json.loads(encoded)
        self.profile=profile
        self.binding=hashlib.sha256(json.dumps({'config':self.config,'profile':profile,'deadline':deadline,'max_external_calls':max_external_calls},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self._initial_binding=self.binding
        self.shared_binding=hashlib.sha256(json.dumps({'version':1,'profile':profile,'allowipv6':config['allowipv6']},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self._initial_shared_binding=self.shared_binding
        self._prepared_cache=json.dumps([self.cache_key,self.cache_count,self.cache_time],allow_nan=False)
        self.lookup,self.interfaces,self.ipv6_probe,self.command_runner=lookup,interfaces,ipv6_probe,command_runner
        self.deadline,self.max_external_calls=deadline,max_external_calls

    def empty_snapshot(self):
        return {'version':2,'binding':self.binding,'ignore':[],'files':None}

    def empty_shared_snapshot(self):
        return {'version':1,'binding':self.shared_binding,'forward':[],'reverse':[]}

    def stage(self,value,*,now,snapshot=None,shared_snapshot=None,ticket=None,jail=None):
        binding=hashlib.sha256(json.dumps({'config':self.config,'profile':self.profile,'deadline':self.deadline,'max_external_calls':self.max_external_calls},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if binding!=self._initial_binding or self.binding!=self._initial_binding or self.shared_binding!=self._initial_shared_binding:raise ValueError('ignore configuration changed after admission')
        if json.dumps([self.cache_key,self.cache_count,self.cache_time],allow_nan=False)!=self._prepared_cache:raise ValueError('prepared ignore cache changed after admission')
        finite(now)
        if not isinstance(value,str) or len(value)>4096:raise ValueError('invalid matched identity')
        if ticket is not None and not isinstance(ticket,dict):raise ValueError('invalid ticket snapshot')
        if jail is not None and not isinstance(jail,dict):raise ValueError('invalid jail snapshot')
        if ticket is not None and not isinstance(ticket.get('data',{}),dict):raise ValueError('invalid ticket data')
        if len(json.dumps([ticket,jail],allow_nan=False).encode())>128*1024:raise ValueError('ticket/jail snapshot budget')
        # Copy through bounded JSON so no returned/mutated object aliases prior state.
        encoded=json.dumps(self.empty_snapshot() if snapshot is None else snapshot,allow_nan=False,separators=(',',':'))
        if len(encoded.encode())>MAX_SNAPSHOT:raise ValueError('ignore snapshot budget')
        state=json.loads(encoded)
        if not isinstance(state,dict) or set(state)!=set(self.empty_snapshot()) or type(state['version']) is not int or state['version']!=2 or state['binding']!=self.binding:raise ValueError('ignore snapshot binding mismatch')
        encoded=json.dumps(self.empty_shared_snapshot() if shared_snapshot is None else shared_snapshot,allow_nan=False,separators=(',',':'))
        if len(encoded.encode())>MAX_SNAPSHOT:raise ValueError('shared DNS snapshot budget')
        shared=json.loads(encoded)
        if not isinstance(shared,dict) or set(shared)!=set(self.empty_shared_snapshot()) or type(shared['version']) is not int or shared['version']!=1 or shared['binding']!=self.shared_binding:raise ValueError('shared DNS snapshot binding mismatch')
        deadline=time.monotonic()+self.deadline
        calls=0
        def remaining():
            nonlocal calls
            calls+=1
            left=deadline-time.monotonic()
            if calls>self.max_external_calls or left<=0:raise ExternalWorkBudget('external policy work budget')
            return left
        def lookup(kind,name,**kwargs):
            if kind=='forward':kwargs['ipv6']=ipv6_policy()
            kwargs['timeout']=min(kwargs.get('timeout',self.deadline),remaining())
            answer=self.lookup(kind,name,**kwargs)
            expected={'addresses','error'} if kind=='forward' else {'name','error'}
            if not isinstance(answer,dict) or not expected<=set(answer) or set(answer)-{'addresses','name','error'}:raise ValueError('invalid resolver dependency result')
            answer={key:answer[key] for key in expected}
            if answer['error'] is not None and (not isinstance(answer['error'],str) or len(answer['error'])>4096):raise ValueError('invalid resolver dependency diagnostic')
            if kind=='forward':
                if not isinstance(answer['addresses'],(list,tuple,set)) or len(answer['addresses'])>4096 or any(not isinstance(v,str) or len(v)>4096 for v in answer['addresses']):raise ValueError('resolver answer budget')
            elif answer['name'] is not None and (not isinstance(answer['name'],str) or len(answer['name'])>4096):raise ValueError('resolver name budget')
            return answer
        resolver=policy.Resolver(lookup,ipv6=True,timeout=self.deadline)
        cache_restore(resolver.forward_cache,'forward',shared['forward'])
        cache_restore(resolver.reverse_cache,'reverse',shared['reverse'])
        def interfaces():
            cached=resolver.forward_cache.get(MARKERS['interfaces'],now)
            if cached is not None:return cached
            remaining()
            try:values=self.interfaces()
            except OSError as error:
                diagnostics.append(type(error).__name__);values=set()
            if not isinstance(values,(list,tuple,set)) or len(values)>65536:raise ValueError('interface observation budget')
            values={identity_restore(identity_json(v)) if isinstance(v,policy.Identity) else policy.identity(v) for v in values}
            resolver.forward_cache.set(MARKERS['interfaces'],values,now)
            return values
        detecting_ipv6=False
        def ipv6_policy():
            nonlocal detecting_ipv6
            if self.config['allowipv6']!='auto':return self.config['allowipv6']=='yes'
            if detecting_ipv6:return True # reference self-discovery recursion guard
            allowed=resolver.forward_cache.get(MARKERS['ipv6'],now)
            if allowed is None:
                remaining();allowed=self.ipv6_probe()
                if allowed is None:
                    observed=interfaces()
                    if not observed:
                        detecting_ipv6=True
                        try:observed=self_provider()
                        finally:detecting_ipv6=False
                    allowed=any(isinstance(v.address,ipaddress.IPv6Address) for v in observed)
                if type(allowed) is not bool:raise ValueError('invalid IPv6 capability observation')
                resolver.forward_cache.set(MARKERS['ipv6'],allowed,now)
            return allowed
        usedns=self.config['usedns'].lower()
        diagnostics=[]
        if usedns not in ('yes','warn','no','raw'):
            diagnostics.append('invalid-usedns-mode')
            usedns='no'
        def self_provider():
            own=resolver.forward_cache.get(MARKERS['self-ips'],now)
            if own is not None:return own
            own=set(interfaces())
            names=resolver.reverse_cache.get(MARKERS['self-names'],now)
            if names is None:
                names={'localhost'}
                for fqdn in (False,True):
                    answer=resolver.hostname(fqdn,now)
                    if answer['error']:diagnostics.append(answer['error'])
                    if answer['name']:names.add(answer['name'])
                resolver.reverse_cache.set(MARKERS['self-names'],names,now)
            for name in names:
                answer=resolver.forward(name,now)
                own.update(answer['addresses'])
                if answer['error']:diagnostics.append(answer['error'])
            resolver.forward_cache.set(MARKERS['self-ips'],own,now)
            return own
        current_info=None
        def expand(template):
            if ticket is not None:return action_info.expand_dynamic(template,current_info)
            # Manual checks have only an IP mapping; unknown F-* tags remain
            # literal under the reference static replacement path.
            text=current_info['ip']
            if action_info.SHELL_META.search(text):raise ValueError('manual identity requires a structured ticket for safe command expansion')
            def replacement(match):
                tag=match[1]
                if tag=='ip':return text
                if tag in ('br','sp'):return '\n' if tag=='br' else ' '
                if tag in ('fq-hostname','sh-hostname'):
                    answer=resolver.hostname(tag=='fq-hostname',now)
                    if answer['error']:diagnostics.append(answer['error'])
                    return str(answer['name'])
                return match[0]
            return action_info.TAG.sub(replacement,template)
        def cache_key(identity,values):
            result=expand(self.cache_key)
            if not isinstance(result,str):raise ValueError('ignorecache expansion is not scalar')
            return result
        def command(identity,values):
            descriptor=expand(self.config['ignorecommand'])
            result=self.command_runner(descriptor,timeout=remaining())
            if not isinstance(result,dict) or type(result.get('ignore')) is not bool or 'error' not in result or (result['error'] is not None and (not isinstance(result['error'],str) or len(result['error'])>4096)):raise ValueError('invalid command dependency result')
            return result
        instance=policy.IgnorePolicy(self.config['ignoreip'],ignore_self=self.config['ignoreself'],resolver=resolver,
            cache_key=cache_key if self.cache_key is not None else None,cache_count=self.cache_count,cache_time=self.cache_time,
            command=command if self.config['ignorecommand'] else None,self_provider=self_provider)
        if instance.cache is not None:cache_restore(instance.cache,'ignore',state['ignore'])
        elif state['ignore']:raise ValueError('unexpected ignore cache')
        files=[entry for entry in instance.entries if isinstance(entry,policy.FileIgnoreSet)]
        if state['files'] is not None:
            if not isinstance(state['files'],list) or len(state['files'])!=len(files):raise ValueError('ignore file snapshot mismatch')
            for source,saved in zip(files,state['files']):
                if not isinstance(saved,dict) or set(saved)!={'path','next_check','signature','entries','error'} or saved['path']!=str(source.path):raise ValueError('invalid ignore file snapshot')
                finite(saved['next_check'])
                signature=saved['signature']
                if signature is not None:
                    if not isinstance(signature,list) or len(signature)!=3 or type(signature[1]) is not int or type(signature[2]) is not int or signature[1]<0 or signature[2]<0:raise ValueError('invalid file signature')
                    finite(signature[0])
                if saved['error'] is not None and (not isinstance(saved['error'],str) or len(saved['error'])>128):raise ValueError('invalid file diagnostic')
                source.next_check=saved['next_check'];source.stat=tuple(signature) if signature is not None else None
                source.entries=identities_restore(saved['entries']);source.error=saved['error']
        for source in files:
            original_contains=source.contains
            def bounded_contains(value,clock,source=source,original_contains=original_contains):
                if clock>source.next_check:remaining()
                return original_contains(value,clock)
            source.contains=bounded_contains
        resolved=resolver.text_to_identity(value,usedns,now)
        if resolved['error']:diagnostics.append(resolved['error'])
        decisions=[]
        for identity in sorted(resolved['identities'],key=lambda v:(v.kind,v.text)):
            if ticket is None:current_info={'ip':identity.text}
            else:
                effective_ticket=dict(ticket,data={**ticket.get('data',{}),'ip':identity.text})
                current_info=action_info.ActionInfo(effective_ticket,jail=jail,resolver=resolver,now=now)
            decision=instance.check(identity,now=now)
            decisions.append({'identity':identity_json(identity),'ignored':decision.ignored,'origin':decision.origin,'error':decision.error,'cache_hit':decision.cache_hit})
            if isinstance(current_info,action_info.ActionInfo):diagnostics.extend(current_info.diagnostics)
        shared['forward']=cache_export(resolver.forward_cache,'forward');shared['reverse']=cache_export(resolver.reverse_cache,'reverse')
        state['ignore']=cache_export(instance.cache,'ignore') if instance.cache else []
        state['files']=[{'path':str(source.path),'next_check':source.next_check,'signature':list(source.stat) if source.stat is not None else None,'entries':identities_json(source.entries),'error':source.error} for source in files]
        if len(json.dumps(state,allow_nan=False).encode())>MAX_SNAPSHOT:raise ValueError('ignore snapshot budget')
        if len(json.dumps(shared,allow_nan=False).encode())>MAX_SNAPSHOT:raise ValueError('shared DNS snapshot budget')
        return {'shared_snapshot':shared,'decisions':decisions,'dns_warning':resolved['warning'],'diagnostics':diagnostics,'snapshot':state}
