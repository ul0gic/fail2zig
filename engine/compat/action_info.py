# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Lazy ActionInfo views over explicit ticket/jail snapshots and dynamic tag expansion.

The worker provides already-authorized templates. Foreign field values become positional
shell parameters when shell metacharacters occur; they are never evaluated as source.
"""
from collections.abc import Mapping
import ipaddress
import math
import re

TAG = re.compile(r'<([^ <>]+)>')
CAPTURE_TAG = re.compile(r'<F-([A-Z0-9_\-]+)>')
SHELL_META = re.compile(r'''[\\#&;`|*?~<>^()\[\]{}$'"\n\r]''')


class ActionInfo(Mapping):
    KEYS = ('ip','family','ip-rev','ip-host','fid','failures','time','bantime',
            'bancount','matches','restored','F-*','ipmatches','ipjailmatches',
            'ipfailures','ipjailfailures','raw-ticket','jail.name','jail.banned',
            'jail.banned_total','jail.found','jail.found_total')

    def __init__(self,ticket,*,jail=None,resolver=None,now=0):
        if not isinstance(ticket,dict) or not math.isfinite(now):
            raise ValueError('invalid action-info snapshot')
        self.ticket=ticket
        self.jail=jail or {}
        self.resolver=resolver
        self.now=now
        self.memo={}
        self.diagnostics=[]

    def __iter__(self):
        return iter(self.KEYS)

    def __len__(self):
        return len(self.KEYS)

    def __getitem__(self,key):
        if key in self.memo:
            return self.memo[key]
        value=self._get(key)
        self.memo[key]=value
        return value

    def _get(self,key):
        ticket=self.ticket
        if key=='ip':
            return ticket.get('data',{}).get('ip',ticket['id'])
        if key=='fid':
            return ticket['id']
        if key in ('family','ip-rev','ip-host'):
            text=str(self['ip'])
            if key=='ip-host':
                if self.resolver is None:
                    raise ValueError('reverse resolver is unavailable')
                answer=self.resolver.reverse(text,self.now)
                if answer.get('error'):
                    self.diagnostics.append(answer['error'])
                return answer['name']
            try:
                address=ipaddress.ip_address(text)
            except ValueError:
                if key=='family':
                    return None
                return ''
            if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                address=address.ipv4_mapped
            if key=='family':
                return 'inet4' if address.version==4 else 'inet6'
            return address.reverse_pointer.removesuffix('.in-addr.arpa').removesuffix('.ip6.arpa')+'.'
        field={'failures':'attempts','time':'time','bancount':'ban_count','raw-ticket':'repr'}.get(key)
        if field:
            if field not in ticket:
                raise ValueError('missing ticket snapshot field: '+field)
            return ticket[field]
        if key=='bantime':
            value=ticket.get('ban_time')
            if value is None:
                value=self.jail.get('ban_time')
            if type(value) not in (int,float) or not math.isfinite(value):
                raise ValueError('missing finite ban time')
            return int(value)
        if key=='matches':
            return '\n'.join(ticket.get('matches',[]))
        if key=='restored':
            return 1 if ticket.get('restored',False) else 0
        if key=='F-*':
            return ticket.get('data',{})
        if key in ('ipmatches','ipjailmatches','ipfailures','ipjailfailures'):
            merged=ticket.get('merged_all' if key in ('ipmatches','ipfailures') else 'merged_jail') or ticket
            return '\n'.join(merged.get('matches',[])) if key.endswith('matches') else merged['attempts']
        if key.startswith('jail.') and key in self.KEYS:
            field=key[5:]
            if field not in self.jail:
                raise ValueError('missing jail snapshot field: '+field)
            return self.jail[field]
        raise KeyError(key)


def expand_dynamic(template,info,*,hostnames=None):
    if not isinstance(template,str) or len(template)>65536:
        raise ValueError('invalid dynamic template')
    variables={}
    special={'br':'\n','sp':' '}
    def escape(tag,value):
        value=str(value)
        if len(value)>65536:
            raise ValueError('tag value exceeds budget')
        if SHELL_META.search(value):
            name='f2bV_'+re.sub(r'\W','_',tag)
            variables[name]=value
            return '$'+name
        return value
    def replace(match):
        key=match[1]
        try:
            return escape(key,info[key])
        except KeyError:
            if key in ('fq-hostname','sh-hostname'):
                if hostnames is not None and key in hostnames:
                    return str(hostnames[key])
                resolver=getattr(info,'resolver',None)
                if resolver is None:
                    raise ValueError('hostname resolver is unavailable')
                answer=resolver.hostname(key=='fq-hostname',info.now)
                if answer.get('error'):
                    info.diagnostics.append(answer['error'])
                return str(answer['name'])
            return special.get(key,match[0])
    command=TAG.sub(replace,template)
    if '<' in command:
        data=info.get('F-*') or {}
        def capture(match):
            key=match[1].lower()
            key={'id':'fid','port':'fport'}.get(key,key)
            return escape('F_'+key,data[key]) if key in data else ''
        command=CAPTURE_TAG.sub(capture,command)
    if len(command)+sum(map(len,variables.values()))>65536 or len(variables)>255:
        raise ValueError('expanded command exceeds budget')
    if not variables:
        return command
    assignments=' '.join(name+'=$'+str(index) for index,name in enumerate(variables))
    return [assignments+' \n'+command,*variables.values()]


def cache_key(template,info,*,hostnames=None):
    value=expand_dynamic(template,info,hostnames=hostnames)
    # A dynamic expansion with shell variables is a list in the reference and is
    # not a hashable cache key. Reject it explicitly instead of inventing a key.
    if isinstance(value,list):
        raise ValueError('ignorecache expansion is not a scalar key')
    return value
