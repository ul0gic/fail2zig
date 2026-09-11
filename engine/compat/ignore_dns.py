# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Address/DNS/ignore policy components with bounded, explicit external dependencies.

Callers provide interface/self identities and trusted command expansion. Raw identifiers
remain distinct from addresses. Resolver/command errors are observable, never an ignore.
"""
from collections import OrderedDict
from dataclasses import dataclass
import ipaddress
import json
import math
import os
import re
import signal
import subprocess
import sys
import socket
import stat
from pathlib import Path


@dataclass(frozen=True)
class Identity:
    kind: str
    text: str
    address: object = None
    prefix: int | None = None


def identity(text,*,raw=False,search=False):
    if not isinstance(text,str) or len(text)>4096:
        raise ValueError('invalid identity')
    if raw:
        return Identity('raw',text)
    value=text
    if search and value.startswith('[') and value.endswith(']'):
        value=value[1:-1]
    if '%' in value:
        return Identity('unresolved',text)
    try:
        if '/' in value:
            network=ipaddress.ip_network(value,strict=False)
            return Identity('ipv'+str(network.version),str(network.network_address),network.network_address,network.prefixlen)
        address=ipaddress.ip_address(value)
        if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address=address.ipv4_mapped
        return Identity('ipv'+str(address.version),str(address),address,address.max_prefixlen)
    except ValueError:
        return Identity('unresolved',text)


class Cache:
    def __init__(self,max_count=1000,max_time=300):
        if type(max_count) is not int or not 1<=max_count<=100000 or not math.isfinite(max_time) or max_time<0:
            raise ValueError('invalid cache limits')
        self.max_count,self.max_time=max_count,max_time
        self.items=OrderedDict()

    def get(self,key,now,default=None):
        if not math.isfinite(now):
            raise ValueError('nonfinite cache clock')
        entry=self.items.get(key)
        if entry is not None:
            if entry[1]>now:
                return entry[0]
            del self.items[key]
        return default

    def set(self,key,value,now):
        if not math.isfinite(now):
            raise ValueError('nonfinite cache clock')
        if len(self.items)>=self.max_count:
            while self.items:
                _,old=self.items.popitem(last=False)
                if old[1]>now and len(self.items)<self.max_count:
                    break
        self.items[key]=(value,now+self.max_time)


_RESOLVER = r'''
import json,resource,socket,sys
resource.setrlimit(resource.RLIMIT_AS,(256*1024*1024,)*2)
resource.setrlimit(resource.RLIMIT_CPU,(2,2))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
kind,name,ipv6=sys.argv[1:]
if kind=='fqdn':
    try:
        rows=socket.getaddrinfo(name,None,0,socket.SOCK_DGRAM,0,socket.AI_CANONNAME)
        names=[row[3] for row in rows[:4096] if row[3]]
        result={'name':next((item for item in names if item.startswith(name+'.')),names[0] if names else None),'error':None}
    except OSError:
        try: result={'name':socket.getfqdn(name),'error':None}
        except OSError as exc: result={'name':None,'error':type(exc).__name__}
elif kind=='reverse':
    try: result={'name':socket.gethostbyaddr(name)[0],'error':None}
    except OSError as exc: result={'name':None,'error':type(exc).__name__}
else:
    addresses=set(); errors=[]
    for family in ([socket.AF_INET,socket.AF_INET6] if ipv6=='1' else [socket.AF_INET]):
        try:
            for row in socket.getaddrinfo(name,None,family,0,socket.IPPROTO_TCP):
                if len(addresses)>=4096: raise ValueError('DNS answer budget exceeded')
                if len(row)>4 and row[4]: addresses.add(str(row[4][0]))
        except OSError as exc: errors.append(type(exc).__name__)
    result={'addresses':sorted(addresses),'error':errors[-1] if errors and not addresses else None}
output=json.dumps(result)
if len(output)>65536: raise ValueError('DNS output budget exceeded')
print(output)
'''


def bounded_resolve(kind,name,*,ipv6=True,timeout=2.0):
    if kind not in ('forward','reverse','fqdn') or not isinstance(name,str) or not 1<=len(name)<=4096 or '\x00' in name:
        raise ValueError('invalid resolver request')
    if not math.isfinite(timeout) or not 0<timeout<=30:
        raise ValueError('invalid resolver deadline')
    try:
        result=subprocess.run([sys.executable,'-I','-c',_RESOLVER,kind,name,'1' if ipv6 else '0'],
                              stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                              timeout=timeout,check=True)
        if len(result.stdout)>65536:
            raise ValueError('resolver output budget exceeded')
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired,subprocess.CalledProcessError,OSError) as exc:
        return {'addresses':[],'name':None,'error':type(exc).__name__}


class Resolver:
    def __init__(self,lookup=bounded_resolve,*,ipv6=True,timeout=2.0):
        self.lookup,self.ipv6,self.timeout=lookup,ipv6,timeout
        self.forward_cache,self.reverse_cache=Cache(),Cache()

    def forward(self,name,now):
        cached=self.forward_cache.get(name,now)
        if cached is not None:
            return dict(cached,cache_hit=True)
        answer=self.lookup('forward',name,ipv6=self.ipv6,timeout=self.timeout)
        addresses={identity(value) for value in answer.get('addresses',[]) if identity(value).address is not None}
        result=dict(addresses=addresses,error=answer.get('error'),cache_hit=False)
        self.forward_cache.set(name,result,now)
        return result

    def reverse(self,address,now):
        cached=self.reverse_cache.get(address,now)
        if cached is not None:
            return dict(cached,cache_hit=True)
        answer=self.lookup('reverse',address,ipv6=self.ipv6,timeout=self.timeout)
        result=dict(name=answer.get('name'),error=answer.get('error'),cache_hit=False)
        self.reverse_cache.set(address,result,now)
        return result

    def hostname(self,fqdn,now):
        key=('hostname',bool(fqdn))
        cached=self.reverse_cache.get(key,now)
        if cached is not None:
            return dict(cached,cache_hit=True)
        try:
            short=socket.gethostname()
        except OSError as exc:
            short=''
            error=type(exc).__name__
        else:
            error=None
        if fqdn and short:
            answer=self.lookup('fqdn',short,ipv6=self.ipv6,timeout=self.timeout)
            result=dict(name=answer.get('name'),error=answer.get('error'),cache_hit=False)
        else:
            result=dict(name=short,error=error,cache_hit=False)
        self.reverse_cache.set(key,result,now)
        return result

    def text_to_identity(self,text,mode,now):
        if type(mode) is bool:
            mode='yes' if mode else 'no'
        mode=mode.lower()
        invalid_mode=mode not in ('yes','warn','no','raw')
        if invalid_mode:
            mode='no'
        if mode=='raw':
            return dict(identities={identity(text,raw=True)},warning=False,error=None,mode=mode)
        plain=identity(text,search=True)
        if plain.address is not None and '/' not in text:
            return dict(identities={plain},warning=False,error=None,mode=mode)
        if mode in ('yes','warn'):
            resolved=self.forward(text,now)
            return dict(identities=resolved['addresses'],warning=bool(resolved['addresses']) and mode=='warn',error=resolved['error'],mode=mode)
        return dict(identities=set(),warning=False,error='invalid-usedns-mode' if invalid_mode else None,mode=mode)


def bounded_command(command,*,timeout=2.0):
    """Execute only an already-expanded administrator command, never record text.

    Dynamic tag expansion belongs to the trusted action adapter. The caller must not
    interpolate raw identifiers into shell source. Entire process group dies on timeout.
    """
    parts=[command] if isinstance(command,str) else command
    if not isinstance(parts,list) or not parts or not parts[0] or len(parts)>256 or any(not isinstance(part,str) or '\x00' in part for part in parts) or sum(map(len,parts))>65536:
        raise ValueError('invalid trusted command')
    if not math.isfinite(timeout) or not 0<timeout<=30:
        raise ValueError('invalid command deadline')
    process=subprocess.Popen(['/bin/sh','-c',*parts],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,start_new_session=True)
    try:
        code=process.wait(timeout=timeout)
        return dict(ignore=code==0,exit_code=code,error=None if code in (0,1) else 'command-exit-error')
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        return dict(ignore=False,exit_code=None,error='command-timeout')


@dataclass(frozen=True)
class IgnoreDecision:
    ignored: bool
    origin: str
    error: str | None = None
    cache_hit: bool = False


class IgnorePolicy:
    def __init__(self,entries=(),*,ignore_self=True,self_identities=(),resolver=None,
                 cache_key=None,cache_count=100,cache_time=300,command=None,self_provider=None):
        if len(entries)>100000:
            raise ValueError('ignore entry budget exceeded')
        self.entries=[]
        self.host_entries=set()
        for value in entries:
            if not value:
                continue
            if value.startswith('file:'):
                self.entries.append(FileIgnoreSet(value))
                continue
            entry=identity(value)
            if entry.address is not None and entry.prefix==entry.address.max_prefixlen:
                self.host_entries.add(entry)
            elif entry not in self.entries:
                self.entries.append(entry)
        self.ignore_self=ignore_self
        self.self_provider=self_provider
        self.self_identities=set()
        for value in self_identities:
            if isinstance(value,Identity):
                if value.kind in ('ipv4','ipv6'):
                    if type(value.prefix) is not int:
                        raise ValueError('invalid self identity prefix')
                    expected=identity(value.text+'/'+str(value.prefix))
                else:
                    expected=identity(value.text,raw=value.kind=='raw')
                if value!=expected:
                    raise ValueError('invalid self identity')
                self.self_identities.add(value)
            else:
                self.self_identities.add(identity(value))
        self.resolver=resolver or Resolver()
        self.cache_key=cache_key
        self.cache=Cache(cache_count,cache_time) if cache_key is not None else None
        self.command=command

    def check(self,value,*,now,cache_values=None):
        value=identity(value) if isinstance(value,str) else value
        if not isinstance(value,Identity):
            raise ValueError('invalid ignore identity')
        key=None
        if self.cache is not None:
            key=self.cache_key(value,cache_values or {})
            if not isinstance(key,str) or len(key)>65536:
                raise ValueError('invalid ignore cache key')
            cached=self.cache.get(key,now)
            if cached is not None:
                return IgnoreDecision(cached,'cache',cache_hit=True)
        def finish(ignored,origin,error=None,cache=True):
            if self.cache is not None and cache:
                self.cache.set(key,ignored,now)
            return IgnoreDecision(ignored,origin,error)
        if self.ignore_self and value in (self.self_provider() if self.self_provider is not None else self.self_identities):
            return finish(True,'self')
        if value in self.host_entries:
            return finish(True,'ip',cache=False)
        diagnostic=None
        for entry in self.entries:
            if isinstance(entry,FileIgnoreSet):
                covered,error=entry.contains(value,now)
                diagnostic=error or diagnostic
                if covered:
                    return finish(True,'file',error)
                continue
            if entry.address is not None:
                if value.address is None or value.kind!=entry.kind:
                    continue
                if entry.prefix==entry.address.max_prefixlen and value==entry:
                    # The reference returns before populating ignorecache for exact hosts.
                    return finish(True,'ip',cache=False)
                network=ipaddress.ip_network((entry.address,entry.prefix),strict=False)
                if value.address in network:
                    return finish(True,'network')
            else:
                answer=self.resolver.forward(entry.text,now)
                diagnostic=answer['error'] or diagnostic
                if value in answer['addresses']:
                    return finish(True,'dns')
        if self.command is not None:
            result=self.command(value,cache_values or {})
            return finish(bool(result['ignore']),'command',result.get('error'))
        return finish(False,'none',diagnostic)


class FileIgnoreSet:
    """Administrator-configured regular file; failures retain last good entries.

    Intentional recovery improvement: source inspection of the pinned reference
    FileIPAddrSet._isModified shows metadata is published before content is read.
    Here metadata commits only with parsed contents, and outstanding errors force
    retry after backoff even if metadata is unchanged. A candidate-only injected
    ordinary read failure verifies recovery; it is not an upstream equality claim.
    """
    def __init__(self,uri,*,max_bytes=1 << 20):
        match=re.match(r'^file:(?:/{0,2}(?=/(?!/|.{1,2}/))|/{0,2})(.*)$',uri)
        if not match or not match[1] or len(match[1])>4096 or not 1<=max_bytes<=1 << 20:
            raise ValueError('invalid ignore file configuration')
        self.path=Path(match[1])
        self.max_bytes=max_bytes
        self.next_check=0.0
        self.stat=None
        self.entries=set()
        self.error=None

    def contains(self,value,now):
        if not math.isfinite(now):
            raise ValueError('invalid ignore file clock')
        if now>self.next_check:
            self.next_check=now+1
            try:
                info=self.path.stat()
                signature=(info.st_mtime,info.st_ino,info.st_size)
                if signature!=self.stat or self.error is not None:
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError('ignore source is not a regular file')
                    descriptor=os.open(self.path,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
                    try:
                        opened=os.fstat(descriptor)
                        if not stat.S_ISREG(opened.st_mode):
                            raise ValueError('ignore source is not a regular file')
                        signature=(opened.st_mtime,opened.st_ino,opened.st_size)
                        with os.fdopen(descriptor,'rb',closefd=False) as stream:
                            data=stream.read(self.max_bytes+1)
                    finally:
                        os.close(descriptor)
                    if len(data)>self.max_bytes:
                        raise ValueError('ignore file exceeds size budget')
                    text=data.decode('utf-8')
                    text=re.sub(r'(?m)\s*[#;].*$','',text)
                    tokens=re.split(r'[,\s]+',text)
                    self.entries={identity(token) for token in tokens if token}
                    # Publish identity only with successfully parsed entries. A
                    # failed read must remain retryable even if metadata is stable.
                    self.stat=signature
                self.error=None
            except (OSError,UnicodeError,ValueError) as exc:
                self.next_check+=60
                self.error=type(exc).__name__
        for entry in self.entries:
            if value==entry:
                return True,self.error
            if entry.address is not None and value.address is not None and entry.kind==value.kind:
                network=ipaddress.ip_network((entry.address,entry.prefix),strict=False)
                if value.address in network:
                    return True,self.error
        return False,self.error


def local_interface_identities():
    """Linux getifaddrs, no resolver calls or shell commands."""
    if not sys.platform.startswith('linux'):
        raise ValueError('interface enumeration requires Linux profile')
    import ctypes
    class Interface(ctypes.Structure):
        pass
    Interface._fields_=[('next',ctypes.POINTER(Interface)),('name',ctypes.c_char_p),
                       ('flags',ctypes.c_uint),('address',ctypes.c_void_p),
                       ('netmask',ctypes.c_void_p),('broadcast',ctypes.c_void_p),('data',ctypes.c_void_p)]
    library=ctypes.CDLL(None,use_errno=True)
    library.getifaddrs.argtypes=[ctypes.POINTER(ctypes.POINTER(Interface))]
    library.getifaddrs.restype=ctypes.c_int
    library.freeifaddrs.argtypes=[ctypes.POINTER(Interface)]
    library.freeifaddrs.restype=None
    head=ctypes.POINTER(Interface)()
    if library.getifaddrs(ctypes.byref(head))!=0:
        raise OSError(ctypes.get_errno(),'getifaddrs failed')
    result=set()
    try:
        current=head
        count=0
        while current:
            count+=1
            if count>65536:
                raise ValueError('interface enumeration budget exceeded')
            entry=current.contents
            if entry.address:
                family=ctypes.c_ushort.from_address(entry.address).value
                if family==socket.AF_INET:
                    result.add(identity(socket.inet_ntop(family,ctypes.string_at(entry.address+4,4))))
                elif family==socket.AF_INET6:
                    result.add(identity(socket.inet_ntop(family,ctypes.string_at(entry.address+8,16))))
            current=entry.next
    finally:
        library.freeifaddrs(head)
    return result


def self_identities(resolver,*,now,names=(),interfaces=None):
    """Union local interfaces and supervisor-resolved host names; returns diagnostics."""
    values=set(local_interface_identities() if interfaces is None else interfaces)
    errors=[]
    short=resolver.hostname(False,now)
    fqdn=resolver.hostname(True,now)
    errors.extend(value['error'] for value in (short,fqdn) if value['error'])
    for name in dict.fromkeys(['localhost',short['name'],fqdn['name'],*names]):
        if not name:
            continue
        answer=resolver.forward(name,now)
        values.update(answer['addresses'])
        if answer['error']:
            errors.append(answer['error'])
    return values,errors
