# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Bounded journal field formatting with binding-first UTF-8 conversion.

A journal field successfully decoded by python-systemd is already Unicode; the
configured log encoding is used only for bytes that failed that conversion.
No file-decoder warning-cache mutation is associated with journal formatting.
"""
from datetime import timedelta
from text_codec import resolve_encoding


def format_entry(fields, encoding, monotonic_us, *, max_bytes=128*1024):
    encoding=resolve_encoding(encoding)
    if not isinstance(fields,list) or len(fields)>4096:
        raise ValueError('journal field count')
    grouped={}
    total=0
    for item in fields:
        if not isinstance(item,tuple) or len(item)!=2:
            raise ValueError('journal field shape')
        name,value=item
        if not isinstance(name,str) or not isinstance(value,bytes):
            raise ValueError('journal field type')
        total+=len(name)+len(value)
        if total>max_bytes: raise ValueError('journal input budget')
        if name not in ('_HOSTNAME','SYSLOG_IDENTIFIER','_COMM','SYSLOG_PID','_PID','MESSAGE','_SOURCE_MONOTONIC_TIMESTAMP'):
            raise ValueError('unexpected formatter field')
        try:
            if name in ('SYSLOG_PID','_PID'): converted=int(value)
            elif name=='_SOURCE_MONOTONIC_TIMESTAMP': converted=timedelta(microseconds=int(value))
            else: converted=value.decode('utf-8')
        except ValueError: converted=value
        grouped.setdefault(name,[]).append(converted)
    def scalar(name):
        values=grouped.get(name)
        if not values: return None
        if len(values)!=1: raise ValueError('repeated journal scalar')
        return values[0]
    replaced=False
    def text(value):
        nonlocal replaced
        if isinstance(value,str): return value
        if not isinstance(value,bytes): raise ValueError('nontext journal field')
        try: return value.decode(encoding,'strict')
        except (UnicodeDecodeError,UnicodeEncodeError):
            replaced=True
            return value.decode(encoding,'replace')
    elements=[]
    host=scalar('_HOSTNAME')
    if host: elements.append(text(host))
    identifier=scalar('SYSLOG_IDENTIFIER') or scalar('_COMM')
    if identifier:
        label=text(identifier)
        pid=scalar('SYSLOG_PID') or scalar('_PID')
        if pid:
            if isinstance(pid,int): value=str(pid)
            else:
                try: value=str(int(pid,0))
                except (TypeError,ValueError): value=str(pid)
            label+='['+value+']'
        label+=':'
        elements.append(label)
        if label=='kernel:':
            monotonic=scalar('_SOURCE_MONOTONIC_TIMESTAMP')
            if monotonic is None:
                if not isinstance(monotonic_us,str) or not monotonic_us or len(monotonic_us)>20 or any(c not in '0123456789' for c in monotonic_us):
                    raise ValueError('missing journal monotonic time')
                monotonic=timedelta(microseconds=int(monotonic_us))
            if not isinstance(monotonic,timedelta): raise ValueError('invalid source monotonic time')
            elements.append('[%12.6f]' % monotonic.total_seconds())
    messages=grouped.get('MESSAGE',[''])
    elements.append(' '.join(text(value) for value in messages))
    line=' '.join(elements).replace('\n','\\n')
    if len(line)>max_bytes or len(line.encode('utf-8'))>max_bytes*4:
        raise ValueError('journal output budget')
    return dict(text=line,codec=encoding,disposition='replacement' if replaced else 'decoded',
                diagnostic='invalid-byte-sequence' if replaced else None,warning_due=False)
