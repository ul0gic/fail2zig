# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Bounded codec-aware file-record boundaries, without filesystem access.

`eof` means the reader observed the current file end, not that the writer closed it.
Decoders reset at record boundaries as in the selected reference. UTF-16/32 boundaries
remain aligned instead of reproducing the reference's re-encoding offset/data-loss bug.
A returned boundary is tentative until the supervisor commits its record and state.
"""
import codecs
from dataclasses import dataclass
import sys


@dataclass(frozen=True)
class FrameResult:
    disposition: str
    consumed: int = 0
    text: str | None = None
    diagnostic: str | None = None


def _decode(data,encoding):
    try:
        return data.decode(encoding,'strict'),None
    except (UnicodeDecodeError,UnicodeEncodeError) as problem:
        if problem.end==len(data) and data[problem.start] in (10,13):
            return data[:problem.start].decode(encoding,'replace'),None
        return data.decode(encoding,'replace'),'invalid-byte-sequence'


def _width(encoding,data):
    if encoding in ('utf-16-le','utf-16-be','utf-32-le','utf-32-be'):
        return (2 if encoding.startswith('utf-16') else 4),('little' if encoding.endswith('le') else 'big')
    if encoding=='utf-16':
        return 2,('big' if data.startswith(codecs.BOM_UTF16_BE) else 'little' if data.startswith(codecs.BOM_UTF16_LE) else sys.byteorder)
    if encoding=='utf-32':
        return 4,('big' if data.startswith(codecs.BOM_UTF32_BE) else 'little' if data.startswith(codecs.BOM_UTF32_LE) else sys.byteorder)
    return None


def _raw_boundary(data,encoding,characters):
    decoder=codecs.getincrementaldecoder(encoding)(errors='replace')
    emitted=0
    for offset,byte in enumerate(data,1):
        output=decoder.decode(bytes([byte]),final=False)
        emitted+=len(output)
        if emitted==characters:
            return offset
        if emitted>characters:
            # Byte consumption cannot represent a split inside atomic decoder output.
            return None
    output=decoder.decode(b'',final=True)
    emitted+=len(output)
    return len(data) if emitted==characters else None


def frame(data,encoding,*,eof,max_bytes=128*1024):
    if not isinstance(data,bytes) or type(eof) is not bool or type(max_bytes) is not int or not 1<=max_bytes<=128*1024:
        raise ValueError('invalid framing input')
    if len(data)>max_bytes:
        return FrameResult('resource_limit',diagnostic='record-byte-budget')
    if not isinstance(encoding,str) or not encoding or len(encoding)>128:
        raise ValueError('invalid framing encoding')
    codec=codecs.lookup(encoding)
    if not getattr(codec,'_is_text_encoding',False):
        raise ValueError('not a text encoding')
    encoding=codec.name
    if not data:
        return FrameResult('incomplete')
    def complete(end,text,diagnostic):
        if len(text)>max_bytes or len(text.encode('utf-8'))>max_bytes*4:
            return FrameResult('resource_limit',diagnostic='decoded-record-budget')
        return FrameResult('complete',end,text,diagnostic)
    fixed=_width(encoding,data)
    if fixed:
        width,byteorder=fixed
        for start in range(0,len(data)-width+1,width):
            if int.from_bytes(data[start:start+width],byteorder)==10:
                end=start+width
                text,diagnostic=_decode(data[:end],encoding)
                return complete(end,text.rstrip('\r\n'),diagnostic)
        if eof and len(data)%width==0:
            text,diagnostic=_decode(data,encoding)
            if text.endswith(('\r','\n')):
                return complete(len(data),text.rstrip('\r\n'),diagnostic)
        return FrameResult('resource_limit',diagnostic='record-byte-budget') if len(data)==max_bytes else FrameResult('incomplete')
    endpoints=[]
    for index,byte in enumerate(data):
        if byte==10:
            endpoints.append(index+1)
            if len(endpoints)>256:
                break
    if eof and (not endpoints or endpoints[-1]!=len(data)):
        endpoints.append(len(data))
    if not endpoints:
        return FrameResult('resource_limit',diagnostic='record-byte-budget') if len(data)==max_bytes else FrameResult('incomplete')
    diagnostic=None
    for index,end in enumerate(endpoints):
        if index>=256:
            return FrameResult('resource_limit',diagnostic='prefix-decode-budget')
        decoded,error=_decode(data[:end],encoding)
        diagnostic=error or diagnostic
        if index:
            newline=decoded.find('\n')
            if newline>=0 and newline!=len(decoded)-1:
                boundary=_raw_boundary(data[:end],encoding,newline+1)
                if boundary is None:
                    return FrameResult('unsupported_boundary',diagnostic='atomic-decoder-output-needs-continuation')
                return complete(boundary,decoded[:newline],diagnostic)
        trimmed=decoded.rstrip('\r\n')
        if trimmed!=decoded:
            return complete(end,trimmed,diagnostic)
    if len(data)==max_bytes:
        return FrameResult('resource_limit',diagnostic='record-byte-budget')
    return FrameResult('incomplete',diagnostic=diagnostic)
