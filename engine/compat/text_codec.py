# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Bounded text decoding component for the compatibility worker.

No upstream dependency, process launch, filesystem access or action execution.
The supervisor must enforce D1 process limits and pass one complete byte record.
This module does not split UTF-16 records or implement the worker transport.
"""
from collections import OrderedDict
from dataclasses import dataclass
import codecs
import math


def preferred_encoding(locale_encoding, stdout_encoding, environment):
    """Resolve the reference preference from an explicit worker profile snapshot."""
    if not isinstance(locale_encoding, str) or not locale_encoding:
        raise ValueError('invalid locale encoding')
    result = locale_encoding
    if result.startswith('ANSI_'):
        if stdout_encoding is not None and not stdout_encoding.startswith('ANSI_'):
            result = stdout_encoding
        elif all(environment.get(key) in (None, '') for key in ('LANGUAGE','LC_ALL','LC_CTYPE','LANG')):
            result = 'UTF-8'
    return result


def resolve_encoding(encoding, *, preferred_encoding=None):
    if not isinstance(encoding, str) or not encoding or len(encoding) > 128:
        raise ValueError('invalid encoding name')
    if encoding.lower() == 'auto':
        if not isinstance(preferred_encoding, str) or not preferred_encoding or len(preferred_encoding) > 128:
            raise ValueError('auto encoding requires an explicit profile preference')
        encoding = preferred_encoding
    entry = codecs.lookup(encoding)
    if not getattr(entry, '_is_text_encoding', False):
        raise ValueError('encoding is not a text codec')
    return entry.name


@dataclass(frozen=True)
class DecodedRecord:
    text: str
    codec: str
    disposition: str
    diagnostic: str | None
    warning_due: bool


class TextDecoder:
    def __init__(self, encoding: str, *, max_bytes: int = 1 << 20,
                 max_warning_sources: int = 1000, warning_ttl: float = 86400,
                 preferred_encoding: str | None = None):
        if not isinstance(encoding, str) or not encoding or len(encoding) > 128:
            raise ValueError('invalid encoding name')
        if not 1 <= max_bytes <= 1 << 20 or not 1 <= max_warning_sources <= 1000:
            raise ValueError('invalid decoder bounds')
        if not math.isfinite(warning_ttl) or warning_ttl < 0:
            raise ValueError('invalid warning TTL')
        self.encoding = resolve_encoding(encoding, preferred_encoding=preferred_encoding)
        self.max_bytes = max_bytes
        self.max_warning_sources = max_warning_sources
        self.warning_ttl = warning_ttl
        self._warnings = OrderedDict()

    def empty_context(self):
        return {'version': 1, 'codec': self.encoding, 'max_bytes': self.max_bytes,
                'max_warning_sources': self.max_warning_sources,
                'warning_ttl': self.warning_ttl, 'warnings': []}

    def export_context(self):
        context = self.empty_context()
        context['warnings'] = [[source, expiry] for source, expiry in self._warnings.items()]
        return context

    def restore_context(self, context):
        expected = self.empty_context()
        if not isinstance(context, dict) or set(context) != set(expected):
            raise ValueError('invalid codec context schema')
        if any(type(context[key]) is not type(value) or context[key] != value for key,value in expected.items() if key != 'warnings'):
            raise ValueError('codec context configuration mismatch')
        entries = context['warnings']
        if not isinstance(entries, list) or len(entries) > self.max_warning_sources:
            raise ValueError('invalid codec warning context size')
        restored = OrderedDict()
        for entry in entries:
            if not isinstance(entry,list) or len(entry) != 2:
                raise ValueError('invalid codec warning context entry')
            source,expiry = entry
            if not isinstance(source,str) or len(source) > 4096 or source in restored:
                raise ValueError('invalid codec warning context source')
            if type(expiry) not in (int,float) or not math.isfinite(expiry):
                raise ValueError('invalid codec warning context expiry')
            restored[source] = expiry
        self._warnings = restored

    def _warning_due(self, source, now):
        expiry = self._warnings.get(source)
        warning = expiry is None or expiry <= now
        if warning:
            self._warnings[source] = now + self.warning_ttl
            self._warnings.move_to_end(source)
            while len(self._warnings) > self.max_warning_sources:
                self._warnings.popitem(last=False)
        return warning

    def accept_framed(self, source, text, diagnostic, now):
        """Stage warning state for already-decoded authoritative framer output.

        Only the configured worker may supply this result. No re-encoding is used
        to infer consumption; raw-byte boundaries remain the framer's authority.
        """
        if not isinstance(source, str) or len(source) > 4096:
            raise ValueError('invalid source identity')
        if type(now) not in (int,float) or not math.isfinite(now):
            raise ValueError('invalid observation time')
        if not isinstance(text,str) or len(text)>self.max_bytes or len(text.encode('utf-8'))>self.max_bytes*4:
            raise ValueError('record exceeds decoder output budget')
        if diagnostic not in (None,'invalid-byte-sequence','terminal-newline-truncated'):
            raise ValueError('invalid framer diagnostic')
        if diagnostic=='invalid-byte-sequence':
            return DecodedRecord(text,self.encoding,'replacement',diagnostic,self._warning_due(source,now))
        return DecodedRecord(text,self.encoding,'terminal-newline-truncated' if diagnostic else 'decoded',None,False)

    def decode(self, source: str, data: bytes, now: float) -> DecodedRecord:
        if not isinstance(source, str) or len(source) > 4096:
            raise ValueError('invalid source identity')
        if not isinstance(data, bytes) or len(data) > self.max_bytes:
            raise ValueError('record exceeds decoder input budget')
        if not math.isfinite(now):
            raise ValueError('invalid observation time')
        try:
            text = data.decode(self.encoding, 'strict')
            disposition, diagnostic, warning = 'decoded', None, False
        except (UnicodeDecodeError, UnicodeEncodeError) as problem:
            if problem.end == len(data) and data[problem.start] in (10, 13):
                text = data[:problem.start].decode(self.encoding, 'replace')
                disposition, diagnostic, warning = 'terminal-newline-truncated', None, False
            else:
                text = data.decode(self.encoding, 'replace')
                disposition, diagnostic = 'replacement', 'invalid-byte-sequence'
                warning = self._warning_due(source,now)
        if len(text) > self.max_bytes or len(text.encode('utf-8')) > self.max_bytes * 4:
            raise ValueError('record exceeds decoder output budget')
        return DecodedRecord(text, self.encoding, disposition, diagnostic, warning)
