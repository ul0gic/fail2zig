# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Strict bounded D1 framing for the private compatibility worker transport."""
import json
import math

MAX_FRAME = 1 << 20
MAX_DEPTH = 64
MAX_NODES = 40000
MAX_SEQUENCE = (1 << 64) - 1
FIELDS = {'wire_version', 'kind', 'request_id', 'daemon_epoch', 'worker_epoch',
          'config_generation', 'jail_id', 'sequence', 'capabilities', 'payload'}
KINDS = {'hello', 'configure', 'record', 'decision', 'action', 'result',
         'checkpoint', 'restore', 'barrier', 'cancel', 'health', 'close'}
IDENTITIES = ('request_id', 'daemon_epoch', 'worker_epoch', 'config_generation', 'jail_id')


class ProtocolError(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError('duplicate_key')
        result[key] = value
    return result


def _finite(text):
    value = float(text)
    if not math.isfinite(value):
        raise ProtocolError('nonfinite')
    return value


def _constant(_):
    raise ProtocolError('nonfinite')


def _depth(data):
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                raise ProtocolError('depth')
        elif byte in (93, 125):
            depth -= 1


def validate(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ProtocolError('field_set')
    if type(value['wire_version']) is not int or value['wire_version'] != 1:
        raise ProtocolError('version')
    if not isinstance(value['kind'], str) or value['kind'] not in KINDS:
        raise ProtocolError('kind')
    for key in IDENTITIES:
        if not isinstance(value[key], str) or not value[key] or len(value[key]) > 4096:
            raise ProtocolError('identity')
    seq = value['sequence']
    if (not isinstance(seq, str) or not seq or len(seq) > 20 or
            not seq.isascii() or not seq.isdigit() or (len(seq) > 1 and seq[0] == '0') or
            int(seq) > MAX_SEQUENCE):
        raise ProtocolError('sequence')
    if value['capabilities'] != [] or not isinstance(value['payload'], dict):
        raise ProtocolError('capability_or_payload')
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise ProtocolError('complexity')
        if isinstance(item, str):
            try:
                item.encode('utf-8', errors='strict')
            except UnicodeError:
                raise ProtocolError('unicode') from None
        elif isinstance(item, float) and not math.isfinite(item):
            raise ProtocolError('nonfinite')
        elif isinstance(item, dict):
            pending.extend((key, depth + 1) for key in item)
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def decode_frame(data):
    if len(data) < 4:
        raise ProtocolError('short_header')
    size = int.from_bytes(data[:4], 'big')
    if size == 0 or size > MAX_FRAME or len(data) != size + 4:
        raise ProtocolError('frame_length')
    payload = data[4:]
    _depth(payload)
    try:
        value = json.loads(payload.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=_constant, parse_float=_finite)
    except ProtocolError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError('invalid_json') from None
    return validate(value)


def encode_frame(value):
    validate(value)
    try:
        data = json.dumps(value, sort_keys=True, separators=(',', ':'),
                          allow_nan=False, ensure_ascii=True).encode('utf-8')
    except (ValueError, TypeError, RecursionError):
        raise ProtocolError('invalid_json') from None
    if not data or len(data) > MAX_FRAME:
        raise ProtocolError('frame_length')
    return len(data).to_bytes(4, 'big') + data


def _read_exact(stream, count, *, clean_eof=False):
    parts, remaining = [], count
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            if clean_eof and remaining == count:
                return None
            raise ProtocolError('truncated_frame')
        parts.append(chunk)
        remaining -= len(chunk)
    return b''.join(parts)


def read_frame(stream):
    header = _read_exact(stream, 4, clean_eof=True)
    if header is None:
        return None
    size = int.from_bytes(header, 'big')
    if size == 0 or size > MAX_FRAME:
        raise ProtocolError('frame_length')
    return decode_frame(header + _read_exact(stream, size))


def write_frame(stream, value):
    stream.write(encode_frame(value))
    stream.flush()
