#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Private D1 date/codec/duration/ignore worker; no matching or action execution.

The parent owns per-call wall/CPU deadlines, output caps and process reaping. This
worker enforces address-space/descriptor bounds and drops privilege before imports
of the configured compatibility components. State is supplied and returned per call;
a returned context is not a daemon commit or a durable checkpoint acknowledgment.
"""
import argparse
import base64
import ctypes
from dataclasses import asdict
import hashlib
import math
import json
import locale
import time
import unicodedata
import os
from pathlib import Path
import resource
import re
import struct
import sys

# Isolated Python (-I) deliberately omits the script directory. Add only the
# installed worker directory; never accept an import path from an input record.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from protocol import ProtocolError, MAX_FRAME, read_frame, write_frame

ADDRESS_SPACE = 256 * 1024 * 1024
MAX_REQUESTS = 10000
MAX_RECORD_BYTES = 128 * 1024
IDENTITY_KEYS = ('daemon_epoch', 'worker_epoch', 'config_generation', 'jail_id')


class InputError(ValueError):
    pass


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise InputError('payload_field_set')


def clock(bits):
    if not isinstance(bits, str) or len(bits) != 16 or any(c not in '0123456789abcdef' for c in bits):
        raise InputError('clock_bits')
    value = struct.unpack('>d', bytes.fromhex(bits))[0]
    if not math.isfinite(value):
        raise InputError('nonfinite_clock')
    return value


def bits(value):
    if value is None:
        return None
    if not math.isfinite(value):
        raise InputError('nonfinite_result')
    return struct.pack('>d', value).hex()


def component_profile():
    from text_codec import preferred_encoding
    from journal_time import LOCAL_TIMEZONE
    preference_environment = {key: os.environ.get(key) for key in ('LANGUAGE', 'LC_ALL', 'LC_CTYPE', 'LANG')}
    locale_encoding = locale.getpreferredencoding()
    stdout_encoding = getattr(sys.stdout, 'encoding', None)
    preference = {'locale_encoding': locale_encoding, 'stdout_encoding': stdout_encoding,
                  'environment': preference_environment,
                  'resolved': preferred_encoding(locale_encoding, stdout_encoding, preference_environment)}
    files = {}
    for name in ('protocol.py', 'worker.py', 'date_time.py', 'date_profile.json',
                 'text_codec.py', 'duration.py', 'record_framer.py', 'journal_time.py', 'journal_format.py',
                 'ignore_adapter.py', 'ignore_dns.py', 'action_info.py'):
        data = Path(__file__).with_name(name).read_bytes()
        files[name] = hashlib.sha256(data).hexdigest()
    return {
        'schema_version': 1,
        'scope': 'helper_components_and_runtime_context',
        'component_files': files,
        'python': sys.version,
        'unicode_database': unicodedata.unidata_version,
        'preferred_encoding': preference,
        'locale': {'LC_CTYPE': locale.setlocale(locale.LC_CTYPE),
                   'LC_TIME': locale.setlocale(locale.LC_TIME)},
        'timezone': {'TZ': os.environ.get('TZ'), 'tzname': list(time.tzname),
                     'timezone': time.timezone, 'altzone': time.altzone,
                     'daylight': time.daylight, 'journal_fixed_offset': str(LOCAL_TIMEZONE)},
    }


def dependency_hash(profile=None):
    # This is a helper/context identity, not a complete OS/dependency SBOM.
    data = json.dumps(component_profile() if profile is None else profile, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')
    return hashlib.sha256(data).hexdigest()


class Session:
    def __init__(self, identity):
        if set(identity) != set(IDENTITY_KEYS) or any(not isinstance(v, str) or not v for v in identity.values()):
            raise InputError('identity')
        self.identity = dict(identity)
        self.sequence = 0
        self.requests = set()
        self.hello = False
        self.configured = False
        self.closed = False
        self.decoder = self.detector = None
        self.profile = component_profile()
        self.profile_hash = dependency_hash(self.profile)

    @staticmethod
    def outcome(outcome, stage, reason, data=None):
        return dict(outcome=outcome, stage=stage, reason=reason, data={} if data is None else data)

    def handle(self, request):
        response = {**request, 'kind': 'result'}
        if self.closed:
            response['payload'] = self.outcome('invalid_input', 'protocol', 'closed')
            return response
        if any(request[key] != value for key, value in self.identity.items()):
            response['payload'] = self.outcome('invalid_input', 'protocol', 'identity_mismatch')
            return response
        if int(request['sequence']) != self.sequence or request['request_id'] in self.requests:
            response['payload'] = self.outcome('invalid_input', 'protocol', 'sequence_or_request_replay')
            return response
        if len(self.requests) >= MAX_REQUESTS:
            self.closed = True
            response['payload'] = self.outcome('resource_limit', 'protocol', 'worker_request_lifetime')
            return response
        # Accepted calls consume transport order even on invalid operation input.
        # Component contexts never mutate implicitly: caller must supply next context.
        self.requests.add(request['request_id'])
        self.sequence += 1
        try:
            response['payload'] = self.dispatch(request['kind'], request['payload'])
        except MemoryError:
            response['payload'] = self.outcome('resource_limit', 'component', 'memory_limit')
        except InputError as error:
            response['payload'] = self.outcome('invalid_input', 'component', str(error))
        except SyntaxError:
            response['payload'] = self.outcome('invalid_input', 'component', 'invalid_expression_syntax')
        except ArithmeticError:
            response['payload'] = self.outcome('invalid_input', 'component', 'invalid_arithmetic')
        except re.error:
            response['payload'] = self.outcome('invalid_input', 'component', 'invalid_date_pattern')
        except (ValueError, TypeError, KeyError, LookupError):
            response['payload'] = self.outcome('invalid_input', 'component', 'invalid_component_input')
        except Exception:
            response['payload'] = self.outcome('internal_error', 'component', 'component_failure')
        return response

    def dispatch(self, kind, payload):
        if kind == 'hello':
            fields(payload, ())
            if self.hello:
                raise InputError('duplicate_hello')
            self.hello = True
            return self.outcome('complete', 'protocol', 'hello', {
                'profile_hash': self.profile_hash,
                'profile': self.profile,
                'operations': ['decode', 'date', 'duration', 'decode_date', 'decode_journal', 'format_journal', 'frame', 'frame_decode', 'ignore'],
                'limits': {'frame_bytes': MAX_FRAME, 'record_bytes': MAX_RECORD_BYTES,
                           'address_space_bytes': ADDRESS_SPACE, 'max_requests': MAX_REQUESTS,
                           'ignore_deadline_seconds': 2, 'ignore_external_calls': 32},
                'state_model': 'supplied_context', 'uid': os.geteuid(),
            })
        if not self.hello:
            raise InputError('hello_required')
        if kind == 'close':
            fields(payload, ())
            self.closed = True
            return self.outcome('complete', 'protocol', 'closed')
        if kind == 'health':
            fields(payload, ())
            return self.outcome('complete', 'protocol', 'healthy', {'configured': self.configured})
        if kind == 'configure':
            fields(payload, ('profile_hash', 'encoding', 'date_patterns', 'reference_year', 'default_tz'))
            if self.configured or payload['profile_hash'] != self.profile_hash or dependency_hash() != self.profile_hash:
                raise InputError('configuration_binding')
            if type(payload['reference_year']) is not int or not 1 <= payload['reference_year'] <= 9999:
                raise InputError('reference_year')
            from text_codec import TextDecoder
            from date_time import DateDetector
            decoder = TextDecoder(payload['encoding'], max_bytes=MAX_RECORD_BYTES,
                                  preferred_encoding=self.profile['preferred_encoding']['resolved'])
            detector = DateDetector(payload['date_patterns'], reference_year=payload['reference_year'],
                                    default_tz=payload['default_tz'])
            self.decoder, self.detector = decoder, detector
            self.configured = True
            return self.outcome('complete', 'configure', 'configured', {
                'codec_context': decoder.empty_context(), 'date_context': detector.empty_context(),
            })
        if kind != 'record':
            # No false barrier/checkpoint/action acknowledgments: those require
            # daemon-side transaction/queue semantics that are not implemented here.
            return self.outcome('unsupported', 'protocol', 'operation_not_implemented')
        operation = payload.get('operation')
        if operation == 'ignore':
            fields(payload, ('operation', 'profile_hash', 'effective_config', 'matched_identity',
                             'now_bits', 'snapshot', 'shared_snapshot', 'ticket', 'jail'))
            if payload['profile_hash'] != self.profile_hash:
                raise InputError('profile_mismatch')
            config = payload['effective_config']
            if not isinstance(config, dict):
                raise InputError('ignore_config')
            # Imported command text is never authority to execute a program.
            # The separate TrustedCommand seam is deliberately not exposed here.
            if config.get('ignorecommand'):
                return self.outcome('unsupported', 'ignore', 'ignorecommand_requires_admission')
            from ignore_adapter import Adapter, ExternalWorkBudget
            profile = self.profile_hash + ':' + self.identity['config_generation']
            adapter = Adapter(config, profile, deadline=2.0, max_external_calls=32)
            try:
                result = adapter.stage(payload['matched_identity'], now=clock(payload['now_bits']),
                    snapshot=payload['snapshot'], shared_snapshot=payload['shared_snapshot'],
                    ticket=payload['ticket'], jail=payload['jail'])
            except (TimeoutError, ExternalWorkBudget):
                return self.outcome('resource_limit', 'ignore', 'external_work_budget')
            return self.outcome('complete', 'ignore', 'policy_staged',
                dict(result, binding=adapter.binding, shared_binding=adapter.shared_binding))
        if operation == 'frame':
            fields(payload, ('operation', 'bytes_b64', 'encoding', 'eof'))
            if type(payload['eof']) is not bool:
                raise InputError('eof')
            encoded = payload['bytes_b64']
            if not isinstance(encoded, str) or len(encoded) > ((MAX_RECORD_BYTES + 2) // 3) * 4:
                raise InputError('record_budget')
            from record_framer import frame
            from text_codec import resolve_encoding
            encoding = resolve_encoding(payload['encoding'], preferred_encoding=self.profile['preferred_encoding']['resolved'])
            result = frame(base64.b64decode(encoded, validate=True), encoding,
                           eof=payload['eof'], max_bytes=MAX_RECORD_BYTES)
            if result.disposition == 'resource_limit':
                return self.outcome('resource_limit', 'framing', 'record_budget', asdict(result))
            if result.disposition == 'unsupported_boundary':
                return self.outcome('unsupported', 'framing', 'unsupported_boundary', asdict(result))
            if result.disposition == 'incomplete':
                # This acknowledges the framing query only. consumed=0 is not an
                # acknowledged record/cursor, and the caller must retain the bytes.
                return self.outcome('complete', 'framing', 'need_more_bytes', asdict(result))
            if result.disposition != 'complete':
                raise RuntimeError('unexpected_framing_disposition')
            return self.outcome('complete', 'framing', 'record_framed', asdict(result))
        if operation == 'duration':
            fields(payload, ('operation', 'text', 'history'))
            if type(payload['history']) is not bool:
                raise InputError('history')
            from duration import parse
            duration = parse(payload['text'], history=payload['history'])
            if duration.value is None:
                result = {'kind': duration.kind}
            elif type(duration.value) is int:
                result = {'kind': duration.kind, 'representation': 'integer', 'value': str(duration.value)}
            else:
                result = {'kind': duration.kind, 'representation': 'binary64', 'value': bits(duration.value)}
            return self.outcome('complete', 'duration', 'resolved', result)
        if not self.configured:
            raise InputError('configure_required')
        if operation == 'format_journal':
            fields(payload, ('operation', 'source', 'fields', 'now_bits', 'codec_context', 'timestamp_us', 'monotonic_us'))
            if not isinstance(payload['source'], str) or len(payload['source']) > 4096:
                raise InputError('source')
            clock(payload['now_bits'])
            values = payload['fields']
            if not isinstance(values, list) or len(values) > 4096:
                raise InputError('journal_field_budget')
            decoded_fields = []
            for value in values:
                fields(value, ('name', 'bytes_b64'))
                encoded = value['bytes_b64']
                if not isinstance(encoded, str) or len(encoded) > ((MAX_RECORD_BYTES + 2) // 3) * 4:
                    raise InputError('record_budget')
                decoded_fields.append((value['name'], base64.b64decode(encoded, validate=True)))
            from journal_time import convert
            from journal_format import format_entry
            try:
                converted = convert(payload['timestamp_us'])
            except (ValueError, OverflowError, OSError):
                return self.outcome('invalid_input', 'journal_time', 'journal_timestamp_range')
            self.decoder.restore_context(payload['codec_context'])
            formatted = format_entry(decoded_fields, self.decoder.encoding, payload['monotonic_us'], max_bytes=MAX_RECORD_BYTES)
            return self.outcome('complete', 'journal_format', 'journal_formatted',
                {'decoded': formatted, 'journal_time': converted, 'codec_context': self.decoder.export_context()})
        if operation == 'frame_decode':
            fields(payload, ('operation', 'bytes_b64', 'eof', 'source', 'now_bits', 'codec_context'))
            if type(payload['eof']) is not bool:
                raise InputError('eof')
            if not isinstance(payload['source'], str) or len(payload['source']) > 4096:
                raise InputError('source')
            now = clock(payload['now_bits'])
            encoded = payload['bytes_b64']
            if not isinstance(encoded, str) or len(encoded) > ((MAX_RECORD_BYTES + 2) // 3) * 4:
                raise InputError('record_budget')
            self.decoder.restore_context(payload['codec_context'])
            from record_framer import frame
            framed = frame(base64.b64decode(encoded, validate=True), self.decoder.encoding,
                           eof=payload['eof'], max_bytes=MAX_RECORD_BYTES)
            data = {'disposition': framed.disposition, 'consumed': framed.consumed,
                    'decoded': None, 'codec_context': self.decoder.export_context()}
            if framed.disposition == 'incomplete':
                return self.outcome('complete', 'framing', 'need_more_bytes', data)
            if framed.disposition == 'resource_limit':
                return self.outcome('resource_limit', 'framing', 'record_budget', data)
            if framed.disposition == 'unsupported_boundary':
                return self.outcome('unsupported', 'framing', 'unsupported_boundary', data)
            if framed.disposition != 'complete':
                raise RuntimeError('unexpected_framing_disposition')
            decoded = self.decoder.accept_framed(payload['source'], framed.text, framed.diagnostic, now)
            data.update(decoded=asdict(decoded), codec_context=self.decoder.export_context())
            return self.outcome('complete', 'framing', 'record_framed', data)
        if operation in ('decode', 'decode_date', 'decode_journal'):
            expected = {'operation', 'source', 'bytes_b64', 'now_bits', 'codec_context'}
            if operation == 'decode_date':
                expected |= {'usage_time_bits', 'date_context'}
            if operation == 'decode_journal':
                expected |= {'timestamp_us'}
            fields(payload, expected)
            encoded = payload['bytes_b64']
            if not isinstance(encoded, str) or len(encoded) > ((MAX_RECORD_BYTES + 2) // 3) * 4:
                raise InputError('record_budget')
            data = base64.b64decode(encoded, validate=True)
            self.decoder.restore_context(payload['codec_context'])
            decoded = self.decoder.decode(payload['source'], data, clock(payload['now_bits']))
            result = {'decoded': asdict(decoded), 'codec_context': self.decoder.export_context()}
            if operation == 'decode':
                return self.outcome('complete', 'codec', 'decoded', result)
            if operation == 'decode_journal':
                from journal_time import convert
                try:
                    converted = convert(payload['timestamp_us'])
                except (ValueError, OverflowError, OSError):
                    return self.outcome('invalid_input', 'journal_time', 'journal_timestamp_range')
                result['journal_time'] = converted
                return self.outcome('complete', 'journal_time', 'journal_decoded', result)
            date, context = self.detector.process(decoded.text, now=clock(payload['now_bits']),
                                                 usage_time=clock(payload['usage_time_bits']),
                                                 context=payload['date_context'])
            result.update(date=self.date_result(date), date_context=context)
            return self.date_outcome(date, result)
        if operation == 'date':
            fields(payload, ('operation', 'line', 'now_bits', 'usage_time_bits', 'date_context'))
            if not isinstance(payload['line'], str) or len(payload['line'].encode('utf-8')) > MAX_RECORD_BYTES:
                raise InputError('record_budget')
            date, context = self.detector.process(payload['line'], now=clock(payload['now_bits']),
                                                 usage_time=clock(payload['usage_time_bits']),
                                                 context=payload['date_context'])
            return self.date_outcome(date, {'date': self.date_result(date), 'date_context': context})
        return self.outcome('unsupported', 'record', 'operation_not_implemented')

    def date_outcome(self, date, data):
        if date is None:
            return self.outcome('no_match', 'date', 'date_not_found', data)
        if date.kind == 'invalid':
            return self.outcome('invalid_input', 'date', 'invalid_calendar_time', data)
        return self.outcome('complete', 'date', 'date_decoded', data)

    @staticmethod
    def date_result(date):
        if date is None:
            return None
        result = asdict(date)
        result['effective_bits'] = bits(result.pop('effective'))
        result['raw_timestamp_bits'] = bits(result.pop('raw_timestamp'))
        return result


def harden(uid=None, gid=None):
    if os.geteuid() == 0:
        if uid is None or gid is None or uid <= 0 or gid <= 0:
            raise RuntimeError('privileged_worker_refused')
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    elif uid is not None or gid is not None:
        raise RuntimeError('unexpected_privilege_arguments')
    if os.geteuid() == 0:
        raise RuntimeError('privileged_worker_refused')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # Linux PR_SET_NO_NEW_PRIVS
        raise RuntimeError('no_new_privs_failed')
    # Enumerate before reducing NOFILE: inherited descriptors may exceed that
    # future limit. /proc is a required Linux hardening capability for this worker.
    with os.scandir('/proc/self/fd') as entries:
        inherited = [int(entry.name) for entry in entries if entry.name.isdecimal()]
    for descriptor in inherited:
        if descriptor > 2:
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != 9:  # The enumeration descriptor already closed.
                    raise
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE, ADDRESS_SPACE))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stdio', action='store_true', required=True)
    for key in IDENTITY_KEYS:
        parser.add_argument('--' + key.replace('_', '-'), required=True)
    parser.add_argument('--uid', type=int)
    parser.add_argument('--gid', type=int)
    args = parser.parse_args()
    try:
        harden(args.uid, args.gid)
        session = Session({key: getattr(args, key) for key in IDENTITY_KEYS})
        while not session.closed:
            request = read_frame(sys.stdin.buffer)
            if request is None:
                break
            response = session.handle(request)
            try:
                write_frame(sys.stdout.buffer, response)
            except ProtocolError:
                response['payload'] = session.outcome('resource_limit', 'protocol', 'output_frame_budget')
                write_frame(sys.stdout.buffer, response)
    except (ProtocolError, RuntimeError, OSError) as error:
        # Never print the record, arbitrary exception details or configured secrets.
        reason = str(error) if isinstance(error, (ProtocolError, RuntimeError)) else 'transport_or_setup_error'
        print('compatibility worker: ' + reason[:128], file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
