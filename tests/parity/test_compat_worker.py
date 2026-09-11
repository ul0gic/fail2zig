#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Original private subprocess protocol tests; no network, firewall or actions."""
import base64
import copy
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
COMPAT = ROOT / 'engine/compat'
sys.path.insert(0, str(COMPAT))
import protocol
import worker

IDENTITY = dict(daemon_epoch='daemon-test', worker_epoch='worker-test',
                config_generation='generation-test', jail_id='test-jail')


def envelope(sequence=0, kind='hello', payload=None, **changes):
    return dict(wire_version=1, kind=kind, request_id=f'request-{sequence}',
                **{**IDENTITY, **changes}, sequence=str(sequence), capabilities=[],
                payload={} if payload is None else payload)


def clock(value):
    return struct.pack('>d', value).hex()


class ProtocolTests(unittest.TestCase):
    def test_round_trip_and_truncated_stream(self):
        original = envelope(payload={'text': 'original café'})
        frame = protocol.encode_frame(original)
        self.assertEqual(original, protocol.decode_frame(frame))
        self.assertEqual(original, protocol.read_frame(io.BytesIO(frame)))
        self.assertIsNone(protocol.read_frame(io.BytesIO()))
        for incomplete in (frame[:2], frame[:-1]):
            with self.assertRaises(protocol.ProtocolError):
                protocol.read_frame(io.BytesIO(incomplete))

    def test_duplicate_nonfinite_utf8_and_depth_rejected(self):
        valid = json.dumps(envelope()).encode()
        invalid = [valid.replace(b'"wire_version": 1', b'"wire_version": 1, "wire_version": 1'),
                   valid.replace(b'"payload": {}', b'"payload": {"x": 1e999}'),
                   valid.replace(b'"payload": {}', b'"payload": {"x": NaN}'),
                   valid.replace(b'"payload": {}', b'"payload": {"x": "\\ud800"}'),
                   b'\xff', b'[' * 100 + b']' * 100]
        for data in invalid:
            with self.subTest(data=data[:40]), self.assertRaises(protocol.ProtocolError):
                protocol.decode_frame(len(data).to_bytes(4, 'big') + data)
        with self.assertRaises(protocol.ProtocolError):
            protocol.read_frame(io.BytesIO((protocol.MAX_FRAME + 1).to_bytes(4, 'big')))

    def test_unknown_fields_versions_and_sequences_rejected(self):
        for field, value in [('wire_version', True), ('wire_version', 2), ('capabilities', ['execute']),
                             ('sequence', '01'), ('sequence', '-1'), ('sequence', str(2**64)),
                             ('kind', 'shell')]:
            data = envelope()
            data[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(protocol.ProtocolError):
                protocol.encode_frame(data)
        data = envelope()
        data['extra'] = True
        with self.assertRaises(protocol.ProtocolError):
            protocol.encode_frame(data)


class SessionTests(unittest.TestCase):
    def test_ignore_stages_explicit_jail_and_shared_context(self):
        hello = self.request('hello')['data']
        self.assertIn('ignore', hello['operations'])
        payload = dict(operation='ignore', profile_hash=hello['profile_hash'],
            effective_config=dict(ignoreself=False, usedns='no', allowipv6='no', ignoreip=['192.0.2.1']),
            matched_identity='192.0.2.1', now_bits=clock(100), snapshot=None,
            shared_snapshot=None, ticket=None, jail=None)
        first = self.request('record', payload)
        self.assertEqual('complete', first['outcome'])
        self.assertTrue(first['data']['decisions'][0]['ignored'])
        self.assertEqual(2, first['data']['snapshot']['version'])
        self.assertEqual(1, first['data']['shared_snapshot']['version'])
        other_identity = dict(IDENTITY, jail_id='other-jail')
        other = worker.Session(other_identity)
        other.handle(envelope(0, 'hello', jail_id='other-jail'))
        changed = dict(payload, effective_config=dict(ignoreself=False, usedns='no', allowipv6='no'),
                       shared_snapshot=first['data']['shared_snapshot'])
        second = other.handle(envelope(1, 'record', changed, jail_id='other-jail'))['payload']
        self.assertEqual('complete', second['outcome'])
        self.assertFalse(second['data']['decisions'][0]['ignored'])
        self.assertEqual(first['data']['shared_binding'], second['data']['shared_binding'])
        self.assertNotEqual(first['data']['binding'], second['data']['binding'])
        resumed = self.request('record', dict(payload, snapshot=first['data']['snapshot'],
            shared_snapshot=second['data']['shared_snapshot']))
        self.assertEqual('complete', resumed['outcome'])

    def test_ignore_rejects_commands_bad_profiles_and_stale_context(self):
        hello = self.request('hello')['data']
        payload = dict(operation='ignore', profile_hash=hello['profile_hash'],
            effective_config=dict(ignoreself=False, usedns='no', allowipv6='no'),
            matched_identity='192.0.2.1', now_bits=clock(100), snapshot=None,
            shared_snapshot=None, ticket=None, jail=None)
        result = self.request('record', dict(payload, effective_config={'ignorecommand': 'original-unadmitted-helper'}))
        self.assertEqual(('unsupported', 'ignorecommand_requires_admission'), (result['outcome'], result['reason']))
        self.assertEqual('invalid_input', self.request('record', dict(payload, profile_hash='other'))['outcome'])
        self.assertEqual('invalid_input', self.request('record', dict(payload, extra=True))['outcome'])
        first = self.request('record', payload)['data']
        self.assertEqual('invalid_input', self.request('record', dict(payload,
            shared_snapshot=dict(first['shared_snapshot'], version=True)))['outcome'])
        import ignore_adapter
        with mock.patch.object(ignore_adapter.Adapter, 'stage', side_effect=TimeoutError):
            result = self.request('record', payload)
        self.assertEqual(('resource_limit', 'external_work_budget'), (result['outcome'], result['reason']))
        config = dict(payload['effective_config'], ignoreip=['file:original-' + str(i) for i in range(33)])
        calls = []
        def ordinary_miss(source, value, now):
            calls.append(str(source.path))
            return False, None
        with mock.patch.object(ignore_adapter.policy.FileIgnoreSet, 'contains', ordinary_miss):
            result = self.request('record', dict(payload, effective_config=config))
        self.assertEqual(32, len(calls))
        self.assertEqual(('resource_limit', 'external_work_budget'), (result['outcome'], result['reason']))
        self.assertEqual({}, result['data'])

    def setUp(self):
        self.session = worker.Session(IDENTITY)
        self.sequence = 0

    def request(self, kind, payload=None):
        value = self.session.handle(envelope(self.sequence, kind, payload))['payload']
        self.sequence += 1
        return value

    def configure(self):
        hello = self.request('hello')
        self.assertEqual('complete', hello['outcome'])
        result = self.request('configure', dict(profile_hash=hello['data']['profile_hash'],
                                               encoding='utf-8', date_patterns=['{EPOCH}'],
                                               reference_year=2026, default_tz='UTC'))
        self.assertEqual('complete', result['outcome'])
        return result['data']

    def test_auto_encoding_is_bound_to_profile_for_decode_and_frame(self):
        with mock.patch.object(worker.locale, 'getpreferredencoding', return_value='ISO-8859-1'):
            self.session = worker.Session(IDENTITY)
            hello = self.request('hello')['data']
            self.assertEqual('ISO-8859-1', hello['profile']['preferred_encoding']['resolved'])
            configured = self.request('configure', dict(profile_hash=hello['profile_hash'],
                encoding='AuTo', date_patterns=['{EPOCH}'], reference_year=2026, default_tz='UTC'))
            self.assertEqual('complete', configured['outcome'])
            decoded = self.request('record', dict(operation='decode', source='fixture',
                bytes_b64=base64.b64encode(b'caf\xe9').decode(), now_bits=worker.bits(1.0),
                codec_context=configured['data']['codec_context']))
            self.assertEqual('café', decoded['data']['decoded']['text'])
            framed = self.request('record', dict(operation='frame', encoding='AUTO', eof=True,
                bytes_b64=base64.b64encode(b'caf\xe9\n').decode()))
            self.assertEqual('café', framed['data']['text'])
        self.assertNotEqual(self.session.profile_hash, worker.dependency_hash())

    def test_frame_decode_stages_warning_context_and_preserves_incomplete(self):
        configured = self.configure()
        context = configured['codec_context']
        payload = dict(operation='frame_decode', source='original-fixture', eof=True,
            now_bits=worker.bits(10.0), codec_context=context,
            bytes_b64=base64.b64encode(b'bad\xff').decode())
        incomplete = self.request('record', payload)
        self.assertEqual('need_more_bytes', incomplete['reason'])
        self.assertEqual(0, incomplete['data']['consumed'])
        self.assertEqual(context, incomplete['data']['codec_context'])
        payload['bytes_b64'] = base64.b64encode(b'bad\xff\nnext\n').decode()
        complete = self.request('record', payload)['data']
        self.assertEqual(5, complete['consumed'])
        self.assertEqual('bad\ufffd', complete['decoded']['text'])
        self.assertTrue(complete['decoded']['warning_due'])
        payload['codec_context'] = complete['codec_context']
        replay = self.request('record', payload)['data']
        self.assertFalse(replay['decoded']['warning_due'])
        self.assertEqual(context['warnings'], [])

    def test_journal_decode_preserves_iso_tuple_text_and_rejects_calendar_overflow(self):
        configured = self.configure()
        context = configured['codec_context']
        payload = dict(operation='decode_journal', source='original-journal',
            bytes_b64=base64.b64encode(b'ordinary journal message').decode(),
            now_bits=worker.bits(1730000005.0), codec_context=context,
            timestamp_us='1730000000000001')
        result = self.request('record', payload)
        self.assertEqual('complete', result['outcome'])
        self.assertEqual('2024-10-27T03:33:20.000001+00:00 ', result['data']['journal_time']['time_text'])
        self.assertEqual('1730000000000001', result['data']['journal_time']['timestamp_us'])
        self.assertEqual('ordinary journal message', result['data']['decoded']['text'])
        payload['timestamp_us'] = '253402300799999999'
        self.assertEqual('journal_timestamp_range', self.request('record', payload)['reason'])
        self.assertEqual([], context['warnings'])

    def test_journal_fields_use_binding_utf8_before_configured_fallback(self):
        hello = self.request('hello')['data']
        configured = self.request('configure', dict(profile_hash=hello['profile_hash'],
            encoding='latin1', date_patterns=['{EPOCH}'], reference_year=2026, default_tz='UTC'))['data']
        fields = [('SYSLOG_IDENTIFIER', 'émission'.encode()), ('SYSLOG_PID', b'0'),
                  ('_PID', b'42'), ('MESSAGE', 'café'.encode()), ('MESSAGE', b'part\xff')]
        payload = dict(operation='format_journal', source='original-journal',
            fields=[dict(name=name, bytes_b64=base64.b64encode(value).decode()) for name,value in fields],
            now_bits=worker.bits(1730000005.0), codec_context=configured['codec_context'],
            timestamp_us='1730000000000001', monotonic_us='1000001')
        result = self.request('record', payload)
        self.assertEqual('complete', result['outcome'])
        self.assertEqual('émission[42]: café partÿ', result['data']['decoded']['text'])
        self.assertFalse(result['data']['decoded']['warning_due'])
        self.assertEqual(configured['codec_context'], result['data']['codec_context'])

    def test_identity_and_sequence_rejection_do_not_advance(self):
        for key in IDENTITY:
            bad = envelope(**{key: 'wrong'})
            self.assertEqual('identity_mismatch', self.session.handle(bad)['payload']['reason'])
        self.assertEqual(0, self.session.sequence)
        self.request('hello')
        for sequence in (0, 3):
            self.assertEqual('sequence_or_request_replay', self.session.handle(envelope(sequence, 'health'))['payload']['reason'])
        self.assertEqual(1, self.session.sequence)
        self.assertEqual('complete', self.request('health')['outcome'])

    def test_duration_preserves_large_integer_and_fraction(self):
        self.request('hello')
        large = self.request('record', {'operation':'duration', 'text':'9007199254740993', 'history':False})
        self.assertEqual({'kind':'finite', 'representation':'integer', 'value':'9007199254740993'}, large['data'])
        fraction = self.request('record', {'operation':'duration', 'text':'0.5', 'history':False})
        self.assertEqual(clock(.5), fraction['data']['value'])
        invalid = self.request('record', {'operation':'duration', 'text':'unresolved_name', 'history':False})
        self.assertEqual('invalid_input', invalid['outcome'])

    def test_decode_date_context_roundtrip_and_no_match_distinction(self):
        context = self.configure()
        payload = dict(operation='decode_date', source='original-log',
                       bytes_b64=base64.b64encode(b'1700000000.500 harmless').decode(),
                       now_bits=clock(1700000001), usage_time_bits=clock(1700000001), **context)
        result = self.request('record', payload)
        self.assertEqual('complete', result['outcome'])
        self.assertEqual(clock(1700000000.5), result['data']['date']['effective_bits'])
        payload.update(bytes_b64=base64.b64encode(b'no timestamp here').decode(),
                       date_context=result['data']['date_context'], codec_context=result['data']['codec_context'])
        result = self.request('record', payload)
        self.assertEqual('no_match', result['outcome'])
        payload['now_bits'] = '7ff0000000000000'
        self.assertEqual('invalid_input', self.request('record', payload)['outcome'])

    def test_codec_warning_state_is_supplied_and_replayable(self):
        context = self.configure()
        payload = dict(operation='decode', source='original-log', bytes_b64='/w==',
                       now_bits=clock(100), codec_context=context['codec_context'])
        first = self.request('record', payload)
        self.assertTrue(first['data']['decoded']['warning_due'])
        payload['codec_context'] = first['data']['codec_context']
        second = self.request('record', payload)
        self.assertFalse(second['data']['decoded']['warning_due'])
        payload['codec_context'] = context['codec_context']
        self.assertTrue(self.request('record', payload)['data']['decoded']['warning_due'])

    def test_framing_is_codec_aware_and_never_acknowledges_incomplete_input(self):
        hello = self.request('hello')
        self.assertIn('frame', hello['data']['operations'])
        self.assertIn('record_framer.py', hello['data']['profile']['component_files'])
        data = 'first\nsecond\n'.encode('utf-16-le')
        result = self.request('record', dict(operation='frame', bytes_b64=base64.b64encode(data).decode(),
                                             encoding='utf-16-le', eof=False))
        self.assertEqual('complete', result['outcome'])
        self.assertEqual('first', result['data']['text'])
        self.assertEqual(12, result['data']['consumed'])
        self.assertEqual('complete', result['data']['disposition'])
        incomplete = self.request('record', dict(operation='frame', bytes_b64='eA==', encoding='utf-8', eof=False))
        self.assertEqual('need_more_bytes', incomplete['reason'])
        self.assertEqual(0, incomplete['data']['consumed'])
        self.assertEqual('incomplete', incomplete['data']['disposition'])
        invalid = self.request('record', dict(operation='frame', bytes_b64='eA==', encoding='utf-8', eof=1))
        self.assertEqual('invalid_input', invalid['outcome'])
        unknown = self.request('record', dict(operation='frame', bytes_b64='eA==', encoding='utf-8', eof=True, extra=1))
        self.assertEqual('invalid_input', unknown['outcome'])

    def test_saved_context_rejects_boolean_versions_and_fractional_identity(self):
        contexts = self.configure()
        for field, value in (('version', True), ('max_bytes', float(worker.MAX_RECORD_BYTES))):
            context = copy.deepcopy(contexts['codec_context'])
            context[field] = value
            response = self.request('record', dict(operation='decode', source='source', bytes_b64='',
                                                   now_bits=clock(0), codec_context=context))
            self.assertEqual('invalid_input', response['outcome'])
        context = copy.deepcopy(contexts['date_context'])
        context['version'] = True
        response = self.request('record', dict(operation='date', line='1700000000 harmless',
                                               now_bits=clock(1700000000), usage_time_bits=clock(1700000000),
                                               date_context=context))
        self.assertEqual('invalid_input', response['outcome'])

    def test_invalid_configuration_is_not_a_worker_internal_error(self):
        hello = self.request('hello')
        for expression in ('1e3', '1/0'):
            value = self.request('record', {'operation':'duration', 'text':expression, 'history':False})
            self.assertEqual('invalid_input', value['outcome'])
        invalid = self.request('configure', dict(profile_hash=hello['data']['profile_hash'],
                                                 encoding='utf-8', date_patterns=['('],
                                                 reference_year=2026, default_tz='UTC'))
        self.assertEqual('invalid_input', invalid['outcome'])
        self.assertFalse(self.session.configured)
        configured = self.request('configure', dict(profile_hash=hello['data']['profile_hash'],
                                                    encoding='utf-8', date_patterns=['%Y-%m-%d'],
                                                    reference_year=2026, default_tz='UTC'))
        self.assertEqual('complete', configured['outcome'])
        invalid_date = self.request('record', dict(operation='date', line='2026-02-31 original',
                                                   now_bits=clock(1770000000), usage_time_bits=clock(1770000000),
                                                   date_context=configured['data']['date_context']))
        self.assertEqual('invalid_input', invalid_date['outcome'])
        self.assertEqual('invalid_calendar_time', invalid_date['reason'])

    def test_unimplemented_effects_and_checkpoints_are_not_success(self):
        self.request('hello')
        for kind in ('action', 'checkpoint', 'restore', 'barrier', 'cancel'):
            self.assertEqual('unsupported', self.request(kind)['outcome'])

    def test_unknown_payload_and_unbound_reconfigure_rejected(self):
        context = self.configure()
        value = self.request('record', dict(operation='decode', source='x', bytes_b64='',
                                           now_bits=clock(0), codec_context=context['codec_context'], extra=1))
        self.assertEqual('invalid_input', value['outcome'])
        value = self.request('configure', dict(profile_hash=self.session.profile_hash,
                                               encoding='utf-8', date_patterns=['{EPOCH}'],
                                               reference_year=2026, default_tz='UTC'))
        self.assertEqual('invalid_input', value['outcome'])


class SubprocessTests(unittest.TestCase):
    def command(self):
        command = [sys.executable, '-I', '-B', str(COMPAT/'worker.py'), '--stdio']
        for key, value in IDENTITY.items():
            command += ['--'+key.replace('_','-'), value]
        return command

    def test_real_child_handshake_duration_and_close(self):
        if os.geteuid() == 0:
            self.skipTest('normal child test requires nonroot caller')
        requests = [envelope(), envelope(1, 'record', {'operation':'duration','text':'1h 30m','history':False}),
                    envelope(2, 'close')]
        completed = subprocess.run(self.command(), input=b''.join(map(protocol.encode_frame, requests)),
                                   capture_output=True, timeout=10,
                                   env={'PATH': '/usr/bin:/bin', 'LANG':'C.UTF-8', 'PYTHONDONTWRITEBYTECODE':'1'})
        self.assertEqual(0, completed.returncode, completed.stderr)
        stream = io.BytesIO(completed.stdout)
        replies = [protocol.read_frame(stream) for _ in requests]
        self.assertEqual(['complete']*3, [reply['payload']['outcome'] for reply in replies])
        self.assertEqual('5400', replies[1]['payload']['data']['value'])
        self.assertNotEqual(0, replies[0]['payload']['data']['uid'])
        self.assertIsNone(protocol.read_frame(stream))
        self.assertEqual(b'', completed.stderr)

    def test_real_child_context_restores_after_worker_restart(self):
        if os.geteuid() == 0:
            self.skipTest('normal child test requires nonroot caller')
        from text_codec import TextDecoder
        config = dict(profile_hash=worker.dependency_hash(), encoding='utf-8',
                      date_patterns=['{EPOCH}'], reference_year=2026, default_tz='UTC')
        context = TextDecoder('utf-8', max_bytes=worker.MAX_RECORD_BYTES).empty_context()
        for expected_warning in (True, False):
            requests = [envelope(), envelope(1, 'configure', config),
                        envelope(2, 'record', dict(operation='decode', source='saved-source',
                                                  bytes_b64='/w==', now_bits=clock(100), codec_context=context)),
                        envelope(3, 'close')]
            completed = subprocess.run(self.command(), input=b''.join(map(protocol.encode_frame, requests)),
                                       capture_output=True, timeout=10)
            self.assertEqual(0, completed.returncode, completed.stderr)
            stream = io.BytesIO(completed.stdout)
            replies = [protocol.read_frame(stream) for _ in requests]
            self.assertEqual('complete', replies[2]['payload']['outcome'])
            result = replies[2]['payload']['data']
            self.assertEqual(expected_warning, result['decoded']['warning_due'])
            context = result['codec_context']

    def test_real_child_has_address_space_descriptor_and_privilege_limits(self):
        if os.geteuid() == 0 or not hasattr(os, 'getuid') or not Path('/proc/self/status').exists():
            self.skipTest('Linux nonroot process inspection required')
        import resource
        child = subprocess.Popen(self.command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        try:
            protocol.write_frame(child.stdin, envelope())
            hello = protocol.read_frame(child.stdout)
            self.assertEqual('complete', hello['payload']['outcome'])
            self.assertEqual((worker.ADDRESS_SPACE, worker.ADDRESS_SPACE), resource.prlimit(child.pid, resource.RLIMIT_AS))
            self.assertEqual((32, 32), resource.prlimit(child.pid, resource.RLIMIT_NOFILE))
            self.assertEqual((0, 0), resource.prlimit(child.pid, resource.RLIMIT_CORE))
            status = Path(f'/proc/{child.pid}/status').read_text()
            self.assertIn('NoNewPrivs:\t1', status)
            protocol.write_frame(child.stdin, envelope(1, 'close'))
            self.assertEqual('complete', protocol.read_frame(child.stdout)['payload']['outcome'])
            child.stdin.close()
            self.assertEqual(0, child.wait(timeout=5))
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream and not stream.closed:
                    stream.close()

    def test_real_child_closes_inherited_descriptor_above_new_limit(self):
        if os.geteuid() == 0:
            self.skipTest('normal child test requires nonroot caller')
        import fcntl
        with open('/dev/null', 'rb') as harmless:
            descriptor = fcntl.fcntl(harmless.fileno(), fcntl.F_DUPFD, 128)
        try:
            child = subprocess.Popen(self.command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, pass_fds=(descriptor,))
            try:
                protocol.write_frame(child.stdin, envelope())
                self.assertEqual('complete', protocol.read_frame(child.stdout)['payload']['outcome'])
                self.assertFalse(Path(f'/proc/{child.pid}/fd/{descriptor}').exists())
                protocol.write_frame(child.stdin, envelope(1, 'close'))
                protocol.read_frame(child.stdout)
                self.assertEqual(0, child.wait(timeout=5))
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                for stream in (child.stdin, child.stdout, child.stderr):
                    stream.close()
        finally:
            os.close(descriptor)

    def test_child_rejects_oversize_header_without_body_read(self):
        if os.geteuid() == 0:
            self.skipTest('normal child test requires nonroot caller')
        result = subprocess.run(self.command(), input=(protocol.MAX_FRAME+1).to_bytes(4,'big'),
                                capture_output=True, timeout=10)
        self.assertEqual(2, result.returncode)
        self.assertEqual(b'', result.stdout)
        self.assertIn(b'frame_length', result.stderr)

    def test_privileged_default_refused_before_component_dispatch(self):
        with mock.patch.object(worker.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'privileged_worker_refused'):
                worker.harden()


if __name__ == '__main__':
    unittest.main()
