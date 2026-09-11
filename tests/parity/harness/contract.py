# SPDX-License-Identifier: AGPL-3.0-or-later
"""Version 1 strict, exact comparison contract. No implicit normalization."""
import json
import math
import re
from pathlib import PurePosixPath

SCHEMA_VERSION = 1
REFERENCE_COMMIT = 'f60978618a101427b06924fc932b44350fec2b63'
REFERENCE_PROFILE = 'upstream-1.1.1'
# Optional future event families are declared here, never synthesized for a runner.
EVENT_FIELDS = {
    'config': {'value': 'nullable-string'},
    'filter_time': {'matched': 'boolean', 'parsed_time': 'nullable-number', 'stored_time': 'nullable-number', 'pending_retry': 'integer'},
    'persisted': {'pending_retry': 'integer', 'pending_last_time': 'nullable-number', 'threshold_reached': 'boolean', 'attempt_count': 'integer', 'ban_count': 'integer', 'ban_expiry': 'nullable-number'},
    'restored': {'pending_retry': 'integer', 'pending_last_time': 'nullable-number', 'threshold_reached': 'boolean', 'attempt_count': 'integer', 'ban_count': 'integer', 'ban_expiry': 'nullable-number'},
    'ticket': {'pending_retry': 'integer', 'pending_last_time': 'nullable-number', 'threshold_reached': 'boolean'},
    'source': {'record': 'string', 'cursor': 'string'},
    'timestamp': {'timestamp': 'number'},
    'match': {'identity': 'nullable-string', 'result': 'string'},
    'jail': {'name': 'string'},
    'action': {'operation': 'string', 'jail': 'string', 'ip': 'string', 'protocol': 'string', 'ports': 'string-list'},
    'expiry': {'absolute': 'nullable-number'},
    'history': {'identity': 'string', 'ban_count': 'integer'},
    'command': {'command': 'string', 'status': 'string', 'response': 'json'},
    'health': {'previous': 'string', 'current': 'string'},
}


def _fail(message):
    raise ValueError(message)


def _object(value, fields, path):
    if type(value) is not dict or set(value) != set(fields):
        _fail(f'{path}: expected exactly {sorted(fields)}')


def _finite(value, path='$'):
    if type(value) is float and not math.isfinite(value):
        _fail(f'{path}: nonfinite number')
    if type(value) not in (dict, list, str, int, float, bool, type(None)):
        _fail(f'{path}: not JSON')
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                _fail(f'{path}: non-string key')
            _finite(item, f'{path}.{key}')
    if type(value) is list:
        for index, item in enumerate(value):
            _finite(item, f'{path}[{index}]')


def load_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail(f'duplicate JSON key: {key}')
            result[key] = value
        return result
    result = json.loads(text, object_pairs_hook=pairs,
                        parse_constant=lambda value: _fail(f'nonfinite number: {value}'))
    _finite(result)
    return result


def _typed(value, kind, path):
    if kind.startswith('nullable-') and value is None:
        return
    kind = kind.removeprefix('nullable-')
    valid = {'string': lambda: type(value) is str,
             'integer': lambda: type(value) is int and value >= 0,
             'number': lambda: type(value) in (int, float),
             'boolean': lambda: type(value) is bool,
             'string-list': lambda: type(value) is list and all(type(x) is str for x in value),
             'json': lambda: True}[kind]()
    if not valid:
        _fail(f'{path}: expected {kind}')
    _finite(value, path)


def validate_observations(observations, kind=None):
    if type(observations) is not list:
        _fail('observations: expected array')
    for index, observation in enumerate(observations):
        _object(observation, ('event', 'sequence', 'values'), f'observations[{index}]')
        event = observation['event']
        if type(event) is not str or event not in EVENT_FIELDS:
            _fail('unknown event')
        allowed = {'config': ('config',), 'effective_config': ('config',), 'ssh_log': ('match',), 'tickets': ('ticket',), 'filter_time': ('filter_time',), 'persistence': ('persisted', 'restored')}
        if kind in allowed and event not in allowed[kind]:
            _fail('event does not match case kind')
        if type(observation['sequence']) is not int or observation['sequence'] != index:
            _fail('sequence must be ordered contiguous integers starting at zero')
        _object(observation['values'], EVENT_FIELDS[event], f'{event}.values')
        for field, expected in EVENT_FIELDS[event].items():
            _typed(observation['values'][field], expected, f'{event}.{field}')
        if kind == 'ssh_log':
            values = observation['values']
            if values['result'] not in ('matched', 'ignored'):
                _fail('ssh_log result must be matched or ignored')
            if (values['result'] == 'matched') != (values['identity'] is not None):
                _fail('ssh_log matched requires identity; ignored requires null identity')


def validate_case(case):
    _finite(case)
    _object(case, ('id', 'kind', 'profile', 'requirements', 'issues', 'split', 'input',
                   'expected_reference', 'provenance'), 'case')
    for field in ('id', 'profile'):
        if type(case[field]) is not str or not case[field]:
            _fail(f'case.{field}: nonempty string required')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', case['id']):
        _fail('case id must be a bounded single safe path component')
    if case['kind'] not in ('config', 'effective_config', 'tickets', 'filter_time', 'persistence', 'ssh_log') or type(case['kind']) is not str:
        _fail('unsupported case kind')
    if case['split'] not in ('development', 'held-out'):
        _fail('unknown fixture split')
    for field in ('requirements', 'issues'):
        values = case[field]
        if type(values) is not list or any(type(x) is not str or not x for x in values) or len(set(values)) != len(values):
            _fail(f'case.{field}: unique string array required')
    if not case['requirements']:
        _fail('case requires requirement ownership')
    _object(case['provenance'], ('origin', 'license', 'source_anchors'), 'provenance')
    if any(type(case['provenance'][key]) is not str or not case['provenance'][key]
           for key in ('origin', 'license')):
        _fail('provenance origin/license required')
    _typed(case['provenance']['source_anchors'], 'string-list', 'source_anchors')
    if not case['provenance']['source_anchors']:
        _fail('source anchors required')
    request = case['input']
    if case['kind'] in ('config', 'effective_config'):
        _object(request, ('files', 'section', 'option'), 'config input')
        if type(request['files']) is not dict or 'jail.conf' not in request['files']:
            _fail('config files require jail.conf')
        for name, content in request['files'].items():
            path = PurePosixPath(name)
            if not name or name == '.' or '\x00' in name or path.is_absolute() or '..' in path.parts or '\\' in name or str(path) != name:
                _fail('fixture file must be normalized relative path without traversal')
            if type(content) is not str:
                _fail('fixture content must be text')
        for field in ('section', 'option'):
            _typed(request[field], 'string', field)
    elif case['kind'] == 'ssh_log':
        _object(request, ('line',), 'ssh_log input')
        line = request['line']
        _typed(line, 'string', 'line')
        try:
            length = len(line.encode('utf-8'))
        except UnicodeEncodeError:
            _fail('ssh_log must be valid UTF-8 text')
        if length == 0 or length > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in line):
            _fail('ssh_log must be one bounded ordinary line without control characters')
        if not re.search(r'(?:^| )sshd(?:-session)?\[\d+\]: (?:Failed password for |Accepted publickey for ).+ from [0-9A-Fa-f:.]+ port [0-9]+ ssh2(?:$|: )', line):
            _fail('ssh_log accepts only ordinary sanitized password-failure/publickey-success records')
    elif case['kind'] == 'filter_time':
        _object(request, ('now', 'findtime', 'live', 'event'), 'filter_time input')
        for field in ('now', 'findtime', 'event'):
            _typed(request[field], 'number', field)
        _typed(request['live'], 'boolean', 'live')
        if request['findtime'] <= 0:
            _fail('findtime must be positive')
    else:
        _object(request, ('now', 'findtime', 'maxretry', 'events'), 'tickets input')
        for field in ('now', 'findtime'):
            _typed(request[field], 'number', field)
        _typed(request['maxretry'], 'integer', 'maxretry')
        if request['findtime'] <= 0 or request['maxretry'] <= 0:
            _fail('findtime/maxretry must be positive')
        if type(request['events']) is not list or not request['events']:
            _fail('events must be nonempty array')
        for event in request['events']:
            _typed(event, 'number', 'event')
    validate_observations(case['expected_reference'], case['kind'])
    expected_length = (0 if case['kind'] == 'persistence' else
                       len(request['events']) if case['kind'] == 'tickets' else 1)
    if len(case['expected_reference']) != expected_length:
        _fail('expected trace length differs from input operations')
    return case


def validate_bundle(bundle):
    _finite(bundle)
    _object(bundle, ('schema_version', 'reference_commit', 'profile', 'cases'), 'bundle')
    if type(bundle['schema_version']) is not int or bundle['schema_version'] != SCHEMA_VERSION:
        _fail('unknown schema version')
    if bundle['reference_commit'] != REFERENCE_COMMIT:
        _fail('reference commit differs from version 1 pin')
    if bundle['profile'] != REFERENCE_PROFILE:
        _fail('profile must match version 1 pinned upstream-1.1.1 reference')
    if type(bundle['cases']) is not list or not bundle['cases']:
        _fail('bundle cases required')
    ids = set()
    for case in bundle['cases']:
        validate_case(case)
        if case['id'] in ids:
            _fail('duplicate case id')
        ids.add(case['id'])
        if case['profile'] != bundle['profile']:
            _fail('case profile differs from bundle')
    return bundle


def validate_outcome(outcome, case):
    _finite(outcome)
    _object(outcome, ('status', 'observations', 'raw', 'details'), 'outcome')
    if outcome['status'] not in ('ok', 'unsupported', 'error', 'timeout'):
        _fail('unknown outcome status')
    _object(outcome['raw'], ('stdout', 'stderr', 'returncode'), 'raw')
    for stream in ('stdout', 'stderr'):
        _typed(outcome['raw'][stream], 'string', stream)
    code = outcome['raw']['returncode']
    if code is not None and type(code) is not int:
        _fail('returncode must be integer or null')
    if type(outcome['details']) is not dict:
        _fail('details must be object')
    validate_observations(outcome['observations'], case['kind'])
    expected_length = 2 if case['kind'] == 'persistence' else len(case['expected_reference'])
    if outcome['status'] == 'ok' and case['kind'] == 'persistence' and [x['event'] for x in outcome['observations']] != ['persisted', 'restored']:
        _fail('persistence requires persisted then restored')
    if outcome['status'] == 'ok' and (code != 0 or len(outcome['observations']) != expected_length):
        _fail('successful outcome requires exit zero and complete trace')
    return outcome
