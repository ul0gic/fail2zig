# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exact ordered comparisons. Known gaps and unexpected passes require review."""
from copy import deepcopy
try:
    from .contract import validate_case, validate_outcome
except ImportError:
    from contract import validate_case, validate_outcome


def differences(expected, actual, path='$'):
    """No coercion, ignored fields, ordering normalization or timing tolerance."""
    if type(expected) is not type(actual):
        # JSON integer and float are both numeric, but booleans never are.
        if type(expected) in (int, float) and type(actual) in (int, float) and expected == actual:
            return []
        return [{'path': path, 'expected': expected, 'actual': actual, 'reason': 'type-or-value'}]
    if type(expected) is dict:
        result = []
        for key in sorted(expected.keys() | actual.keys()):
            if key not in expected or key not in actual:
                result.append({'path': f'{path}.{key}', 'expected': expected.get(key),
                               'actual': actual.get(key), 'reason': 'missing-or-extra-field'})
            else:
                result.extend(differences(expected[key], actual[key], f'{path}.{key}'))
        return result
    if type(expected) is list:
        result = []
        if len(expected) != len(actual):
            result.append({'path': path + '.length', 'expected': len(expected), 'actual': len(actual), 'reason': 'length'})
        for index, (left, right) in enumerate(zip(expected, actual)):
            result.extend(differences(left, right, f'{path}[{index}]'))
        return result
    return [] if expected == actual else [{'path': path, 'expected': expected, 'actual': actual, 'reason': 'value'}]


def compare_case(case, reference, candidate):
    result = {'id': case.get('id'), 'decision': 'error', 'requirements': case.get('requirements', []),
              'issues': case.get('issues', []), 'reference_mismatches': [], 'candidate_mismatches': [],
              'normalization': 'none', 'timing_tolerance': 0, 'review_required': False}
    try:
        validate_case(case)
        validate_outcome(reference, case)
        validate_outcome(candidate, case)
    except (ValueError, TypeError, KeyError) as error:
        result['error'] = str(error)
        return result
    statuses = (reference['status'], candidate['status'])
    result['reference_status'], result['candidate_status'] = statuses
    if reference['status'] == 'ok':
        result['reference_mismatches'] = differences(case['expected_reference'], reference['observations'])
        if candidate['status'] == 'ok':
            result['candidate_mismatches'] = differences(reference['observations'], candidate['observations'])
    # A missing candidate capability cannot erase a failed reference oracle.
    if result['reference_mismatches']:
        result['decision'] = 'reference-drift'
        result['review_required'] = True
        return result
    for status in ('error', 'timeout', 'unsupported'):
        if status in statuses:
            result['decision'] = status
            return result
    if result['candidate_mismatches']:
        result['decision'] = 'known-gap' if case['issues'] else 'mismatch'
        result['review_required'] = True
    elif case['issues']:
        result['decision'] = 'unexpected-pass'
        result['review_required'] = True
    else:
        result['decision'] = 'pass'
    return result


def self_tests():
    case = {'id': 'control', 'kind': 'config', 'profile': 'upstream-1.1.1',
            'requirements': ['CFG-01'], 'issues': [], 'split': 'development',
            'input': {'files': {'jail.conf': '[probe]\nmaxretry = 2\n'}, 'section': 'probe', 'option': 'maxretry'},
            'expected_reference': [{'event': 'config', 'sequence': 0, 'values': {'value': '2'}}],
            'provenance': {'origin': 'Original comparator control', 'license': 'AGPL-3.0-or-later',
                           'source_anchors': ['fail2ban/client/configreader.py:ConfigReaderUnshared']}}
    good = {'status': 'ok', 'observations': deepcopy(case['expected_reference']),
            'raw': {'stdout': '', 'stderr': '', 'returncode': 0}, 'details': {}}
    wrong = deepcopy(case)
    wrong['expected_reference'][0]['values']['value'] = '99'
    malformed = deepcopy(good)
    malformed['observations'][0]['values']['extra'] = True
    unsupported = dict(good, status='unsupported', observations=[])
    known = dict(case, issues=['SYS-026'])
    checks = [
        ('equal-control', compare_case(case, good, good)['decision'] == 'pass'),
        ('wrong-expected-through-real-comparator', compare_case(wrong, good, good)['decision'] == 'reference-drift'),
        ('malformed-not-pass', compare_case(case, good, malformed)['decision'] == 'error'),
        ('unsupported-not-pass', compare_case(case, good, unsupported)['decision'] == 'unsupported'),
        ('known-gap-removal-needs-review', compare_case(known, good, good)['decision'] == 'unexpected-pass'),
    ]
    for field, left, right in [('ip', '192.0.2.10', '192.0.2.11'), ('port', '22', '443'),
                               ('count', 3, 4), ('status', 'banned', 'unbanned'),
                               ('expiry', 1800000600, 1800000601), ('boolean', 1, True)]:
        checks.append((f'wrong-{field}', bool(differences({field: left}, {field: right}))))
    checks.append(('wrong-order', bool(differences([{'ip': '192.0.2.10'}, {'ip': '192.0.2.11'}],
                                                 [{'ip': '192.0.2.11'}, {'ip': '192.0.2.10'}]))))
    return {'passed': all(passed for _, passed in checks),
            'checks': [{'id': name, 'passed': passed} for name, passed in checks]}
