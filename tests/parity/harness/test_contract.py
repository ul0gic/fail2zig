# SPDX-License-Identifier: AGPL-3.0-or-later
import copy
import json
from pathlib import Path
import unittest
from contract import load_json, validate_bundle, validate_case, validate_observations, validate_outcome
from compare import compare_case, differences, self_tests


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.bundle = load_json((Path(__file__).parent / 'fixtures/baseline-v1.json').read_text())
        self.case = self.bundle['cases'][0]
        self.outcome = {'status': 'ok', 'observations': copy.deepcopy(self.case['expected_reference']),
                        'raw': {'stdout': '', 'stderr': '', 'returncode': 0}, 'details': {}}

    def test_original_and_held_out(self):
        validate_bundle(self.bundle)
        self.assertEqual(len(self.bundle['cases']), 17)
        self.assertEqual(sum(bool(c['issues']) for c in self.bundle['cases']), 9)
        self.assertEqual(sum(c['split'] == 'held-out' for c in self.bundle['cases']), 4)

    def test_effective_default_observes_resolved_configuration(self):
        case = next(x for x in self.bundle['cases'] if x['id'] == 'held-config-default')
        validate_case(case)
        self.assertEqual(case['kind'], 'effective_config')
        self.assertEqual(case['split'], 'held-out')
        self.assertEqual(case['expected_reference'][0]['values']['value'], '6')
        self.assertEqual(case['issues'], [])
        self.assertIn('native.resolveJail', case['provenance']['origin'])
        self.assertIn('filter = sshd', case['input']['files']['jail.conf'])
        outcome = {'status': 'ok', 'observations': copy.deepcopy(case['expected_reference']),
                   'raw': {'stdout': '', 'stderr': '', 'returncode': 0}, 'details': {}}
        validate_outcome(outcome, case)
        self.assertEqual(compare_case(case, outcome, outcome)['decision'], 'pass')

    def test_profile_matches_reference_version(self):
        self.bundle['profile'] = 'upstream-1.0.2'
        with self.assertRaises(ValueError):
            validate_bundle(self.bundle)

    def test_strict_json(self):
        for text in ['{"x":1,"x":2}', '{"n":NaN}', '{"n":Infinity}', '{"n":1e9999}']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                load_json(text)

    def test_bool_is_not_number(self):
        ticket = next(c for c in self.bundle['cases'] if c['kind'] == 'tickets')
        ticket['input']['maxretry'] = True
        with self.assertRaises(ValueError):
            validate_case(ticket)
        self.assertTrue(differences({'number': 1}, {'number': True}))

    def test_missing_extra_unknown_event_and_order(self):
        mutations = [lambda x: x.update(extra=1), lambda x: x.pop('raw'),
                     lambda x: x['observations'][0].update(event='unknown'),
                     lambda x: x['observations'][0].update(sequence=1),
                     lambda x: x['observations'][0]['values'].update(extra=True),
                     lambda x: x['raw'].update(returncode=True),
                     lambda x: x['raw'].update(returncode=7),
                     lambda x: x.update(observations=[])]
        for mutate in mutations:
            bad = copy.deepcopy(self.outcome)
            mutate(bad)
            with self.assertRaises(ValueError):
                validate_outcome(bad, self.case)
            self.assertEqual(compare_case(self.case, self.outcome, bad)['decision'], 'error')

    def test_failure_statuses_never_pass(self):
        for status in ('unsupported', 'error', 'timeout'):
            outcome = dict(self.outcome, status=status, observations=[])
            self.assertEqual(compare_case(self.case, self.outcome, outcome)['decision'], status)

    def test_reference_drift_cannot_be_hidden_by_equal_candidate(self):
        self.case['expected_reference'][0]['values']['value'] = 'not-observed'
        report = compare_case(self.case, self.outcome, self.outcome)
        self.assertEqual(report['decision'], 'reference-drift')
        self.assertEqual(report['reference_mismatches'][0]['path'], '$[0].values.value')

    def test_reference_drift_visible_when_candidate_unsupported(self):
        controls = load_json((Path(__file__).parent / 'fixtures/controls-v1.json').read_text())
        case = next(x for x in controls['cases'] if x['kind'] == 'filter_time')
        reference = {'status': 'ok', 'observations': copy.deepcopy(case['expected_reference']),
                     'raw': {'stdout': '', 'stderr': '', 'returncode': 0}, 'details': {}}
        candidate = {'status': 'unsupported', 'observations': [],
                     'raw': {'stdout': '', 'stderr': '', 'returncode': None}, 'details': {}}
        self.assertEqual(compare_case(case, reference, candidate)['decision'], 'unsupported')
        reference['observations'][0]['values']['pending_retry'] += 1
        result = compare_case(case, reference, candidate)
        self.assertEqual(result['decision'], 'reference-drift')
        self.assertEqual(result['candidate_status'], 'unsupported')
        self.assertEqual(result['reference_mismatches'][0]['path'], '$[0].values.pending_retry')
        self.assertEqual(result['candidate_mismatches'], [])
        self.assertTrue(result['review_required'])
        # An unsupported reference has no oracle observations to compare.
        unsupported_reference = dict(candidate)
        self.assertEqual(compare_case(case, unsupported_reference, candidate)['decision'], 'unsupported')

    def test_ssh_log_positive_negative_contracts(self):
        for message, identity, result in [
            ('Failed password for example from 192.0.2.10 port 42420 ssh2', '192.0.2.10', 'matched'),
            ('Accepted publickey for example from 192.0.2.10 port 42420 ssh2: ED25519 SHA256:originalfixture', None, 'ignored'),
        ]:
            case = copy.deepcopy(self.case)
            case.update(kind='ssh_log', input={'line': 'Sep 10 12:00:00 fixture sshd[123]: ' + message},
                        expected_reference=[{'event': 'match', 'sequence': 0,
                                             'values': {'identity': identity, 'result': result}}])
            validate_case(case)
            outcome = {'status': 'ok', 'observations': copy.deepcopy(case['expected_reference']),
                       'raw': {'stdout': '', 'stderr': '', 'returncode': 0}, 'details': {}}
            validate_outcome(outcome, case)
            self.assertEqual(compare_case(case, outcome, outcome)['decision'], 'pass')
            for suffix in ('\n', '\x00', 'x' * 4096):
                malformed = copy.deepcopy(case)
                malformed['input']['line'] += suffix
                with self.assertRaises(ValueError):
                    validate_case(malformed)
            malformed = copy.deepcopy(outcome)
            malformed['observations'][0]['values']['result'] = 'passed'
            with self.assertRaises(ValueError):
                validate_outcome(malformed, case)

    def test_known_gap_and_unexpected_pass(self):
        self.case['issues'] = ['SYS-026']
        wrong = copy.deepcopy(self.outcome)
        wrong['observations'][0]['values']['value'] = '3'
        self.assertEqual(compare_case(self.case, self.outcome, wrong)['decision'], 'known-gap')
        self.assertEqual(compare_case(self.case, self.outcome, self.outcome)['decision'], 'unexpected-pass')

    def test_path_escape_and_duplicate_case(self):
        for name in ('../escape', '/absolute', 'dir/../escape', 'dir//name', 'dir\\name', '.', 'nul\x00file'):
            bad = copy.deepcopy(self.case)
            bad['input']['files'][name] = 'x'
            with self.assertRaises(ValueError):
                validate_case(bad)
        for case_id in ('../escape', '/absolute', 'a/b', '.', '..', 'nul\x00id', 'x' * 129):
            bad = copy.deepcopy(self.case)
            bad['id'] = case_id
            with self.assertRaises(ValueError):
                validate_case(bad)
        self.bundle['cases'].append(copy.deepcopy(self.case))
        with self.assertRaises(ValueError):
            validate_bundle(self.bundle)

    def test_future_trace_fields_are_exact(self):
        action = {'event': 'action', 'sequence': 0, 'values': {'operation': 'ban', 'jail': 'ssh',
                  'ip': '192.0.2.10', 'protocol': 'tcp', 'ports': ['22']}}
        validate_observations([action])
        for field, value in [('ip', '192.0.2.11'), ('jail', 'http'), ('protocol', 'udp'), ('ports', ['443'])]:
            altered = copy.deepcopy(action)
            altered['values'][field] = value
            self.assertEqual(differences([action], [altered])[0]['path'], '$[0].values.' + field + ('[0]' if field == 'ports' else ''))
        for event, field, left, right in [('expiry', 'absolute', 600, 601), ('history', 'ban_count', 2, 3),
                                         ('health', 'current', 'ready', 'degraded')]:
            self.assertTrue(differences({event: {field: left}}, {event: {field: right}}))

    def test_self_controls(self):
        self.assertTrue(self_tests()['passed'])


if __name__ == '__main__':
    unittest.main()
