# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Synthetic gate aggregation controls; never actual product execution evidence."""
from copy import deepcopy
from pathlib import Path
import unittest

from contract import load_json
from gate import evaluate_gate


class GateTests(unittest.TestCase):
    def setUp(self):
        self.expected = load_json((Path(__file__).parent / 'fixtures/gate-v1.json').read_text())
        cases = []
        for wanted in self.expected['cases']:
            cases.append({
                'id': wanted['id'], 'split': wanted['split'], 'issues': wanted['issues'],
                'reference': {'status': 'ok'}, 'candidate': {'status': 'ok'},
                'comparison': {
                    'decision': 'known-gap' if wanted['candidate_mismatches'] else 'pass',
                    'reference_mismatches': [],
                    'candidate_mismatches': deepcopy(wanted['candidate_mismatches']),
                },
            })
        repetition = {'cases': cases, 'self_tests': {'passed': True},
                      'driver_controls': {'passed': True}, 'isolation': {'verified': True},
                      'real_logs_bundle_sha256': self.expected['real_logs_bundle_sha256'],
                      'real_logs_provenance_sha256': self.expected['real_logs_provenance_sha256'],
                      'real_log_cases': [{'id': identity, 'comparison': {'decision': 'pass'}}
                                         for identity in self.expected['real_log_case_ids']]}
        self.report = {
            'bundle_sha256': self.expected['baseline_bundle_sha256'],
            'reproducible': True, 'repetitions': [deepcopy(repetition), deepcopy(repetition)],
            'specification_inventory': {'status': 'validated', 'execution': 'not-run', 'certified': False},
        }

    def assert_rejected(self, report=None):
        result = evaluate_gate(self.report if report is None else report, self.expected)
        self.assertFalse(result['passed'])
        self.assertTrue(any(not check['passed'] for check in result['checks']))

    def test_exact_synthetic_control(self):
        self.assertTrue(evaluate_gate(self.report, self.expected)['passed'])

    def test_missing_equal_or_held_out_cases_rejected(self):
        for wanted in self.expected['cases']:
            if wanted['candidate_mismatches']:
                continue
            with self.subTest(case=wanted['id']):
                report = deepcopy(self.report)
                report['repetitions'][0]['cases'] = [case for case in report['repetitions'][0]['cases']
                                                     if case['id'] != wanted['id']]
                self.assert_rejected(report)

    def test_changed_known_difference_is_not_inherited(self):
        cases = self.report['repetitions'][0]['cases']
        case = next(case for case in cases if case['comparison']['candidate_mismatches'])
        case['comparison']['candidate_mismatches'][0]['actual'] = 'different regression'
        self.assert_rejected()

    def test_wrong_bundle_rejected(self):
        self.report['bundle_sha256'] = '0' * 64
        self.assert_rejected()

    def test_bad_isolation_or_controls_rejected(self):
        for key, field in (('isolation', 'verified'), ('self_tests', 'passed'), ('driver_controls', 'passed')):
            report = deepcopy(self.report)
            report['repetitions'][1][key][field] = False
            with self.subTest(control=key):
                self.assert_rejected(report)

    def test_nonrepeatability_and_missing_repetition_rejected(self):
        report = deepcopy(self.report)
        report['reproducible'] = False
        self.assert_rejected(report)
        self.report['repetitions'].pop()
        self.assert_rejected()

    def test_changed_split_issue_order_or_worker_status_rejected(self):
        for mutate in (
            lambda cases: cases[0].update(split='held-out'),
            lambda cases: cases[0].update(issues=['unreviewed']),
            lambda cases: cases.reverse(),
            lambda cases: cases[0]['reference'].update(status='error'),
            lambda cases: cases[0]['candidate'].update(status='unsupported'),
        ):
            report = deepcopy(self.report)
            mutate(report['repetitions'][0]['cases'])
            self.assert_rejected(report)

    def test_reference_drift_is_not_known_gap(self):
        self.report['repetitions'][0]['cases'][0]['comparison']['reference_mismatches'] = [
            {'path': '$[0].values.value', 'expected': '2', 'actual': '99', 'reason': 'value'}]
        self.assert_rejected()

    def test_missing_or_falsely_certified_inventory_rejected(self):
        for inventory in ({}, {'status': 'validated', 'execution': 'not-run', 'certified': True},
                          {'status': 'validated', 'execution': 'passed', 'certified': False}):
            report = deepcopy(self.report)
            report['specification_inventory'] = inventory
            self.assert_rejected(report)

    def test_missing_changed_or_failed_real_log_cases_rejected(self):
        for mutate in (
            lambda repetition: repetition['real_log_cases'].pop(),
            lambda repetition: repetition.update(real_logs_bundle_sha256='0' * 64),
            lambda repetition: repetition.update(real_logs_provenance_sha256='0' * 64),
            lambda repetition: repetition['real_log_cases'][0]['comparison'].update(decision='mismatch'),
            lambda repetition: repetition['real_log_cases'][0]['comparison'].update(decision='unsupported'),
        ):
            report = deepcopy(self.report)
            mutate(report['repetitions'][0])
            self.assert_rejected(report)


if __name__ == '__main__':
    unittest.main()
