# SPDX-License-Identifier: AGPL-3.0-or-later
"""Synthetic held-out rejection checks, separate from product evidence."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
import test_gate
from p2_config_gate import evaluate


class ConfigRegressionGateTests(unittest.TestCase):
    def setUp(self):
        seed = test_gate.GateTests()
        seed.setUp()
        self.original = seed.expected
        self.report = seed.report
        folder = Path(__file__).parent / 'fixtures'
        self.spec = json.loads((folder / 'p2-config-gate-v1.json').read_text())
        self.baseline = json.loads((folder / 'baseline-v1.json').read_text())
        self.report['bundle'] = deepcopy(self.baseline)
        for repetition in self.report['repetitions']:
            for closure in self.spec['reviewed_closures']:
                case = next(case for case in repetition['cases'] if case['id'] == closure['id'])
                for side in ('reference', 'candidate'):
                    case[side]['observations'] = deepcopy(closure['observations'])
                case['comparison'].update(decision='unexpected-pass', candidate_mismatches=[])

    def accepted(self, report):
        return evaluate(report, self.spec, self.baseline, self.original)['passed']

    def test_control_and_no_phase_certification(self):
        self.assertTrue(self.accepted(self.report))
        self.assertFalse(evaluate(self.report, self.spec, self.baseline, self.original)['G2_complete'])

    def test_changed_observation_or_original_oracle_rejected(self):
        for target in ('candidate', 'reference', 'bundle'):
            report = deepcopy(self.report)
            if target == 'bundle':
                report['bundle']['cases'][1]['expected_reference'][0]['values']['value'] = '99'
            else:
                report['repetitions'][0]['cases'][1][target]['observations'][0]['values']['value'] = '99'
            self.assertFalse(self.accepted(report), target)

    def test_unchanged_ticket_signatures_and_isolation_required(self):
        report = deepcopy(self.report)
        case = next(case for case in report['repetitions'][0]['cases'] if case['comparison']['decision'] == 'known-gap')
        case['comparison']['candidate_mismatches'][0]['actual'] = 'unreviewed difference'
        self.assertFalse(self.accepted(report))
        self.report['repetitions'][1]['isolation']['verified'] = False
        self.assertFalse(self.accepted(self.report))


if __name__ == '__main__':
    unittest.main()
