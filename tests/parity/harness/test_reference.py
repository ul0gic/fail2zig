#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Reference runner boundary controls; no upstream checkout needed."""

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import reference


class ReferenceRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.context = {'work': self.work, 'reference': self.work}
        self.case = {'kind': 'config', 'input': {'files': {'jail.conf': '[probe]\nx = y\n'},
                                                'section': 'probe', 'option': 'x'}}

    def execute(self, script, **options):
        return reference._execute([sys.executable, '-I', '-B', '-c', script], cwd=self.work,
                                  payload=b'{}', timeout=options.get('timeout', 2),
                                  output_limit=options.get('output_limit', 4096))

    def test_output_is_bounded_before_decode(self):
        code, out, err, reason = self.execute("print('x' * 8192)", output_limit=128)
        self.assertEqual(len(out.encode()) + len(err.encode()), 128)
        self.assertEqual(reason, 'output limit exceeded')

    def test_deadline_terminates_worker(self):
        code, out, err, reason = self.execute('import time; time.sleep(2)', timeout=0.05)
        self.assertEqual(reason, 'deadline exceeded')
        self.assertLess(code, 0)

    def test_failure_preserves_both_streams(self):
        code, out, err, reason = self.execute(
            "import sys; print('record'); print('problem', file=sys.stderr); sys.exit(7)")
        self.assertEqual((code, out, err, reason), (7, 'record\n', 'problem\n', None))

    def test_environment_does_not_inherit_credentials(self):
        with patch.dict('os.environ', {'PARITY_SYNTHETIC_SECRET': 'must-not-inherit'}):
            code, out, err, reason = self.execute(
                "import os; print(os.environ.get('PARITY_SYNTHETIC_SECRET', 'absent'))")
        self.assertEqual((code, out, err, reason), (0, 'absent\n', '', None))

    def test_unknown_adapter_is_explicitly_unsupported(self):
        result = reference.run_case({'kind': 'unimplemented'}, self.context)
        self.assertEqual(result['status'], 'unsupported')
        self.assertEqual(set(result), {'status', 'observations', 'raw', 'details'})

    def test_invalid_fixture_never_starts_worker(self):
        self.case['input']['files'] = {'../outside.conf': 'ordinary fixture'}
        with patch.object(reference, '_execute') as execute:
            result = reference.run_case(self.case, self.context)
        self.assertEqual(result['status'], 'error')
        execute.assert_not_called()

    def test_nonfinite_clock_never_starts_worker(self):
        case = {'kind': 'tickets', 'input': {'now': float('inf'), 'findtime': 60,
                                             'maxretry': 3, 'events': [1]}}
        with patch.object(reference, '_execute') as execute:
            self.assertEqual(reference.run_case(case, self.context)['status'], 'error')
        execute.assert_not_called()

    def test_ssh_adapter_accepts_only_one_line_without_pattern_options(self):
        for data in ({'line': 'first\nsecond'}, {'line': 'x' * 4097},
                     {'line': 'ordinary record', 'regex': 'not accepted'}):
            with patch.object(reference, '_execute') as execute:
                self.assertEqual(reference.run_case({'kind': 'ssh_log', 'input': data},
                                                    self.context)['status'], 'error')
            execute.assert_not_called()

    def test_malformed_worker_preserves_raw_output(self):
        with patch.object(reference, '_execute', return_value=(0, 'not-json\n', 'detail', None)):
            result = reference.run_case(self.case, self.context)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['raw'], {'stdout': 'not-json\n', 'stderr': 'detail', 'returncode': 0})

    def test_wrong_observation_envelope_is_rejected(self):
        response = '{"observations":[{"event":"config","sequence":true,"values":{}}],"source_dependencies":[]}'
        with patch.object(reference, '_execute', return_value=(0, response, '', None)):
            self.assertEqual(reference.run_case(self.case, self.context)['status'], 'error')


if __name__ == '__main__':
    unittest.main()
