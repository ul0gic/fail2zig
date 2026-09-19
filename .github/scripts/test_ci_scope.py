"""Regressions for selective checks and fail-closed aggregation."""
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import ci_scope as ci


class ScopeTests(unittest.TestCase):
    def test_allowlist(self):
        for path in ['README.md', 'docs/architecture.md', '.github/ISSUE_TEMPLATE/feature_request.yml', '.github/PULL_REQUEST_TEMPLATE.md']:
            with self.subTest(path=path):
                self.assertEqual(ci.route([path]), 'light')
        for path in ['engine/main.zig', 'vendor/sqlite/sqlite3.c', 'build.zig', 'build.zig.zon', 'tests/example.md', 'docs/man/fail2zig.1', 'docs/example.sh', '.github/workflows/ci.yml', '.github/scripts/ci_scope.py', '.github/dependabot.yml', '.yamllint', 'unknown.md', 'docs/../engine/main.zig', '/README.md']:
            with self.subTest(path=path):
                self.assertEqual(ci.route(['README.md', path]), 'full')
        self.assertEqual(ci.route([]), 'full')
        self.assertEqual(ci.route(None), 'full')

    def test_unavailable_history(self):
        self.assertIsNone(ci.changed_paths({'before': '0' * 40, 'after': 'a' * 40}))
        with patch.object(ci, 'git', side_effect=subprocess.CalledProcessError(1, 'git')):
            self.assertIsNone(ci.changed_paths({'before': 'a' * 40, 'after': 'b' * 40}))

    def test_git_diff_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], stderr=subprocess.DEVNULL).decode().strip()
            git('init')
            git('config', 'user.email', 'ci@example.invalid')
            git('config', 'user.name', 'CI test')
            root = Path(directory)
            (root / 'README.md').write_text('first\n')
            (root / 'engine').mkdir()
            (root / 'engine/a.zig').write_text('source\n')
            git('add', '.')
            git('commit', '-m', 'base')
            base = git('rev-parse', 'HEAD')
            git('checkout', '-b', 'feature')
            (root / 'README.md').write_text('second\n')
            git('commit', '-am', 'docs')
            head = git('rev-parse', 'HEAD')
            real_git = ci.git
            with patch.object(ci, 'git', side_effect=lambda *args: real_git('-C', directory, *args)):
                self.assertEqual(ci.route(ci.changed_paths({'before': base, 'after': head})), 'light')
                git('checkout', '-b', 'base-advance', base)
                (root / 'engine/a.zig').write_text('unrelated base edit\n')
                git('commit', '-am', 'base moved')
                advanced = git('rev-parse', 'HEAD')
                self.assertEqual(ci.route(ci.changed_paths({'pull_request': {'base': {'sha': advanced}, 'head': {'sha': head}}})), 'light')
                git('checkout', 'feature')
                git('mv', 'engine/a.zig', 'renamed.md')
                (root / 'docs').mkdir()
                (root / 'docs/odd\nname.md').write_text('doc\n')
                git('add', '.')
                git('commit', '-m', 'rename')
                paths = ci.changed_paths({'before': head, 'after': git('rev-parse', 'HEAD')})
                self.assertIn('engine/a.zig', paths)
                self.assertIn('docs/odd\nname.md', paths)
                self.assertEqual(ci.route(paths), 'full')

    def test_gate_failure_matrix(self):
        for mode in ['light', 'full']:
            needs = {name: {'result': 'skipped' if mode == 'light' and name in ci.FULL_JOBS else 'success'} for name in ci.FULL_JOBS | {'scope', 'community'}}
            needs['scope']['outputs'] = {'route': mode}
            self.assertTrue(ci.gate(needs))
            for name in needs:
                for result in ['failure', 'cancelled', 'skipped']:
                    if result == needs[name]['result']:
                        continue
                    bad = copy.deepcopy(needs)
                    bad[name]['result'] = result
                    self.assertFalse(ci.gate(bad), (mode, name, result))
            bad = copy.deepcopy(needs)
            del bad['test']
            self.assertFalse(ci.gate(bad))
            needs['scope']['outputs']['route'] = 'unknown'
            self.assertFalse(ci.gate(needs))


if __name__ == '__main__':
    unittest.main()
