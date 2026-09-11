# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Held-out inventory checks using temporary trees, never editing live helpers."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PATH = Path(__file__).with_name('run.py')
SPEC = importlib.util.spec_from_file_location('f2z_harness_inventory_runner', PATH)
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


class InventoryTests(unittest.TestCase):
    def test_helper_source_profile_and_attribution_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compat = root / 'engine/compat'
            compat.mkdir(parents=True)
            (compat / 'decoder.py').write_text('VALUE = 1\n')
            (compat / 'profile.json').write_text('{"version": 1}\n')
            (compat / 'COPYING.profile').write_text('Original fixture attribution.\n')
            # Interpreter cache is not a source input or execution authority.
            (compat / 'decoder.pyc').write_bytes(b'original non-code cache fixture')
            here = root / 'tests/parity/harness'
            here.mkdir(parents=True)
            with mock.patch.object(RUN, 'ROOT', root), mock.patch.object(RUN, 'HERE', here):
                first = RUN.source_hashes()
                self.assertEqual({'engine/compat/decoder.py', 'engine/compat/profile.json',
                                  'engine/compat/COPYING.profile'}, set(first))
                (compat / 'decoder.py').write_text('VALUE = 2\n')
                changed_code = RUN.source_hashes()
                self.assertNotEqual(first['engine/compat/decoder.py'], changed_code['engine/compat/decoder.py'])
                self.assertEqual(first['engine/compat/profile.json'], changed_code['engine/compat/profile.json'])
                (compat / 'profile.json').write_text('{"version": 2}\n')
                changed_profile = RUN.source_hashes()
                self.assertNotEqual(first['engine/compat/profile.json'], changed_profile['engine/compat/profile.json'])
                self.assertEqual(changed_code['engine/compat/decoder.py'], changed_profile['engine/compat/decoder.py'])


if __name__ == '__main__':
    unittest.main()
