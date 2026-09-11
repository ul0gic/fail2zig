#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
import importlib.util
from pathlib import Path
import sys
import unittest

PATH = Path(__file__).resolve().parents[2] / 'engine/compat/duration.py'
SPEC = importlib.util.spec_from_file_location('f2z_duration_test',PATH)
DURATION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DURATION
SPEC.loader.exec_module(DURATION)


class DurationTests(unittest.TestCase):
    def test_exact_integers_and_arithmetic(self):
        self.assertEqual(DURATION.expression('9007199254740993'),9007199254740993)
        self.assertEqual(DURATION.expression('1year-6mo'),15778800.0)
        self.assertEqual(DURATION.expression('1e+3'),1000.0)
        self.assertEqual(DURATION.expression('0xff'),255)
        self.assertEqual(DURATION.expression('1_000'),1000)
        self.assertEqual(DURATION.expression('2h**2'),25920000)

    def test_reference_preprocessing_diagnostics(self):
        for text in ('1e3','0x10','0b10'):
            with self.assertRaises(SyntaxError):
                DURATION.expression(text)

    def test_only_bounded_numeric_syntax(self):
        for text in ('abs(-1)','[1][0]','True','2**1000000','1 << 1000000','1e+999'):
            with self.assertRaises(ValueError):
                DURATION.expression(text)
        with self.assertRaises(ZeroDivisionError):
            DURATION.expression('1/0')

    def test_explicit_sentinel_tags(self):
        self.assertEqual(DURATION.parse('-1').kind,'permanent')
        self.assertEqual(DURATION.parse('-2',history=True).kind,'legacy_unknown')
        with self.assertRaises(ValueError):
            DURATION.parse('-2')


if __name__ == '__main__':
    unittest.main()
