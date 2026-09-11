#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import unittest

PATH = Path(__file__).resolve().parents[2] / 'engine/compat/date_time.py'
SPEC = importlib.util.spec_from_file_location('f2z_date_time_test', PATH)
DATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DATE
SPEC.loader.exec_module(DATE)


class DateTimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous_tz = os.environ.get('TZ')
        os.environ['TZ'] = 'UTC'
        time.tzset()

    @classmethod
    def tearDownClass(cls):
        if cls.previous_tz is None:
            os.environ.pop('TZ',None)
        else:
            os.environ['TZ'] = cls.previous_tz
        time.tzset()

    def test_pattern_fraction_and_authoritative_epoch_are_distinct(self):
        detector = DATE.DateDetector(['%Y-%m-%dT%H:%M:%S.%f%z'],reference_year=2026)
        result,_ = detector.process('2026-01-01T00:00:00.125+0000',now=1767225600,usage_time=100)
        self.assertEqual(result.effective,1767225600)
        self.assertEqual(result.raw_timestamp,1767225600.125)
        detector = DATE.DateDetector(['EPOCH'],reference_year=2026)
        result,_ = detector.process('1767225600.125',now=1767225600,usage_time=100)
        self.assertEqual(result.effective,1767225600.125)

    def test_context_roundtrip_and_config_binding(self):
        detector = DATE.DateDetector(reference_year=2026,default_tz='UTC')
        _,context = detector.process('Jan 01 00:00:01 neutral',now=1767225603,usage_time=100)
        restored = json.loads(json.dumps(context))
        a,ca = detector.process('[1767225602.125] neutral',now=1767225603,usage_time=101,context=context)
        b,cb = detector.process('[1767225602.125] neutral',now=1767225603,usage_time=101,context=restored)
        self.assertEqual((a,ca),(b,cb))
        other = DATE.DateDetector(reference_year=2025,default_tz='UTC')
        with self.assertRaises(ValueError):
            other.process('neutral',now=1767225603,usage_time=101,context=context)

    def test_invalid_date_is_not_current_time(self):
        detector = DATE.DateDetector(['%Y-%m-%d %H:%M:%S'],reference_year=2026,default_tz='UTC')
        result,_ = detector.process('2026-02-29 00:00:00',now=1767225603,usage_time=100)
        self.assertIsNone(result.effective)
        self.assertEqual(result.kind,'invalid')
        self.assertEqual(result.diagnostic,'invalid-calendar-time')

    def test_none_marker_is_explicit_optional_empty(self):
        detector = DATE.DateDetector(['{NONE}'],reference_year=2026)
        result,_ = detector.process('neutral',now=1767225603,usage_time=100)
        self.assertEqual(result.kind,'optional-empty')
        self.assertIsNone(result.effective)

    def test_unknown_timezone_and_input_limits(self):
        with self.assertRaises(ValueError):
            DATE.DateDetector(reference_year=2026,default_tz='Europe/Paris')
        with self.assertRaises(ValueError):
            DATE.DateDetector(['%Q'],reference_year=2026)
        detector = DATE.DateDetector(reference_year=2026)
        with self.assertRaises(ValueError):
            detector.process('x'*(2**20+1),now=1,usage_time=1)
        with self.assertRaises(ValueError):
            detector.process('neutral',now=float('inf'),usage_time=1)

    def test_context_rejects_corrupt_stats(self):
        detector = DATE.DateDetector(reference_year=2026)
        invalid=detector.empty_context()
        invalid['version']=True
        with self.assertRaises(ValueError):
            detector.process('neutral',now=1,usage_time=1,context=invalid)
        for key,value in [('used',True),('hits',-1),('match_hits',2**63),('used',float('nan')),('distance',-1)]:
            context = copy.deepcopy(detector.empty_context())
            context['stats'][0][key] = value
            with self.assertRaises(ValueError):
                detector.process('neutral',now=1,usage_time=1,context=context)


if __name__ == '__main__':
    unittest.main()
