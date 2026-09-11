#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
import importlib.util
from pathlib import Path
import sys
import unittest

PATH=Path(__file__).resolve().parents[2]/'engine/compat/action_info.py'
SPEC=importlib.util.spec_from_file_location('f2z_action_info_test',PATH)
INFO=importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name]=INFO
SPEC.loader.exec_module(INFO)


class ActionInfoTests(unittest.TestCase):
    def info(self):
        return INFO.ActionInfo(dict(id='192.0.2.1',attempts=3,time=1000.125,ban_count=2,
                                    matches=['neutral first','neutral second'],data={'user':"O'Brien"}),
                               jail={'ban_time':60,'name':'neutral'})

    def test_lazy_fields_and_fractional_time(self):
        info=self.info()
        self.assertEqual(info['family'],'inet4')
        self.assertEqual(info['ip-rev'],'1.2.0.192.')
        self.assertEqual(info['time'],1000.125)
        self.assertEqual(info['bantime'],60)
        self.assertEqual(info['jail.name'],'neutral')
        self.assertEqual(info['ipfailures'],3)
        self.assertNotIn('ip-host',info.memo)

    def test_dynamic_values_are_separate_positional_arguments(self):
        expanded=INFO.expand_dynamic('record "<F-USER>" "<matches>"',self.info())
        self.assertEqual(expanded[1:], ['neutral first\nneutral second',"O'Brien"])
        self.assertIn('$f2bV_F_user',expanded[0])
        self.assertNotIn("O'Brien",expanded[0])
        self.assertNotIn('neutral first',expanded[0])

    def test_scalar_cache_key_and_explicit_invalid_shape(self):
        self.assertEqual(INFO.cache_key('<ip>:<jail.name>',self.info()),'192.0.2.1:neutral')
        with self.assertRaises(ValueError):
            INFO.cache_key('<F-USER>',self.info())

    def test_missing_capture_and_unknown_standard_tag(self):
        self.assertEqual(INFO.expand_dynamic('<F-MISSING>|<unknown>|<sp>|<br>',self.info()),'|<unknown>| |\n')


if __name__=='__main__':
    unittest.main()
