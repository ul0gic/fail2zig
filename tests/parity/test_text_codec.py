#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
import importlib.util
from pathlib import Path
import sys
import unittest

PATH = Path(__file__).resolve().parents[2] / 'engine/compat/text_codec.py'
SPEC = importlib.util.spec_from_file_location('f2z_text_codec', PATH)
CODEC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CODEC
SPEC.loader.exec_module(CODEC)


class TextCodecTests(unittest.TestCase):
    def test_authoritative_framed_text_warning_context(self):
        decoder=CODEC.TextDecoder('unicode_escape',max_bytes=32,warning_ttl=10)
        self.assertEqual(decoder.accept_framed('a','first',None,100).text,'first')
        self.assertTrue(decoder.accept_framed('a','bad �','invalid-byte-sequence',100).warning_due)
        saved=decoder.export_context()
        resumed=CODEC.TextDecoder('unicode_escape',max_bytes=32,warning_ttl=10)
        resumed.restore_context(saved)
        self.assertFalse(resumed.accept_framed('a','bad �','invalid-byte-sequence',109).warning_due)
        self.assertTrue(resumed.accept_framed('a','bad �','invalid-byte-sequence',110).warning_due)
        before=resumed.export_context()
        for text,diagnostic,now in [('x'*33,None,111),('bad','unknown',111),('bad',None,True)]:
            with self.assertRaises(ValueError):
                resumed.accept_framed('a',text,diagnostic,now)
            self.assertEqual(resumed.export_context(),before)

    def test_auto_uses_explicit_profile_and_locale_fallback(self):
        self.assertEqual(CODEC.TextDecoder('AuTo',preferred_encoding='latin1').decode('a',b'\xe9',100).text,'é')
        with self.assertRaises(ValueError):
            CODEC.TextDecoder('auto')
        for stdout,environment,expected in [('utf-8',{'LANG':'C'},'utf-8'),
                (None,{},'UTF-8'),(None,{'LANG':'C'},'ANSI_X3.4-1968'),
                ('ANSI_X3.4-1968',{},'UTF-8')]:
            self.assertEqual(CODEC.preferred_encoding('ANSI_X3.4-1968',stdout,environment),expected)

    def test_utf8_replacement_warning_expiry_and_source_bound(self):
        decoder = CODEC.TextDecoder('utf-8', max_warning_sources=2, warning_ttl=10)
        result = decoder.decode('a', b'neutral \xff text', 100)
        self.assertEqual(result.text, 'neutral \ufffd text')
        self.assertTrue(result.warning_due)
        self.assertFalse(decoder.decode('a', b'\xff', 109).warning_due)
        self.assertTrue(decoder.decode('a', b'\xff', 110).warning_due)
        decoder.decode('b', b'\xff', 111)
        decoder.decode('c', b'\xff', 112)
        self.assertEqual(len(decoder._warnings), 2)
        self.assertTrue(decoder.decode('a', b'\xff', 113).warning_due)

    def test_terminal_utf16_newline_is_not_replacement_warning(self):
        decoder = CODEC.TextDecoder('utf-16-le')
        result = decoder.decode('a', 'neutral'.encode('utf-16-le') + b'\n', 100)
        self.assertEqual(result.text, 'neutral')
        self.assertEqual(result.disposition, 'terminal-newline-truncated')
        self.assertFalse(result.warning_due)

    def test_config_and_record_limits(self):
        for encoding in ('nonexistent-codec', 'base64_codec'):
            with self.assertRaises((ValueError, LookupError)):
                CODEC.TextDecoder(encoding)
        decoder = CODEC.TextDecoder('utf8', max_bytes=3)
        with self.assertRaises(ValueError):
            decoder.decode('a', b'1234', 100)
        with self.assertRaises(ValueError):
            decoder.decode('a', b'a', float('nan'))

    def test_saved_warning_context_and_wrong_config_rejection(self):
        decoder = CODEC.TextDecoder('utf8')
        decoder.decode('source',b'\xff',100)
        saved = decoder.export_context()
        resumed = CODEC.TextDecoder('utf8')
        resumed.restore_context(saved)
        self.assertFalse(resumed.decode('source',b'\xff',101).warning_due)
        with self.assertRaises(ValueError):
            CODEC.TextDecoder('latin1').restore_context(saved)
        for field,value in [('version',True),('max_bytes',float(saved['max_bytes']))]:
            invalid=dict(saved,**{field:value})
            with self.assertRaises(ValueError):
                resumed.restore_context(invalid)
        saved['warnings'].append(['source',101])
        with self.assertRaises(ValueError):
            resumed.restore_context(saved)

    def test_multibyte_and_legacy_codecs(self):
        for encoding in ('utf8', 'utf16', 'utf-16-le', 'utf-16-be', 'utf32', 'latin1', 'cp1252', 'shift_jis'):
            decoder = CODEC.TextDecoder(encoding)
            text = 'neutral 123'
            result = decoder.decode('a', text.encode(encoding), 100)
            self.assertEqual(result.text, text)
            self.assertEqual(result.disposition, 'decoded')


if __name__ == '__main__':
    unittest.main()
