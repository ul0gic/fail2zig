#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
import importlib.util
from pathlib import Path
import sys
import unittest

PATH=Path(__file__).resolve().parents[2]/'engine/compat/record_framer.py'
SPEC=importlib.util.spec_from_file_location('f2z_record_framer_test',PATH)
FRAMER=importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name]=FRAMER
SPEC.loader.exec_module(FRAMER)


class RecordFramerTests(unittest.TestCase):
    def test_encoded_newline_and_observed_eof(self):
        for codec,data in [('unicode_escape',b'neutral\\n'),('raw_unicode_escape',b'neutral\\u000a'),('utf-7',b'neutral+AAo-')]:
            result=FRAMER.frame(data,codec,eof=False)
            self.assertEqual(result.disposition,'incomplete')
            result=FRAMER.frame(data,codec,eof=True)
            self.assertEqual((result.disposition,result.consumed,result.text),('complete',len(data),'neutral'))

    def test_complete_literal_line_and_terminal_cr(self):
        self.assertEqual(FRAMER.frame(b'first\nsecond\n','utf8',eof=False).consumed,6)
        self.assertEqual(FRAMER.frame(b'neutral\r','utf8',eof=True).text,'neutral')
        self.assertEqual(FRAMER.frame(b'neutral\r','utf8',eof=False).disposition,'incomplete')
        self.assertEqual(FRAMER.frame(b'partial','utf8',eof=True).disposition,'incomplete')

    def test_multibyte_alignment_preserves_following_record(self):
        for codec,width in [('utf-16-le',2),('utf-16-be',2),('utf-32-le',4),('utf-32-be',4)]:
            data='Ċ\r\nb\npartial'.encode(codec)
            first=FRAMER.frame(data,codec,eof=True)
            self.assertEqual((first.text,first.consumed),('Ċ',3*width))
            second=FRAMER.frame(data[first.consumed:],codec,eof=True)
            self.assertEqual((second.text,second.consumed),('b',2*width))

    def test_second_chunk_decoded_newline_maps_original_bytes(self):
        data=b'a\\nb\\\nc'
        result=FRAMER.frame(data,'unicode_escape',eof=True)
        self.assertEqual((result.text,result.consumed),('a',3))

    def test_budget_and_type_rejection(self):
        with self.assertRaises(ValueError):
            FRAMER.frame(b'a','utf8',eof=1)
        with self.assertRaises(ValueError):
            FRAMER.frame(b'a','base64_codec',eof=True)
        self.assertEqual(FRAMER.frame(b'1234','utf8',eof=True,max_bytes=3).disposition,'resource_limit')


if __name__=='__main__':
    unittest.main()
