#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
import importlib.util
from pathlib import Path
import sys
import unittest
import tempfile
from unittest.mock import patch, MagicMock

PATH=Path(__file__).resolve().parents[2]/'engine/compat/ignore_dns.py'
SPEC=importlib.util.spec_from_file_location('f2z_ignore_test',PATH)
IGNORE=importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name]=IGNORE
SPEC.loader.exec_module(IGNORE)


class IgnoreDnsTests(unittest.TestCase):
    def test_discovered_self_identities_feed_policy_without_conversion(self):
        resolver=IGNORE.Resolver(lambda kind,name,**kwargs: {'addresses':['192.0.2.4'],'name':'original.test','error':None})
        with patch.object(IGNORE.socket,'gethostname',return_value='original'):
            values,errors=IGNORE.self_identities(resolver,now=100,interfaces={IGNORE.identity('192.0.2.3')})
        self.assertEqual(errors,[])
        policy=IGNORE.IgnorePolicy(self_identities=values)
        self.assertTrue(policy.check('192.0.2.3',now=100).ignored)
        self.assertTrue(policy.check('192.0.2.4',now=100).ignored)
        self.assertFalse(policy.check('192.0.2.5',now=100).ignored)
        self.assertTrue(IGNORE.IgnorePolicy(self_identities=['192.0.2.3']).check('192.0.2.3',now=100).ignored)
        with self.assertRaises(ValueError):
            IGNORE.IgnorePolicy(self_identities=[IGNORE.Identity('ipv4','192.0.2.3',None,32)])

    def test_ignore_file_failed_read_retries_unchanged_metadata(self):
        with tempfile.TemporaryDirectory(prefix='f2z-original-ignore-recovery-') as directory:
            path=Path(directory)/'ignore.txt'
            path.write_text('192.0.2.1\n')
            source=IGNORE.FileIgnoreSet('file:'+str(path))
            old,new=IGNORE.identity('192.0.2.1'),IGNORE.identity('192.0.2.2')
            self.assertEqual(source.contains(old,100),(True,None))
            signature=source.stat
            path.write_text('192.0.2.2\n# changed configuration\n')
            failing=MagicMock()
            failing.__enter__.return_value.read.side_effect=OSError('original injected read failure')
            with patch.object(IGNORE.os,'fdopen',return_value=failing):
                self.assertEqual(source.contains(old,102),(True,'OSError'))
            self.assertEqual(source.stat,signature)
            self.assertEqual(source.contains(new,150),(False,'OSError'))
            self.assertEqual(source.contains(new,164),(True,None))
            self.assertEqual(source.contains(old,164),(False,None))

    def test_identity_scope_and_mapped_address(self):
        self.assertEqual(IGNORE.identity('::ffff:192.0.2.1'),IGNORE.identity('192.0.2.1'))
        self.assertNotEqual(IGNORE.identity('::ffff:192.0.2.1/128').kind,'ipv4')
        self.assertNotEqual(IGNORE.identity('192.0.2.1'),IGNORE.identity('192.0.2.1',raw=True))
        policy=IGNORE.IgnorePolicy(['0.0.0.0/0'],ignore_self=False)
        self.assertTrue(policy.check('192.0.2.1',now=100).ignored)
        self.assertFalse(policy.check('2001:db8::1',now=100).ignored)

    def test_cache_boundary_fifo_and_cached_false(self):
        cache=IGNORE.Cache(2,10)
        cache.set('a',False,100)
        self.assertIs(cache.get('a',109),False)
        self.assertIsNone(cache.get('a',110))
        cache.set('a',1,111)
        cache.set('b',2,112)
        cache.get('a',113)
        cache.set('c',3,114)
        self.assertIsNone(cache.get('a',114))
        self.assertEqual(cache.get('b',114),2)

    def test_dns_failure_cache_expiry_and_modes(self):
        calls=[]
        def lookup(kind,name,**kwargs):
            calls.append((kind,name))
            return {'addresses':['192.0.2.1'],'error':None} if name=='neutral.test' else {'addresses':[],'error':'unresolved'}
        resolver=IGNORE.Resolver(lookup)
        self.assertEqual(resolver.text_to_identity('neutral.test','no',100)['identities'],set())
        self.assertEqual(calls,[])
        self.assertTrue(resolver.text_to_identity('neutral.test','warn',100)['warning'])
        resolver.text_to_identity('neutral.test','yes',399)
        self.assertEqual(len(calls),1)
        resolver.text_to_identity('neutral.test','yes',400)
        self.assertEqual(len(calls),2)
        self.assertEqual(resolver.text_to_identity('neutral.test','raw',400)['identities'],{IGNORE.identity('neutral.test',raw=True)})
        self.assertEqual(resolver.text_to_identity('missing.test','yes',400)['error'],'unresolved')
        resolver.text_to_identity('missing.test','yes',401)
        self.assertEqual(len(calls),3)

    def test_ignore_precedence_command_cache_and_self(self):
        calls=[]
        def command(identity,values):
            calls.append(identity.text)
            return {'ignore':False,'error':None}
        policy=IGNORE.IgnorePolicy(['192.0.2.1','2001:db8::/32'],self_identities=['127.0.0.1'],
                                  command=command,cache_key=lambda identity,values:identity.text,cache_time=10)
        self.assertEqual(policy.check('127.0.0.1',now=100).origin,'self')
        self.assertEqual(policy.check('192.0.2.1',now=100).origin,'ip')
        self.assertEqual(policy.check('192.0.2.1',now=101).origin,'ip')
        self.assertEqual(policy.check('2001:db8::1',now=100).origin,'network')
        self.assertFalse(policy.check('192.0.2.2',now=100).ignored)
        self.assertTrue(policy.check('192.0.2.2',now=109).cache_hit)
        policy.check('192.0.2.2',now=110)
        self.assertEqual(calls,['192.0.2.2','192.0.2.2'])

    def test_original_noop_commands_and_deadline(self):
        with self.assertRaises(ValueError):
            IGNORE.bounded_command('')
        self.assertTrue(IGNORE.bounded_command('exit 0')['ignore'])
        self.assertFalse(IGNORE.bounded_command('exit 1')['ignore'])
        self.assertEqual(IGNORE.bounded_command('exit 2')['error'],'command-exit-error')
        # Original local no-op wait tests process-group deadline; no external action.
        self.assertEqual(IGNORE.bounded_command('sleep 2',timeout=0.05)['error'],'command-timeout')


if __name__=='__main__':
    unittest.main()
