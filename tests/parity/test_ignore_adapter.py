#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch,MagicMock
import errno
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'engine/compat'))
import ignore_adapter as adapter


class IgnoreAdapterTests(unittest.TestCase):
    def test_shared_dns_two_jails_and_discarded_stage(self):
        calls=[]
        def lookup(kind,name,**kwargs):
            calls.append(name);return {'addresses':['192.0.2.1'],'error':None}
        first=adapter.Adapter({'ignoreself':False,'allowipv6':'no','usedns':'yes','ignoreip':['192.0.2.1']},'profile',lookup=lookup)
        second=adapter.Adapter({'ignoreself':False,'allowipv6':'no','usedns':'yes'},'profile',lookup=lookup)
        shared=first.empty_shared_snapshot();saved=copy.deepcopy(shared)
        staged=first.stage('neutral.test',now=100,shared_snapshot=shared)
        self.assertEqual(shared,saved)
        self.assertNotIn('forward',staged['snapshot'])
        self.assertTrue(staged['decisions'][0]['ignored'])
        discarded=second.stage('neutral.test',now=101,shared_snapshot=shared)
        self.assertEqual(len(calls),2) # Discarded proposal did not publish DNS.
        accepted=second.stage('neutral.test',now=101,shared_snapshot=staged['shared_snapshot'])
        self.assertEqual(len(calls),2)
        self.assertFalse(accepted['decisions'][0]['ignored'])
        self.assertNotEqual(staged['snapshot']['binding'],accepted['snapshot']['binding'])
        for changed in [dict(shared,version=True),dict(shared,binding='other')]:
            with self.assertRaises(ValueError):second.stage('neutral.test',now=101,shared_snapshot=changed)
        incompatible=adapter.Adapter({'ignoreself':False,'allowipv6':'yes'},'profile',lookup=lookup)
        with self.assertRaises(ValueError):incompatible.stage('neutral.test',now=101,shared_snapshot=staged['shared_snapshot'])
        with self.assertRaises(ValueError):second.stage('neutral.test',now=101,snapshot=staged['snapshot'],shared_snapshot=staged['shared_snapshot'])

    def test_local_ipv6_capability_fallback_uses_reference_error_policy(self):
        for error,expected in [(None,True),(errno.EAFNOSUPPORT,False),(errno.EACCES,True),(errno.EIO,None)]:
            probe=MagicMock()
            if error is not None:probe.bind.side_effect=OSError(error,'original capability observation')
            with patch.object(adapter.socket,'has_ipv6',True),patch('builtins.open',side_effect=OSError('original unavailable proc setting')),patch.object(adapter.socket,'socket',return_value=probe):
                self.assertIs(adapter.system_ipv6_support(),expected)
            probe.close.assert_called_once()

    def test_command_admission_cache_restore_and_discarded_stage(self):
        config={'ignoreip':[],'ignoreself':False,'allowipv6':'no','usedns':'no','ignorecache':{'key':'<ip>-<F-USER>','max-count':'2','max-time':'10s'},'ignorecommand':'original-helper <ip> <F-USER>'}
        calls=[]
        def command(descriptor,**kwargs):
            calls.append(descriptor);return {'ignore':False,'error':None}
        with self.assertRaises(ValueError):adapter.Adapter(config,'profile')
        policy=adapter.Adapter(config,'profile',trusted_command=adapter.TrustedCommand(config['ignorecommand'],'profile'),command_runner=command)
        original=policy.empty_snapshot();before=copy.deepcopy(original)
        ticket={'id':'192.0.2.1','data':{'user':'neutral'}}
        first=policy.stage('192.0.2.1',now=100,snapshot=original,ticket=ticket)
        self.assertEqual(original,before)
        second=policy.stage('192.0.2.1',now=109,snapshot=first['snapshot'],shared_snapshot=first['shared_snapshot'],ticket=ticket)
        self.assertTrue(second['decisions'][0]['cache_hit']);self.assertEqual(len(calls),1)
        policy.stage('192.0.2.1',now=110,snapshot=second['snapshot'],shared_snapshot=second['shared_snapshot'],ticket=ticket)
        self.assertEqual(len(calls),2)
        # Discarding the proposed state leaves the original cache empty.
        policy.stage('192.0.2.1',now=109,snapshot=original,ticket=ticket)
        self.assertEqual(len(calls),3)

    def test_resolution_fanout_policy_and_snapshot_boundaries(self):
        calls=[]
        def lookup(kind,name,**kwargs):
            calls.append((kind,name,kwargs['ipv6']))
            return {'addresses':['192.0.2.1']+(['2001:db8::1'] if kwargs['ipv6'] else []),'error':None}
        policy=adapter.Adapter({'ignoreself':False,'allowipv6':'yes','ignoreip':['192.0.2.1']},'profile',lookup=lookup)
        first=policy.stage('neutral.test',now=100)
        self.assertEqual([r['ignored'] for r in first['decisions']],[True,False])
        self.assertTrue(first['dns_warning'])
        resumed=adapter.Adapter(policy.config,'profile',lookup=lookup)
        resumed.stage('neutral.test',now=101,snapshot=first['snapshot'],shared_snapshot=first['shared_snapshot']);self.assertEqual(len(calls),1)
        for altered in [dict(first['snapshot'],version=True),dict(first['snapshot'],binding='wrong')]:
            with self.assertRaises(ValueError):resumed.stage('neutral.test',now=101,snapshot=altered)
        policy.config['ignoreip'].append('2001:db8::/32')
        with self.assertRaises(ValueError):policy.stage('neutral.test',now=101,snapshot=first['snapshot'],shared_snapshot=first['shared_snapshot'])

    def test_file_state_and_self_discovery_compose(self):
        with tempfile.TemporaryDirectory(prefix='f2z-original-adapter-') as directory:
            path=Path(directory)/'ignore';path.write_text('192.0.2.9\n')
            def lookup(kind,name,**kwargs):return {'addresses':[],'error':None} if kind=='forward' else {'name':'original.test','error':None}
            policy=adapter.Adapter({'ignoreip':['file:'+str(path)],'allowipv6':'no'},'profile',lookup=lookup,interfaces=lambda:{'192.0.2.8'})
            with patch.object(adapter.policy.socket,'gethostname',return_value='original'):
                first=policy.stage('192.0.2.8',now=100)
                self.assertEqual(first['decisions'][0]['origin'],'self')
                second=policy.stage('192.0.2.9',now=100,snapshot=first['snapshot'],shared_snapshot=first['shared_snapshot'])
                self.assertEqual(second['decisions'][0]['origin'],'file')
                path.write_text('192.0.2.10\n')
                third=policy.stage('192.0.2.10',now=102,snapshot=second['snapshot'],shared_snapshot=second['shared_snapshot'])
                self.assertTrue(third['decisions'][0]['ignored'])

    def test_ipv6_auto_cache_and_nonfinite_proposed_expiry(self):
        probes=[]
        def support():probes.append(1);return None
        policy=adapter.Adapter({'ignoreself':False,'allowipv6':'auto','usedns':'yes'},'profile',ipv6_probe=support,interfaces=lambda:{'2001:db8::1'},lookup=lambda *args,**kwargs:{'addresses':['192.0.2.1'],'error':None})
        first=policy.stage('neutral.test',now=100)
        self.assertTrue(next(entry[1] for entry in first['shared_snapshot']['forward'] if entry[0]=={'marker':'ipv6'}))
        policy.stage('neutral.test',now=399,snapshot=first['snapshot'],shared_snapshot=first['shared_snapshot']);self.assertEqual(len(probes),1)
        policy.stage('neutral.test',now=400,snapshot=first['snapshot'],shared_snapshot=first['shared_snapshot']);self.assertEqual(len(probes),2)
        huge=adapter.Adapter({'ignoreself':False,'allowipv6':'no','ignorecache':{'key':'<ip>','max-time':1e308}},'profile')
        original=huge.empty_snapshot();before=copy.deepcopy(original)
        with self.assertRaises(ValueError):huge.stage('192.0.2.1',now=1e308,snapshot=original)
        self.assertEqual(original,before)

    def test_external_budget_and_rejected_input_do_not_publish(self):
        policy=adapter.Adapter({'ignoreself':False,'allowipv6':'auto'},'profile',max_external_calls=1,ipv6_probe=lambda:None,interfaces=lambda:set())
        saved=policy.empty_snapshot()
        with self.assertRaises(ValueError):policy.stage('neutral.test',now=100,snapshot=saved)
        self.assertEqual(saved,policy.empty_snapshot())
        policy.deadline=10
        with self.assertRaises(ValueError):policy.stage('192.0.2.1',now=100,snapshot=saved)
        invalid=adapter.Adapter({'usedns':'INVALID','ignoreself':False,'allowipv6':'no'},'profile')
        self.assertIn('invalid-usedns-mode',invalid.stage('192.0.2.1',now=100)['diagnostics'])
        self.assertEqual(invalid.stage('neutral.test',now=100)['decisions'],[])

    def test_cache_hit_precedes_expired_self_discovery(self):
        calls=[]
        def interfaces():calls.append('interfaces');return {'192.0.2.8'}
        def lookup(kind,*args,**kwargs):calls.append('dns');return {'addresses':[],'error':None} if kind=='forward' else {'name':'original.test','error':None}
        policy=adapter.Adapter({'ignorecache':'key=<ip>,max-time=1000','allowipv6':'auto'},'profile',interfaces=interfaces,lookup=lookup,ipv6_probe=lambda:True)
        with patch.object(adapter.policy.socket,'gethostname',return_value='original'):
            first=policy.stage('192.0.2.8',now=100)
            count=len(calls)
            second=policy.stage('192.0.2.8',now=401,snapshot=first['snapshot'],shared_snapshot=first['shared_snapshot'])
        self.assertTrue(second['decisions'][0]['cache_hit'])
        self.assertEqual(len(calls),count)

    def test_parameter_parser_and_explicit_null_reader(self):
        self.assertEqual(adapter.parse_ignorecache('key="<ip>,<F-USER>"][max-count=2,max-time=1h'),{'key':'<ip>,<F-USER>','max-count':'2','max-time':'1h'})
        self.assertEqual(adapter.parse_ignorecache('key=a,key=b,'),{'key':'b'})
        self.assertEqual(adapter.parse_ignorecache('key="unterminated'),{'key':'"unterminated'})
        for text in ('key =x','broken','key=x]junk'):
            with self.assertRaises(ValueError):adapter.parse_ignorecache(text)
        absent={'reader':None,'error_name':None,'derived_filter_asset':None}
        plan={'schema_version':1,'admission':'prepared-only','jail':'original','diagnostics':[],**{name:copy.deepcopy(absent) for name in ('ignoreip','ignoreself','usedns','ignorecache','ignorecommand')},'allowipv6':{'option':copy.deepcopy(absent),'policy':'automatic','adapter_value':'auto'}}
        self.assertEqual(adapter.from_plan(plan),{'allowipv6':'auto'})
        plan['ignoreself']['reader']={'presence':'explicit','resolution':'reference_fallback','value_type':'boolean','raw':'invalid','value':{'null_value':{}},'origin':None,'default_identity':'reader-default'}
        self.assertEqual(adapter.from_plan(plan),{'allowipv6':'auto','ignoreself':False})


if __name__=='__main__':unittest.main()
