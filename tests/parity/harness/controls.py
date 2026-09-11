# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original harness drivers and their controls, explicitly not product evidence."""
import json
from pathlib import Path
import random
import socket
import subprocess
import sys


class Clock:
    def __init__(self, now):
        self.now = now

    def advance(self, duration):
        if duration < 0:
            raise ValueError('clock advance must not be negative')
        self.now += duration
        return self.now


class DNS:
    """Injected resolver: explicit fixture answers, never fallback to real DNS."""
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def resolve(self, name):
        self.calls.append(name)
        if name not in self.answers:
            raise LookupError('unconfigured fixture DNS name')
        return list(self.answers[name])


class ActionRecorder:
    """Records typed desired effects without executing command/provider payloads."""
    def __init__(self):
        self.events = []

    def record(self, *, jail, ip, protocol, ports, expiry):
        self.events.append({'jail': jail, 'ip': ip, 'protocol': protocol,
                            'ports': [str(port) for port in ports], 'expiry': expiry})
        return {'status': 'recorded', 'effect_observed': False}


# Tiny original fixture service. Each invocation is a fresh process; durable offsets
# belong to this harness control, not either product's recovery implementation.
SERVICE = r'''
import json, os, pathlib, sys
root=pathlib.Path(sys.argv[1]); log=root/'events.log'; state=root/'cursor.json'
previous=json.loads(state.read_text()) if state.exists() else None
stat=log.stat(); identity=[stat.st_dev,stat.st_ino]
offset=previous['offset'] if previous and previous['identity']==identity and previous['offset']<=stat.st_size else 0
with log.open('rb') as stream:
 stream.seek(offset); data=stream.read(8193); position=stream.tell()
if len(data)>8192: raise RuntimeError('fixture too large')
cursor={'identity':identity,'offset':position}
temporary=state.with_suffix('.tmp'); temporary.write_text(json.dumps(cursor)); os.replace(temporary,state)
print(json.dumps({'records':data.decode().splitlines(),'cursor':cursor,'pid':os.getpid()}))
'''


def service(root):
    from reference import _execute
    code, stdout, stderr, reason = _execute(
        [sys.executable, '-I', '-B', '-c', SERVICE, str(root)],
        cwd=root, payload=b'', timeout=5, output_limit=32768)
    if code or reason:
        raise RuntimeError('fixture service failed: ' + str(reason) + stderr)
    return {'observed': json.loads(stdout), 'raw': {'stdout': stdout,
            'stderr': stderr, 'returncode': code}}



def run_controls(root):
    root.mkdir(parents=True)
    checks = []
    clock = Clock(1800000000)
    checks.append(('controlled-clock', clock.advance(0.5) == 1800000000.5))
    dns = DNS({'fixture.invalid': ['192.0.2.10', '2001:db8::10']})
    checks.append(('injected-dns-answer', dns.resolve('fixture.invalid') == ['192.0.2.10', '2001:db8::10']))
    try:
        dns.resolve('unconfigured.invalid')
        checks.append(('dns-no-fallback', False))
    except LookupError:
        checks.append(('dns-no-fallback', True))
    recorder = ActionRecorder()
    receipt = recorder.record(jail='synthetic', ip='192.0.2.10', protocol='tcp', ports=[22], expiry=1800000600)
    checks.append(('action-scope-recorded', recorder.events == [{'jail':'synthetic','ip':'192.0.2.10','protocol':'tcp','ports':['22'],'expiry':1800000600}]))
    checks.append(('recorded-is-not-enforced', receipt['effect_observed'] is False))
    random_a, random_b = random.Random(471), random.Random(471)
    values = [random_a.randrange(10, 21) for _ in range(256)]
    checks.append(('seeded-random-repeat', values == [random_b.randrange(10, 21) for _ in range(256)]))
    checks.append(('random-bounds', all(10 <= value <= 20 for value in values)))
    # Predeclared broad sanity check for this fixed generator control. It is not
    # a statistical proof about either product's randomized ban implementation.
    checks.append(('random-distribution-control', all(5 <= values.count(n) <= 50 for n in range(10, 21))))
    log = root / 'events.log'
    log.write_text('original record one\n')
    first = service(root)
    with log.open('a') as stream:
        stream.write('original record two\n')
    second = service(root)
    checks.append(('restart-cursor-continuity', second['observed']['records'] == ['original record two'] and first['observed']['pid'] != second['observed']['pid']))
    log.rename(root / 'events.log.1')
    log.write_text('replacement record\n')
    third = service(root)
    checks.append(('rename-rotation', third['observed']['records'] == ['replacement record'] and third['observed']['cursor']['identity'] != second['observed']['cursor']['identity']))
    log.write_text('short\n')
    fourth = service(root)
    checks.append(('truncate-rotation', fourth['observed']['records'] == ['short']))
    fifth = service(root)
    checks.append(('restart-no-duplicate', fifth['observed']['records'] == []))
    from contract import validate_observations
    from compare import differences
    # These intentionally generated controls exercise every shared trace family;
    # they are kept separate from actual runner observations.
    pairs = [
        ('source', {'record': 'original record one', 'cursor': str(first['observed']['cursor']['offset'])}),
        ('timestamp', {'timestamp': clock.now}),
        ('match', {'identity': '192.0.2.10', 'result': 'matched'}),
        ('jail', {'name': 'synthetic'}),
        ('action', {'operation':'ban','jail':'synthetic','ip':'192.0.2.10','protocol':'tcp','ports':['22']}),
        ('expiry', {'absolute':1800000600}),
        ('history', {'identity':'192.0.2.10','ban_count':1}),
        ('command', {'command':'status','status':'ok','response':{'active_bans':1}}),
        ('health', {'previous':'healthy','current':'degraded'}),
    ]
    canonical_trace = [{'event':event,'sequence':i,'values':values} for i,(event,values) in enumerate(pairs)]
    validate_observations(canonical_trace)
    checks.append(('all-shared-event-families-valid', True))
    changed = json.loads(json.dumps(canonical_trace))
    changed[4]['values']['ports'] = ['443']
    checks.append(('canonical-scope-change-detected', bool(differences(canonical_trace, changed))))
    with socket.socket() as peer:
        peer.settimeout(0.1)
        try:
            peer.connect(('192.0.2.1', 9))
            checks.append(('external-network-unreachable', False))
        except OSError:
            checks.append(('external-network-unreachable', True))
    return {'scope': 'harness-driver controls only; no product/DNS/action/source/restart certification',
            'passed': all(passed for _, passed in checks),
            'checks': [{'id': name, 'passed': passed} for name, passed in checks],
            'source_service_runs': [first, second, third, fourth, fifth],
            'canonical_driver_trace': canonical_trace, 'action_requests': recorder.events, 'dns_calls': dns.calls,
            'random': {'seed':471,'bounds':[10,20],'samples':values,'distribution_count_bounds':[5,50]}}
