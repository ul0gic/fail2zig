#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Bounded component runner for reviewed, original fail2ban scenarios.

This module does not start a daemon or run actions. The orchestrator must validate
the pinned reference and provide filesystem/network isolation. Resource limits
and an empty credential environment supplement, but do not replace, isolation.
"""

import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time


WORKER = r'''
import json, logging, resource, sys
resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
request = json.load(sys.stdin)
sys.path.insert(0, sys.argv[1])
kind, data = request['kind'], request['input']
observations = []
errors = []
class Collector(logging.Handler):
    def emit(self, record):
        errors.append(record.getMessage())
logging.getLogger().addHandler(Collector(level=logging.ERROR))
if kind in ('config', 'effective_config'):
    from fail2ban.client.configreader import ConfigReaderUnshared
    reader = ConfigReaderUnshared(basedir=sys.argv[2])
    if not reader.read('jail'):
        raise RuntimeError('reference could not read original configuration fixture')
    value = reader.get(data['section'], data['option'], fallback=None)
    observations.append({'event': 'config', 'sequence': 0, 'values': {'value': value}})
elif kind == 'ssh_log':
    from fail2ban.client.filterreader import FilterReader
    from fail2ban.server.filter import Filter
    from fail2ban.server.mytime import MyTime
    reader = FilterReader('sshd', 'synthetic', {'mode': 'normal'},
                          basedir=sys.argv[1] + '/config')
    if not reader.read():
        raise RuntimeError('could not read pinned stock sshd filter')
    reader.getOptions({})
    options = reader.getCombined()
    matcher = Filter(None, useDns='raw')
    matcher.ignoreSelf = False
    if options.get('maxlines') is not None:
        matcher.setMaxLines(options['maxlines'])
    matcher.prefRegex = options['prefregex']
    for pattern in options['failregex'].splitlines():
        if pattern:
            matcher.addFailRegex(pattern)
    for pattern in options['ignoreregex'].splitlines():
        if pattern:
            matcher.addIgnoreRegex(pattern)
    if options.get('datepattern'):
        matcher.setDatePattern(options['datepattern'])
    MyTime.setTime(1800000000)
    # Use the real reference date-prefix matcher, while keeping event chronology
    # fixed. This adapter compares failure decisions, not date conversion.
    line = data['line']
    date_match = matcher.dateDetector.matchTime(line)[0]
    if date_match:
        start, end = date_match.span(1)
        framed = (line[:start], line[start:end], line[end:])
    else:
        framed = ('', '', line)
    matches = matcher.processLine(framed, 1800000000)
    if matcher._errors:
        raise RuntimeError('reference suppressed an ssh filter error')
    if len(matches) > 1:
        raise RuntimeError('single-record adapter cannot represent multiple identities')
    observations.append({'event': 'match', 'sequence': 0, 'values': {
        'identity': str(matches[0][1]) if matches else None,
        'result': 'matched' if matches else 'ignored'}})
elif kind in ('tickets', 'filter_time'):
    from fail2ban.server.failmanager import FailManager, FailManagerEmpty
    from fail2ban.server.ticket import FailTicket
    from fail2ban.server.ipdns import IPAddr
    from fail2ban.server.mytime import MyTime
    MyTime.setTime(data['now'])
    address = IPAddr('192.0.2.10')
    def pending(manager):
        item = manager._FailManager__failList.get(address)
        return {'pending_retry': manager.getFailCount()[1],
                'pending_last_time': item.getTime() if item is not None else None}
    if kind == 'tickets':
        manager = FailManager()
        manager.setMaxTime(data['findtime'])
        manager.setMaxRetry(data['maxretry'])
        for sequence, timestamp in enumerate(data['events']):
            manager.addFailure(FailTicket(address, timestamp,
                matches=['original synthetic record'], data={'failures': 1}))
            reached = False
            try:
                manager.toBan(address)  # Extract a ticket; no action dispatch.
                reached = True
            except FailManagerEmpty:
                pass
            observations.append({'event': 'ticket', 'sequence': sequence,
                'values': dict(pending(manager), threshold_reached=reached)})
    else:
        from fail2ban.server.filter import Filter
        def make_filter():
            item = Filter(None, useDns='raw')
            item.ignoreSelf = False
            item.setFindTime(data['findtime'])
            item.setMaxRetry(1024)
            item.addFailRegex(r'^synthetic failure from <ADDR>$')
            item.inOperation = data['live']
            return item
        line = ('', '', 'synthetic failure from 192.0.2.10')
        matcher = make_filter()
        parsed = matcher.processLine(line, data['event'])
        stored = make_filter()
        stored.processLineAndAdd(line, data['event'])
        if stored._errors:
            raise RuntimeError('reference suppressed a filter processing error')
        observations.append({'event': 'filter_time', 'sequence': 0, 'values': {
            'matched': bool(parsed), 'parsed_time': parsed[0][2] if parsed else None,
            'stored_time': pending(stored.failManager)['pending_last_time'],
            'pending_retry': pending(stored.failManager)['pending_retry']}})
else:
    raise RuntimeError('unsupported worker kind')
if errors:
    raise RuntimeError('reference logged processing errors: ' + repr(errors))
sources = sorted({str(module.__file__) for name, module in sys.modules.items()
                  if name.startswith('fail2ban') and getattr(module, '__file__', None)})
print(json.dumps({'observations': observations, 'source_dependencies': sources}, allow_nan=False))
'''


def _result(status, *, observations=None, stdout='', stderr='', returncode=None, **details):
    return {'status': status, 'observations': observations or [],
            'raw': {'stdout': stdout, 'stderr': stderr, 'returncode': returncode},
            'details': details}


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def _validate(case):
    kind, data = case['kind'], case['input']
    if not isinstance(data, dict):
        raise ValueError('input must be an object')
    if kind in ('config', 'effective_config'):
        if not isinstance(data.get('files'), dict) or not data['files']:
            raise ValueError('configuration files must be a nonempty mapping')
        for name, contents in data['files'].items():
            if not isinstance(name, str) or not isinstance(contents, str):
                raise ValueError('configuration names and contents must be strings')
            path = Path(name)
            if path.is_absolute() or '..' in path.parts or not path.parts:
                raise ValueError('configuration path must stay inside fixture')
        for field in ('section', 'option'):
            if not isinstance(data.get(field), str) or not data[field]:
                raise ValueError(field + ' must be a nonempty string')
    elif kind == 'ssh_log':
        line = data.get('line')
        if (set(data) != {'line'} or not isinstance(line, str) or not line
                or len(line.encode('utf-8')) > 4096 or any(value in line for value in ('\n', '\r', '\0'))):
            raise ValueError('ssh_log requires one bounded, nonempty sanitized line')
    else:
        if not all(_finite(data.get(key)) for key in ('now', 'findtime')) or data['findtime'] <= 0:
            raise ValueError('clock and positive findtime must be finite numbers')
        if kind == 'tickets':
            if type(data.get('maxretry')) is not int or not 1 <= data['maxretry'] <= 1024:
                raise ValueError('maxretry must be an integer in 1..1024')
            if not isinstance(data.get('events'), list) or not 1 <= len(data['events']) <= 1024:
                raise ValueError('events must contain 1..1024 finite timestamps')
            if not all(_finite(value) for value in data['events']):
                raise ValueError('events must be finite timestamps')
        elif not _finite(data.get('event')) or type(data.get('live')) is not bool:
            raise ValueError('filter event must be finite and live must be boolean')


def _terminate(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _execute(command, *, cwd, payload, timeout, output_limit):
    """Bound combined pipe bytes while reading; kill the group on every exit."""
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    reason = None
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(cwd), 'TMPDIR': str(cwd),
                   'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC',
                   'PYTHONDONTWRITEBYTECODE': '1'}
    # A regular input file avoids a blocked parent write before the deadline starts.
    with tempfile.TemporaryFile(dir=cwd) as request:
        request.write(payload)
        request.seek(0)
        process = subprocess.Popen(command, stdin=request, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=cwd, env=environment,
                                   start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                for name in streams:
                    selector.register(getattr(process, name), selectors.EVENT_READ, name)
                total = 0
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        reason = 'deadline exceeded'
                        break
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 16384)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        available = max(0, output_limit - total)
                        streams[key.data].extend(chunk[:available])
                        total += len(chunk)
                        if total > output_limit:
                            reason = 'output limit exceeded'
                            break
                    if reason:
                        break
                if reason is None:
                    try:
                        process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        reason = 'deadline exceeded'
        finally:
            _terminate(process)
            process.stdout.close()
            process.stderr.close()
    return (process.returncode, *(streams[name].decode('utf-8', errors='replace')
                                 for name in ('stdout', 'stderr')), reason)


def run_case(case: dict, context: dict) -> dict:
    """Run one original fixture through real pinned reference component APIs."""
    kind = case.get('kind')
    if kind not in ('config', 'effective_config', 'tickets', 'filter_time', 'ssh_log'):
        return _result('unsupported', reason='no reference adapter for kind', kind=kind)
    raw = {}
    try:
        _validate(case)
        payload = json.dumps({'kind': kind, 'input': case['input']}, allow_nan=False).encode()
        if len(payload) > 256 * 1024:
            raise ValueError('fixture exceeds 256 KiB input bound')
        timeout = context.get('timeout_seconds', 5)
        limit = context.get('output_limit', 256 * 1024)
        if not _finite(timeout) or not 0 < timeout <= 60:
            raise ValueError('timeout must be positive and at most 60 seconds')
        if type(limit) is not int or not 1 <= limit <= 4 * 1024 * 1024:
            raise ValueError('output bound must be 1 byte through 4 MiB')
        reference = Path(context['reference']).resolve(strict=True)
        work = Path(context['work']).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix='reference-', dir=work) as temporary:
            fixture = Path(temporary)
            if kind in ('config', 'effective_config'):
                for name, contents in case['input']['files'].items():
                    target = fixture / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(contents, encoding='utf-8')
            code, stdout, stderr, reason = _execute(
                [sys.executable, '-I', '-B', '-c', WORKER, str(reference), str(fixture)],
                cwd=fixture, payload=payload, timeout=timeout, output_limit=limit)
        raw = {'stdout': stdout, 'stderr': stderr, 'returncode': code}
        if reason:
            return _result('timeout' if reason == 'deadline exceeded' else 'error',
                           **raw, reason=reason)
        if code != 0:
            return _result('error', **raw, reason='reference worker failed')
        response = json.loads(stdout, parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError('non-finite JSON constant: ' + value)))
        if not isinstance(response, dict) or set(response) != {'observations', 'source_dependencies'}:
            raise ValueError('malformed reference worker response')
        if not isinstance(response['observations'], list) or not isinstance(response['source_dependencies'], list):
            raise ValueError('malformed reference worker collections')
        for index, observation in enumerate(response['observations']):
            if (not isinstance(observation, dict)
                    or set(observation) != {'event', 'sequence', 'values'}
                    or type(observation['sequence']) is not int
                    or observation['sequence'] != index
                    or observation['event'] != {'config': 'config', 'effective_config': 'config', 'tickets': 'ticket', 'ssh_log': 'match',
                                                 'filter_time': 'filter_time'}[kind]
                    or not isinstance(observation['values'], dict)):
                raise ValueError('malformed reference observation')
        if len(response['observations']) != (len(case['input']['events']) if kind == 'tickets' else 1):
            raise ValueError('reference observation count differs from fixture')
        if not all(isinstance(path, str) and Path(path).is_relative_to(reference)
                   for path in response['source_dependencies']):
            raise ValueError('reference dependency outside selected source tree')
        return _result('ok', observations=response['observations'], **raw,
                       source_dependencies=response['source_dependencies'],
                       scope='actual component APIs; no daemon, ingestion, actions or scheduling',
                       filter_profile='pinned stock sshd normal; raw addresses; real date-prefix matcher; fixed converted event date' if kind == 'ssh_log' else None,
                       clock='MyTime.setTime' if kind not in ('config', 'effective_config') else None)
    except (OSError, KeyError, TypeError, ValueError, OverflowError, subprocess.SubprocessError) as error:
        return _result('error', **raw, reason=str(error))
