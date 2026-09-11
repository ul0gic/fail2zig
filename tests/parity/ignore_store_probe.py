#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Actual adapter proposals committed through the candidate SQLite Store API."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'engine/compat'))
from ignore_adapter import Adapter


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    checks = []
    calls = []

    def lookup(kind, name, **kwargs):
        calls.append(name)
        return {'addresses': ['192.0.2.1'], 'error': None}

    adapters = {name: Adapter(dict(ignoreself=False, usedns='yes', allowipv6='no',
                                  ignoreip=['192.0.2.1'] if name == 'a' else []),
                              'original-store-profile', lookup=lookup) for name in ('a', 'b', 'c')}
    shared_name = 'dns:' + adapters['a'].shared_binding
    with tempfile.TemporaryDirectory(prefix='f2z-original-ignore-store-') as directory:
        root = Path(directory)
        request = root / 'request.json'

        def exchange(jail, **values):
            request.write_text(json.dumps(dict(jail=jail, shared_name=shared_name, **values)))
            process = subprocess.run([str(args.candidate.resolve()), str(root / 'state.db'),
                                      str(request)], capture_output=True, check=True)
            return json.loads(process.stdout)

        def stage(jail, hostname, current):
            return adapters[jail].stage(hostname, now=100,
                snapshot=json.loads(current['jail']['payload']) if current['jail']['payload'] else None,
                shared_snapshot=json.loads(current['shared']['payload']) if current['shared']['payload'] else None)

        def commit(jail, occurrence, proposal, current, *, fail=False, read_only=False):
            return exchange(jail, occurrence=occurrence,
                checkpoint=json.dumps(proposal['snapshot'], sort_keys=True),
                shared_payload=None if read_only else json.dumps(proposal['shared_snapshot'], sort_keys=True),
                jail_revision=current['jail']['revision'], shared_revision=current['shared']['revision'], fail=fail)

        empty = exchange('a')
        proposal = stage('a', 'original.test', empty)
        rejected = commit('a', 'a-1', proposal, empty, fail=True)
        assert rejected['outcome'] == 'InjectedFailure' and rejected['published'] is False
        assert rejected['jail'] == empty['jail'] and rejected['shared'] == empty['shared']
        assert rejected['cursor'] is None
        checks.append('injected-after-shared-write-rolls-back-jail-shared-and-cursor')
        retry = stage('a', 'original.test', exchange('a'))
        assert len(calls) == 2
        saved = commit('a', 'a-1', retry, empty)
        assert saved['outcome'] == 'committed' and saved['shared']['revision'] == 1 and saved['published'] is True
        assert retry['decisions'][0]['ignored'] is True
        checks.append('retry-recomputes-unpublished-dns-and-commits')
        other = exchange('b')
        cached = stage('b', 'original.test', other)
        assert len(calls) == 2 and cached['decisions'][0]['ignored'] is False
        assert cached['shared_snapshot'] == json.loads(other['shared']['payload'])
        saved_b = commit('b', 'b-1', cached, other, read_only=True)
        assert saved_b['outcome'] == 'committed' and saved_b['shared']['revision'] == 1
        checks.append('fresh-process-cross-jail-cache-restore-with-independent-ignore-state')
        checks.append('unchanged-shared-read-dependency-commits-without-revision-bump')
        stale = exchange('c')
        stale_proposal = stage('c', 'original.test', stale)
        next_a = exchange('a')
        fresh = stage('a', 'second.test', next_a)
        updated = commit('a', 'a-2', fresh, next_a)
        assert updated['shared']['revision'] == 2
        conflict = commit('c', 'c-1', stale_proposal, stale, read_only=True)
        assert conflict['outcome'] == 'StaleSharedCheckpoint' and conflict['published'] is False and conflict['ready'] is False
        assert conflict['jail']['revision'] == 0 and conflict['cursor'] is None
        assert conflict['shared'] == updated['shared']
        checks.append('stale-read-only-shared-dependency-rejects-entire-jail-transaction')
        current = exchange('c')
        refreshed = stage('c', 'original.test', current)
        accepted = commit('c', 'c-1', refreshed, current, read_only=True)
        assert accepted['outcome'] == 'committed' and accepted['shared']['revision'] == 2
        assert len(calls) == 3
        checks.append('refresh-and-retry-reuses-current-shared-dns')
    repository = Path(__file__).resolve().parents[2]
    files = ['engine/ignore_store_probe.zig', 'engine/core/record_store.zig',
             'engine/core/record_pipeline.zig', 'engine/compat/ignore_adapter.py', 'engine/compat/ignore_dns.py',
             'engine/compat/action_info.py', 'engine/compat/duration.py',
             'tests/parity/ignore_store_probe.py']
    receipt = dict(scope='candidate-only actual adapter→Pipeline→Store SQLite transaction; no daemon or matching claim',
                   checks=checks, passed=len(checks), lookup_trace=calls,
                   candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
                   source_sha256={name: hashlib.sha256((repository / name).read_bytes()).hexdigest() for name in files})
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
