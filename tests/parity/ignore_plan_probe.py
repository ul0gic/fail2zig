#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original importer-to-ignore adapter composition; no matching or commands."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'engine/compat'))
from ignore_adapter import Adapter, from_plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='f2z-original-ignore-plan-') as directory:
        root = Path(directory)
        (root / 'filter.d').mkdir()
        (root / 'filter.d/original.conf').write_text('[Definition]\nfailregex=^original <HOST>$\n')
        (root / 'fail2ban.conf').write_text('[Definition]\nallowipv6=no\n')
        (root / 'input.log').write_text('original neutral\n')
        (root / 'jail.conf').write_text(
            '[DEFAULT]\nignoreip=192.0.2.1\nignoreself=bad\nusedns=no\n'
            'ignorecache=key=<ip>,max-time=10s\nignorecommand=\n'
            '[original]\nenabled=true\nfilter=original\nbackend=polling\n'
            'logpath=' + str(root / 'input.log') + '\n')
        output = root / 'prepared.toml'
        process = subprocess.run([str(args.candidate.resolve()), '--import-config', str(root),
                        '--import-output', str(output)], capture_output=True)
        if process.returncode not in (0, 1) or not output.exists():
            raise RuntimeError(process.stderr.decode(errors='replace'))
        manifest = json.loads(tomllib.loads(output.read_text())['global']['compatibility_manifest'])
        effective = from_plan(manifest['source_plans'][0]['ignore'])
        expected = dict(ignoreip='192.0.2.1', ignoreself=False, usedns='no',
                        ignorecache={'key': '<ip>', 'max-time': '10s'},
                        ignorecommand='', allowipv6='no')
        assert effective == expected, effective
        instance = Adapter(effective, 'original-profile')
        first = instance.stage('192.0.2.1', now=100)
        second = instance.stage('192.0.2.2', now=101, snapshot=first['snapshot'],shared_snapshot=first['shared_snapshot'])
        assert first['decisions'][0]['ignored'] is True
        assert second['decisions'][0]['ignored'] is False
    receipt = dict(scope='candidate-only generated IgnorePlan composition; no reference equality claim',
                   candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
                   effective=effective, checks={'typed_plan': True, 'listed_identity': True,
                                               'unlisted_identity': True},
                   component_sha256={name: hashlib.sha256((Path(__file__).resolve().parents[2] /
                       'engine/compat' / name).read_bytes()).hexdigest()
                       for name in ('ignore_adapter.py', 'ignore_dns.py', 'action_info.py', 'duration.py')})
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
