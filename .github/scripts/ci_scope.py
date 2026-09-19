#!/usr/bin/env python3
"""Select CI work conservatively; no product runtime dependency."""
import argparse
import json
import os
from pathlib import PurePosixPath
import re
import subprocess

ROOT_DOCS = {'README.md', 'CONTRIBUTING.md', 'CHANGELOG.md', 'RELEASE_NOTES.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md'}
FULL_JOBS = {'fmt', 'build-native', 'test', 'release-target', 'shellcheck', 'yamllint', 'zizmor', 'spdx'}


def lightweight(path):
    p = PurePosixPath(path)
    if '..' in p.parts or p.is_absolute():
        return False
    return (path in ROOT_DOCS
            or (path.startswith('docs/') and p.suffix == '.md')
            or path == '.github/PULL_REQUEST_TEMPLATE.md'
            or (p.parent == PurePosixPath('.github/ISSUE_TEMPLATE') and p.suffix in {'.yml', '.yaml', '.md'}))


def git(*args):
    result = subprocess.run(['git', *args], stdout=subprocess.PIPE, timeout=60)
    if result.returncode:
        print(result.stdout[:8192].decode('utf-8', errors='replace'))
        result.check_returncode()
    return result.stdout


def comparison(event):
    if 'pull_request' in event:
        base = event['pull_request']['base']['sha']
        head = event['pull_request']['head']['sha']
        triple = True
    else:
        base, head = event.get('before', ''), event.get('after', '')
        triple = False
    if not all(re.fullmatch(r'[0-9a-f]{40}', x) and x != '0' * 40 for x in (base, head)):
        return None
    try:
        if triple:
            base = git('merge-base', base, head).decode().strip()
        git('cat-file', '-e', f'{base}^{{commit}}')
        git('cat-file', '-e', f'{head}^{{commit}}')
    except (subprocess.SubprocessError, OSError):
        return None
    return base, head


def changed_paths(event):
    refs = comparison(event)
    if refs is None:
        return None
    try:
        raw = git('diff', '--no-renames', '--name-only', '-z', *refs, '--')
    except (subprocess.SubprocessError, OSError):
        return None
    return [p.decode('utf-8', errors='surrogateescape') for p in raw.split(b'\0') if p]


def route(paths):
    # Missing history, an empty diff, and all unknown paths require the full gate.
    return 'light' if paths and all(lightweight(p) for p in paths) else 'full'


def gate(needs):
    expected = {'scope', 'community'} | FULL_JOBS
    if set(needs) != expected:
        return False
    mode = needs['scope'].get('outputs', {}).get('route')
    if mode not in {'light', 'full'}:
        return False
    for job, state in needs.items():
        wanted = 'skipped' if mode == 'light' and job in FULL_JOBS else 'success'
        if state.get('result') != wanted:
            return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['classify', 'gate', 'whitespace'])
    args = parser.parse_args()
    if args.command == 'gate':
        if not gate(json.loads(os.environ['CI_NEEDS'])):
            raise SystemExit('CI failed: required checks failed, were cancelled, or did not run as expected.')
        print('All applicable CI checks passed.')
        return
    with open(os.environ['GITHUB_EVENT_PATH'], encoding='utf-8') as stream:
        event = json.load(stream)
    if args.command == 'whitespace':
        refs = comparison(event)
        # Initial pushes lack a base: still inspect the checked-out commit.
        if refs is None:
            git('show', '--format=', '--check', 'HEAD', '--')
        else:
            git('diff', '--check', *refs, '--')
        print('Changed-file whitespace check passed.')
        return
    mode = route(changed_paths(event))
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
        stream.write(f'route={mode}\n')
    print(f'CI route: {mode}')


if __name__ == '__main__':
    main()
