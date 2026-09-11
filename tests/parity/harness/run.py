#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run original reference/candidate fixtures in a disposable Linux root.

Exit 0: all selected comparisons agree. Exit 1: differences/unsupported cases.
Exit 2: incomplete or invalid evidence. --gate uses the separate G1 infrastructure
acceptance decision as exit status, while preserving all functional mismatches.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
OUTPUT = None
REFERENCE_COMMIT = 'f60978618a101427b06924fc932b44350fec2b63'



def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def command(args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, text=True,
                          capture_output=True, timeout=30).stdout.strip()


def verify_reference(reference):
    if command(['git', 'rev-parse', 'HEAD'], reference) != REFERENCE_COMMIT:
        raise ValueError('reference must be the pinned commit')
    command(['git', 'diff', '--exit-code', 'HEAD', '--'], reference)
    if command(['git', 'ls-files', '--others', '--exclude-standard'], reference):
        raise ValueError('reference has untracked files')
    files = command(['git', 'ls-files'], reference).splitlines()
    hashes = {}
    for name in files:
        if name.startswith(('fail2ban/', 'config/')) or name == 'COPYING':
            path = reference / name
            if path.is_symlink() or not path.is_file():
                raise ValueError('reference input must be a regular file: ' + name)
            hashes[name] = digest(path)
    return hashes


def source_hashes():
    paths = list((ROOT / 'tests/parity').rglob('*.py'))
    paths += list((ROOT / 'tests/parity').rglob('*.zig'))
    paths += list((HERE / 'fixtures').glob('*.json'))
    paths += list((ROOT / 'engine').rglob('*.zig'))
    # P2 helpers execute outside the Zig binaries; bind and stage their source
    # and profile data as explicitly as the native components.
    paths += list((ROOT / 'engine/compat').glob('*.py'))
    paths += list((ROOT / 'engine/compat').glob('*.json'))
    paths += list((ROOT / 'engine/compat').glob('COPYING.*'))
    paths += list((ROOT / 'shared').rglob('*.zig'))
    return {p.relative_to(ROOT).as_posix(): digest(p) for p in sorted(paths)}


def write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def stage(jail, reference, reference_hashes, sources, binaries, bundle):
    for name in ('work/binaries', 'code', 'reference', 'proc', 'dev', 'tmp', 'etc'):
        (jail / name).mkdir(parents=True, exist_ok=True)
    (jail / 'tmp').chmod(0o1777)
    (jail / 'etc/passwd').write_text('root:x:0:0:fixture:/tmp:/bin/false\n')
    (jail / 'etc/group').write_text('root:x:0:\n')
    (jail / 'etc/hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
    for name in sources:
        target = jail / 'code' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    # Only reviewed implementation/configuration modules are staged. Upstream
    # tests, samples and install/build scripts never enter the execution root.
    for name in reference_hashes:
        if name.startswith('fail2ban/tests/'):
            continue
        if not (name.endswith('.py') or name.startswith('config/') or name == 'COPYING'):
            continue
        target = jail / 'reference' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(reference / name, target)
    remapped = json.loads(json.dumps(binaries))
    for name, item in remapped.items():
        if isinstance(item, dict) and 'path' in item:
            target = jail / 'work/binaries' / name
            shutil.copyfile(item['path'], target)
            target.chmod(0o555)
            if digest(target) != item['sha256']:
                raise ValueError('staged binary hash mismatch')
            item['path'] = '/work/binaries/' + name
    request = {'bundle': bundle, 'binaries': remapped,
               'parent_namespaces': {n: os.readlink('/proc/self/ns/' + n)
                                     for n in ('user', 'mnt', 'net', 'pid')}}
    write_json(jail / 'work/request.json', request)


def launch(jail):
    args = ['unshare', '--user', '--map-root-user', '--mount', '--net', '--pid',
            '--fork', '--kill-child', '--', sys.executable, '-I', '-B',
            str(HERE / 'isolate.py'), str(jail)]
    from reference import _execute
    code, stdout, stderr, reason = _execute(args, cwd=jail, payload=b'', timeout=240,
                                          output_limit=256 * 1024)
    if reason or code:
        raise RuntimeError('isolated suite failed: ' + str(reason) + ': ' + stderr[-8192:])
    return {'stdout': stdout, 'stderr': stderr, 'returncode': code}



def internal():
    from contract import load_json, validate_bundle, validate_outcome
    from compare import compare_case, self_tests
    import reference
    import candidate
    from controls import run_controls
    request = load_json(Path('/work/request.json').read_text())
    bundle = request['bundle']
    validate_bundle(bundle)
    namespaces = {n: os.readlink('/proc/self/ns/' + n) for n in ('user', 'mnt', 'net', 'pid')}
    if any(namespaces[n] == request['parent_namespaces'][n] for n in namespaces):
        raise RuntimeError('required namespace isolation missing')
    if Path('/home').exists() or Path('/run').exists():
        raise RuntimeError('host credential locations must not be mounted')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    capabilities = {key: status[key].strip() for key in ('CapEff', 'CapPrm', 'CapAmb', 'NoNewPrivs')}
    readonly = {name: bool(os.statvfs(name).f_flag & os.ST_RDONLY)
                for name in ('/code', '/reference', '/work/binaries')}
    interfaces = [line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    routes = Path('/proc/net/route').read_text().splitlines()[1:]
    verified = (all(int(capabilities[k], 16) == 0 for k in ('CapEff', 'CapPrm', 'CapAmb'))
                and capabilities['NoNewPrivs'] == '1' and all(readonly.values())
                and interfaces == ['lo'] and not routes)
    if not verified:
        raise RuntimeError('post-exec isolation controls failed')
    supplementary = load_json(Path('/code/tests/parity/harness/fixtures/controls-v1.json').read_text())
    validate_bundle(supplementary)
    extra_cases = [] if bundle == supplementary else supplementary['cases']
    real_bundle_path = Path('/code/tests/parity/harness/fixtures/real-logs-v1.json')
    real_bundle = load_json(real_bundle_path.read_text())
    validate_bundle(real_bundle)
    real_cases = [] if bundle == real_bundle else real_bundle['cases']
    results = []
    for case in bundle['cases'] + extra_cases + real_cases:
        work = Path('/work/cases') / case['id']
        work.mkdir(parents=True)
        context = {'root': Path('/code'), 'work': work, 'reference': Path('/reference'),
                   'binaries': request['binaries']}
        left = reference.run_case(case, context)
        right = candidate.run_case(case, context)
        validate_outcome(left, case)
        validate_outcome(right, case)
        results.append({'id': case['id'], 'requirements': case['requirements'],
                        'issues': case['issues'], 'profile': case['profile'],
                        'split': case['split'], 'reference': left, 'candidate': right,
                        'comparison': compare_case(case, left, right)})
    write_json('/work/results.json', {'cases': results[:len(bundle['cases'])],
               'supplementary_cases': results[len(bundle['cases']):len(bundle['cases']) + len(extra_cases)],
               'real_log_cases': results[len(bundle['cases']) + len(extra_cases):],
               'real_logs_bundle_sha256': digest(real_bundle_path),
               'real_logs_provenance_sha256': digest(real_bundle_path.with_name('real-logs-provenance-v1.json')), 'self_tests': self_tests(),
               'driver_controls': run_controls(Path('/work/driver-controls')),
               'isolation': {'verified': verified, 'capabilities': capabilities, 'readonly': readonly, 'interfaces': interfaces, 'routes': routes, 'namespaces': namespaces, 'no_host_home_or_run': True,
                             'network': 'private namespace; no host routes',
                             'filesystem': 'private root; readonly staged code/reference/binaries',
                             'privileges': 'capabilities dropped; no_new_privs',
                             'environment': sorted(os.environ)}})


def trace_fingerprint(result):
    stable = []
    for item in result['cases'] + result.get('supplementary_cases', []) + result.get('real_log_cases', []):
        stable.append({'id': item['id'], 'comparison': item['comparison'],
                       'reference': {k: item['reference'][k] for k in ('status', 'observations')},
                       'candidate': {k: item['candidate'][k] for k in ('status', 'observations')}})
    return hashlib.sha256(canonical(stable).encode()).hexdigest()


def coverage(catalog, cases):
    by_id = {r['id']: [] for r in catalog['requirements']}
    for case in cases:
        for req in case['requirements']:
            if req not in by_id:
                raise ValueError('unknown requirement: ' + req)
            by_id[req].append({'case': case['id'], 'profile': case['profile'],
                              'decision': case['comparison']['decision']})
    return [{'id': req, 'comparisons': entries,
             'status': 'observed-component-cases' if entries else 'not-run',
             'certified': False} for req, entries in by_id.items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, default=HERE / 'fixtures/baseline-v1.json')
    parser.add_argument('--gate', action='store_true')
    args = parser.parse_args()
    global OUTPUT
    OUTPUT = args.output
    from contract import load_json, validate_bundle
    import candidate
    from specs import validate_specifications
    specification_inventory = validate_specifications(HERE / 'fixtures')
    bundle = load_json(args.bundle.read_text())
    validate_bundle(bundle)
    catalog_path = HERE / 'fixtures/requirements-v1.json'
    catalog = load_json(catalog_path.read_text())
    ref = args.reference.resolve(strict=True)
    before = source_hashes()
    ref_before = verify_reference(ref)
    report = {'schema_version': 1, 'scope': 'P1 component comparison infrastructure; no runtime parity certification',
              'bundle': bundle, 'bundle_sha256': digest(args.bundle),
              'specification_inventory': specification_inventory,
              'requirement_catalog_sha256': digest(catalog_path),
              'reference_commit': REFERENCE_COMMIT, 'reference_sources': ref_before,
              'candidate_head': command(['git', 'rev-parse', 'HEAD'], ROOT),
              'candidate_branch': command(['git', 'branch', '--show-current'], ROOT),
              'sources': before, 'host': {'python': sys.version, 'kernel': platform.release(),
                                         'python_executable_sha256': digest(sys.executable)},
              'normalization': 'none; exact typed fields and ordered observations',
              'repetitions': [], 'G1_complete': False}
    with tempfile.TemporaryDirectory(prefix='f2z-p1-') as temporary:
        work = Path(temporary)
        binaries = candidate.prepare({'root': ROOT, 'work': work})
        report['builds'] = binaries
        for repetition in range(2):
            jail = work / ('root-' + str(repetition))
            stage(jail, ref, ref_before, before, binaries, bundle)
            launch_result = launch(jail)
            result = load_json((jail / 'work/results.json').read_text())
            result['launcher'] = launch_result
            result['trace_sha256'] = trace_fingerprint(result)
            report['repetitions'].append(result)
        if source_hashes() != before or verify_reference(ref) != ref_before:
            raise RuntimeError('inputs changed during run; discard evidence')
        for item in binaries.values():
            if isinstance(item, dict) and 'path' in item and digest(item['path']) != item['sha256']:
                raise RuntimeError('candidate binary changed during run')
    first, second = report['repetitions']
    report['reproducible'] = first['trace_sha256'] == second['trace_sha256']
    report['coverage'] = coverage(catalog, first['cases'] + first['supplementary_cases'] + first['real_log_cases'])
    report['real_log_summary'] = dict(Counter(x['comparison']['decision'] for x in first['real_log_cases']))
    report['supplementary_summary'] = dict(Counter(x['comparison']['decision'] for x in first['supplementary_cases']))
    report['summary'] = dict(Counter(x['comparison']['decision'] for x in first['cases']))
    from gate import evaluate_gate
    expected = load_json((HERE / 'fixtures/gate-v1.json').read_text())
    report['gate'] = evaluate_gate(report, expected)
    report['G1_complete'] = report['gate']['passed']
    report['limits'] = ['Config readers and ticket components are actual comparisons, not daemon-wide parity.',
                        'Driver controls prove harness mechanisms, not candidate source/DNS/restart behavior.',
                        'No upstream test bodies or stock samples executed; no configured external actions.',
                        'Only this development runtime profile executed; no platform/provider certification.',
                        'All requirement rows remain uncertified. Known-gap is never a functional pass.']
    write_json(args.output, report)
    print(json.dumps({'summary': report['summary'], 'reproducible': report['reproducible'],
                      'G1_complete': report['G1_complete'], 'output': str(args.output)}))
    if args.gate:
        return 0 if report['G1_complete'] else 2
    complete = (set(report['summary']) == {'pass'}
                and set(report['real_log_summary']) <= {'pass'}
                and set(report['supplementary_summary']) <= {'unsupported'}
                and report['reproducible'])
    return 0 if complete else 1


if __name__ == '__main__':
    try:
        if '--internal' in sys.argv:
            internal()
        else:
            sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        if OUTPUT is not None:
            write_json(OUTPUT, {'schema_version': 1, 'status': 'incomplete',
                               'G1_complete': False, 'error': str(error)})
        print('harness error: ' + str(error), file=sys.stderr)
        sys.exit(2)
