#!/usr/bin/env python3
"""Run one existing acceptance module; no builds, implicit binaries or lab connections."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
MODULES = ('smoke', 'enforcement', 'load', 'backend', 'restart', 'source-repair', 'counters',
           'notify', 'isolated-runtime', 'isolated-firewall', 'migration')
SUITES = {'smoke', 'isolated-runtime', 'isolated-firewall', 'migration'}
LIMITS = dict(smoke=180, enforcement=300, load=3000, backend=600, restart=1200,
              **{'source-repair': 300, 'counters': 360, 'notify': 900,
                 'isolated-runtime': 600, 'isolated-firewall': 600, 'migration': 900})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def executable(name, expected=None):
    path = Path(name).resolve(strict=True)
    require(path.is_file() and os.access(path, os.X_OK), f'not executable: {path}')
    actual = digest(path)
    if expected is not None:
        require(re.fullmatch('[0-9a-fA-F]{64}', expected), 'SHA-256 must contain 64 hex digits')
        require(actual == expected.lower(), f'identity mismatch: {path}')
    return path, actual


def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--preflight', action='store_true', help='validate only; do not create work or execute')
    parser.add_argument('--module', choices=MODULES)
    for option in ('binary', 'sha256', 'work', 'oracle', 'suite-binary', 'suite-sha256', 'fixture', 'old-binary', 'old-sha256'):
        parser.add_argument('--' + option)
    parser.add_argument('--backend', choices=('nftables', 'iptables', 'ipset'))
    parser.add_argument('--plumbing', action='store_true', help='load only; short exercise, never acceptance')
    args = parser.parse_args()
    if args.list:
        print('\n'.join(MODULES))
        sys.exit(0)
    for name in ('module', 'binary', 'sha256', 'work', 'oracle', 'backend'):
        require(getattr(args, name), '--' + name + ' is required')
    require(not args.plumbing or args.module == 'load', '--plumbing only applies to load')
    return args


def preflight(args):
    binary, sha = executable(args.binary, args.sha256)
    oracle, oracle_sha = executable(args.oracle)
    work = Path(args.work).absolute()
    require(not work.exists() and not work.is_symlink(), 'work must be a new directory')
    require(work.parent.is_dir(), 'work parent must already exist')
    work = work.parent.resolve() / work.name
    # Drivers embed paths in TOML; notify also uses systemd specifiers.
    for path in (binary, oracle, work):
        require(re.fullmatch(r'/[a-zA-Z0-9_./-]+', str(path)), f'unsafe driver path characters: {path}')
    require(args.module in {'isolated-runtime', 'isolated-firewall', 'backend'} or args.backend == 'nftables', 'module supports nftables only')
    tools = {'bash', 'unshare', 'ip', 'timeout', 'python3'}
    if args.module == 'enforcement':
        tools |= {'socat', 'ss', 'sha256sum'}
    if args.module == 'load':
        tools |= {'getconf', 'sha256sum'}
    if args.module == 'smoke':
        tools = {'unshare'}
    elif args.backend == 'nftables':
        tools.add('nft')
    else:
        tools |= {'iptables', 'ip6tables'}
        if args.module == 'backend' and args.backend == 'iptables':
            tools.add('iptables-save')
        if args.backend == 'ipset':
            tools.add('ipset')
    if args.module == 'notify':
        require(os.geteuid() != 0, 'notify must run as lab user, not root')
        tools |= {'sudo', 'systemctl', 'systemd-run', 'journalctl'}
    if args.backend in {'iptables', 'ipset'}:
        tools.add('sudo')
    for tool in sorted(tools):
        require(shutil.which(tool), f'missing prerequisite: {tool}')
    require(Path('/proc/self/ns/net').exists(), 'Linux network namespaces required')
    record = {'module': args.module, 'backend': args.backend, 'candidate': str(binary),
              'sha256': sha, 'oracle': str(oracle), 'oracle_sha256': oracle_sha,
              'qualification': 'plumbing-only' if args.plumbing else 'acceptance', 'work': str(work)}
    fixture_files = []
    if args.module in SUITES:
        require(args.suite_binary and args.suite_sha256, 'explicit suite binary and SHA-256 required')
        suite, suite_sha = executable(args.suite_binary, args.suite_sha256)
        record.update(suite_binary=str(suite), suite_sha256=suite_sha)
        if args.module == 'migration':
            require(args.fixture and args.old_binary and args.old_sha256, 'migration requires fixture directory, old binary and --old-sha256')
            fixture = Path(args.fixture).resolve(strict=True)
            require(fixture.is_dir(), 'fixture must be a directory containing state plus matching config.toml')
            for item in fixture.rglob('*'):
                require(not item.is_symlink(), f'fixture symlink refused: {item}')
                require(item.is_dir() or item.is_file(), f'nonregular fixture refused: {item}')
                require(not item.name.endswith(('-wal', '-shm', '-journal')), 'fixture must be a closed coherent snapshot')
            states = list(fixture.rglob('*.sqlite'))
            require(1 <= len(states) <= 7, 'migration requires 1..7 fixture databases')
            require(any((state.parent / 'config.toml').is_file() for state in states), 'missing paired rollback config')
            old, old_sha = executable(args.old_binary, args.old_sha256)
            fixture_files = [(p.relative_to(fixture), digest(p)) for p in fixture.rglob('*') if p.is_file()]
            record.update(fixture=str(fixture), fixture_sha256={str(p): h for p, h in fixture_files},
                          old_binary=str(old), old_sha256=old_sha)
        return record, work, None
    family = 'recovery' if args.module in {'restart', 'source-repair', 'counters'} else args.module
    driver = ROOT / family / (family + '.sh')
    require(driver.is_file(), f'missing driver: {driver}')
    helpers = {'enforcement': ['rig.sh', 'evaluate.py'], 'load': ['evaluate.py'],
               'backend': ['backend_check.py'], 'recovery': ['recovery_check.py'], 'notify': []}
    for helper in helpers[family]:
        require((driver.parent / helper).is_file(), f'missing helper: {helper}')
    if family == 'notify':
        for helper in ('recovery.sh', 'recovery_check.py'):
            require((ROOT / 'recovery' / helper).is_file(), f'missing recovery helper: {helper}')
    return record, work, driver


def kill_group(child, sig):
    try:
        os.killpg(child.pid, sig)  # start_new_session below establishes our exclusive process group.
    except ProcessLookupError:
        pass


def group_alive(child):
    # Ignore unreaped zombies: they cannot retain a listener, namespace or mutation authority.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / 'stat').read_text().rpartition(')')[2].split()
            if int(fields[2]) == child.pid and fields[0] not in {'Z', 'X'}:
                return True
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            # In restricted procfs, conservatively treat an existing group as live.
            try:
                os.killpg(child.pid, 0)
                return True
            except ProcessLookupError:
                return False
    return False


def invoke(command, env, cwd, log, seconds, cleanup_seconds):
    with log.open('ab') as output:
        child = subprocess.Popen(command, env=env, cwd=cwd, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=max(1, seconds))
        except subprocess.TimeoutExpired:
            code = 124
        except KeyboardInterrupt:
            code = 130
        if code == 0:
            # An exited shell may still have a child finishing its exit after
            # its cleanup trap's wait. Give that transition a bounded grace.
            until = time.monotonic() + 2
            while group_alive(child) and time.monotonic() < until:
                time.sleep(0.05)
            if group_alive(child):
                with log.open('ab') as diagnostic:
                    diagnostic.write(b'runner: child process group remained after cleanup\n')
                    for entry in Path('/proc').iterdir():
                        if not entry.name.isdigit():
                            continue
                        try:
                            fields = (entry / 'stat').read_text().rpartition(')')[2].split()
                            if int(fields[2]) == child.pid and fields[0] not in {'Z', 'X'}:
                                argv = (entry / 'cmdline').read_bytes().replace(b'\0', b' ')[:300]
                                diagnostic.write(f'pid={entry.name} '.encode() + argv + b'\n')
                        except (FileNotFoundError, ProcessLookupError, PermissionError):
                            continue
        # A successful parent exit is not success if it left live children behind.
        if child.poll() is None or group_alive(child):
            if code == 0:
                code = 125
            handlers = {sig: signal.signal(sig, signal.SIG_IGN)
                        for sig in (signal.SIGINT, signal.SIGTERM)}
            try:
                kill_group(child, signal.SIGTERM)
                until = time.monotonic() + cleanup_seconds
                while time.monotonic() < until:
                    child.poll()
                    if not group_alive(child):
                        break
                    time.sleep(0.1)
                kill_group(child, signal.SIGKILL)
                child.wait(timeout=10)
                until = time.monotonic() + 5
                while group_alive(child) and time.monotonic() < until:
                    time.sleep(0.1)
                require(not group_alive(child), 'owned process group survived cleanup')
            finally:
                for sig, handler in handlers.items():
                    signal.signal(sig, handler)
        return code


def suite_result(module, backend, log):
    text = log.read_text(errors='replace')
    passed = re.search(r'All ([1-9][0-9]*) tests passed', text)
    summary = re.search(r'([0-9]+) passed; ([0-9]+) skipped; ([0-9]+) failed', text)
    require(passed or summary, 'suite produced no nonzero test summary')
    skips = [line.strip() for line in text.splitlines() if 'SKIP' in line]
    if summary:
        require(int(summary[1]) > 0 and int(summary[3]) == 0, 'empty or failing suite')
        require(len(skips) == int(summary[2]), 'unattributed suite skips')
    allowed = []
    if module == 'isolated-firewall':
        if backend != 'ipset':
            allowed.append('isolated readback accepts kernel expiry between passes and refuses early removal')
        if backend != 'nftables':
            allowed.append('isolated nftables realizes the frozen scoped packet cells and recovers uncertainty')
        else:
            allowed.append('isolated fixed argv realizes the frozen scoped packet cells and exposes partial writes')
    require(all(any(name in line for name in allowed) for line in skips), 'unexpected required test skip')
    return {'passed': int(passed[1]) if passed else int(summary[1]), 'not_applicable': skips}


def run(args, record, work, driver):
    os.umask(0o077)
    work.mkdir(mode=0o700)  # Exclusive: never reuse or recursively remove user work.
    scenario = work / 'scenario'
    scenario.mkdir(mode=0o700)
    log = work / 'run.log'
    env = {k: v for k, v in os.environ.items() if not k.startswith('F2Z_')}
    env.update(F2Z_NATIVE_PARENT_NETNS=os.readlink('/proc/self/ns/net'),
               RATE='3', LOAD_S='1800', DRAIN_S='900', BANTIME='600', HOT_S='2',
               TARGET='400', HOLD_SECONDS='600', READY_SECONDS='60')
    if args.module in {'isolated-runtime', 'isolated-firewall', 'migration'}:
        env['F2Z_NATIVE_FIREWALL_TRANSPORT'] = args.backend
    if args.plumbing:
        env.update(LOAD_S='12', DRAIN_S='20', BANTIME='5', HOT_S='2')
    # Tool backends need host-root privilege for their command subprocesses on
    # the target; both forms still create a private network namespace.
    if args.backend in {'iptables', 'ipset'}:
        forwarded = ('PATH', 'F2Z_NATIVE_PARENT_NETNS', 'F2Z_NATIVE_FIREWALL_TRANSPORT')
        ns = ['sudo', '-n', 'env'] + [f'{key}={env[key]}' for key in forwarded if key in env] + [
            'timeout', '--signal=TERM', '--kill-after=10s', f'{LIMITS[args.module] - 5}s',
            'unshare', '--net', '--']
    else:
        ns = ['unshare', '--user', '--map-root-user', '--net', '--']
    started = time.monotonic()
    record.update(started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), exit_code=1, status='failed')
    code = 1
    try:
        # Recheck binaries immediately before executing; suites are separate artifacts, not candidate builds.
        executable(record['candidate'], record['sha256'])
        executable(record['oracle'], record['oracle_sha256'])
        if args.module in SUITES:
            executable(record['suite_binary'], record['suite_sha256'])
            if args.module == 'smoke':
                env['F2Z_TEST_DAEMON'] = record['candidate']
            else:
                env['F2Z_NATIVE_FIREWALL_TRANSPORT'] = args.backend
            if args.module == 'migration':
                fixtures = work / 'fixtures'
                shutil.copytree(record['fixture'], fixtures)
                copied = {str(p.relative_to(fixtures)) for p in fixtures.rglob('*') if p.is_file()}
                require(copied == set(record['fixture_sha256']), 'fixture membership changed during copy')
                for relative, expected in record['fixture_sha256'].items():
                    require(digest(fixtures / relative) == expected, 'fixture changed during copy')
                executable(record['old_binary'], record['old_sha256'])
                shutil.copy2(record['old_binary'], fixtures / 'fail2zig-v0.4.4')
                executable(fixtures / 'fail2zig-v0.4.4', record['old_sha256'])
                env['F2Z_LOAD_REPAIR_FIXTURES'] = str(fixtures)
            commands = [ns + [record['suite_binary']]]
        else:
            tail = [record['candidate'], str(scenario), record['oracle']]
            if args.module == 'restart':
                commands = [ns + ['bash', str(driver), mode] + tail
                            for mode in ('restart-populate', 'restart-check')]
            elif args.module in {'source-repair', 'counters'}:
                commands = [ns + ['bash', str(driver), args.module] + tail]
            else:
                if args.module == 'backend':
                    tail.append(args.backend)
                commands = [([] if args.module == 'notify' else ns) + ['bash', str(driver)] + tail]
        record['commands'] = commands
        for command in commands:
            executable(record['candidate'], record['sha256'])
            executable(record['oracle'], record['oracle_sha256'])
            if args.module in SUITES:
                executable(record['suite_binary'], record['suite_sha256'])
            if args.module == 'migration':
                executable(work / 'fixtures' / 'fail2zig-v0.4.4', record['old_sha256'])
            remaining = LIMITS[args.module] - (time.monotonic() - started)
            if remaining <= 0:
                code = 124
                break
            code = invoke(command, env, scenario, log, remaining, 120 if args.module == 'notify' else 60)
            if code:
                break
        if code == 0 and args.module in SUITES:
            record['suite'] = suite_result(args.module, args.backend, log)
        record['status'] = ('plumbing-pass' if args.plumbing else 'passed') if code == 0 else ('unqualified' if code == 77 else 'failed')
        if code and args.module in {'enforcement', 'load'}:
            summary = scenario / 'summary.json'
            if summary.is_file():
                verdict = json.loads(summary.read_text()).get('result')
                if verdict == 'incomplete':
                    record['status'] = 'incomplete'
    except KeyboardInterrupt:
        record.update(status='interrupted')
        code = 130
    except (OSError, ValueError, subprocess.SubprocessError) as failure:
        record.update(status='failed', error=str(failure))
        code = 1
    finally:
        record.update(exit_code=code, duration_seconds=round(time.monotonic() - started, 3))
        (work / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
    return code


def main():
    os.environ['PATH'] = os.environ.get('PATH', '/usr/bin:/bin') + ':/usr/sbin:/sbin'
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    args = parse()
    record, work, driver = preflight(args)
    if args.preflight:
        print(json.dumps(dict(record, status='preflight-only', note='No processes or namespaces started; runtime privileges not probed.'), indent=2))
        return 0
    return run(args, record, work, driver)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        print(f'acceptance: {error}', file=sys.stderr)
        sys.exit(2)
