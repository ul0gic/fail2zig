#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Linux-only private mount/network/PID root for the original parity fixtures.

Invoked by run.py through unshare. No fallback to an unisolated execution exists.
Only runtime directories and individual device nodes are mounted from the host.
Code, reference inputs and native probes are staged copies, never the host repository.
"""
import ctypes
import os
from pathlib import Path
import subprocess
import sys


def mount(*args):
    subprocess.run(['/usr/bin/mount', *map(str, args)], check=True,
                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, timeout=10)


def readonly(path):
    mount('--bind', path, path)
    mount('-o', 'remount,bind,ro,nosuid,nodev', path)


def main():
    jail = Path(sys.argv[1]).resolve(strict=True)
    if jail == Path('/') or not (jail / 'work/request.json').is_file():
        raise ValueError('not a staged parity root')
    mount('--make-rprivate', '/')
    # The supported development profile uses merged /usr. Preserve symlinks;
    # conventional separate lib directories are also supported.
    for name in ('usr', 'bin', 'lib', 'lib64'):
        source = Path('/') / name
        target = jail / name
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        elif source.is_dir():
            target.mkdir(exist_ok=True)
            mount('--bind', source, target)
            mount('-o', 'remount,bind,ro,nosuid,nodev', target)
    for name in ('null', 'zero', 'urandom'):
        target = jail / 'dev' / name
        target.touch()
        mount('--bind', Path('/dev') / name, target)
    mount('-t', 'proc', '-o', 'nosuid,nodev,noexec', 'proc', jail / 'proc')
    for name in ('code', 'reference', 'work/binaries'):
        readonly(jail / name)
    os.chroot(jail)
    os.chdir('/work')
    # No mount/chroot capability remains available to fixture workers. Namespace
    # root is still an unprivileged host user; no setuid gain is allowed either.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), 'no_new_privs')
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                    ('inheritable', ctypes.c_uint32)]
    header = Header(0x20080522, 0)
    data = (Data * 2)()
    if libc.capset(ctypes.byref(header), ctypes.byref(data)):
        raise OSError(ctypes.get_errno(), 'drop capabilities')
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp',
           'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC',
           'PYTHONDONTWRITEBYTECODE': '1'}
    os.execve(sys.executable, [sys.executable, '-I', '-B',
              '/code/tests/parity/harness/run.py', '--internal'], env)


if __name__ == '__main__':
    main()
