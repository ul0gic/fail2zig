---
title: Verifying zero dependencies
description: An operator-facing recipe for confirming that fail2zig is actually what it claims — a statically-linked binary that never execs another process and talks to the kernel directly over netlink.
sidebar_position: 3
category: Getting Started
audience: operator
last_verified: 2026-04-21
---

# Verifying zero dependencies

fail2zig's architectural claim is empirical. Either the binary is
statically linked, spawns no subprocesses, and talks to the kernel
directly — or it does not. Operators running a root-privileged security
daemon deserve to check that claim rather than take it on faith.

This guide walks through the verification every reviewer should be
able to run on their own system before deploying fail2zig in
production. Each check takes a few seconds and requires no special
tooling beyond what ships with any modern Linux distribution.

## 1. The binary is statically linked

A static binary has no dynamic library dependencies loaded at runtime.
Its full code is inside the ELF image itself.

```bash
ldd /usr/local/bin/fail2zig
```

**Expected output:**

```text
        statically linked
```

If `ldd` lists shared libraries, the binary was built without the
`-Dtarget=x86_64-linux-musl` flag, or the build picked up glibc
accidentally. Static linking is a release-build property, not an
architectural guarantee — debug builds are dynamic by default.

A second sanity check for musl-linked release binaries:

```bash
file /usr/local/bin/fail2zig
```

Look for `statically linked` in the output, and `ELF 64-bit LSB
executable` with no `interpreter` field.

## 2. The daemon never execs another process

Once fail2zig is running, it should not spawn any subprocess during
normal operation. There is no `fork`, no `execve`, no `system`.

```bash
sudo strace -f -e trace=execve -p $(pgrep fail2zig)
```

**Expected:** no output for the lifetime of the session. Watch for a
minute or two under normal ban traffic. Any `execve` of another
binary — `nft`, `iptables`, `sh`, `systemd-notify`, anything — is a
zero-dependency violation. If you see one, file an advisory via
[SECURITY.md](https://github.com/ul0gic/fail2zig/blob/main/SECURITY.md).

Press `Ctrl-C` to stop the trace when you have watched long enough to
be satisfied.

## 3. Inspect the actual syscall mix

A more complete view shows what fail2zig is doing. Expect to see log
watching, event-loop wakeups, and netlink traffic — nothing that
resembles a subprocess or a filesystem traversal.

```bash
sudo strace -c -p $(pgrep fail2zig) -- sleep 30
```

The `-c` summary (after 30 seconds of sampling) will list the
syscalls the daemon actually uses. Expected entries include:

| Syscall                             | Why fail2zig uses it                              |
| ----------------------------------- | ------------------------------------------------- |
| `epoll_wait`                        | Event loop waiting for watcher / socket activity. |
| `read`                              | Reading new bytes from log files.                 |
| `inotify_add_watch`, `inotify_read` | Watching log files for changes.                   |
| `recvmsg`, `sendmsg`                | Netlink traffic to the kernel firewall.           |
| `accept4`                           | Accepting `fail2zig-client` IPC connections.      |
| `timerfd_settime`                   | Driving ban expiry timers.                        |
| `write`                             | Writing operational logs to stderr / journal.     |

Entries that would be red flags: `execve`, `fork`, `clone` of a new
process (thread creation is fine), `openat` against `/usr/sbin/*` or
`/usr/bin/*`, `connect` to anything outside of the IPC socket and
netlink.

## 4. What talks to nftables at runtime

fail2zig reaches the kernel via netlink, which shows up as an open
socket on an `AF_NETLINK` address family.

```bash
sudo lsof -p $(pgrep fail2zig) | grep -i netlink
```

**Expected output:**

```text
fail2zig ...  NETLINK  ...  connection to "netfilter"
```

This is the socket fail2zig uses to install its scaffold, add
entries to the `banned_ipv4` / `banned_ipv6` sets, and drain ACK
replies. There should be no process spawning a `nft` binary on the
side. See [netlink interop](../architecture/netlink-interop) for the
message-level detail.

## 5. Confirm the kernel state matches claimed state

The last piece is verifying that bans the daemon reports are actually
installed in the kernel, not just remembered in daemon memory.

```bash
# List bans the daemon thinks are active.
sudo fail2zig-client list

# Query the kernel directly.
sudo nft list set inet fail2zig banned_ipv4
```

The two lists should agree. If the daemon claims a ban the kernel
does not know about, that is a reconciliation bug — file it via the
public issue tracker.

## 6. Reproduce the release binary yourself

For an auditor, the strongest verification is building the binary
from source and comparing checksums. fail2zig publishes reproducible
builds.

```bash
git clone https://github.com/ul0gic/fail2zig
cd fail2zig
git checkout v0.1.0   # or your target version
zig build -Doptimize=.ReleaseSafe \
          -Dtarget=x86_64-linux-musl

sha256sum zig-out/bin/fail2zig
curl -s https://fail2zig.com/releases/0.1.0/SHA256SUMS | grep fail2zig
```

The two `sha256sum` values should match, byte-for-byte. A mismatch
means the release artifact does not correspond to the public source
tree at that tag — worth escalating.

## 7. Signed releases

Release binaries are signed with `minisign`. To verify:

```bash
minisign -V \
    -P RWT... \
    -m fail2zig-x86_64-linux
```

The public key fingerprint is published on the releases page. If the
signature fails to verify, do not install the binary.

## When any of these checks fails

If the daemon is not statically linked, is spawning subprocesses, has
dynamic libraries visible in `ldd`, or fails to reproduce against the
published source tree, something is wrong. These are not tuning
issues. They are integrity violations.

- **Shared libraries in `ldd`:** the binary was not built with the
  musl target. Rebuild or download the musl release.
- **`execve` during normal operation:** a regression. File a security
  advisory via [SECURITY.md](https://github.com/ul0gic/fail2zig/blob/main/SECURITY.md).
- **`sha256sum` mismatch:** the binary you have is not the published
  binary. Discard it.
- **`minisign -V` fails:** the binary is not authentic. Discard it
  and escalate.

## Related reading

- [Zero runtime dependencies](../architecture/zero-dependencies) — the
  architectural principle these checks verify.
- [Trusted computing base](../architecture/trusted-computing-base) —
  why the absence of subprocesses and dynamic libraries matters.
- [Netlink interop](../architecture/netlink-interop) — what the
  `NETLINK` socket you see in `lsof` is actually doing.
