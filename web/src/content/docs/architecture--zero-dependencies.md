---
title: Zero runtime dependencies
description: fail2zig is a single static binary that speaks netlink directly to the kernel for every firewall operation. This page documents what that posture means in practice, which kernel ABIs the binary depends on, and why "exec nft safely" was not an acceptable alternative.
sidebar_position: 1
category: Architecture
audience: operator
last_verified: 2026-04-21
---

# Zero runtime dependencies

> A security tool should not be the source of risk it is protecting
> against. That thesis is not a tagline for fail2zig — it is a hard
> constraint that shapes every architectural decision.

## What this means

fail2zig is a single static binary. At runtime it depends on:

- **The Linux kernel** — specifically its netfilter, inotify, epoll,
  and systemd-journal ABIs.
- **Nothing else.**

No Python interpreter. No Perl. No Ruby. No Node. No Java. No C
library beyond the one statically linked into the binary (musl in the
release builds). No `iptables`, `nft`, `ipset`, `systemctl`, `curl`,
`wget`, or other CLI tool. No shell. No config-file preprocessor. No
SELinux helpers. No D-Bus. No plugins. No hot-loaded modules. No
eval, no dynamic code, no JIT.

This is a deliberately aggressive posture. The rest of this document
explains which kernel ABIs fail2zig actually depends on, why a
shell-action architecture was not an acceptable alternative for this
product in 2026, and what the posture costs.

## What fail2zig builds on

fail2ban pioneered this category in the early 2000s and has defended
Linux services on millions of machines for twenty years. Its
architecture — Python orchestration around shell-action templates that
invoke `iptables`, `ipset`, `nft`, or whatever firewall tool an
operator already runs — was a careful, considered choice for the
toolchain and threat model of its era. The mental model (jails,
filters, `maxretry`, `findtime`, `bantime`, `ignoreip`) is fail2ban's
contribution to the operational vocabulary of Linux security, and
fail2zig keeps it intact. Operators should not have to relearn the
category to adopt a new implementation of it.

What has changed in twenty years is the surface area around that
model. Static-linking toolchains, kernel ABIs mature enough to depend
on as library surfaces, and tightened expectations for what a
root-privileged daemon should and should not do. fail2zig takes
advantage of those changes. For the argument in full, see
[Why fail2zig](/why).

## Where a shell-action architecture gets expensive

Any daemon that reacts to matched log lines by forking a shell
template inherits a specific class of attack surface. The template is
expanded from config, with placeholders like `<ip>` and `<host>`
filled in from the log line's contents; the resulting command string
is handed to `/bin/sh` or `execve` for evaluation.

The effective trusted computing base for each ban fire includes:

- The orchestration daemon itself.
- The language interpreter it runs in.
- The shell binary (`/bin/sh`, commonly `dash` or `bash`).
- Every CLI the action template invokes (`iptables`, `ip6tables`,
  `ipset`, `nft`, …) and each of their transitive library
  dependencies.
- The `PATH` environment, and whatever binaries resolve against it.
- The action-template configuration files — essentially small
  programs — shipped by the distribution maintainer.

Compromising any link in that chain compromises ban enforcement.
Replace `/usr/sbin/nft` with a hostile binary and the shell-action
template executes it as root every time a ban fires. Coerce an action
template into composing attacker-influenced bytes into a shell command
and a remote-code-execution path opens on a server that was running
defensive software.

The CVE history in this space is structural, not implementation-level:
the ban-action path is a shell program, and a shell program that
processes attacker-derived inputs is an attack surface regardless of
how carefully each template is written.

## Why "pure netlink" is the answer, not "exec nft safely"

An obvious counter-proposal is to fork `nft` with arguments passed as
a discrete `argv` array (avoiding shell interpretation) and use
`execve` directly. fail2zig rejects that path for five reasons:

1. **`nft` becomes part of fail2zig's TCB.** Every ban depends on
   the correctness of `/usr/sbin/nft`, its version, its parser's
   handling of inputs fail2zig passes, and the integrity of the
   binary on disk. If the binary is replaced — by a compromised
   package mirror, a rootkit, a malicious admin — fail2zig silently
   runs hostile code with `CAP_NET_ADMIN` on every firewall
   operation.

2. **PATH attacks remain.** Even with a hardcoded absolute path,
   upgrades, installer bugs, and filesystem layout changes across
   distributions make the target location fragile.

3. **Version skew over time.** Pinning an exact `nft` version in
   fail2zig's install is unrealistic. Distributions upgrade; error
   message formats change; attribute emission defaults drift. Each
   upstream change becomes an upstream-driven regression fail2zig has
   to chase.

4. **The "zero runtime dependencies" claim on the README becomes
   untrue.** Product honesty matters. Operators choosing fail2zig are
   choosing a specific story — the binary is the trusted computing
   base — and a dependency on `/usr/sbin/nft` at runtime breaks that
   story.

5. **Performance matters too.** Shell-out adds a process spawn to
   every ban (typically 1–5 ms). The ban-latency p99 target is
   &lt;1 ms. Subprocess overhead makes that unreachable.

The pure-netlink path is more code, but it lives inside the fail2zig
binary, compiled with the same memory-safety guarantees as the rest
of the daemon, covered by the same test suite, shipped in the same
signed release. See [Netlink interop](netlink-interop) for the
case-study-level walkthrough.

## What fail2zig depends on, precisely

Zero runtime dependencies is a claim about what lives outside the
binary. It does not mean fail2zig implements its own TCP stack. The
boundary is: **fail2zig depends only on stable kernel ABIs that are
part of Linux's backward-compatibility promise.**

| ABI                              | Used for                                       | Stable since          |
| -------------------------------- | ---------------------------------------------- | --------------------- |
| netlink (`AF_NETLINK`)           | nftables / netfilter subsystem                 | Linux 2.2 (1999)      |
| inotify                          | Watching log files for new content             | Linux 2.6.13 (2005)   |
| epoll                            | Event loop                                     | Linux 2.6 (2004)      |
| `signalfd`, `timerfd`, `eventfd` | Signal + timer integration with the event loop | Linux 2.6.22 / 2.6.25 |
| `procfs` / `sysfs` (read-only)   | Capability checks, `/proc/self/status`         | Stable                |
| `AF_UNIX`                        | IPC socket between daemon and client           | POSIX                 |

These are kernel ABIs, not userspace libraries. They are the
lowest-level primitives available to any Linux program. Depending on
them is equivalent to depending on the kernel itself, which is
unavoidable for anything that runs.

## What fail2zig deliberately does not use

- **`libmnl`, `libnfnetlink`, `libnftnl`** — third-party C libraries
  for netlink helpers. fail2zig builds the TLV frames itself.
- **`libnl-3`, `libnftables`** — likewise.
- **`libcap`, `libcap-ng`** — capability manipulation. fail2zig reads
  `/proc/self/status` and uses the `prctl` syscall directly.
- **`libsystemd`** — the systemd client library. fail2zig reads
  `LISTEN_FDS` and `NOTIFY_SOCKET` environment variables and
  implements the small subset of the `sd_notify` protocol it needs
  in-tree.

Every one of those libraries is an opportunity for supply-chain
compromise. Every one adds transitive C dependencies (glibc, pcre,
json-c, …). None give fail2zig capabilities it could not build in a
few hundred lines of auditable Zig. The trade between "library
ergonomics" and "the binary is the TCB" is decided in favor of the
TCB every time.

## What this cost

Honest trade-offs:

- The initial `NewRule` payload took six hours of Zig + kernel-header
  reading + debugging against a live kernel to get right. A shell-out
  would have been 8 lines of code.
- Four production-impacting bugs were paid for in the netlink path
  across early phases (SYS-003, SYS-004, plus two closed in Phase 3).
  Every one of those bugs surfaced a class of failure that is now
  covered by regression tests. A shell-out would have avoided these
  particular bugs and introduced a different, less-bounded class in
  their place.
- Every new backend (iptables, ipset) follows the same rule: pure
  kernel ABI, no shell-out, no libc helpers. That is more work than
  "just exec iptables-restore."

The cost of the zero-dependency posture is real. The cost of the
alternative — a security tool that becomes the attack surface it was
meant to close — is higher.

## Implications for packaging and audits

For **distributors**:

- fail2zig has no package dependencies. On any Linux kernel ≥ 4.1, it
  runs.
- The release binary is `strip`ped and musl-linked. It runs on every
  distribution without worrying about glibc versions, library paths,
  or `LD_LIBRARY_PATH`.
- The install script creates a config directory and a systemd unit.
  It does not install or require any other package.

For **auditors**:

- The TCB is the fail2zig binary itself, plus the Linux kernel. No
  other userspace code is trusted by the daemon.
- Same source + same Zig version + same target triple =
  byte-identical binary (verified via `sha256sum` against the release
  manifest).
- fail2zig runs under systemd with `CapabilityBoundingSet=` restricted
  to `CAP_NET_ADMIN CAP_DAC_READ_SEARCH` and `ProtectSystem=strict`.
  Because the daemon never execs, those hardening flags cannot be
  bypassed by an intermediary.

For **operators**:

- `fail2zig --validate-config` validates a config without touching
  the firewall or starting event loops — no subprocess, no kernel
  state mutation.
- To audit a running daemon on your own system, follow
  [Verifying zero dependencies](../guides/verifying-zero-dependencies).

## Related reading

- [Trusted computing base](trusted-computing-base) — what actually
  runs as root and how it compares to a typical Python-based IPS.
- [Netlink interop](netlink-interop) — the case study for the
  scaffold installer, showing what "pure netlink" looks like at the
  byte level.
- [Verifying zero dependencies](../guides/verifying-zero-dependencies) —
  operator recipe for confirming the posture on a live system.
- [Why fail2zig](/why) — the rationale for picking this architecture
  in 2026 rather than incrementally improving a shell-action model.
- [Threat model](/threat-model) — the adversary model this posture
  defends against.
