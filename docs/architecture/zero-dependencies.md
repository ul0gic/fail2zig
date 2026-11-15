---
title: 'Runtime dependencies'
description: 'The static executable, embedded SQLite C and host tools required by each input and firewall path.'
sidebar_position: 1
category: Architecture
audience: engineer
last_verified: 2026-11-15
---

## One executable, explicit dependencies

fail2zig ships one static executable per architecture. Zig application code
embeds pinned SQLite C and links musl. Daemon, administration, rule testing and
migration share that executable. No Python runtime, SQLite server, SQLite CLI or
shared SQLite library is required for product operation.

Static linkage packages code inside an artifact; it does not remove that code
from the dependency or security boundary. SQLite updates require a new fail2zig
build, just as changes to the Zig application do.

## Requirements by path

| Path                 | Required host facilities                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------- |
| File input           | Read/search access to configured files and directories; Linux file notification and I/O interfaces. |
| Journal input        | journald and `/usr/bin/journalctl` (a fixed path, not a `PATH` lookup), plus admitted journal origins. |
| nftables enforcement | Linux nf_tables and CAP_NET_ADMIN; direct netlink, no nft CLI or libnftnl.                          |
| iptables enforcement | The host tools at fixed paths under `/usr/sbin` (`iptables`, `ip6tables`, their `-restore` and `-legacy-save` programs) and required kernel support. |
| ipset enforcement    | `/usr/sbin/ipset` together with the iptables tools above, and required kernel support.              |
| Durable state        | Writable persistent storage owned by the service UID.                                               |
| Named timezones      | The selected timezone data under timezone_root.                                                     |
| Shipped service      | systemd and the unit's required capabilities and filesystem access.                                 |

Host tools are invoked with structured argument arrays, not shell templates.
Attacker-provided log bytes are never evaluated as commands. `global.firewall`
can select a backend explicitly; a forced backend does not fall back silently.

## Why direct netlink for nftables

The nftables backend constructs typed messages and communicates with Linux
directly. It does not depend on executable discovery or on interpreting the nft
command's output. Enforcement intent is durable before dispatch; owned kernel
readback establishes installed protection afterwards.

This property belongs to the nftables path. Journal input and iptables/ipset
have the host-tool requirements above, even though the application is statically
linked. See [enforcement](netlink-interop.md).

## Privileges remain part of the contract

The shipped unit runs as the non-login `fail2zig` account, retaining
`CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_DAC_READ_SEARCH`. NET_RAW supports the
iptables ipset extension and permits raw IP sockets; AF_PACKET is excluded.
HTTP shares the same process and capabilities. The dedicated UID does not make
the daemon unprivileged or isolate its HTTP parser from enforcement authority.

Configuration and executables remain administrator-owned. Native state belongs
to the service UID. Monitoring-group members can read aggregate status; ban
lists, history and the firewall inventory need root or the daemon UID, and only
those two can mutate protection.

The daemon and its tools start no other programs. Every external program is run
with a fixed argument array, never through a shell. `support-bundle` additionally
runs `journalctl` and `nft --version` to describe the host; a missing `nft` is
recorded in the bundle and affects nothing else. The build has one optional
dependency, the Tracy profiler, linked only in a diagnostic build and never in a
release.

## Platform qualification

Five Linux artifacts are published: x86_64, ARM64, ARM hard float, MIPS32r2
big endian and MIPS32r2 little endian. Selected live qualification used Debian 13
x86_64 before the version-only change from the unpublished 0.3.1 candidate.
The 0.4.2 artifacts passed native/emulated command checks. Its firewall-observation
path also received isolated live nftables and iptables checks on x86_64.

The 0.4.3 PortSentry v2.0.7 recipe adds Debian 13 IPv4/IPv6 TCP-connect qualification
through nftables ban, expiry and restored connectivity.

Non-x86 targets have cross-build, static-inspection and QEMU smoke evidence;
real-hardware/kernel enforcement is untested. Ubuntu checks cover the 0.4.1 SSH
repair, not firewall support. Static musl linkage alone does not establish support
on every distribution, router or container.
Firewall effects are limited to the daemon's current network namespace; moving
it between namespaces through custom selectors or service overrides is unsupported.

See [artifact verification](../guides/verifying-zero-dependencies.md) and the
[trusted computing base](trusted-computing-base.md).
