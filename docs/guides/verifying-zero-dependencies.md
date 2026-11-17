---
title: Verifying a release build
description: Check release artifact integrity, static linkage, dependencies and host enforcement without assuming universal support.
sidebar_position: 6
category: Getting Started
audience: operator
last_verified: 2026-10-22
---

Static linkage, artifact provenance and installed protection answer different
questions. Verify each boundary before using a release on your host.

## Download and verify

Download the executable for your architecture, `SHA256SUMS` and the shared files
from the [releases page](https://github.com/ul0gic/fail2zig/releases). The
commands on this page use 0.4.9; set `V` to the release you are installing. For
x86_64, in a new download directory:

```bash
V=0.4.9
curl -fLO https://github.com/ul0gic/fail2zig/releases/download/v$V/fail2zig-v$V-x86_64-linux-musl
curl -fLO https://github.com/ul0gic/fail2zig/releases/download/v$V/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify fail2zig-v$V-x86_64-linux-musl --repo ul0gic/fail2zig
```

`sha256sum` prints `fail2zig-v0.4.9-x86_64-linux-musl: OK` for the executable.

`--ignore-missing` checks only files present locally; confirm an `OK` result for
every file you intend to install. A matching checksum establishes integrity
relative to the checksum file. Attestation adds build provenance, not a guarantee
that the source or toolchain is defect-free.

The packet has 13 assets: five executables, the unit, example config, installer,
two man pages, LICENSE, SQLITE-NOTICE.md and SHA256SUMS.
There are 12 content entries in the checksum file. No separate client asset ships.

## Inspect static linkage

```bash
file fail2zig-v$V-x86_64-linux-musl
readelf -l fail2zig-v$V-x86_64-linux-musl
readelf -d fail2zig-v$V-x86_64-linux-musl
```

The release executable is static: inspect for the absence of a dynamic program
interpreter and shared-library NEEDED entries. This does not mean it contains no
third-party code. Zig application code embeds pinned SQLite C and links musl.
No separate SQLite server, CLI or shared library is required at runtime.

Only after verifying the artifact:

```bash
chmod +x fail2zig-v$V-x86_64-linux-musl
./fail2zig-v$V-x86_64-linux-musl --version
./fail2zig-v$V-x86_64-linux-musl --help
```

## Check the selected runtime path

| Path           | Check                                                                                              |
| -------------- | -------------------------------------------------------------------------------------------------- |
| Files          | Service UID can read/search the selected paths; timestamp and rotation contracts match the source. |
| Journal        | journald/journalctl are present and origin checks admit the actual executable paths.               |
| nftables       | Kernel support and NET_ADMIN are available; application uses direct netlink.                       |
| iptables/ipset | Required host tools, kernel extensions and capabilities are available.                             |
| SQLite state   | Persistent parent/store belong to the daemon UID and systemd allows writes.                        |

The shipped service retains NET_ADMIN, NET_RAW and DAC_READ_SEARCH. NET_RAW is
needed by the iptables ipset extension and permits raw IP sockets. HTTP shares
the same capabilities; disable it if unused. See [runtime dependencies](../architecture/zero-dependencies.md).

## Verify installed protection

```bash
sudo fail2zig version
sudo fail2zig status
sudo fail2zig jails
sudo fail2zig list
sudo fail2zig firewall show
```

Inspect storage, source health, owners and enforcement outcomes. With HTTP enabled,
`curl --fail http://127.0.0.1:9100/api/health` checks readiness. A live connection
or a policy decision is not confirmation of installed protection.

Inspect the selected kernel backend and use a controlled external test path.
`fail2zig firewall show` reports the daemon's latest retained observation of its
owned protection; it does not refresh firewall state or prove packet reachability.
For nftables, `sudo nft list tables | grep ' f2z_'` finds the daemon's table and
`sudo nft list table inet f2z_<hash>` prints it. This is an optional independent
inspection; fail2zig's native nftables path does not require `nft`.

## Qualification tiers

| Artifact                | Evidence                                                                                                    |
| ----------------------- | ----------------------------------------------------------------------------------------------------------- |
| `x86_64-linux-musl`     | Selected Debian 13 live systemd/foreground, file/journal, backend, identity, recovery and migration checks. |
| `aarch64-linux-musl`    | Static cross-build, ELF inspection and QEMU command smoke.                                                  |
| `arm-linux-musleabihf`  | ARM hard float; static cross-build, ELF inspection and QEMU command smoke.                                  |
| `mips-linux-musleabi`   | MIPS32r2 soft float, big endian; static cross-build, ELF inspection and QEMU smoke.                         |
| `mipsel-linux-musleabi` | MIPS32r2 soft float, little endian; static cross-build, ELF inspection and QEMU smoke.                      |

The 0.4.0 release established the selected Debian 13 x86_64 baseline. The 0.4.1
SSH repair added isolated Debian and Ubuntu journal-origin and restart checks; that
does not establish Ubuntu firewall support. The 0.4.2 observation path received
isolated nftables and iptables checks, including retained stale state and nftables
inspection with the `nft` executable hidden. Live ipset observation, remote targets,
general end-to-end packet reachability and non-x86 hardware enforcement remain
unqualified by those observation checks. The separate 0.4.3 PortSentry v2.0.7
TCP-connect recipe was qualified on Debian 13 with IPv4/IPv6 nftables bans,
expiry and restored connectivity; see [its exact scope](portsentry.md).
The 0.4.4 firewall fixes also received isolated Debian 13 nftables and ipset
expiry-wave and live SSH enforcement checks. These do not qualify other hardware
or every firewall topology.

The 0.4.5 release qualified source repair, schema migration and rollback, plus
independent Debian 13 x86_64 nftables, iptables and ipset checks. Version 0.4.6
added focused command, formatting, query and restart checks. The 0.4.7 campaign
ran on a one-vCPU, 4 GiB Debian 13 host with nftables: the ignore commands, a
2,000-ban session, the kernel-gated suite on all three backends, a reboot with
PortSentry history truncation, and PortSentry connect, stealth and UDP detection.
The 0.4.8 campaign ran on the same host resized to 8 vCPU and 16 GiB: the schema 26
upgrade of a 65,536-ban state, a 65,536-ban cold restart, idle and stop, `banip`,
origins and timed entries, the lockout guard over SSH, online `repair-source`,
jail add and remove on reload, and the missing, truncated and replaced log cases.
For 0.4.9, a v0.4.8 state with sixteen jails and 5,000 bans was upgraded on that
host under the shipped unit, started, enforced a new ban, showed its matched
line, removed it and restarted with every ban in the kernel; no performance
figures were measured for 0.4.9.
Cross-builds for the other targets do not imply live-kernel qualification there.
See the [release notes](../../RELEASE_NOTES.md)
for the current release's verification scope.

Local builds can inspect and test the tagged source, but matching versions do not
establish byte-identical reproducibility. See the [build instructions](../operations/installation.md#build-from-source)
and retain your own toolchain/environment evidence.
