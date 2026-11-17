---
title: 'Trusted computing base'
description: 'Application code, embedded SQLite, kernel interfaces, host tools and the service privilege boundary.'
sidebar_position: 6
category: Architecture
audience: engineer
last_verified: 2026-11-15
---

## What carries authority

The trusted computing base includes code and host facilities whose compromise
could alter protection. A static executable makes deployment compact, but is not
the entire trust boundary.

| Component                                                     | Role                                                                        |
| ------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Zig application and embedded SQLite C                         | Parse records, commit durable state, decide policy, administer and enforce. |
| Statically linked musl and build toolchain                    | Runtime support and artifact construction.                                  |
| Linux kernel                                                  | Filesystem, process, IPC, capabilities and firewall enforcement.            |
| `/usr/bin/journalctl` and journald                            | Journal input when configured; `support-bundle` also runs it to read the daemon log. |
| iptables and ipset tools under `/usr/sbin`                    | Backend operations when selected: `/usr/sbin/iptables`, `ip6tables`, `iptables-restore`, `ip6tables-restore`, `iptables-legacy-save`, `ip6tables-legacy-save` and `ipset`. |
| Configuration, logs, timezone data and filesystem permissions | Determine admitted inputs, policy and recovery.                             |
| systemd                                                       | Service identity, capability grants, filesystem restrictions and lifecycle. |

SQLite C is pinned and statically embedded. Zig's ReleaseSafe checks do not
prove memory safety of the complete process or remove the need to review C,
subprocesses and kernel interactions. The release includes `SQLITE-NOTICE.md`.

## Service identity and capabilities

The shipped unit uses `User=fail2zig` and `Group=fail2zig`, with:

- `CAP_NET_ADMIN` for firewall operations.
- `CAP_NET_RAW` for the iptables ipset extension, also allowing raw IP sockets.
- `CAP_DAC_READ_SEARCH` for protected log/journal reads.

The unit excludes AF_PACKET and restricts syscalls, writable paths and privilege
gain. These controls reduce exposure; they do not make parser or HTTP compromise
harmless. HTTP remains in the privileged daemon process. Disable the HTTP
listener with `metrics_enabled = false` when not needed; the socket stays
available. The socket is mode 0660, its runtime directory 0710 and the state
directory 0750, and the unit sets `UMask=0077`.

The installer can select a custom service/monitor group. The group grants
aggregate status, statistics and the redacted configuration. Ban lists, history,
the firewall inventory and every mutating request require root or the daemon UID. Native database
and parent ownership must match that UID; config/executable ownership stays with
administrators. See the [service unit](../../deploy/fail2zig.service).

## Data and recovery boundaries

Log bytes are untrusted data. Compiled built-ins and bounded JSON rules produce
typed subjects; they do not execute imported regex code, Python extensions or
shell action templates. Journal origin checks admit local machine identity, root
UID, transport and configured root-owned executables. They cannot prove that a
compromised authorized service logged the truth.

SQLite integrity checks and transactional recovery do not authenticate a database
against an attacker with authority to rewrite it. Protect the state directory and
coherent backups. Startup refuses unusable state instead of silently starting empty.

Offline migration rollback may temporarily need DAC_OVERRIDE, CHOWN and FOWNER to
restore original source metadata. Those belong only to the documented offline
restore command, never to the shipped daemon unit.

## Provenance and verification

The release provides SHA256SUMS and build-provenance attestations. Verify artifact
integrity and provenance before installation; neither proves the absence of defects
or a byte-identical local rebuild. Build provenance and reproducibility are separate
claims. See [verification commands](../guides/verifying-zero-dependencies.md).

The [threat model](../security/threat-model.md) records controls and remaining risks, including
privileged HTTP, resource exhaustion and forged authoritative logs. Independent
security audit remains planned, not a completed release property.
