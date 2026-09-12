# Delivery, dependency and platform contract

Target direction reconciled 2026-09-11. There is one standalone product contract, with
explicitly qualified source/backend/platform capabilities. The old native-versus-full
CPython product profile is retired.

## Delivered artifact

One executable provides daemon, administration and diagnostics. Zig application code may
statically embed the selected upstream SQLite C engine. Application execution requires no
installed Python or SQLite service/CLI/shared library. Document embedded components and
mode-specific OS requirements: journal input uses host journald and journalctl. This is a
self-contained application with system integrations, not a promise of no OS tools. Do not claim all
source is Zig, zero supply-chain risk, or immunity from vulnerabilities.

Kernel interfaces, permissions, configured log availability, selected OS tools and an optional
service manager are operating prerequisites. Build tools are documented separately. All project-owned
runtime, tests, harnesses, release and local utilities must become Python-independent;
removing only files with a .py suffix is insufficient. Pinned upstream source snapshots
may remain comparison/provenance evidence, not executable dependencies of the candidate gate.

SQLite is chosen; size comparison is not an adoption blocker. Pin source/hash, preserve
licensing, review options and security updates, and validate the actual embedded build.
No final executable size has been measured for that integration. Approval of SQLite does
not authorize adding arbitrary libraries; additional embedded components require review.

## Current implementation conflicts and qualification

| Current component | Required disposition |
|---|---|
| Python source workers and comparison/release tools | Native replacement for useful behavior; retire private helper/oracle-only infrastructure. |
| record_store now statically embeds SQLite 3.53.4 | Native/musl transaction, pipeline and process-death checks pass; native checkpoint/daemon migration and wider target qualification remain. See vendor/sqlite provenance. |
| systemd_reader dynamic libsystemd; active journalctl path | Retain host journalctl as the accepted transport; preserve useful staged source invariants through that integration. Qualify journal-only ingestion, errors and durable cursor recovery. No embedded reader required. |
| Legacy iptables/ipset subprocesses | Retain fixed-argument OS-tool integration; qualify exact scopes, IPv4/IPv6 tools, timeouts and reconciliation. nftables direct netlink is baseline. |
| fail2zig plus fail2zig-client distribution | Consolidate into one delivered executable while retaining supported administration. |

The existing five cross-build targets and reference distro images are test inputs, not
runtime certification. Qualify intended architectures/libc/kernel/source/backend combinations
with actual candidate execution, including SQLite, journal recovery and kernel operations.
A cross-build, skipped test or an explicit unsupported-musl return is not acceptance.
Record exclusions with operator impact and migration blockers. Never change claims silently
to conceal an unimplemented required capability.

## Gate

Audit dynamic linkage, process execution, embedded snippets, packaging, CI and local utility
paths against the documented application/system boundary. Test with declared OS prerequisites
present and test visible failure when required journal tooling is absent or unusable. Record exact artifact identities.
Measure bounded memory/CPU/disk use for the delivered process model, crash/resource recovery
and equivalent-workload performance. No Python/full-profile certification or universal
provider/platform catalog completion remains required.
