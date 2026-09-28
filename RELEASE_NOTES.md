# fail2zig v0.4.6

Version 0.4.6 improves operator commands and output: sorted ban lists, on-demand
runtime statistics, and clearer protection status. It addresses #94 and #95.

## Changes

- Add `fail2zig list --sort` for numeric address ordering in human, plain and JSON
  output. IPv4 precedes IPv6; the default listing order is unchanged.
- Add read-only `fail2zig stats` and `stats --details`. These show the worker's
  published runtime snapshot, freshness and counters without triggering database
  scans or firewall inspection. Counters are cumulative since daemon start.
- Move periodic effect-view diagnostics from info to debug logging. Use `stats`
  when you want to inspect current counters without enabling debug logs.
- Distinguish configured MODE from observed PROTECTION in jail output. Unknown
  active counts are shown as unknown rather than zero; history is described as
  retained confirmations rather than lifetime bans.
- Keep every field visible in narrow-terminal `jails --details` using a stacked
  layout, including max retry, find time and ban time.
- Align command help, completions, example configuration and manual pages. Add
  pointers to existing per-jail commands and recommend `enforce` configuration
  instead of the deprecated `banaction` spelling.

## Upgrade and compatibility

Upgrading from v0.4.5 keeps native schema 24. This release does not change SQLite
WAL/FULL durability, ban deadlines, source-continuity checks or firewall ownership.
nftables, iptables and ipset remain supported.

Existing JSON fields are retained; jail output adds `enforce_configured` and the
query interface adds statistics. Scripts parsing plain jail counts must handle
`-` for an unknown count; known zero remains `0`. Human-readable layouts and labels
have changed. See the command migration guide for details.

Back up existing state before upgrading. The known direct v0.4.3-state upgrade
failure remains unresolved; do not assume an intermediate upgrade or a database
reset preserves that state. Schema-23 upgrades from v0.4.4 retain the existing
backup/rollback requirements described in the installation guide.

## Known limitations

- Sustained input can still outpace ingestion on small, slow-storage systems.
  This release makes no new throughput or enforcement-latency guarantee.
- A populated restart hold can report stale protection knowledge. Stale status
  is not confirmation of current kernel protection.
- A file truncated below its committed position still requires explicit offline
  source repair. The reported PortSentry reboot-truncation behavior is separate
  follow-up work; this release does not add automatic recovery or acknowledge
  missing input on the operator's behalf.

## Verification scope

Focused CLI, formatting and query checks, isolated enforcing-daemon/restart and
logging checks, independent source review, and manual command-output review cover
these changes. Release qualification also checks the versioned executable and the
existing PR/main CI and package-verification gates. Existing enforcement/storage
qualification is retained; long-load and populated-hold campaigns are not rerun
for this interface release.

The five static Linux targets remain x86_64, aarch64, ARMv7 hard float, MIPS32r2
big endian and MIPS32r2 little endian. Cross-builds do not imply live-kernel
qualification on every architecture. Verify downloads against `SHA256SUMS`.
