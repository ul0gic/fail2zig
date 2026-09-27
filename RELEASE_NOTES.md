# fail2zig v0.4.5

Version 0.4.5 repairs the load-triggered storage intervention and restart failures
reported in #91, and the incomplete firewall command usage text in #90. It also
corrects reload and migration ownership handling. No new integrations are added.

## Fixes

- Bound storage retention and recovery work so the reproduced 199-ban incident
  can continue ingesting and enforcing bans instead of entering intervention.
- Restore populated state with the original ban deadlines. Progressing startup
  extends the systemd notification timeout without claiming readiness early.
- Reduce repeated firewall readback and settlement work, service expiry and
  cleanup under load, and absorb transient backend uncertainty without pausing
  otherwise healthy ingestion. nftables, iptables and ipset remain supported.
- Report protection knowledge age, pending bans and overdue removals, keeping
  bookkeeping delay separate from confirmed over-blocking.
- Provide `repair-source` for explicit offline recovery from a truncated file
  source. Startup still refuses unacknowledged loss of source continuity.
- Preserve live bans and absent-owner history during a generation-changing reload.
- Limit migration rollback release to that migration's decisions; later native
  decisions and other owners of the same scope keep their protection.
- Include the already-supported `--details` option in `firewall --help` usage.

## Upgrade and rollback

The first start upgrades native schema-23 state to schema 24. A coherent
pre-upgrade backup is created before migration changes the database, and an
interrupted migration can resume. Keep that backup with its matching old binary.
Older binaries refuse schema-24 state: rollback requires restoring the matching
backup, and does not retain decisions made after that backup. Do not replace only
the binary and expect it to read the upgraded state. SQLite WAL with
`synchronous=FULL` remains unchanged by this release.

See the installation guide and `fail2zig(1)` for migration and source-repair
instructions. Source repair acknowledges a continuity break; it cannot recover
log entries already removed by truncation.

## Known limitations

- Sustained input can outpace ingestion on small, slow-storage systems. A
  30-minute lab workload at approximately 3.4 records/s on a one-vCPU,
  HDD-backed VM installed every subject but had p95 append-to-kernel latency
  of 57 seconds. This release does not promise five-second enforcement under
  that workload. New attackers remain unblocked until their records are handled.
- A 400-ban restart hold can report stale protection knowledge and degraded
  status. The observed failures retained 400 reported active bans and healthy
  storage; they did not demonstrate a lost ban. The readback cause and full
  transient duration remain under investigation. Stale status is not a
  confirmation of current kernel protection.

Both findings remain separate follow-up work. The original failed measurements
have not been relabeled as passing.

## Verification scope

Qualification covers the 210-ban incident reproduction, scoped source repair,
schema migration and rollback, and independent nftables, iptables and ipset
ban/readback/restart/expiry checks. Focused checks cover the reload and migration
ownership corrections. Existing unaffected scope and failure-path evidence is
retained; the known long-load and populated-hold limitations above are excluded
from this release's passing checks.

The five static Linux targets remain x86_64, aarch64, ARMv7 hard float, MIPS32r2
big endian and MIPS32r2 little endian. Live kernel qualification is on the
Debian 13 x86_64 lab; cross-builds do not claim live qualification on the other
architectures. Verify downloaded assets against `SHA256SUMS`.
