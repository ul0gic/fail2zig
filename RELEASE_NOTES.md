# fail2zig v0.4.7

Version 0.4.7 is a stabilization release built on the reports from a production
install at 2,000 bans: idle CPU at that size falls from about 56 % of one vCPU to
under 3 %, a stop that took 49 seconds takes one, file sources that lose data on
a reboot can resume under an operator-chosen policy, `ignoreip` edits apply with
a reload, and per-jail exclusions can be managed at runtime. It addresses #98,
#99 and #103, and qualifies PortSentry stealth and UDP detection from #75.

## Changes

- Reduce the daemon's steady-state cost with many installed bans. The jail view
  is published only when it changes, effect owners are confirmed by key lookup
  instead of a scan of every live effect, and the journal source waits one
  second after an empty poll instead of spawning `journalctl` seven times a
  second. Measured on a one-vCPU Debian 13 host with 2,000 nftables bans: mean
  idle CPU 2.61 %, maximum 6.0 % in a five-minute window.
- Withdraw realized rules in batches at a healthy stop. With 2,000 bans the stop
  takes about one second in 32 turns instead of 49 seconds in 2,000.
- Add the `on_truncation` jail key for file sources: `refuse` (the default,
  today's behavior) pauses the source until `fail2zig repair-source` acknowledges
  the loss, while the daemon keeps running and other jails enforce; `restart`
  resumes at the new start of the file and records a durable continuity-loss
  event. `fail2zig status` lists paused sources and retained loss events. The
  same policy and the same command also cover a log deleted and recreated by
  its writer (PortSentry recreates its history file at every start): the
  source resumes at the start of the new file and records a `replaced` loss
  event; under `refuse` the printed `repair-source` command acknowledges it.
  A log recreated while the daemon runs is read without loss, and the old,
  unlinked file retires instead of counting against the source limit.
- Apply literal `ignoreip` edits through `fail2zig reload` without a restart
  refusal, and start on the existing state after a jail is added or enabled.
  The share of the subject budget each jail receives changes with the jail
  count and was part of every jail's saved identity, so adding a jail was
  refused with `RetryGenerationMismatch` until the state was recreated. Saved
  detection generations are rekeyed once at the first start so neither the
  ignore list nor that share forms part of their identity.
- Add `fail2zig ignore add`, `ignore remove` and `ignore list`. Runtime entries
  are stored in the state database, survive restart and reload, and merge with
  the configured `ignoreip`. An existing ban stays until its deadline unless
  `--unban` is given; the output names the ban and the command that lifts it.
  Each jail holds at most 128 entries, configuration and runtime combined.
- Qualify PortSentry 2.0.7 `--stealth -m pcap` detection for TCP SYN, FIN, NULL
  and XMAS scans and for UDP, in addition to `--connect`, each through ban,
  blocking while banned and expiry.
- Clean up committed receipts continuously. The cleanup walk no longer stops at
  the first receipt still held by a live ban: held receipts are set aside and
  deleted once their ban and retry window end, and everything behind them is
  cleaned in order. An install with long or permanent bans previously retained
  every receipt behind the oldest live ban until the 256 MiB state cap paused
  ingestion (#104). With 2,000 bans expiring, receipts fell to the held set
  within seconds on the lab host.
- Never dispatch a ban whose lease has already ended. A kernel element that
  timed out moments before the daemon processed the same deadline was re-sent
  with a deadline in the past, refused by nftables, and treated as backend
  uncertainty, which paused ingestion under short ban times with re-bans. Such
  an owner now goes to the expiry path instead.
- Read the nftables set back as one coherent netlink observation and retry an
  interrupted dump instead of trusting a partial one. `stats` reports the retries.
- Document the 256 MiB state-file cap and the pause-and-recover behavior when a
  commit finds the file full, and the `history_retention` and
  `history_max_matches` keys.
- Fix an applied `ignoreip` reload leaving every `ban`, `unban` and `ignore`
  command refused with a stale revision until restart, and list the `ignore`
  commands in `--help`.

## Upgrade and compatibility

The first start upgrades a state last written by v0.4.6 (schema 24) to schema 25
in place after writing `<state_file>.pre25-backup`; the upgrade needs free space
of twice the database size plus 32 MiB and resumes if interrupted. v0.4.6 is the
only supported upgrade source: states last written by older releases are not an
upgrade path, and v0.4.6 and older binaries refuse schema 25 state. Rollback
restores the backup with the v0.4.6 binary; the installation guide has the steps.

Ban deadlines, source checkpoints, SQLite WAL/FULL durability and firewall
ownership are unchanged. nftables, iptables and ipset remain supported. Existing
plain columns and JSON keys keep their meaning; `status` adds `paused_sources` and
a `sources` array, and the `ignore` commands add their own fields. Entries in a
custom-rule jail (`rule_files`) stay in its `ignore_file`; the runtime commands
refuse such a jail and name the file.

## Known limitations

- The state file is capped at 256 MiB. When a commit finds it full, ingestion
  pauses and retries while rules already in the kernel stay enforced; the file
  does not shrink, and cleanup frees pages only inside it. A receipt whose ban is
  permanent is kept for as long as that decision exists.
- A stopped daemon leaves its empty reserved nftables table. A second fail2zig
  installation on the same host refuses to start with `ForeignState` until that
  table is deleted; an in-place upgrade is unaffected.
- At 2,000 bans one status sample in 300 can report protection knowledge about
  five seconds old during idle. Stale status is not confirmation of current
  kernel protection.
- `list` can show a ban for a few seconds after `ignore add --unban` lifted it,
  until the next readback.
- Admin refusals are still printed as text on standard output in non-JSON modes.

## Verification scope

One campaign on a one-vCPU Debian 13 x86_64 host with the nftables backend
covered: the ignore commands end to end, including a 128-entry bound and a
v0.4.6-state upgrade; a 2,000-ban session for idle cost, stale knowledge, bans
under a running dump and the batched stop; the kernel-gated effect-runtime suite
on nftables, ipset and iptables; a 400-ban restart with a 600-second hold; a
sustained-load run at three records per second; a reboot with PortSentry history
truncation; and PortSentry connect, stealth and UDP detection. Component, fuzz and
release-local suites ran on the development host. Cross-builds for the other
targets do not imply live-kernel qualification there.

The five static Linux targets remain x86_64, aarch64, ARMv7 hard float, MIPS32r2
big endian and MIPS32r2 little endian. Verify downloads against `SHA256SUMS`.
