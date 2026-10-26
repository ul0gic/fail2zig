# Load reproduction rig

Drives hundreds of distinct PortSentry-style bans through a real fail2zig
daemon with the nftables netlink backend, inside a rootless user + network
namespace. No root, no `nft` CLI and no live host are needed; the kernel
must allow unprivileged user namespaces and `nf_tables`.

Not part of `zig build test`. Run artifacts belong under
`.zig-cache/load-repro/`; the state file must sit on non-volatile storage
and the IPC socket under a short path (the scripts use `$XDG_RUNTIME_DIR`).

| File | Purpose |
|------|---------|
| `rig.sh` | Starts the daemon with two file jails (`portsentry`, maxretry 1; idle `sshd`), appends distinct scan records at a fixed rate, samples `status` JSON and daemon CPU once per second, and stops when storage leaves `healthy` or the generator has settled. |
| `restart.sh` | Restarts the daemon on the preserved state directory in a fresh namespace (no scaffold, like a reboot) and records time to readiness. |
| `fixture.zig` (`zig build build-load-fixture`) | State generator through the production Store APIs. The shapes `churn`, `hot`, `pinned`, `reuse` and `oracle-cases` build a state from nothing, one record per transaction. `attach` appends bans to an existing daemon state; see below. Every shape also takes `profile=1` (per-statement SQLite time, VM steps and full-scan steps on stderr ranked by elapsed time, both connections, with a `capacity counts` section for the unfiltered `SELECT count(*) FROM <table>;` checks, and `sqlite_api` prepare/step/finalize/exec calls and nanoseconds in the manifest), `audit=skip` (no end-of-run audit, which scans every table and takes minutes at 65k) and `cache_kib=N` (a harness-only `PRAGMA cache_size` for measuring the page-cache lever). |

```bash
W=$PWD/.zig-cache/load-repro/run260
unshare --user --map-root-user --net bash tests/harness/load_repro/rig.sh zig-out/bin/fail2zig "$W" 260 2 600
unshare --user --map-root-user --net bash tests/harness/load_repro/restart.sh zig-out/bin/fail2zig "$W"
```

Arguments for `rig.sh`: binary, work directory, number of distinct source
addresses, records per second, ban time in seconds. `SETTLE_SECONDS` sets
how long sampling continues after the generator finishes. `JAILS=n` runs n
enforcing `portsentry` jails: after readiness, `portsentry-2` to `portsentry-n`
(maxretry 1) each get one line from 192.0.2.j on their own log, outside the
generator's addresses, and the rig waits until each holds its ban, so every jail
has a daemon-written checkpoint; the generator feeds only `portsentry`.
Unset, the rig has today's two jails.

The Python feeder uses monotonic absolute pacing and reports its achieved rate.
It accepts up to 131,072 distinct addresses. Startup failure, unhealthy storage,
feeder failure and incomplete ingestion return nonzero; the rig stops its own
child processes on exit.

## Appending bans with `attach`

```bash
f2z-load-fixture attach <state-dir> jail=portsentry,portsentry-2 count=5000 sync=off
```

`attach` appends `count` live bans to `fail2zig.sqlite` in `state-dir` so the
daemon starts on it as its own. Run it with the daemon stopped, as the
state's owner, on a directory that is not group- or world-writable. It
writes `fixture-attach.json` beside the state and refuses to overwrite one.

| Part | What `attach` does |
|------|--------------------|
| Writes | Group-commit frames of the Store's 64 records (`beginBatch`, `openBatchRecord`, `reserveReceiptStep`, `closeBatchRecord`, `commitBatch`), then one `settleInstalled` readback per frame; one sampled record per frame must have both action targets confirmed |
| Refusal | The refused record is dropped, the records before it are committed and settled, `first_refusal` and `attach.attempted`/`committed` are recorded, and the run stops with the state kept as evidence |
| History | The saved history consumer is restored as the daemon restores it (a base without one is a harness failure); with `normalize=1` (default) the base backlog is consumed first (`attach.history.base_backlog`), and the consumer and retention run after every frame; `normalize=0` leaves the appended backlog declared in `attach.history.backlog` |
| Recurrence | Not processed: every subject is fresh |
| Clock | Starts at the larger of wall time and the persisted receipt and admission floors, advances 1 µs per record and re-syncs to wall time at each frame; a floor above wall time sets `attach.clock.future_dated` and is never lowered |
| Jails | `jail=` takes up to 16 distinct existing jails; bans go round-robin under each jail's own generation, decoded policy (`bantime_s` is ignored) and pipeline checkpoint, and occurrences number after the records already present for the fixture source, so `attach` can run repeatedly on one state |
| Addresses | Sequential in 198.19.0.0/16 from `address_start=` (default 0; `address_start + count` at most 65,536), disjoint from the rig's first 65,536 generated addresses. The rig can generate 131,072 distinct addresses in 198.18.0.0/15; its second half overlaps the fixture range |
| Timing | `build_mode` records the generator's optimization mode; `timing_ns` covers open, restore, base_catchup, append, final_normalize, close and audit; `attach.chunks` samples elapsed time and page-cache hits and misses every 1,024 bans and at the end |
| Publication | With `normalize=1`, `attach.publication.failures` names every failed check: refusal, harness failure, future-dated clock, `kept_existing`, history head not at the consumer checkpoint, pending receipts, live (`lease_kind<>0`) `native_effects` or `effect_owners` growth other than `count` (spent-scope pruning removes only spent rows), any action target not confirmed. Any failure, a refusal or a harness failure exits 1 |

### Measured build times

Dev host, rootless, ReleaseFast, `sync=off`:

| Build | Time | Before |
|-------|------|--------|
| 5,000 bans, one jail, history at the head, retention run each chunk | 19.5 s | 27.1 s, with no history work |
| 20,000 bans, one jail | 85.4 s | 108.8 s |
| 5,000 bans over 16 jails | 21.4 s | — |
| Daemon restart to ready, one-jail 5k state | 19 s | — |
| Daemon restart to ready, 16-jail 5k state (5,016 active bans) | 34 s | — |

Of a 5k build, 12.0 s is SQL preparation inside the Store (120 prepares per
ban) and 0.35 s the capacity counts; the fixture cannot reduce either.

### Constraints

- Restart a state under the exact source configuration (jail `logpath`s) of
  the base it came from. If you relocate a state and rewrite the logpaths, the
  daemon refuses it with `RetryGenerationMismatch`.
- With `normalize=1`, retention runs with the fixture's `retention_s` and
  `max_matches`. Their defaults equal the daemon's; pass the base daemon's
  configured values when they differ.
