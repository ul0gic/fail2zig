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
| `fixture.zig` (`zig build build-load-fixture`) | State generator through the production Store APIs. The shapes `churn`, `hot`, `pinned`, `reuse` and `oracle-cases` build a state from nothing. `attach <state-dir> jail=NAME count=N [bantime_s=S seed=N sync=off]` appends N live bans with distinct 198.18.0.0/15 addresses to an existing daemon state (`fail2zig.sqlite` in `state-dir`) under that jail's own generation, policy and pipeline checkpoint, so the daemon starts on it as its own: the fast way to a 20k or 65k state for restart and readback measurements (about 60 bans/s at 20k live, 16 ms per ban with the product's 2 MB page cache). Run it with the daemon stopped, as the state's owner, on a directory that is not group- or world-writable. Every shape also takes `profile=1` (per-statement SQLite VM steps and full-scan steps on stderr, both connections), `audit=skip` (no end-of-run audit, which scans every table and takes minutes at 65k) and `cache_kib=N` (a harness-only `PRAGMA cache_size` for measuring the page-cache lever); the manifest's `stats.ban_loop_ms` times the ban loop alone. `attach` numbers its occurrences after the records already present for its source, so it can run repeatedly on one state. |

```bash
W=$PWD/.zig-cache/load-repro/run260
unshare --user --map-root-user --net bash tests/harness/load_repro/rig.sh zig-out/bin/fail2zig "$W" 260 2 600
unshare --user --map-root-user --net bash tests/harness/load_repro/restart.sh zig-out/bin/fail2zig "$W"
```

Arguments for `rig.sh`: binary, work directory, number of distinct source
addresses, records per second, ban time in seconds. `SETTLE_SECONDS` sets
how long sampling continues after the generator finishes.
