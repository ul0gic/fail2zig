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
| `measure.c` | Vendored-SQLite probe. `measure <state>` reports VM steps, full-scan steps and plans for each per-tick and maintenance query against the daemon's 1,000,000-step per-transaction budget (optional third argument: setup SQL or `@file`, applied read-write to a copy). `measure synth <copy> S D M E J` adds S subjects × D decisions (last M with details, evidence E bytes, J jails) of synthetic confirmed history. `measure retention <copy> max_matches [first] [page]` compares the shipped retention candidate with windowed variants (`SKIP_UNBOUNDED=1` skips the unbounded forms). `measure exec-measure <copy> "SQL"` runs one statement under the step counter, for example index creation. |

```bash
gcc -O1 -DSQLITE_OMIT_LOAD_EXTENSION=1 -I vendor/sqlite -o .zig-cache/load-repro/measure \
  tests/harness/load_repro/measure.c vendor/sqlite/sqlite3.c -lpthread -lm
W=$PWD/.zig-cache/load-repro/run260
unshare --user --map-root-user --net bash tests/harness/load_repro/rig.sh zig-out/bin/fail2zig "$W" 260 2 600
.zig-cache/load-repro/measure "$W/state/fail2zig.sqlite"
cp "$W"/state/fail2zig.sqlite* .zig-cache/load-repro/synth/ && .zig-cache/load-repro/measure synth .zig-cache/load-repro/synth/fail2zig.sqlite 100 1024 1024 0 2 \
  && SKIP_UNBOUNDED=1 .zig-cache/load-repro/measure retention .zig-cache/load-repro/synth/fail2zig.sqlite 1024 1 29
unshare --user --map-root-user --net bash tests/harness/load_repro/restart.sh zig-out/bin/fail2zig "$W"
```

Arguments for `rig.sh`: binary, work directory, number of distinct source
addresses, records per second, ban time in seconds. `SETTLE_SECONDS` sets
how long sampling continues after the generator finishes.
