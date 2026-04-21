# System harness

Shell-based harness that drives a **real running fail2zig daemon**
against synthesized traffic and observes real firewall state. Not part
of `zig build test` — requires a Linux lab host with `nftables` and
`systemd`.

Complements the three Zig-based test surfaces (`integration/`,
`benchmark/`, `fuzz/`) by exercising the paths they can't: inotify
delivery, systemd lifecycle, real `nft` rule installation, kernel DROP
on attacker traffic.

## Requirements

- Linux with `nftables`, `systemd`, `logger`
- `fail2zig` installed and active (or an in-tree build with matching
  config)
- Root or passwordless sudo for `nft` commands and log writes
- For `ssh_brute.sh` only: a second host (the attacker VM) with network
  reach to the target

## Scripts

| File | Purpose |
|------|---------|
| `reset.sh` | Clean-slate helper. Stops the daemon, drops `/var/lib/fail2zig/state.bin`, flushes the nftables table (tolerates ENOENT), truncates watched log files (preserves perms/ownership/inode), restarts the daemon, polls IPC until ready. `--no-start` leaves the daemon down. Idempotent. |
| `inject.sh` | Synthesize realistic log lines for a given jail. Usage: `inject.sh <jail> <source-ip> <count> [--delay-ms N]`. Supports `sshd`, `nginx-http-auth`, `nginx-botsearch`, `postfix`, `apache-auth`, `dovecot`. Writes via `logger` (sshd) or `sudo tee -a` for file-backed jails. |
| `observe.sh` | Sample daemon state into JSONL for post-run analysis. Usage: `observe.sh [--interval-ms N] [--output PATH] [--duration-s N]`. Polls the metrics endpoint, `/proc/<pid>/status`, and `nft list set` each tick. |
| `measure.sh` | One-shot performance probes, each emitting a single JSON line. Subcommands: `ban-latency`, `memory-per-ban`, `sustained-throughput`, `cold-start-with-state`. |
| `ssh_brute.sh` | Real SSH bruteforce from an attacker host. Usage: `ssh_brute.sh <target-ip> [attempts=5]`. Uses `hydra` when available, otherwise a serial `ssh`-with-bogus-credentials loop that produces the same auth-log pattern. Runs *on the attacker VM*, not the target. |

## Typical flow

```bash
tests/harness/reset.sh                        # clean slate
tests/harness/inject.sh sshd 198.51.100.7 10  # push 10 ssh failures
tests/harness/observe.sh --duration-s 5       # confirm the ban landed
tests/harness/measure.sh ban-latency          # record timing
```

The injected source IPs come from RFC 5737 TEST-NET-2 (`198.51.100.0/24`)
so synthesized traffic never collides with real-world addressing.

## Canonical smoke path

`make harness-smoke` runs `reset.sh` then `ssh_brute.sh` — the full
end-to-end path that validates inotify → parser → state → nftables →
kernel DROP on real attacker traffic. The only Makefile target that
assumes a lab host.

## Lint

All scripts are `shellcheck -S warning` clean. `make lint` exercises
them alongside `scripts/install.sh`.
