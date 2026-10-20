# Diag runs

One command runs one short, isolated check on a named scenario and keeps the evidence. Development tooling only: bash and Python 3 standard library, never shipped. The runbook for the telemetry stack around it is `.devops/README.md`; the scenario catalog is `.devops/scenarios.md`.

## diag-run

```text
diag-run --scenario NAME --binary PATH --sha256 HEX --check NAME [--minutes N] [--mode upgrade|candidate]
         [--rig] [--nlmon] [--label TEXT] [--out DIR]
```

| Option | Meaning |
|---|---|
| `--scenario` | Target: a Proxmox snapshot of VM 106 listed in `scenarios.md`. Rig: `empty`, or a directory holding `fail2zig.sqlite` (with its `-wal`/`-shm`) |
| `--binary`, `--sha256` | The candidate and its expected SHA-256; a mismatch stops the run before anything happens. Target runs need an x86_64 musl build |
| `--check` | A script in `checks/` |
| `--minutes` | Window length, 1 to 10 (default 5) |
| `--mode` | Target only. `candidate` (default): side by side with the installed service, in network namespace `f2z-diag` with a copy of its state, its own socket and unit `f2z-diag`, metrics on `172.16.150.253:9108`. `upgrade`: replaces `/usr/local/bin/fail2zig` and restarts `fail2zig` |
| `--rig` | Run in a rootless user and network namespace on the dev host instead of the target |
| `--nlmon` | Checks that support it also capture the namespace's netlink traffic (small CPU cost, so leave it off for CPU references) |
| `--label`, `--out` | Suffix for the run folder name; or an explicit run folder |

Evidence goes to `.project/diag-runs/<UTC time>-[rig-]<scenario>-<check>[-label]/`, with `summary.md` first: its `Result:` line is the check's verdict (`pass`, `fail`, or `info` for a measurement).

### What a target run does

1. Refuses if another `diag-run` on this host holds `.zig-cache/diag-run-target.lock`, or the running target holds `/run/f2z-diag-run.lock`.
2. `pve.py rollback <scenario>`, then `start` if the snapshot is disk-only; waits for SSH (key and option rule from `tech-stack.md`), restarts `systemd-timesyncd` and refuses to go on unless the target clock is within 1 s of the dev host (a memory snapshot resumes up to an hour behind). Both offsets go in `summary.md`.
3. Takes the target lock, stages the binary and this folder under `/var/tmp/f2z-diag/<run>/`, and runs `lib/target.sh prepare`.
4. For a `+diag` binary sets `FAIL2ZIG_DIAG_DIR` and `FAIL2ZIG_DIAG_DSN` (from `GLITCHTIP_DSN` in `.devops/.env`, sent over SSH stdin and stored in a root-only environment file). In candidate mode the namespace has only loopback, so the DSN points at `127.0.0.1:18000`, bridged to GlitchTip through a Unix socket.
5. Runs the check for the window, then collects `status.json`, `jails.json`, the diag JSONL, the unit's journal as `daemon.log`, `support-bundle.json` (a binary without the command records the failure in `support-bundle.err`) and `unit-status.txt`.
6. Saves Grafana's "f2z-target overview" for the window plus a minute each side: `grafana/overview.png` when the image renderer is installed, otherwise every panel's query result as JSON (the renderer is not installed today).
7. Always, even after a failure or Ctrl-C: `pve.py rollback baseline`, `start`, the same clock step, and confirms `fail2zig` is active before writing `summary.md`.

A target run takes the window plus 3 to 7 minutes: two rollbacks, and the candidate's start (0.4.7 needed 229 s to install 2,040 bans into the empty `f2z-diag` namespace on `v047-idle-2k-ram`). Nobody else uses the target meanwhile (`tech-stack.md`).

### What a rig run does

Starts the binary in `unshare --user --map-root-user --net` with two file jails (`portsentry` with maxretry 1, idle `sshd`), state under `.zig-cache/diag-rig/<run>/` (not tmpfs, kept afterwards), socket under `$XDG_RUNTIME_DIR/f2zd/`, metrics on `127.0.0.1:9108` inside the namespace (saved as `metrics.txt`). There is no Grafana data for a rig.

### Examples

```bash
B=.zig-cache/t6/out/bin/fail2zig      # zig build -Ddiag=true -Doptimize=ReleaseSafe --prefix .zig-cache/t6/out
tests/harness/diag/diag-run --rig --scenario empty --check idle --minutes 2 --binary $B --sha256 $(sha256sum $B | cut -d' ' -f1)
# diag-run: result: info: cpu 1.08% over 119 s; 23 readbacks (every 5.1 s); ...

tests/harness/diag/diag-run --scenario v047-idle-2k-ram --mode candidate --check idle --minutes 3 \
  --binary .zig-cache/t6/fail2zig-0.4.7 --sha256 01a6e60ba0b5adda9b4ee13ff79f7010375edc63ff8804dbc04cae682fe822c3
```

## rig-many

```text
rig-many N CHECK --binary PATH --sha256 HEX [--minutes M] [--scenario empty|DIR]
```

Runs N rig runs at once (at most 32), each with its own namespace, state directory and socket, into `.project/diag-runs/<time>-rig-many<N>-<check>/r1..rN`, and prints one result line per rig. It exits non-zero if any rig fails. Use it for functional checks; timing belongs on the target.

## Checks

A check is an executable in `checks/`. It runs as root in the daemon's environment, reads these variables, writes its files into `$F2Z_OUT`, and writes one line to `$F2Z_OUT/result.txt` beginning `pass:`, `fail:` or `info:`.

| Variable | Meaning |
|---|---|
| `F2Z_MODE` | `target-candidate`, `target-upgrade` or `rig` |
| `F2Z_SCENARIO`, `F2Z_SECONDS`, `F2Z_NLMON` | The run's scenario, window and `--nlmon` (`1` or `0`) |
| `F2Z_BIN`, `F2Z_SOCK`, `F2Z_CONFIG`, `F2Z_UNIT`, `F2Z_PID` | The daemon under test (`F2Z_UNIT` is empty in a rig) |
| `F2Z_NS_EXEC` | Prefix that runs a command in the daemon's network namespace (`ip netns exec f2z-diag` in candidate mode, empty otherwise) |
| `F2Z_PORTSENTRY_LOG` | The portsentry jail's log file |
| `F2Z_STARTED_AT`, `F2Z_READY_AT` | Epoch seconds of the daemon start and of its first status answer |
| `F2Z_DIAG_DIR`, `F2Z_HARNESS`, `F2Z_OUT` | Diag journal directory; this folder (for `gen/` and `kernel/`); output folder |

| Check | What it does |
|---|---|
| `idle` | Drives nothing. Samples daemon CPU and `status` each second, counts readbacks (changes of `confirmed_at_us`), records kernel element counts at both ends and every element add or delete. `info`, or `fail` if the daemon died or storage left `healthy`. Figures in `figures.json` |
| `upgrade` | Needs `--mode upgrade` on `v047-wall-2040`. Passes when the upgraded daemon reports at least 2,040 active bans and kernel elements, then bans 50 new sources (`198.18.8.41` onward) within the window |

## Generators (`gen/`)

- `gen/lines portsentry|sshd COUNT RATE [--start N] [--per-address K]` writes paced lines to stdout. Address `n` is `198.(18 + a/256).(a%256).(b+1)` with `a, b = divmod(n, 250)`, inside the RFC 2544 range 198.18.0.0/15 (128,000 addresses), so `--start 2040` continues where `v047-wall-2040` stopped. PortSentry lines use the 2.0.7 history format: `gen/lines portsentry 50 10 --start 2040 >> /var/log/portsentry.log`.
- `gen/sshd-journal COUNT RATE [START] [PER_ADDRESS]` (root) sends `Failed password for root from <IP> port <P> ssh2` to the journal, 3 lines per address by default.

**Can synthetic journal lines match the sshd jail?** Only through the emitter. The sshd jail accepts a journal record only with `_TRANSPORT=syslog`, `_UID=0` and an `_EXE` listed in `journal_executables` (`engine/core/native_journal_origin.zig`). `logger --journald` gives `_TRANSPORT=journal`, and `systemd-cat` gives `stdout`, so both are rejected (`origin_transport`). `gen/sshd-journal` therefore sends through `/usr/local/libexec/f2z-diag/sshd-emitter`, a root copy of `logger` writing to `/dev/log`, and keeps it alive 5 s after the last line, because journald reads `_EXE` from the live sender. That path must already be in `journal_executables` when the scenario's state is created: the list is part of the state's saved source profile, and a daemon whose list differs refuses to start (`RetryGenerationMismatch`). So `diag-run` copies the installed config unchanged apart from paths and metrics. No scenario lists the emitter today (the installed config has `/usr/sbin/sshd` and `/usr/lib/openssh/sshd-session` only), so synthetic sshd lines match nothing on the current scenarios; drive real SSH failures from `p33ker`, or build a scenario whose config lists the emitter.

In candidate mode the candidate and the installed service read the same PortSentry log, so generated PortSentry lines are banned by both. The final rollback removes both.

## Kernel truth (`kernel/`)

Run as root inside the daemon's namespace (prefix `$F2Z_NS_EXEC`).

- `kernel/nft-count` prints `table set elements` for every set of every `f2z_*` table (`nft -j list ruleset`).
- `kernel/nft-watch SECONDS` streams `nft monitor elements` with an epoch timestamp per line. The daemon's adds show as `create element`.
- `kernel/nlmon-capture SECONDS OUT.pcap` creates an `nlmon` interface, runs `tcpdump -s 256` on it and prints the packet count. It works on f2z-target and in the rootless rig on the dev host; it exits 3 when the `nlmon` module cannot be loaded.
