# Independent daemon acceptance

Run one capability against one explicit candidate. No command builds a candidate,
installs a service, runs a preceding scenario, or starts a performance campaign by
omission. `run.py --list` lists selections; `--preflight` checks inputs without
starting a process or creating the work directory.

Python 3.11+ is harness tooling only. The product remains Zig with embedded SQLite.
These adapters preserve the BUG-075/R3 scenarios formerly kept in lab scratch
scripts: enforcement=B1, restart=B2, notify=B4, source-repair=B3, counters=B8,
backend=B6, load=B5. The raw nftables oracle remains in `../load_repro/`.

## Build once

From the repository root (Zig 0.14.1):

```bash
zig build -Doptimize=ReleaseSafe --prefix .zig-cache/acceptance-bin
zig build build-smoke-tests build-native-effect-runtime-tests \
  build-native-firewall-tests build-load-repair-migration-tests \
  -Doptimize=ReleaseSafe --prefix .zig-cache/acceptance-bin
cc -O2 -Wall -Wextra tests/harness/load_repro/kernel_oracle.c \
  -o .zig-cache/acceptance-bin/bin/kernel_oracle
sha256sum .zig-cache/acceptance-bin/bin/*
```

The `build-*-tests` steps compile and install into the given prefix **without
executing**. Use `-Dtarget=x86_64-linux-musl` for the target binaries when needed.
Build the oracle for the target too. Record candidate and suite hashes from the
same source; hashes establish artifact identity, not matching-source provenance.
Do not rebuild or overwrite artifacts during a run.

## Select one module

On the authorized Linux test host, with the repository's harness directory and
artifacts present:

```bash
python3 tests/harness/acceptance/run.py --module backend --backend nftables \
  --binary /absolute/path/fail2zig --sha256 EXPECTED_64_HEX_DIGITS \
  --oracle /absolute/path/kernel_oracle --work /var/tmp/f2z-backend-new
```

`--work` must not exist; its parent must exist. Each run owns that directory,
its network namespaces, sockets and child processes. Drivers reject paths that
cannot safely be embedded in their generated configuration. Every run records
command, artifact identity, exit status and elapsed time in `result.json`, with
output in `run.log` and scenario data in `scenario/`. Missing tools, unexpected
skips, empty suites and incomplete evidence are not passes.

| Module | Independent behavior | Approximate fixed workload |
|---|---|---|
| `smoke` | Delivered daemon/client status, jails, version and deadlines | One existing integration case |
| `enforcement` | 210 bans, kernel membership, banned/reachable TCP controls, clean stop | 4/s, 60s settle, 120s hold |
| `backend` | Host IPv4 ban, readback, stop, restart with original deadlines, expiry and TCP controls | Three bans; 120s lifetime, 240s on ipset |
| `isolated-runtime` | Existing runtime ownership, recovery and failure cases | Existing suite; selected backend |
| `isolated-firewall` | Existing exact scope/IPv4/IPv6 and partial mutation cases | Existing suite; selected backend |
| `restart` | Creates 400 bans, restarts in a fresh namespace without moving sources, compares deadlines | 600s post-restart hold |
| `source-repair` | Truncation refusal, scoped offline repair, idempotent token, renewed ingestion | Own three-ban fixture |
| `notify` | Type=notify progress extends startup; stalled start times out without READY | 20s systemd timeout, own 400-ban fixture |
| `counters` | Warning, repeated-start error, clean reset | Own state across three starts |
| `migration` | Existing schema migration/crash/rollback suite with a genuine old state | Explicit fixture and released binary |
| `load` | Sustained arrivals, hot/permanent owners, expiry/retirement, drain, resource and latency evidence | 30min load + 15min drain |

Backend selection is required. `backend` and the two isolated suites support
`nftables`, `iptables` and `ipset`; other scenarios use nftables. The small backend
scenario covers IPv4 host entries; **scope/IPv6 coverage comes from the isolated
firewall suite**, not that three-ban scenario. Run it separately for each backend.

Compiled suites additionally require `--suite-binary /absolute/path/SUITE` and
`--suite-sha256 EXPECTED_HASH`. `smoke` uses `smoke-tests`; the other names match
the compile-only targets above. `F2Z_TEST_DAEMON` binds the smoke/integration
harness to the verified candidate, including its client subprocesses.

Migration also requires `--fixture /absolute/closed-fixtures`, `--old-binary`
and `--old-sha256`. The fixture root contains one to seven schema-23 `.sqlite`
files; at least one has its matching `config.toml` beside it. Preserve that
configuration's original sources and their identities. Never copy an active DB
without its WAL or migrate the sole incident copy. The runner copies and verifies
the closed fixture before the suite mutates its own copies.

Nftables work runs in disposable user/network namespaces. Iptables and ipset
modules use `sudo -n` to enter a separate root-owned network namespace because
their command helpers need host-root privilege on the qualification target; a
bounded root-side timeout covers the entire module. `notify` alone creates
uniquely named systemd units and named namespaces through `sudo -n`; it stops and
removes only those resources. It never changes the installed service. If startup
is too fast to exercise the timeout extension, it reports unqualified, not pass.
Run modules serially when comparing performance on a small target.

## B5 without the chain

Select `--module load` directly with the same explicit candidate arguments.
There are no dependencies on enforcement, restart or migration. The original
preset is 3 new subjects/s, a hot subject every 2s, 600s bans, 1800s load and 900s
drain. `--plumbing` selects a short mechanics-only exercise, clearly labelled;
it cannot satisfy the full performance requirement.

BUG-079 remains open: the R3 workload retained all subjects but failed the 5s p95
latency requirement. An expected failure still returns nonzero. The evaluator
bounds latency from the preceding absence to completion of first presence;
ambiguous samples are incomplete. Resource ceilings remain 150MiB RSS and 272MiB
DB+WAL. Idle CPU is measured, without the retired 2% gate. Review load-phase
plateau and hot-subject retention evidence separately where the automatic
summary cannot establish them; it must not claim full acceptance from latency
alone. Continuing a failed run's drain should answer a specific cleanup question.

For changes to test wiring alone, retained R3 evidence can validate the evaluator
and the short exercise can validate orchestration. That is not fresh full-load
qualification. Do not repeatedly run B5 to rediscover its known failure.

After acceptance and a local checkpoint, remove ordinary scratch runs. Preserve
only material needed by an active defect or release qualification. Git retains
scenario code; one module summary is enough, not a receipt per assertion.
