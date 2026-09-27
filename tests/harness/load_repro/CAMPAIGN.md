# Load repair campaign

Failure-first matrix, fixtures and oracles for the load-intervention repair. Not part
of `zig build test` or CI. Expected results below were fixed before any candidate
code; a candidate never changes them to pass. Run artifacts go under
`.zig-cache/load-repro/repair-phase-N/`, one consolidated `result.json` per phase.

| File | Purpose |
|---|---|
| `fixture.zig` | Builds valid current-schema state through production Store APIs with a controlled clock; writes a manifest and checks integrity, foreign keys and application invariants |
| `oracle.c` | Independent retention oracle: complete ascending deletion vector under the shipped predicate at a fixed cutoff/fence, plus the non-resetting measurement wrapper and its negative controls |
| `kernel_oracle.c` | Reads nftables set elements over raw netlink without product code |
| `campaign.sh` | Runs a daemon workload in a rootless namespace with kernel and TCP oracles and positive controls |
| `rig.sh`, `restart.sh`, `measure.c` | Original reproduction rig; reused, not modified |

## Constraints

- Fixtures use only production Store transaction paths: detail-bearing history comes
  from `commitRecord` retry ingestion, not direct owner replacement or raw SQL. Never
  disable foreign keys or raise caps to make a state reachable; record the first cap
  or refusal instead.
- A diagnostic copy that bypasses an earlier failure is labeled as such and is never
  presented as an untouched daemon baseline.
- Daemon runs use an explicit binary path and its SHA-256; no shared `zig-out/bin`.
  State lives on non-volatile storage with mode 0700; sockets under `$XDG_RUNTIME_DIR`.
- CLI counts and the product inspector are not protection evidence.

## Fixture shapes

Each shape records: generator path and seed, controlled clock range, all table
counts, detail provenance, consumer/generation checkpoints, first cap/refusal, and
`PRAGMA integrity_check` / `foreign_key_check` results.

| ID | Shape | Expected observation on the current source |
|---|---|---|
| FX-1 | Near-cap distinct churn: finite distinct scopes confirmed and expired | First refusal is a stored-scope/revision/intent capacity reached while active scopes are far below 4,096, because history pins spent scopes |
| FX-2 | Hot subject: one `(family, subject)` with many retry-linked confirmations and details, optionally across jails | Reachable maximum is limited by owner-revision/intent caps before 65,536 events; record the actual bound |
| FX-3 | Permanently live oldest owner followed by churn | Confirmed-stream prefix reclamation stops at the pinned event; later consumed events are retained |
| FX-4 | Repeatedly reused scope | Obsolete revisions/intents/observations accumulate for the live scope beyond one retention window |

Each shape is paired, in the campaign, with a short natural ingestion tail and a
real-clock daemon restart on a copy.

## Retention oracle cases

The oracle computes the deletion order that the shipped one-row query would produce
when repeated at one transaction's cutoff and consumer fence. It has two independent
evaluators that must agree on every case: the shipped SQL repeated on a copy under an
explicit offline allowance, and an in-memory C evaluation of the same predicate.
The allowance is never a production fallback.

| ID | Case | Required oracle result |
|---|---|---|
| OR-1 | Age, count and byte candidates compete | Strict ascending sequence order of the combined predicate |
| OR-2 | Consumer lag: checkpoint 100, earliest otherwise eligible detail 101 | No deletion |
| OR-3 | Partial rebuild: A details 2/4, B details 1/3, `max_matches` 10→1 | First deletion is sequence 1, not 2 |
| OR-4 | Limit raised 1→10 with a stale count candidate | No deletion of details ineligible under the new limit |
| OR-5 | Repeated lower/raise/lower policy changes | Each result matches the policy current at that transaction |
| OR-6 | NULL and non-NULL evidence around the 16,384-byte subject limit | Only non-NULL evidence details are byte candidates |
| OR-7 | `max_matches` 0, 10 and 1024 | Zero makes every retained subject detail a count candidate |
| OR-8 | Age cutoff advancing between steps | Each step uses its own cutoff; an earlier newly eligible sequence is chosen first |
| OR-9 | Live insert between steps | Inserted detail participates from the next step at its sequence |

Negative controls, each expected to exit non-zero:

| ID | Control |
|---|---|
| NC-1 | Reduced progress budget forces `SQLITE_INTERRUPT` during a measured operation |
| NC-2 | Final summary/write statement fails after an earlier successful delete |
| NC-3 | Oracle and SQL evaluator deliberately disagree (injected off-by-one) |

Measurement never clears statement VM counters; it reads deltas and reports
progress callbacks separately.

## Daemon baseline and enforcement oracle

| ID | Case | Expected observation |
|---|---|---|
| BL-1 | Exact v0.4.4, about 200 distinct PortSentry bans | Reuse saved `run210`: `Interrupted` at 199 bans, about 580 s populated restart then re-interruption |
| BL-2 | Refactor head, same workload | Same failure class near 199 bans; any difference is recorded, not assumed |
| BL-3 | Kernel oracle during load and degraded status | Independently read elements equal the expected ban set; record whether entries persist while CLI confirmation is lost |
| BL-4 | TCP oracle with positive controls | Listener reachable before ban; banned source's fresh connections fail; unbanned control stays reachable; banned source reachable after expiry |
| BL-5 | Populated restart on preserved head state | Record stage timing, readiness and whether still-live bans keep their original deadlines |

Report probe interval, connection timeout, sample count and probe CPU separately from
daemon CPU. Sampling shows sampled outcomes only, not the absence of brief gaps.

## Running on the lab target

Daemon cases run on the lab target, not the development host. `campaign.sh`,
`rig.sh` and `restart.sh` work unchanged in rootless namespaces there; build
`kernel_oracle` on the target. Stage state under `/var/tmp` (the target's `/tmp`
is tmpfs) and keep socket directories mode 0700.

- The namespace has no route to or from the traffic peer without host routing or
  NAT changes, so TCP positive controls use local banned/unbanned sources inside
  the namespace.
- Saved state binds each file source to its host path and inode. State copied from
  another host migrates, then refuses admission with `RetryGenerationMismatch` or
  `ResumeLost`. Populated-restart cases therefore use state created on the target.
- The gated rollback case in `test-load-repair-migration` needs, under
  `F2Z_LOAD_REPAIR_FIXTURES`, a `fail2zig-v0.4.4` binary and each `*.sqlite` fixture
  next to the `config.toml` that created it on the same host. A fixture without its
  config checks only the refusal half and then fails the restore assertion.
- Isolated kernel cases in `test-native-effect-runtime` run with
  `F2Z_NATIVE_FIREWALL_TRANSPORT=<backend>` and `F2Z_NATIVE_PARENT_NETNS` set to the
  parent namespace link, under `unshare --user --map-root-user --net`.
