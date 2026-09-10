# Reference comparison tests

These are product behavior tests for the parity program. They require Zig 0.14.1,
Python 3.13.5 for the current reference profile and a clean, separately obtained fail2ban checkout pinned to
`f60978618a101427b06924fc932b44350fec2b63` (1.1.1). No upstream source or log fixtures
are vendored here. The configuration fixtures are original synthetic test data.

Run the initial configuration comparison from the repository root. On the development
Linux host, use a disposable user/network namespace with no external network:

```sh
unshare --user --map-root-user --net -- \
  python3 tests/parity/config_baseline.py \
  --reference /tmp/fail2ban-parity-reference-1.1.1 \
  --output /tmp/fail2zig-config-comparison.json
```

The runner builds a temporary ReleaseSafe probe of the real fail2zig INI loader and
compares it with the pinned reference reader. No daemon, firewall or action is started.
Configuration inputs and both observed values are retained in the JSON report, together
with source and binary hashes. Run serially with other Zig builds.

Exit 0 means these cases agree; exit 1 means actual behavior mismatches; exit 2 means
the comparison could not complete. Known issue links never turn a mismatch into a pass.
P0 initially observes four mismatches and two equal controls. This covers only config
layering/includes and a simple interpolation case. It does not certify the whole reader,
the application, platform support, or the later P1 trace harness.

## Reference identity and snapshot prototypes

```sh
timeout 30s unshare --user --map-root-user --net -- \
  python3 -I -B tests/parity/reference_semantics.py \
  --reference /tmp/fail2ban-parity-reference-1.1.1 \
  --output /tmp/fail2zig-reference-semantics.json

timeout 30s unshare --user --map-root-user --net -- \
  python3 -I -B tests/parity/sqlite_snapshot_probe.py \
  --output /tmp/fail2zig-sqlite-snapshot.json
```

The first probe checks 15 small reference-only contracts: captures, raw identifiers,
separate addresses, CIDR prefixes, and invalid/error/deadline outcomes. The deadline
control waits for a signal; it does not use an expensive regex. These are reference
observations and a worker prototype, not candidate parity or complete resource bounds.

The second constructs its own temporary databases and checks three snapshot scenarios.
It accepts no live-database path. Separate retained events/latest policy/active owners,
committed WAL-only data and unknown-schema rejection are tested. Runtime tickets,
concurrent writers, restrictive permissions and cutover remain separate work.

User/network namespaces isolate identity and networking, not the host filesystem.
These probes use private generated fixtures and do not start a daemon or action.
See [the compatibility contract](../../docs/parity/README.md) for claim boundaries.

## Controlled timing and action lifecycle

Build the small StateTracker probe serially with other Zig work, then compare its
observable ticket state with the pinned reference:

```sh
zig build-exe -O ReleaseSafe --dep state --dep shared \
  -Mroot=tests/parity/time_probe.zig --dep shared \
  -Mstate=engine/core/state.zig -Mshared=shared/root.zig \
  -femit-bin=/tmp/fail2zig-time-probe
timeout 60s unshare --user --map-root-user --net -- \
  python3 -I -B tests/parity/time_baseline.py \
  --reference /tmp/fail2ban-parity-reference-1.1.1 \
  --candidate-probe /tmp/fail2zig-time-probe \
  --output /tmp/fail2zig-time-comparison.json
```

The current seven component comparisons yield two agreements and five mismatches.
Startup/live timestamps, cleanup and history-weighting are separately observed in the
23 reference cases; they are not candidate ingestion tests. The dedicated maxretry=129
case demonstrates a component limit beyond the current native configuration's supported
range. Other comparative cases use supported threshold values. No action is dispatched.
The runner hashes the supplied binary; record its build command and inputs separately.

The [action contract](../../docs/parity/action-contract.md) gives the command for the
in-memory recorder probe. Sixteen reference cases verify lifecycle ordering, restored
suppression, errors and the distinction between ticket state and actual effects.
No configured action, command, provider or firewall is executed. These passes do not
certify a candidate action executor.

## Stock fixture metadata inventory

```sh
python3 -I -B tests/parity/reference_fixture_inventory.py \
  --reference /tmp/fail2ban-parity-reference-1.1.1 \
  --output /tmp/fail2zig-fixture-inventory.json
```

This reads source metadata, expected fields and LF-based record hashes/anchors without
importing upstream modules, evaluating conditions or executing sample records. It retains
symbolic option/condition state and lists unresolved expansion. Counts are declarations
and source references, not executed or passing tests. Original sample text is not copied.

## P0 mode, configuration and runtime contracts

The mode/config inventory commands also consume the local planning inputs under
`.project/parity/`. That directory is gitignored; these are current workspace probes,
not yet a standalone fresh-checkout CI suite. P1 must package a versioned harness input
bundle before advertising reproducible external acceptance.

```sh
timeout 120s unshare --user --map-root-user --net -- \
  python3 -I -B tests/parity/mode_test_inventory.py \
  --reference /tmp/fail2ban-parity-reference-1.1.1 \
  --output /tmp/fail2zig-mode-test-inventory.json

timeout 60s unshare --user --map-root-user --net -- \
  python3 -I -B tests/parity/config_command_contract_probe.py \
  --reference /tmp/fail2ban-parity-reference-1.1.1 \
  --source-audit .project/parity/source-audit.json \
  --output /tmp/fail2zig-config-command-contract.json

python3 -I -B tests/parity/runtime_contract_probe.py \
  --output /tmp/fail2zig-runtime-contract.json
```

The [mode contract](../../docs/parity/fixture-contract.md) maps definitions/generated
families and resolves sample eligibility/cache construction without executing records.
It records 775 repeated configuration-reader outcomes: 774 streams and one stable
standalone-helper interpolation error. They are not candidate comparisons.

The [configuration/command contract](../../docs/parity/config-command-contract.md)
adds 24 actual reference reader/formatter cases and ten separately labeled model controls,
including original SQLite publication transactions. The
[runtime contract](../../docs/parity/runtime-contract.md) adds 34 data/schema/transaction
controls. Model owner/barrier predicates do not prove a real supervisor, durable daemon,
arbitrary Python ABI or live source migration. Those require the later implementation gates.
