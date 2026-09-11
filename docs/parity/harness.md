# Acceptance harness transition

Reconciled 2026-09-11. The existing P1/P2 Python comparison infrastructure is historical
implementation awaiting replacement or retirement. It is not the selected product/test
architecture. No conversion occurred in this planning update.

The legacy sources under tests/parity/harness and the comparison probes remain available for
inspection. Earlier receipts retain exact commands, versions, fixture/source/binary hashes,
raw traces, isolation checks, repetitions and known differences. Preserve versioned fixture
manifests and receipts unchanged. The historical G1 infrastructure pass is not candidate
feature acceptance; G2 was never passed.

## Retain useful verification, remove Python reliance

Implement the useful runner, fixture loading, bounded process observation, canonical trace,
resource/recovery checks and result reporting in Zig as their owning stages are delivered.
Retire upstream private-module/ActionInfo/traceback/command-string equality probes with no
remaining native requirement. Preserve their factual findings as dated data. This includes
ordinary tests, e2e/release runners, embedded Python strings and ignored project-owned tools;
there is no testing exception to the no-Python direction.

New native expectation sets must be separate from frozen original reference expectations.
Document deliberate semantic differences and test the native contract independently. Keep
original configuration fixes, source/recovery cases and all five ticket observations; classify
the latter against native policy instead of adjusting an oracle to make it green.

## Successor gate requirements

- Use original reviewed benign fixtures, deterministic clocks and explicit support scope.
- Record exact sources/toolchain/build options, candidate binary and fixture hashes.
- Bound input/output, time, memory and queues; isolate cases needing process/kernel effects
  in disposable environments and preserve management access during authorized lab work.
- Keep raw execution outcomes separate from parsed assertions and infrastructure failures.
- Distinguish native acceptance, reference facts, model controls and actual daemon/kernel tests.
- Report each selected requirement as passed/failed/skipped/unsupported/not-run with evidence;
  planned IDs and catalog metadata never count as executed tests.
- Qualify actual standalone target paths without Python or installed runtime libraries/helpers.

The final command interface will be documented when implemented. Current normal build/test
registration still includes dependency-bearing foundations; do not claim the candidate already
passes a Python-free gate. See [component status](p2-components.md),
[fixture contract](fixture-contract.md) and [delivery contract](profile-contract.md).
