# Native acceptance fixtures and reference provenance

Reconciled 2026-09-11. Native requirements determine acceptance; the pinned fail2ban inventory
is evidence and a source of useful cases, not a universal implementation denominator.

## Existing reference evidence

The original inventory pins fail2ban 1.1.1 commit
f60978618a101427b06924fc932b44350fec2b63 and records definitions, modes, configuration branches,
selectors and fixture metadata. Its 444 discovered definitions and 3,061 specification records
are not counts of executed candidate tests. Catalog/include/helper entries overlap and cannot
be treated as distinct supported features. Existing original synthetic inputs and sanitized
real-log provenance remain valuable. Source/package profiles do not certify candidate platforms.

Preserve the versioned JSON under tests/parity/harness/fixtures and its original manifest
hashes. Those files describe the earlier oracle contract. Do not rewrite expected values,
known gaps or ownership snapshots to manufacture agreement with new native semantics. The
current local requirements ledger holds the reconciled scope; it does not retroactively
change frozen receipts. Retain applicable license/source attribution, including the explicitly
upstream-derived date profile wherever its material remains.

## Active native fixture contract

For each selected capability, identify the native requirement, exact input/provenance,
supported mode/configuration, expected decision and relevant scope/time/state effects.
Include positive, negative and boundary cases, unsupported-input diagnostics, and resource
limits. Avoid tests that merely mirror implementation internals. Service-name equivalence
cannot establish native detector equivalence; qualify actual patterns and modes.

Preserve all 15 current detector registry entries as the baseline to requalify. Additional
catalog services/providers remain support candidates until selected for concrete deployments.
Selection creates explicit native behavior and environment acceptance, not an obligation to
implement each upstream file. A selected critical workload cannot be removed silently because
its implementation is difficult.

Keep deterministic clocks, bounded original records, file/journal occurrence identity and
repeatable recovery cases. Test config preparation separately from pattern matching and actual
action effects: successful configuration streams prove neither detection nor enforcement.
Meaningful source/correlation cases retain ordering and shared context; do not flatten a
session into unrelated single-record tests.

## Harness transition and evidence

Replace useful project-owned comparison/harness/test logic with Zig; retire private Python
module probes and incidental reference-cache/exception/ABI checks that no longer serve a
native requirement. Reference facts may become reviewed data fixtures with provenance and
native expected outcomes. No Python execution is required by the eventual normal gate.
Current Python files still exist; this documentation reconciliation does not convert them.

Reports identify exact candidate bytes/build/source, fixtures, clocks, environment, support
scope, expected/observed values and actual execution result. Separate skipped, unsupported,
not-run, intentional difference and failure. A planned test ID or matching input hash is not
a passing test. Only candidate/native acceptance plus the required real-system evidence can
close selected requirements; model controls and historical reference comparisons cannot.
