# Native configuration, import and administration contract

Reconciled 2026-09-11. Foreign syntax matters at the import boundary; native configuration,
commands and errors are independent product interfaces. This is a target contract; see
[current components](p2-components.md) for implementation limits.

## Effective configuration and admission

Maintain one typed native configuration model with checked durations, addresses, scopes,
source plans and explicit defaults. Validate cross-field constraints before activation.
Native settings must have clear units, ranges and error locations, without copying Python
ConfigParser exception classes or arbitrary expression evaluation.

For supported fail2ban imports, resolve actual include/conf/local ordering, interpolation,
parameters, inherited known values and source-specific defaults accurately. Preserve source
path/line/asset provenance and the effective value used. Existing layered parsing, checked
arithmetic, source preparation and guarded projection are reusable correctness work.

Every enabled protection group receives a disposition: supported mapping, required operator
change or blocker. Unknown/custom executable assets and unsupported matcher, scope, source,
policy or formula semantics remain visible with original data in a protected manifest. A
recognized service name does not prove custom filter equivalence. Never silently disable
unsupported protection and call the migration complete. Inspection and planning do not
execute imported commands, shell expansions or Python. Treat foreign configuration as data.

Configured file patterns/selectors and supported encodings have explicit startup/recovery
semantics. Distinguish an unavailable source from an empty healthy one. Allowlists support
literal addresses/networks without DNS; optional configured hostnames require bounded
resolution/cache/timeout/multi-answer behavior and last-valid-state handling. Arbitrary
ignorecommand execution is not required. Never silently widen an ignore after parse failure.

## Reload and administrative operations

Build and validate a proposed configuration generation before publishing it. Reject the
whole invalid transition, preserve current protection, and reconcile ownership/actions
against a coherent generation. Define restart-only settings explicitly. Coordinate in-flight
source records/checkpoints with reload; stale responses cannot mutate new state.

Provide native status/config validation, enable/disable/reload, ban/unban, history reset,
source health and local rule-test/explain workflows as supported typed operations. Keep
read-only queries free of action execution and bound result sizes/pagination. Authorization
and transport permissions must protect mutation and sensitive configuration data.

Deliver daemon/admin/diagnostic functionality through one executable, reusing existing
client behavior where useful. Final command spellings and schema versions require a reviewed
interface; do not document unimplemented examples as runnable. Structured output and exit
status distinguish success, rejected input, partial/uncertain effect and unavailable service.
No fail2zig-fail2ban adapter, exact legacy help/error text or private fail2ban socket protocol
is promised. Script migration maps supported workflows and identifies deliberate differences.

## Acceptance

Use original effective-config regression cases, boundary/overflow/cycle/unknown-asset cases,
manifest roundtrips and activation guards. Verify real daemon reload while sources and
protection are active, unauthorized IPC, stable structured output and bounded diagnostics.
Retain old oracle receipts and test useful semantics against Zig; foreign private-command
or exception-string equality is not a native acceptance gate.
