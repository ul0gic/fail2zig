# Native acceptance and retained reference evidence

The project direction was reconciled on 2026-09-11: a reliable independent Zig replacement,
with no project-owned Python in runtime or tooling. This directory still contains earlier
Python reference probes/harnesses awaiting a scoped Zig replacement or retirement; no code
was removed by the documentation update.

Read the [harness transition](../../docs/parity/harness.md) and
[fixture contract](../../docs/parity/fixture-contract.md). The pinned reference is fail2ban
1.1.1 at f60978618a101427b06924fc932b44350fec2b63; source/package observations are historical
facts, not blanket product equality requirements. Original synthetic configuration/log
fixtures and sanitized real-log provenance remain useful.

Keep harness/fixtures JSON and its manifest unchanged as original evidence. Its reference
requirements/specifications describe the old contract and are not the current release scope.
Recorded command lines and output hashes belong to their dated receipts. Do not promote
3,061 specification records or a historical G1 pass into executed native feature coverage.

Reimplement useful fixture/observation/reporting and regression logic in Zig. Retire private
Python ABI, exact exception/output and universal catalog checks lacking a retained native
requirement. Add separate native expected outcomes for deliberate differences; do not rewrite
old oracles. Preserve INI fixes, all five SYS-029 observations, source continuity, transaction
rollback and error/capacity tests. Actual source/SQLite/journal/daemon execution is required
before standalone target claims; a successful cross-build or skip is insufficient.

Current build/test dependencies are described in [component status](../../docs/parity/p2-components.md).
The Python-free replacement gate and its command entry points remain implementation work.
