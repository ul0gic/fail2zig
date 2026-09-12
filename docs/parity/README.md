# Native replacement contracts and reference evidence

Updated 2026-09-11. fail2ban informs operational completeness and supported migration;
exact private APIs, Python behavior and universal catalog coverage are not product goals.
The target is a self-contained Zig application, one delivered executable and documented OS
requirements, with upstream SQLite embedded statically and disclosed. Journal input retains
the host's journald/journalctl; no embedded journal reader is required. This direction is
not yet implemented throughout the current 0.3.1-dev checkout.

| Document | Purpose |
|---|---|
| [Current components](p2-components.md) | Actual importer/source/helper/storage seams and remaining integration limits |
| [Native ingestion preview](native-runtime.md) | Explicit SQLite daemon activation, retry/restart behavior and remaining N2 limits |
| [Configuration and commands](config-command-contract.md) | Faithful supported import, native validation/reload and administration |
| [Runtime and storage](runtime-contract.md) | Bounded native processing, time/policy, embedded SQLite and recovery |
| [Actions](action-contract.md) | Exact scope/ownership, typed effects and uncertainty reconciliation |
| [Delivery/platforms](profile-contract.md) | Single executable, dependency disclosure and real target acceptance |
| [Source foundations](source-runtime.md) | Current source implementation findings and native replacement obligations |
| [Fixtures](fixture-contract.md) | Selected native acceptance and unchanged reference provenance |
| [Harness transition](harness.md) | Replace useful Python verification with Zig and retire incidental equality checks |

## Current versus planned

The default daemon uses its existing compiled filters/state/lifecycle. An explicit native
preview now selects SQLite-backed file/journal sessions and durable retry decisions, with
actual daemon file/restart acceptance at log-only scope. Enforcing activation remains refused.
Legacy staged Python/dynamic-libsystemd consumers remain separately. Configuration
preparation affects actual import/validation. The old default journald
path invokes journalctl, legacy firewall modes invoke tools, and distribution has separate
daemon/client binaries. These facts prevent a blanket current standalone claim.

The record store now retains its transactions through statically embedded upstream SQLite;
its dynamic loader and static-musl rejection are removed. Focused native/musl transaction and
process-death recovery tests pass. Custom-rule qualification and journal durability/integration still
need implementation/design work. No arbitrary Python/shell extension runtime, private socket adapter
or generic SQL dashboard is required. An optional future GUI remains uncommitted scope.

Reference inventories and dated P0/P1/P2 receipts retain their original expectations. Old
passes do not validate native replacements, and no changed requirement is certified merely
by this documentation. Upstream source paths/metadata have provenance; the date_profile.json
asset explicitly derives from upstream and retains its accompanying attribution. Do not
claim every asset is independently originated or erase notices during a rewrite.
