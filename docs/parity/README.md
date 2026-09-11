# Native replacement contracts and reference evidence

Updated 2026-09-11. fail2ban informs operational completeness and supported migration;
exact private APIs, Python behavior and universal catalog coverage are not product goals.
The target is a Zig application, one delivered executable and **zero external runtime
dependencies**, with upstream SQLite embedded statically and disclosed. This direction is
not yet implemented throughout the current 0.3.1-dev checkout.

| Document | Purpose |
|---|---|
| [Current components](p2-components.md) | Actual importer/source/helper/storage seams and remaining integration limits |
| [Configuration and commands](config-command-contract.md) | Faithful supported import, native validation/reload and administration |
| [Runtime and storage](runtime-contract.md) | Bounded native processing, time/policy, embedded SQLite and recovery |
| [Actions](action-contract.md) | Exact scope/ownership, typed effects and uncertainty reconciliation |
| [Delivery/platforms](profile-contract.md) | Single executable, dependency disclosure and real target acceptance |
| [Source foundations](source-runtime.md) | Current source implementation findings and native replacement obligations |
| [Fixtures](fixture-contract.md) | Selected native acceptance and unchanged reference provenance |
| [Harness transition](harness.md) | Replace useful Python verification with Zig and retire incidental equality checks |

## Current versus planned

The active daemon uses its existing compiled filters/state/lifecycle. New configuration
preparation affects actual import/validation. New file/journal/record-processing sessions
remain component foundations, with Python workers, dynamic SQLite/libsystemd and target
limitations; they are not general daemon-wide native ingestion. The old active journald
path invokes journalctl, legacy firewall modes invoke tools, and distribution has separate
daemon/client binaries. These facts prevent a blanket current standalone claim.

The accepted storage direction retains useful SQLite transactions and removes dynamic
loading. Custom-rule language/engine and journal/backend transport/support still need
feasibility decisions. No arbitrary Python/shell extension runtime, private socket adapter
or generic SQL dashboard is required. An optional future GUI remains uncommitted scope.

Reference inventories and dated P0/P1/P2 receipts retain their original expectations. Old
passes do not validate native replacements, and no changed requirement is certified merely
by this documentation. Upstream source paths/metadata have provenance; the date_profile.json
asset explicitly derives from upstream and retains its accompanying attribution. Do not
claim every asset is independently originated or erase notices during a rewrite.
