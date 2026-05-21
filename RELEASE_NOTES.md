# fail2zig 0.1.1

First patch release. Two correctness fixes for behavior the v0.1.0
schema documented but the daemon didn't actually deliver.

## Fixed

- **Per-jail `maxretry` / `findtime` / `bantime` / `bantime_increment` are now applied.** ([#14](https://github.com/ul0gic/fail2zig/issues/14)) In v0.1.0 these per-jail values were parsed but silently ignored — every jail received whatever was in `[defaults]`. v0.1.1 routes log matches through per-jail `StateTracker` instances, so an operator setting `[jails.nginx-botsearch].maxretry = 1` actually gets a maxretry of 1 on that jail.
- **`bantime_increment_multiplier` and `bantime_increment_factor` now accept fractional values.** ([#13](https://github.com/ul0gic/fail2zig/issues/13)) Both fields are `f64` in the schema, but the TOML parser was reading them as integers only. `factor = 1.5` for a softer escalation curve now works.

## Upgrade impact

- **Drop-in binary replacement.** No config changes required.
- **State file format bumped to v2.** v0.1.0 state files load via a one-shot migration shim and are auto-rewritten as v2 on the next checkpoint. No data loss.
- **Existing operators who worked around #14** by putting their tightest values in `[defaults]` will now get the per-jail values they actually wrote. Re-check `[jails.*]` blocks after upgrade — if `[defaults]` was intentionally binding, you may want to remove now-redundant per-jail entries.

## CI hygiene (no user-visible impact)

- `actions/cache` 4 → 5
- `actions/upload-artifact` 4 → 7
- `actions/download-artifact` 4 → 8

## Stats

- Binaries: x86_64-linux-musl, aarch64-linux-musl (stripped musl static)
- Tests: 625 passed, 7 skipped, 0 failed, 0 leaks
- 38/38 build steps clean

## Acknowledgements

[#14](https://github.com/ul0gic/fail2zig/issues/14) was discovered during Phase 9B live-demo provisioning on 2026-04-24 when per-jail overrides on the honeypot box silently did nothing.
