# fail2zig v0.3.0

Stabilization release: every open issue closed, validated on a real Debian 13 host with the shipping static binary. Adds an explicit observe-only escape hatch when no firewall backend is usable, makes `recidive` work on a default install, and ships mips. Thanks to @mwriter for the first external bug report (#45).

## Upgrade notes

- **A world- or group-writable `config.toml` now refuses to start** with the mode and the fix (`chmod 0640`). The installer already writes 0640; hand-managed configs may need the chmod.
- **State file format v4.** Older state files load unchanged; the first save writes v4. Downgrading to v0.2.x after that starts from empty state.
- **`state_file` on `/run` or tmpfs warns at startup** that state will not survive a restart. If you copied an early example that used `/run/fail2zig/state.bin`, move it to `/var/lib/fail2zig/state.bin`.
- **`recidive` no longer needs a log file.** A `[jails.recidive]` with no existing `logpath` is fed in-process from confirmed bans in the other jails; delete any `logpath` pointing at a log the daemon does not write.

## Added

- **`backend` jail key** accepted as a deprecated fail2ban alias of `source` (`systemd` → journald; `auto`/`polling`/`pyinotify`/`gamin` → auto). One deprecation warning per use. The importer emits `source`. (#45)
- **Config errors carry `file:line:col`, key and section**: `config: /etc/fail2zig/config.toml:37:1: UnknownKey (key 'logpaht' in [jails.sshd])`. Duplicate keys in a section are rejected. `--validate-config` prints one resolution line per jail. (#45)
- **`on_no_backend = "fail-closed" | "log-only"`** (default `fail-closed`). With `log-only`, a host with no usable firewall backend runs DEGRADED as observe-only instead of exiting; the cause (`missing CAP_NET_ADMIN`, no nf_tables, transient) is in `fail2zig-client status`, `/api/status`, `/metrics` (`fail2zig_protection_state{state="degraded"}`), and the event stream. A config whose jails are all `log-only` no longer needs a backend at all and runs unprivileged.
- **`recidive` fed in-process** via a new `internal` source; the default config escalates repeat offenders for the first time.
- **mips**: `mips-linux-musleabi` and `mipsel-linux-musleabi` static binaries (soft-float MIPS32r2), built and smoke-tested under qemu in CI. No real-hardware report yet; `install.sh` detects both byte orders.

## Changed

- **journald polling no longer blocks the event loop.** `journalctl` runs as a non-blocking child on the loop; IPC p99 under journald load is 4 ms (was 21 ms). No threads were added.
- **IPC status round-trip p99 under 1 ms** (was 3–6 ms): client and response buffers are pooled at startup instead of mapped per connection.
- **Firewall detection names its cause** and the nftables capability probe is a read-only `GETGEN`, so "missing CAP_NET_ADMIN" is reported at detect time instead of surfacing as a generic init failure.
- **Known startup failures exit 1 with the cause and no error-return-trace.**
- `fail2zig-client`: every table column sizes from its longest value; `Protection: DEGRADED (<cause>)`; a closed stdout pipe (`| head`) is a quiet exit.
- Source tree comment purge: comments are now only the few load-bearing *why* lines.

## Fixed

- **A log-only would-ban was persisted as a real ban** and reinstalled in the firewall by reconcile after a restart; expiry then called the backend to unban it. State v4 records enforcement; reconcile and expiry act only on enforced entries.
- **journald: one file descriptor leaked per poll** in the new loop-driven path, and entries logged between service start and the first poll were dropped as history. Both found on the real-box gate, both now covered by regression tests.
- State was saved twice on SIGTERM.
- Non-root: the "no usable backend" cause read `NotAvailable` instead of `PermissionDenied`.

## Internal

- Integration suites `startup_failclosed`, `config_diag`, `no_backend`; benchmark `loop_latency`; e2e `stabilization_live.sh`. ADR-007, ADR-011, ADR-012, ADR-013 recorded.
