# Deployment-regression e2e harness

The fifth test surface. Installs the **real ReleaseSafe static-musl
artifact** via `scripts/install.sh` and runs the daemon under the
**unmodified shipped systemd unit** `deploy/fail2zig.service`, then asserts
the deployment invariants that nothing else in the project can see.

Not part of the local aggregate: it needs a real systemd host and root.

## Why this exists

SYS-019 was a CRITICAL regression: the daemon crash-looped under its own
shipped unit. A daemon-side `chown` is a `@privileged` syscall that the
unit's `SystemCallFilter=~@privileged` SIGSYS-kills, and `CAP_CHOWN` is not
in the bounding set — so the chown could never succeed anyway. The fix
moved socket/dir ownership to systemd. The current unit uses both
`User=fail2zig` and `Group=fail2zig`; it permits SQLite's `fchown` call
without granting `CAP_CHOWN`.

That class of bug is **invisible** to everything else we run:

- `zig fmt`, `zig build`, `zig build test` only ever see `.zig` files —
  never the unit file, the seccomp filter, or the capability set.
- Unit and integration tests run **non-root with no systemd sandbox**, so
  the seccomp/capability surface that killed the daemon is never exercised.

The only thing that catches it is installing the real artifact and running
the real unit on a real systemd box. This harness is that, scripted so it
can never silently reship.

## What it asserts

1. Service reaches `active (running)` with `NRestarts=0` (a non-zero
   restart count is the crash-loop signature of SYS-019).
2. **No** `SIGSYS` / seccomp / chown markers in the service's **current**
   systemd invocation — scoped via `_SYSTEMD_INVOCATION_ID`, never `-b`
   (boot history may contain pre-fix crash-loops, which would
   false-positive).
3. `/run/fail2zig` is `fail2zig:fail2zig` `0750`. The shipped unit ships
   `RuntimeDirectoryMode=0710` — that is only the transient pre-daemon
   value; the daemon chmods the directory to `0750` at startup (the
   `fchmodat` in `ensureSocketDir` kept by the SYS-019 fix). The harness
   checks **steady state** after the service is active, so `0750` is the
   correct invariant.
4. Socket `/run/fail2zig/fail2zig.sock` is `fail2zig:fail2zig` `0660`.
5. A root client connects (`fail2zig status`).
6. A `fail2zig`-group user connects (non-root).
7. A non-group user (`nobody`) is denied — client exit code `3` plus the
   daemon's own `requires group 'fail2zig' membership` message.

## Requirements

- A **real systemd PID 1**: a VM, a `systemd-nspawn --boot` container, or
  bare metal. A plain network namespace is **not** enough — it gives no
  systemd and no unit sandbox, which is the entire point.
- **root** on the target.
- **x86_64** (the harness installs the `x86_64-linux-musl` artifact).
- `zig` on the target **only** when using `--build`; otherwise prebuilt
  binaries are expected in `--local-bin`.

## Running it

### Locally, on the systemd box

```bash
# Cross-build ReleaseSafe musl, install, run all seven assertions:
sudo tests/e2e/deploy_regression.sh --build

# Or install from prebuilt binaries (no zig on the host):
zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe   # on a build box
sudo tests/e2e/deploy_regression.sh --local-bin zig-out/bin

# Purge installed executable/unit/state and harness-created accounts on exit:
sudo tests/e2e/deploy_regression.sh --build --purge
```

Flags: `--build`, `--local-bin DIR`, `--purge` (teardown installed
executable/unit/state + the throwaway test user, and the `fail2zig` service
account/group only if the harness created them), `--skip-install` (check an
already installed candidate), `--force` (run even if a fail2zig service is already
active).

### Against a disposable systemd baseline over SSH

This driver stops and replaces the target's baseline service temporarily.
Use a separately authorized disposable VM or booted container. Do not run it
against the published lab service; use the isolated `service_user.sh` harness
for checks beside that service.

```bash
tests/e2e/run-remote.sh user@disposable-systemd-host -- --hold-seconds 30
```

`run-remote.sh` builds locally and sends only binaries, deployment files, scripts,
and e2e harnesses using tar-over-SSH into a unique temporary directory. It runs
`release_gate.sh`, which requires an existing baseline installation, saves its
binaries/unit/config/state, exercises isolated backend checks and deployment gates,
and restores the baseline even on failure. With all writers stopped, it verifies a
copy of the original state tree, moves the original out of the active state path,
and installs the candidate with a fresh native SQLite database at the default
`/var/lib/fail2zig/state.bin`. State and backup directories must share a filesystem
so moving the original state uses an atomic rename. This is a fresh-state cutover, not conversion of
legacy counters, bans or source positions. Before restarting the baseline, it
restores and checks the original state bytes, ownership and modes. Any service
account/group created by the installer is removed; pre-existing identities stay.
A failed state restoration leaves the service stopped. A successful exact restoration removes
its backup; a failed restoration retains the backup for recovery. No fixed directory
is deleted. `--force` is accepted for older callers;
`--purge` is intentionally unavailable through this driver.

The target needs iproute2, util-linux, curl, nftables, iptables (including ip6tables), and
ipset. No product or release-gate Python is required. Every SSH connection uses the specified key with
`IdentitiesOnly=yes` and `PreferredAuthentications=publickey`; override the key
with `F2Z_SSH_KEY`. No password-guessing traffic is needed: fixtures exercise
normal detection, and ordinary TCP probes verify enforcement.

Build the test-only lifecycle helper beside the product artifact; it is not a release payload:

```bash
zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe --prefix "$PREFIX"
zig build test-release-lifecycle -Dtarget=x86_64-linux-musl \
  -Doptimize=ReleaseSafe --prefix "$PREFIX"
```

`fail2zig-release-lifecycle ABSOLUTE_FAIL2ZIG_PATH (nftables|iptables|ipset)` must run as
root in a fresh network namespace. The release gate uses the deep nftables profile for
IPv4/IPv6, ownership overlap, restart, expiry and cleanup, then representative iptables/ipset
install, readback, expiry and cleanup profiles. Common operator cases are not repeated for every
backend.

## Design notes

- **Service only.** The harness mirrors exactly what `install.sh` deploys:
  the daemon binds its own socket; no systemd socket unit exists or is supported.
- **Byte-identical unit guard.** After install, the harness `cmp`s the
  on-disk unit against `deploy/fail2zig.service` and refuses to proceed if
  they differ, and refuses if any drop-in exists under `fail2zig.service.d/`.
  This is what makes the test about the *shipped* unit, not a local tweak.
- **Journal scoping.** Always `_SYSTEMD_INVOCATION_ID=<current>`, captured
  after start — never `journalctl -b`.
- **Group checks.** The group-member check uses
  `runuser -u <user> -g fail2zig` so the supplementary group is in the
  credential set for the exact exec the daemon reads via `SO_PEERCRED`
  (deterministic; avoids `sg`/`newgrp` PTY fragility). The denial check
  uses `nobody`, asserting both exit code `3` and the daemon's wording.
- **Idempotent / re-runnable.** A `trap … EXIT` stops the service, removes
  the throwaway user, and (with `--purge`) removes installed artifacts. The
  `fail2zig` service account/group are deleted on purge **only if the harness created them**,
  so it never destroys pre-existing operator state.

## Other harnesses in this directory

`deploy_regression.sh` (above) is one of several real-system harnesses here:

- **`deploy_status_honesty.sh`** — asserts the status rollup, resolved-source
  labels, and persisted lifetime-ban surface (SYS-017, BUG-006).
- **`degraded_file_source.sh`** — runs the shipped binary in `--foreground`
  with one enforcing file jail, rotates and recreates the source, writes new
  failures only to the replacement inode, and requires a confirmed ban plus a
  healthy source/protection surface. It is self-contained (throwaway socket,
  SQLite state, config and network namespace) and never touches operator state.
  It needs **root** because the jail uses a real firewall backend. Run:

  ```bash
  sudo tests/e2e/degraded_file_source.sh
  ```

  Component tests retain the broader source-health edge cases; this release cell
  covers only the critical candidate-level rotation/reopen boundary.

- **`stabilization_live.sh`** — runs the *installed* shipped
  binary + unit through the stabilization contract: `--validate-config` on a copy
  of the live config with `backend = "systemd"` (exit 0, `source=journald`,
  deprecation warning); an unknown key injected at a known line reported as
  `file:line:col`; the live config `chmod 0666` → the unit fails closed with the
  SEC-012 cause in its invocation's journal, then `0640` restored → active with
  `NRestarts=0`; `state_file` under `/run` → the SYS-021 warning; and no Zig
  error-return-trace in either invocation's journal (DBT-005). Bounces the
  service and restores config bytes, mode and owner on every exit path. Run on
  the box as root after `deploy_regression.sh` has installed:

  ```bash
  sudo tests/e2e/stabilization_live.sh --force
  ```

## Firewall cause distinction

The probe→cause logic is covered by inline tests tagged `SYS-014`
(`backend.zig`: kernel-absent fall-through, transient fall-through, fail-closed;
`netlink.zig`: `ProtocolUnsupported` mapping; `nftables.zig`: `probeAvailable` ↔
`probeReason`). The one path `zig build test` cannot assert is the
**missing-CAP_NET_ADMIN** message — it only fires when a real privileged netlink
op is denied, and the cause is a `std.log` line. Verify manually:

- **No CAP_NET_ADMIN:** run the daemon unprivileged (no cap) → it must **fail
  closed** (refuse to run, non-zero exit) and log the missing-`CAP_NET_ADMIN`
  cause at the scaffold site, not a generic error.
- **No nf_tables in kernel** (`CONFIG_NF_TABLES` off / module blacklisted):
  `detect()` logs "nf_tables not in kernel" and falls through to ipset/iptables;
  if none is usable, the daemon fails closed.

## Lint

All `tests/e2e/*.sh` scripts are written to be `shellcheck -S warning` clean,
matching the convention for `tests/harness/*.sh` and `scripts/install.sh`.
