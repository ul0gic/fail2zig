# Deployment-regression e2e harness

The fifth test surface. Installs the **real ReleaseSafe static-musl
artifact** via `scripts/install.sh` and runs the daemon under the
**unmodified shipped systemd unit** `deploy/fail2zig.service`, then asserts
the deployment invariants that nothing else in the project can see.

Not part of `zig build test` — like `tests/harness/`, it needs a real
systemd host and root. It belongs to Phase 7.5 real-system validation
(the `SYS-` issue prefix).

## Why this exists

SYS-019 was a CRITICAL regression: the daemon crash-looped under its own
shipped unit. A daemon-side `chown` is a `@privileged` syscall that the
unit's `SystemCallFilter=~@privileged` SIGSYS-kills, and `CAP_CHOWN` is not
in the bounding set — so the chown could never succeed anyway. The fix
moved socket/dir ownership to systemd-native `Group=fail2zig`.

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
3. `/run/fail2zig` is `root:fail2zig` `0750`. The shipped unit ships
   `RuntimeDirectoryMode=0710` — that is only the transient pre-daemon
   value; the daemon chmods the directory to `0750` at startup (the
   `fchmodat` in `ensureSocketDir` kept by the SYS-019 fix). The harness
   checks **steady state** after the service is active, so `0750` is the
   correct invariant.
4. Socket `/run/fail2zig/fail2zig.sock` is `root:fail2zig` `0660`.
5. A root client connects (`fail2zig-client status`).
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

# Hermetic run — remove everything the harness installed/created on exit:
sudo tests/e2e/deploy_regression.sh --build --purge
```

Flags: `--build`, `--local-bin DIR`, `--purge` (teardown installed
artifacts + the throwaway test user, and the `fail2zig` group only if the
harness created it), `--force` (run even if a fail2zig service is already
active).

### Against the lab VM over SSH

```bash
tests/e2e/run-remote.sh ul0gic@172.16.150.253 -- --build --purge
```

`run-remote.sh` is **transport only** — it `rsync`s the repo to the target
and invokes `deploy_regression.sh` over SSH. It carries the mandatory
self-ban guard flags (`-o IdentitiesOnly=yes -o
PreferredAuthentications=publickey`) so the SSH connection never trips
fail2zig's own sshd jail and bans the operator. Override the key with
`F2Z_SSH_KEY`.

## Design notes

- **Service only.** The harness mirrors exactly what `install.sh` deploys:
  the daemon binds its own socket. `deploy/fail2zig.socket` is not involved.
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
  `fail2zig` group is deleted on purge **only if the harness created it**,
  so it never destroys pre-existing operator state.

## Other harnesses in this directory

`deploy_regression.sh` (above) is one of several real-system harnesses here:

- **`deploy_status_honesty.sh`** — asserts the status rollup, resolved-source
  labels, and persisted lifetime-ban surface (SYS-017, BUG-006).
- **`degraded_file_source.sh`** (ENH-004) — runs the shipped binary in
  `--foreground` against a real inotify break: a was-reading **file** jail whose
  log is moved away flips `protection` to `degraded` and drops
  `fail2zig_jail_log_source_healthy{jail} 0` after the ~2 s detach debounce,
  while a quiet-healthy jail, a rotation flicker, and a never-appeared log do
  **not** false-flag. Self-contained (throwaway temp socket/state/config, no
  systemd, never touches operator state); needs **root** — an enforcing jail
  fails closed without a firewall backend (principle #5). Run:

  ```bash
  sudo tests/e2e/degraded_file_source.sh
  ```

  The ENH-004 verdict is also covered in-process by the `ENH-004 e2e:` tests in
  `engine/main.zig` (real watcher → adapter → `computeOverallState` → metrics);
  this harness is the only check that runs the *shipped* binary through the real
  IPC + HTTP surfaces under the wall-clock debounce.

## SYS-014 #2 — firewall cause-distinction (mostly automated; one manual check)

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

## QA-002 — startup-time bench (privileged host)

The `startup_time` bench needs root/CAP_NET_ADMIN (the daemon binds the firewall
+ IPC at startup), so it **skips** on an unprivileged dev box. Capture the number
on a privileged host or in CI:

```bash
sudo zig build test -Dbench=true -Dtest-filter="startup_time" -Doptimize=ReleaseSafe
# → {"bench":"startup_time","elapsed_ns":...,"elapsed_ms":<N>,"target_ms":100}
```

Pass: `elapsed_ms < target_ms` (100). v0.2.2 aim after the lazy-init fix:
**< 80 ms**. Do **not** lower `target_ms` below 100 — it's the CI-flake margin.

## Lint

All `tests/e2e/*.sh` scripts are written to be `shellcheck -S warning` clean,
matching the convention for `tests/harness/*.sh` and `scripts/install.sh`.
