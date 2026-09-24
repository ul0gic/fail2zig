# Integration tests

These tests exercise fail2zig's daemon behavior end-to-end. Some test the
module-level save/load contract (no daemon spawn needed); others spawn the
real `zig-out/bin/fail2zig` binary and verify operator-visible flows.

## Scope

This directory holds assembled CLI, IPC and daemon tests. `build.zig` is the
current source of truth for each test's CI lane, binary dependency and release
local membership. `ipc_roundtrip_test.zig` has its own registered step; the
other integration files are listed in `integration_files`. Tests that need
root privileges, namespaces or a firewall use explicit skip conditions.

## Build

Each file is self-contained: it imports `shared` and `engine` as named
modules. `engine` in turn imports `shared` and `build_options` (the `version`
option `build.zig` generates), so a standalone run needs a one-line stub for
the latter and `-lc`:

```bash
printf 'pub const version: []const u8 = "test";\n' > /tmp/build_options.zig
zig test -lc \
  --dep shared --dep engine -Mroot=tests/integration/<name>.zig \
  --dep shared --dep build_options -Mengine=engine/main.zig \
  -Mshared=shared/root.zig \
  -Mbuild_options=/tmp/build_options.zig
```

The `--dep` clauses before an `-M` name that module's own imports; omitting
`--dep build_options` before `-Mengine` fails with
`no module named 'build_options' available within module engine`.

Files that spawn the daemon look for `zig-out/bin/fail2zig` relative to the
repo root: run `zig build` first and invoke `zig test` from the repo root.

## Wiring into `build.zig`

Most files are listed in the `integration_files` array in `build.zig`; the
loop creates the module, adds the `shared` and `engine` imports, links libc,
and registers the selected maintained or deferred test lane. The IPC round-trip
test is registered separately:

```zig
.{ .name = "native_daemon", .path = "tests/integration/native_daemon_test.zig",
   .needs_daemon_binary = true, .ci = .assembled, .release_local = true },
```

To add a file, append one row. `needs_daemon_binary = true` makes the run
depend on `b.getInstallStep()`, so `zig-out/bin/fail2zig` is built before the
test spawns it; set it for every file that starts the daemon as a subprocess
(`ban`, `persistence`, `startup_failclosed`, `config_diag`, `no_backend`).
Keep changes to this registration table synchronized with the affected integration file.

`no_backend_test.zig` (SYS-014 / ADR-007 / ENH-006) is the inverse of the
root-gated files: it must run unprivileged so the firewall really is
unusable. Scenarios (b) and (c) assert the status surface twice: the JSON from
`GET /api/status` on the metrics port, and the rendered rows from
`zig-out/bin/fail2zig --socket <path> status` (the non-root daemon
admits its own uid as an IPC peer, QA-004). A rejected peer fails the test
outright. They assert on the stable strings
(`no usable backend`, `refusing to run unprotected`,
`running DEGRADED as log-only`, a non-empty `protection_cause`), not on
the cause token. Its
`LiveDaemon` helper pumps the daemon's stderr on a thread so a test can
wait for a log line (`would-ban:`) while the process is still running.

The same file carries the ENH-007 / ENH-008 process-level coverage, because
those scenarios reuse `Scenario`, `LiveDaemon` and the empty-`PATH`
environment trick (ipset/iptables are probed by `PATH` lookup, so an empty
`PATH` makes a forced ipset/iptables deterministically unusable at any uid):

- (d) `firewall = "iptables"` + default policy → exit 1, `no usable backend
  (forced by config) (iptables not usable …)`, nothing accepting on the
  metrics port, no `selected` / scaffold line.
- (d') `firewall = "nftables"` unprivileged → exit 1 with the `netlink denied`
  cause and no fallback (root skips).
- (e) `firewall = "ipset"` + `on_no_backend = "log-only"` → up and DEGRADED;
  `/api/status` carries `protection_cause` `IpsetUnavailable`, the client
  renders `Protection:  DEGRADED (IpsetUnavailable)`, a would-ban logs only.
- (f) `firewall = "nftables"` inside `unshare -Urn` (an owned user+net
  namespace grants CAP_NET_ADMIN over a throwaway nf_tables instance) → the
  daemon logs `nftables selected (forced by config)`, installs its scaffold,
  and the client, run inside the same namespace so its uid maps to 0, shows
  `Backend:     nftables`. Skips where unprivileged namespaces are disabled or
  nf_tables is not reachable from one.
- (g) `metrics_enabled = false` → `http: disabled by config`, banner
  `http=off`, `connect()` to the metrics port is refused before and after an
  IPC `status` round-trip that still answers.

`config_diag_test.zig` covers the matching `--validate-config` diagnostics:
`metrics_port = 0` → `InvalidValue` at `line:col` plus the
`set metrics_enabled = false` hint; `firewall = "bogus"` in `[global]` →
`InvalidValue (key 'firewall' in [global])` at `line:col` with no hint; a
forced `firewall = "ipset"` + `metrics_enabled = false` validates and echoes
`config: firewall=ipset`.

## Skip semantics

Every test that can't run in the current environment returns
`error.SkipZigTest` rather than failing. That's a hard contract — a test
that would fail in an unprivileged CI must skip, never turn red.
