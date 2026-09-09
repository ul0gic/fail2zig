# Integration tests

These tests exercise fail2zig's daemon behavior end-to-end. Some test the
module-level save/load contract (no daemon spawn needed); others spawn the
real `zig-out/bin/fail2zig` binary and verify operator-visible flows.

## Files

| File | Spawns daemon? | Requires root? | Skip conditions |
|------|----------------|----------------|-----------------|
| `harness.zig` | No (helpers only) | No | non-Linux |
| `ban_test.zig` | Yes | Yes (IPC auth) | non-Linux, non-root, daemon binary missing, firewall unavailable |
| `migration_test.zig` | No (pure module drive) | No | non-Linux |
| `persistence_test.zig` | Mixed: 2 module tests always run; 1 subprocess test requires root | Yes (for subprocess case) | non-Linux, non-root (subprocess only) |
| `status_surface_test.zig` | No (in-process command dispatch) | No | non-Linux |
| `startup_failclosed_test.zig` | Yes (expects each run to exit 1) | No — one assertion in scenario (b) is root-only (ENH-006) | non-Linux, daemon binary missing |
| `config_diag_test.zig` | Yes (`--validate-config` only) | No | non-Linux, daemon binary missing |

Unprivileged developer machines see every root-gated subprocess case skip
cleanly. A CI job with `sudo` (or a privileged container) exercises the full
stack.

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

Every file is listed in the `integration_files` array in `build.zig`; the
loop below it creates the module, adds the `shared` and `engine` imports,
links libc, and registers the test run on `zig build test`:

```zig
const integration_files = [_]IntegrationFile{
    .{ .name = "harness", .path = "tests/integration/harness.zig", .needs_daemon_binary = false },
    .{ .name = "ban", .path = "tests/integration/ban_test.zig", .needs_daemon_binary = true },
};
```

To add a file, append one row. `needs_daemon_binary = true` makes the run
depend on `b.getInstallStep()`, so `zig-out/bin/fail2zig` is built before the
test spawns it; set it for every file that starts the daemon as a subprocess
(`ban`, `persistence`, `startup_failclosed`, `config_diag`). Only Lead edits
`build.zig`, at the sub-phase close.

## Skip semantics

Every test that can't run in the current environment returns
`error.SkipZigTest` rather than failing. That's a hard contract — a test
that would fail in an unprivileged CI must skip, never turn red.
