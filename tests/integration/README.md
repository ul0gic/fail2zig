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

Unprivileged developer machines see every subprocess case skip cleanly.
A CI job with `sudo` (or a privileged container) exercises the full stack.

## Build

Each file is self-contained: it imports `shared` and `engine` as named
modules and can compile standalone via:

```bash
zig test \
  --dep shared --dep engine -Mroot=tests/integration/<name>.zig \
  --dep shared -Mengine=engine/main.zig \
  -Mshared=shared/root.zig
```

The `--dep shared -Mengine=engine/main.zig` clause is mandatory — the
`engine` module itself imports `shared`, and the `-M` form is how that
edge is expressed on the command line.

## Wiring into `build.zig`

When Lead adds these to `build.zig`, follow the existing
`tests/integration_ipc_roundtrip.zig` pattern (`build.zig:103-117`):

```zig
const harness_mod = b.createModule(.{
    .root_source_file = b.path("tests/integration/<name>.zig"),
    .target = target,
    .optimize = optimize,
    .link_libc = true,
});
harness_mod.addImport("shared", shared_mod);
harness_mod.addImport("engine", engine_mod);

const harness_tests = b.addTest(.{
    .root_module = harness_mod,
    .filters = test_filters,
});
test_step.dependOn(&b.addRunArtifact(harness_tests).step);
```

Repeat for each file: `harness.zig`, `ban_test.zig`, `migration_test.zig`,
`persistence_test.zig`. The `ban_test` and `persistence_test` files
import `harness.zig` directly (relative), so they share the same test
module layout.

The subprocess-based tests expect `zig-out/bin/fail2zig` to already be
built — `b.getInstallStep()` dependency is appropriate:

```zig
run_ban_tests.step.dependOn(b.getInstallStep());
```

## Skip semantics

Every test that can't run in the current environment returns
`error.SkipZigTest` rather than failing. That's a hard contract — a test
that would fail in an unprivileged CI must skip, never turn red.
