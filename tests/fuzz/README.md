# Fuzz corpus

Security-owned fuzz tests for the four attacker-reachable parse
boundaries in fail2zig:

| File                     | Target                             | Status |
|--------------------------|------------------------------------|--------|
| `fuzz_parser.zig`        | log-line parser (`engine/core/parser.zig`) | compiles, all tests pass |
| `fuzz_ip.zig`            | IP address parser (`shared/types.zig`)     | compiles, all tests pass |
| `fuzz_protocol.zig`      | IPC protocol deserializer (`shared/protocol.zig`) | compiles, all tests pass |
| `fuzz_config.zig`        | native TOML config parser (`engine/config/native.zig`) | compiles, all tests pass |

Each file combines:

1. A curated seed corpus of adversarial inputs (integer-overflow probes,
   malformed framing, integer-wrap length prefixes, pathological unicode,
   regression seeds for filed `SEC-*` issues).
2. PRNG-driven expansion with tens of thousands of random byte streams
   per run — deterministic across runs (fixed seeds).
3. Tight memory bounding via `std.heap.FixedBufferAllocator` and/or the
   `std.testing.FailingAllocator` so unbounded allocation surfaces as
   `error.OutOfMemory` rather than silently succeeding.

`std.testing.fuzz(...)` from Zig 0.14.1 requires a custom `@import("root").fuzz`
implementation provided by the fuzzer runtime (AFL++/libFuzzer). For CI we
use synchronous `test` blocks driven by `std.Random.DefaultPrng` so the
tests pass under plain `zig build test` without any external runtime.
The same seed corpus can be fed to AFL++ later — each curated input is a
standalone bytestring.

## Running standalone (what Lead can run at the gate)

Each fuzz file compiles as a standalone `zig test` with its own module
graph. These are the exact invocations Lead can copy-paste to verify
7.1.6 without touching `build.zig`:

```bash
cd /home/ul0gic/fail2zig

# parser
zig test \
  --dep shared --dep parser \
  -Mroot=tests/fuzz/fuzz_parser.zig \
  --dep shared \
  -Mparser=engine/core/parser.zig \
  -Mshared=shared/root.zig

# ip
zig test \
  --dep shared \
  -Mroot=tests/fuzz/fuzz_ip.zig \
  -Mshared=shared/root.zig

# protocol
zig test \
  --dep shared \
  -Mroot=tests/fuzz/fuzz_protocol.zig \
  -Mshared=shared/root.zig

# config
zig test \
  --dep shared --dep config_native \
  -Mroot=tests/fuzz/fuzz_config.zig \
  --dep shared \
  -Mconfig_native=engine/config/native.zig \
  -Mshared=shared/root.zig
```

All four were last verified 2026-04-21 under Zig 0.14.1. Every test
passes.

## Wiring into `build.zig` at the gate

Lead owns `build.zig`. To integrate these under `zig build test -Dtest-filter=fuzz`
add the block below next to the existing integration test block (after
line 117, keeping ordering consistent). This mirrors the
`integration_mod` pattern already present.

```zig
// Fuzz tests (tests/fuzz/). Each fuzz file has a narrow module graph
// — only the parse boundary it targets, not the whole engine — so
// the fuzz binaries compile fast and are trivially reproducible.

// fuzz_parser
const fuzz_parser_mod = b.createModule(.{
    .root_source_file = b.path("tests/fuzz/fuzz_parser.zig"),
    .target = target,
    .optimize = optimize,
});
const parser_only_mod = b.createModule(.{
    .root_source_file = b.path("engine/core/parser.zig"),
    .target = target,
    .optimize = optimize,
});
parser_only_mod.addImport("shared", shared_mod);
fuzz_parser_mod.addImport("shared", shared_mod);
fuzz_parser_mod.addImport("parser", parser_only_mod);
const fuzz_parser_tests = b.addTest(.{
    .root_module = fuzz_parser_mod,
    .filters = test_filters,
});
test_step.dependOn(&b.addRunArtifact(fuzz_parser_tests).step);

// fuzz_ip (needs only shared)
const fuzz_ip_mod = b.createModule(.{
    .root_source_file = b.path("tests/fuzz/fuzz_ip.zig"),
    .target = target,
    .optimize = optimize,
});
fuzz_ip_mod.addImport("shared", shared_mod);
const fuzz_ip_tests = b.addTest(.{
    .root_module = fuzz_ip_mod,
    .filters = test_filters,
});
test_step.dependOn(&b.addRunArtifact(fuzz_ip_tests).step);

// fuzz_protocol (needs only shared)
const fuzz_protocol_mod = b.createModule(.{
    .root_source_file = b.path("tests/fuzz/fuzz_protocol.zig"),
    .target = target,
    .optimize = optimize,
});
fuzz_protocol_mod.addImport("shared", shared_mod);
const fuzz_protocol_tests = b.addTest(.{
    .root_module = fuzz_protocol_mod,
    .filters = test_filters,
});
test_step.dependOn(&b.addRunArtifact(fuzz_protocol_tests).step);

// fuzz_config (native TOML parser)
const fuzz_config_mod = b.createModule(.{
    .root_source_file = b.path("tests/fuzz/fuzz_config.zig"),
    .target = target,
    .optimize = optimize,
});
const config_native_only_mod = b.createModule(.{
    .root_source_file = b.path("engine/config/native.zig"),
    .target = target,
    .optimize = optimize,
});
config_native_only_mod.addImport("shared", shared_mod);
fuzz_config_mod.addImport("shared", shared_mod);
fuzz_config_mod.addImport("config_native", config_native_only_mod);
const fuzz_config_tests = b.addTest(.{
    .root_module = fuzz_config_mod,
    .filters = test_filters,
});
test_step.dependOn(&b.addRunArtifact(fuzz_config_tests).step);
```

After wiring, `zig build test -Dtest-filter=fuzz` should list the five
fuzz test names from `fuzz_parser`, and similar for the other three
files. Build-plan task 7.1.6 considers this block installed + passing.

## Extending to real fuzzers

The seed corpus inside each `fuzz_*.zig` is the ground-truth AFL++
starter corpus. To run AFL++:

1. Write each seed to a file under `fuzz-corpus/<target>/`.
2. Build an AFL++ harness binary that reads stdin and calls the same
   entry point (e.g. `parser.compile(sshd_pattern)(input)`).
3. Run `afl-fuzz -i fuzz-corpus/parser -o findings/parser -- ./harness`.

That work is out of scope for Phase 7.1 but the groundwork is here.
