# Benchmark suite

These benchmarks measure the performance targets the PRD commits to.
They run as ordinary Zig tests but are gated behind the
`FAIL2ZIG_RUN_BENCH=1` environment variable — they aren't part of the
default `zig build test` cycle.

## Targets

| File | Metric | Target | Observed (ReleaseSafe) |
|------|--------|--------|------------------------|
| `parse_throughput.zig` | Lines/sec through `parser.compile` | ≥ 22,000 | ~5.96M |
| `memory_ceiling.zig` | Entries under attack over budget | Never exceed | 21,845 entries, 15,606 evictions across 50K attempts |
| `startup_time.zig` | Process spawn → accepting IPC | < 100ms | Skips on unprivileged hosts (daemon can't run) |
| `ban_latency.zig` | Match → ban decision | < 1ms | p50 365ns, p99 932ns |

## Running

```bash
# Release build first — Debug parsers are ~10x slower and miss the target.
zig build -Doptimize=.ReleaseSafe

# Individual benchmark:
FAIL2ZIG_RUN_BENCH=1 zig test -O ReleaseSafe \
  --dep shared --dep engine -Mroot=tests/benchmark/<name>.zig \
  --dep shared -Mengine=engine/main.zig \
  -Mshared=shared/root.zig
```

Every benchmark emits one JSON line to stdout for CI diffing, e.g.:

```json
{"bench":"ban_latency","iterations":10000,"p50_ns":365,"p99_ns":932,"mean_ns":406,"target_ns":1000000}
```

## Wiring into `build.zig`

Follow the same pattern as the integration tests (see
`tests/integration/README.md`). Additionally, Lead may want to expose
a `-Dbench=true` build option that flips the gate without needing the
env var. Suggested addition to `build.zig`:

```zig
const bench_opt = b.option(bool, "bench", "Run performance benchmarks") orelse false;
if (bench_opt) {
    // Create test modules per benchmark file as above, and set the env
    // var on the run step so the test gate opens automatically.
    run_bench_parse.setEnvironmentVariable("FAIL2ZIG_RUN_BENCH", "1");
}
```

## Skip semantics

Same contract as integration tests: a benchmark that can't run in the
current environment returns `error.SkipZigTest`. In particular,
`startup_time.zig` skips when the daemon binary is missing or the daemon
refuses to start (no firewall backend) — both are legitimate dev-machine
conditions.

The parse_throughput, memory_ceiling, and ban_latency benchmarks
additionally require `FAIL2ZIG_RUN_BENCH=1` so a developer's default
`zig build test` doesn't burn 15+ seconds on a full benchmark run.
