# Benchmark suite

These opt-in developer microbenchmarks help detect large local regressions. They are not release
qualification, cross-machine comparisons or published performance claims. They run as ordinary
Zig tests behind `FAIL2ZIG_RUN_BENCH=1` and are not part of the default test cycle.

## Targets

| File | Measurement |
|------|-------------|
| `parse_throughput.zig` | Lines per second through `parser.compile` |
| `memory_ceiling.zig` | Bounded tracker behavior under excess subjects |
| `startup_time.zig` | Process spawn to accepting IPC; skips without a usable backend |
| `ban_latency.zig` | Match-to-decision latency distribution |
| `loop_latency.zig` | IPC status latency while a deliberately slow journal poll overlaps the loop |

## Running

```bash
zig build test -Doptimize=ReleaseSafe -Dbench=true -Dtest-filter=benchmark --summary all
```

Every benchmark emits one JSON line to stderr for local comparison. Zig's build test runner
reserves stdout for its control protocol; writing benchmark JSON there can leave the build waiting
indefinitely. Record the binary, machine, optimization mode, workload and concurrent load before
comparing results.

`-Dbench=true` sets `FAIL2ZIG_RUN_BENCH=1` for these test artifacts. Omit it for
the normal suite, where benchmarks skip.

## Skip semantics

Same contract as integration tests: a benchmark that can't run in the
current environment returns `error.SkipZigTest`. In particular,
`startup_time.zig` skips when the daemon binary is missing or the daemon
refuses to start (no firewall backend) — both are legitimate dev-machine
conditions.

`loop_latency.zig` needs no daemon binary or privileges: it runs
`EventLoop` + `JournaldSource` + `IpcServer` + `commands.Context`
in-process (the daemon has no config key for the `journalctl` path — the
seam is `JournaldSource.Options.journalctl_path`), polls a fake
`journalctl` that sleeps 1 s, and drives `status` from a client thread at
10 ms pacing so the ~5 s run spans several poll cycles. It also asserts at
least two poll batches were consumed, so a run that never overlapped a
poll fails rather than reporting a flattering number. Wire it with
`needs_daemon_binary = false`.

The parse_throughput, memory_ceiling, and ban_latency benchmarks
additionally require `FAIL2ZIG_RUN_BENCH=1` so a developer's default
`zig build test` doesn't burn 15+ seconds on a full benchmark run.
