# Parser throughput benchmark

`parse_throughput.zig` measures lines per second through the live `parser.compile`
matcher. It is an opt-in developer measurement, not daemon throughput or release
qualification. Record the candidate, machine, workload and concurrent load before
comparing results.

```bash
zig build test -Doptimize=ReleaseSafe -Dbench=true -Dtest-filter=benchmark --summary all
```

The benchmark requires `FAIL2ZIG_RUN_BENCH=1` (set by `-Dbench=true`) and writes
its JSON result to stderr because Zig reserves stdout for the test protocol.

The retired StateTracker memory/ban benchmarks and legacy journal-loop benchmark
have been removed. Socket availability is not native readiness; service lifecycle
checks cover actual readiness and the acceptance harness covers populated restart.
See [the test guide](../README.md) for behavioral checks.
