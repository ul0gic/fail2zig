# fail2zig tests

Four test surfaces. Each subdirectory has its own README with usage and
build details.

- **`integration/`** — Zig integration tests: config loading, IPC
  protocol, state persistence, firewall wiring. Runs under
  `zig build test`. See [`integration/README.md`](integration/README.md).
- **`benchmark/`** — Zig microbenchmarks gated behind `-Dbench=true` /
  `FAIL2ZIG_RUN_BENCH=1`. Parse throughput, ban latency, memory ceiling,
  startup time. See [`benchmark/README.md`](benchmark/README.md).
- **`fuzz/`** — Zig fuzz corpora for the four attacker-reachable parse
  boundaries (log lines, TOML config, IPC framing, IP addresses). See
  [`fuzz/README.md`](fuzz/README.md).
- **`harness/`** — shell-based system harness that drives a real running
  daemon against synthesized traffic and real `nftables` state. Requires
  a Linux lab host — not part of `zig build test`. See
  [`harness/README.md`](harness/README.md).

Unit tests live inline with the code they test (`test "..." { ... }`
blocks in the source files themselves) — that's Zig's convention.
`zig build test` picks up both the inline tests and anything wired into
`build.zig` under `tests/integration/`.
