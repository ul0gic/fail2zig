# fail2zig tests

Tests are grouped by the boundary they exercise:

- **`component/`** — isolated Zig storage, detection, configuration, firewall,
  migration and source tests. `build.zig` registers named test steps
  and maintained CI shards. Engine tests import internals through the test-only
  `engine/test_api.zig` module; client-format tests use a separate test module.
- **`integration/`** — assembled CLI, IPC and daemon behavior. The daemon tests
  share `zig-out/bin/fail2zig` and must be serialized; see its README.
- **`e2e/`** — authorized live-system and remote qualification scripts.
- **`fuzz/`** — bounded attacker-input fuzz targets.
- **`benchmark/`** — explicit performance measurements, not correctness gates.
- **`harness/`** — lab scripts for a running daemon and firewall.
- **`fixtures/`** — captured and synthetic inputs with provenance where needed.
- **`guards/`** — architecture checks, including the module graph guard.

Use the named steps in `build.zig` for affected components and assembled tests.
The broad `zig build test` still includes deferred legacy paths; it is not the
maintained acceptance gate. The module graph guard forbids parent-relative
imports under `tests/` so a source file cannot enter a test binary through two
different Zig modules. Inline tests remain appropriate for small local
invariants; the record-store contract suite lives in `component/store/`.
