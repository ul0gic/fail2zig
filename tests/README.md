# fail2zig tests

Start with the behavior you changed. The default is small:

```bash
zig build test -Doptimize=ReleaseSafe  # alias: test-smoke
```

This starts the real daemon and checks the delivered client's status, jails,
version and decision deadlines. It does not run the component inventory or a
load campaign. Named checks in `build.zig` remain independently selectable.

| Need | Entry point |
|---|---|
| Client formatting | `test-client-format` |
| Configuration / detection | `test-native-config-inline` / `test-native-detection` |
| File/journal continuity | `test-native-source` / `test-native-journal` |
| Retry/store/runtime boundary | The affected `test-native-*` component step |
| Actual daemon startup/restart | `test-startup` / `test-native-daemon` |
| Live kernel enforcement or sustained load | [Independent acceptance modules](harness/acceptance/README.md) |
| Full maintained local qualification | The four lanes below, explicitly selected |

```bash
zig build test-ci-components-a test-ci-components-b test-ci-fuzz -Doptimize=ReleaseSafe -j2
zig build test-ci-assembled -Doptimize=ReleaseSafe -j2
```

Do not also invoke individual steps already covered by these lanes. Fuzz runs
only its 20 named input cases plus the module graph guard, without collecting
unrelated imported unit cases. Kernel-gated skips are not live backend evidence.
Some manual/deferred roots such as `test-engine` remain separately selectable;
they are not routine acceptance gates.

## Keep useful checks, remove duplication

Prefer observable daemon/kernel behavior. Retain small isolated checks where a
material fault (for example rollback, malformed input or exact ownership) cannot
be exercised reliably at the daemon boundary. Do not add getter/constant
restatements, duplicate setup/outcomes or assertions of private scheduling steps.
No coverage quota or one-test-per-function requirement applies.

The DBT-022 removal checkpoint deleted 547 obsolete or redundant cases and their
unused support. Live importer behavior, typed-scope protection, atomicity, source
continuity and independent kernel/TCP controls remain. A failed check is not a
reason to delete its guarantee.

## Layout and isolation

- `component/`: named boundary suites; internal imports through test-only `engine/test_api.zig`.
- `integration/`: assembled CLI/IPC/daemon behavior; see its README.
- `harness/acceptance/`: independent scenario selection, explicit candidate hashes and owned cleanup.
- `harness/load_repro/`: retained incident investigation tools and independent raw kernel oracle.
- `fuzz/`: bounded attacker-input cases; `guards/`: module graph checks.
- `benchmark/`: explicitly selected measurements; `fixtures/`: original inputs.
- `e2e/`: separately authorized live-system/release tooling.

The native integration harness accepts absolute `F2Z_TEST_DAEMON` for an already
built candidate. Its native-daemon client subprocesses use that same path.
Other integration entry points still use `zig-out/bin/fail2zig`; serialize their
build/install consumers. A different cache or install prefix alone does not
change those implicit paths. Compile-only target steps and the acceptance runner
avoid that ambiguity for moved modules.

CI uses smoke plus affected named groups for narrowly mapped pull requests.
Unknown/shared/store/runtime/build changes retain the full maintained gate;
docs-only changes remain light. Code pushes and manual qualification retain full
checks and release provenance. Long load and privileged backend campaigns are
explicit and do not run automatically in hosted CI. Local routing validation
cannot establish a remote GitHub run's result or measured runtime.
