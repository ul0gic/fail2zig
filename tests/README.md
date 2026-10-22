# fail2zig tests

Start with the behavior you changed. The default is small:

```bash
zig build test -Doptimize=ReleaseSafe  # alias: test-smoke
```

This starts the real daemon and checks the delivered client's status, jails,
version and decision deadlines. It does not run a load campaign.

| Need | Entry point |
|---|---|
| Firewall readback parsing | `test-firewall` |
| Actual daemon startup/restart | `test-startup` / `test-native-daemon` |
| One-executable entry points | `test-cli-entry` |
| Live kernel enforcement or sustained load | [Independent acceptance modules](harness/acceptance/README.md) |
| Full local qualification | The two steps below |

```bash
zig build test-firewall -Doptimize=ReleaseSafe -j2
zig build test-ci-assembled -Doptimize=ReleaseSafe -j2
```

`test-firewall` runs `test-native-firewall`, `test-nftables-inline` and
`test-firewall-inspection-inline`. `test-ci-assembled` runs every suite in
`integration/`. Do not also invoke their member steps. Kernel-gated skips are
not live backend evidence; run them on the lab target.

## Layout and isolation

- `component/`: the three firewall readback suites; internal imports through test-only `engine/test_api.zig`.
- `integration/`: assembled CLI/IPC/daemon behavior; see its README.
- `harness/acceptance/`: independent scenario selection, explicit candidate hashes and owned cleanup.
- `harness/load_repro/`: the rootless load rig, the state fixture generator and the independent raw kernel oracle.
- `harness/ci/local-ci`: the local trusted-trigger CI run.
- `e2e/`: separately authorized live-system and release tooling.
- `fixtures/`: original fail2ban configuration and rule-test inputs.

The native integration harness accepts absolute `F2Z_TEST_DAEMON` for an already
built candidate. Its native-daemon client subprocesses use that same path.
Other integration entry points still use `zig-out/bin/fail2zig`; serialize their
build/install consumers. A different cache or install prefix alone does not
change those implicit paths. Compile-only target steps and the acceptance runner
avoid that ambiguity.

A pull request whose code changes all fall under `client/`, `engine/firewall/`
or their suites runs smoke plus `test-cli-entry`, `test-firewall` or both, as
touched. Other code changes run `test-ci-assembled` and `test-firewall`;
docs-only changes stay light. Long load and privileged backend campaigns are
explicit and do not run in hosted CI.
