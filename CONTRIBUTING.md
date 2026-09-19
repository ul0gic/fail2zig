# Contributing to fail2zig

Bug reports, filters, documentation fixes and code contributions are welcome.
Start with an existing [issue](https://github.com/ul0gic/fail2zig/issues), or
open a [discussion](https://github.com/ul0gic/fail2zig/discussions) if you want
to work through an idea first. You do not need to submit a PR to request a feature.

Security vulnerabilities belong in a [private report](SECURITY.md).

## Where to start

The [`good first issue`](https://github.com/ul0gic/fail2zig/labels/good%20first%20issue)
label is a useful starting point. Filters for services we do not cover are another
way to contribute. Include representative log lines that should match and ones
that should not, with sensitive details removed.

| Area | Current implementation | Before proposing an extension |
|------|------------------------|-------------------------------|
| Filters and rules | Built-in filters in `engine/filters/` and bounded native custom rules | Explain the log format and how a match identifies the responsible address. |
| Sources | Native file and journal ingestion in `engine/` | Discuss origin validation, restart continuity and resource limits. Remote/cloud sources are proposals, not supported source types. |
| Firewall backends | nftables, iptables and ipset in `engine/firewall/` | Discuss exact scope, ownership, readback and recovery. Cloud APIs and other backends need a design discussion. |

Contributions are compiled into the executable. There is no runtime plugin or
arbitrary action-loading interface. See the [runtime architecture](docs/architecture.md)
for the current boundaries. Fleet management and other broader ideas need their
own scope and discussion; they are not part of the current host runtime.

## Build and check a change

Use Linux and **Zig 0.14.1 exactly**, available from
[ziglang.org/download](https://ziglang.org/download/).

```bash
git clone https://github.com/ul0gic/fail2zig
cd fail2zig
zig build -Doptimize=ReleaseSafe
make fmt-check

# Run the maintained CI test aggregates locally.
make test
```

The build produces one executable, `zig-out/bin/fail2zig`, containing the daemon
and administrative commands. SQLite C is vendored and linked statically. The
runtime needs neither Python nor a SQLite service, CLI or shared library.
Journal ingestion uses the host's `journalctl`; iptables and ipset backends use
those host tools. nftables enforcement uses kernel netlink directly.

While editing, run the relevant named suite, for example:

```bash
zig build test-native-detection -Doptimize=ReleaseSafe
zig build test-native-ipc-auth -Doptimize=ReleaseSafe
make fuzz
```

`make test` runs component shards, assembled integration tests and bounded fuzz
cases in sequence. `make fuzz` runs bounded fuzz cases and the test module-graph
guard, not an ongoing fuzzing campaign. Local test builds use two compile jobs by default;
override this with `make test ZIG_JOBS=4` when resources allow. Avoid the broad
`zig build test` entry point: it still includes legacy tests outside the maintained
CI inventory. Suite definitions live in
[build.zig](build.zig).

Do not run daemon/startup test suites concurrently in the same checkout: they
share `zig-out/bin/fail2zig`. Some integration tests need privileges, host tools
or kernel features and may skip when those are absent. Include skips and the
environment in your PR's verification notes; a hosted test pass does not prove
live firewall enforcement on every supported architecture. Use an isolated test
machine or namespace for tests that change firewall state.

Local checks are optional conveniences, not substitutes for required CI. Docs
and community-only changes take the small CI route; code, build and workflow
changes take the full route. Formatting, shell/YAML checks, workflow security
analysis, maintained test suites and five release cross-builds run where
applicable. See [CI](.github/workflows/ci.yml) for the exact checks.

## Filing an issue

Choose the form that fits:

- [Bug report](https://github.com/ul0gic/fail2zig/issues/new?template=bug_report.yml): what happened, what you expected and how to reproduce it.
- [Feature request](https://github.com/ul0gic/fail2zig/issues/new?template=feature_request.yml): the problem you want to solve and what would help. Examples and interest in submitting a PR are optional.
- [Filter contribution](https://github.com/ul0gic/fail2zig/issues/new?template=filter_contribution.yml): a service filter and representative input.

Use [Discussions](https://github.com/ul0gic/fail2zig/discussions) for setup questions
or ideas that are not yet actionable.

## Sending a PR

Keep each PR focused on one problem. Explain the resulting behavior, why it helps,
and how you checked it. Link the relevant issue or discussion. For code changes,
include tests for the behavior and meaningful failure cases; a bug fix should
include a regression test where practical. Documentation changes do not need
unrelated runtime tests.

Follow the existing commit style, such as `fix(client): ...` or `docs: ...`.
Run `make fmt` for Zig changes, including build files. New Zig files need SPDX
headers. Use checked arithmetic, explicit errors and clear allocation ownership;
do not disable runtime safety or introduce attacker-reachable panics. Use leak
checking where the test owns allocations. Some engineering rules need code review
and are not mechanically enforced by CI.

Preserve these runtime contracts:

- Zig application code with pinned, statically embedded SQLite C. New dependencies need discussion; do not add runtime downloads or interpreters.
- Persist receipts, source progress and consumer state consistently. Publish state after commit, and retain enforcement intent until its outcome is known.
- Bound inputs, queues and storage. Do not evict critical receipts, active owners or unresolved effects to meet a budget. Exhaustion must remain visible without silently losing protection.
- Treat logs, protocol frames and subprocess output as untrusted data. Never turn input into shell commands or dynamically loaded code.
- Preserve authorization, exact firewall scope and ownership. A policy decision is not proof that the kernel installed protection.

The shipped systemd service runs as the dedicated `fail2zig` account with specific
capabilities, rather than requiring a root daemon. Installation still needs root.
See [SECURITY.md](SECURITY.md) for the privilege boundary.

## Conduct

Treat other contributors with respect. Harassment and bad-faith engagement can
result in removal from the project. Reports go to **devteam@corelift.io** and
are handled privately.

## License

By submitting a PR, you agree that your contribution is licensed
**AGPL-3.0-or-later**, the same license as the project. There is no CLA or
sign-off requirement. The trademark on the fail2zig name and logo is separate;
see [Trademark](README.md#trademark).
