# Contributing to fail2zig

Thanks for being here. fail2zig is built in the open — issues, PRs,
roadmap, all visible. Every shipped feature has been a public PR; that
won't change.

This guide tells you where to start and what we expect of a good
contribution.

## TL;DR

- **Start here:** the [`good first issue`](https://github.com/ul0gic/fail2zig/labels/good%20first%20issue) label.
- **Easiest contribution:** add a filter for a service we don't cover yet. See the [Filter contribution template](https://github.com/ul0gic/fail2zig/issues/new?template=filter_contribution.yml).
- **License:** AGPL-3.0-or-later. By submitting a PR you agree your contribution lands under that license.
- **Discussions for questions, Issues for actionable work.** Don't open an Issue with "how do I…" — that goes in [Discussions](https://github.com/ul0gic/fail2zig/discussions).
- **Security vulnerabilities go through [private advisories](https://github.com/ul0gic/fail2zig/security/advisories/new),** never public Issues.

## The three contribution lanes

fail2zig has three plug-points where the community can land work without
touching the engine core. Each is a clean module boundary; each gets
comptime-baked into the binary at build time (no runtime plugins, no
dynamic code loading).

| Lane | What it is | Where the code lives | Effort |
|------|-----------|---------------------|--------|
| **Filters** | Pattern matchers for new services (Vaultwarden, Caddy, Authelia, k8s, etc.) | `engine/filters/` | Low — a few dozen lines per filter |
| **Sources** | New places log lines come from (journald, syslog over network, Docker engine, k8s pod logs, cloud audit logs) | `engine/core/log_watcher.zig` and friends | Medium — needs a watcher implementation |
| **Backends** | New places bans get applied (AWS WAF, Cloudflare, Tailscale ACLs, k8s NetworkPolicy, eBPF/XDP) | `engine/firewall/` | Medium-High — depends on the target API |

If you're not sure where to start, **start with a filter.** It's the
shortest path from "I have an idea" to "my work shipped in a release."

## Quick start

```bash
# Clone
git clone https://github.com/ul0gic/fail2zig
cd fail2zig

# Build (debug)
zig build

# Run tests (must pass clean, zero leaks)
zig build test

# Format check (CI-enforced)
zig fmt --check engine/ client/ shared/ tests/
```

Requires **Zig 0.14.1 exactly.** Newer versions may break the build.
Install from [ziglang.org/download](https://ziglang.org/download/).

## Filing an issue

Use one of the three templates — they ask the questions a maintainer
needs answered.

- **[Bug report](https://github.com/ul0gic/fail2zig/issues/new?template=bug_report.yml)** — something doesn't work as documented.
- **[Feature request](https://github.com/ul0gic/fail2zig/issues/new?template=feature_request.yml)** — propose new behavior or knobs.
- **[Filter contribution](https://github.com/ul0gic/fail2zig/issues/new?template=filter_contribution.yml)** — propose a new service filter.

Don't open a blank issue. The templates exist so triage doesn't have to
go back and forth asking for basic info.

## A good PR

- **One purpose per PR.** A bug fix is not a refactor + rename + unrelated cleanup. If the description wants to say "also," split it.
- **Commit messages follow the existing style:** `feat(scope): …`, `fix(scope): …`, `docs(scope): …`, `chore(scope): …`. Scope is the directory or module.
- **Description explains *why*.** The diff already shows *what*. If it fixes a bug, link the issue.
- **Tests.** A bug fix includes a regression test that would have failed before the fix. A feature covers the happy path plus at least one error case. Filter contributions include positive + negative log lines.
- **CI green.** If CI is broken on `main`, that's its own PR first.

A PR that hits those marks gets reviewed. Feedback is aimed at landing
the change, not gatekeeping — if something needs adjusting, we'll say
what and why.

## Standards (CI enforces these)

**Zig:**
- `zig fmt engine/ client/ shared/ tests/` before every commit — CI-enforced
- `zig build` and `zig build test` pass, zero failures, zero leaks
- Zero compiler warnings; `zig build -Doptimize=.ReleaseSafe` clean
- No `@panic` in production code — propagate errors explicitly
- No `@setRuntimeSafety(false)` without a comment proving the safety invariant
- All tests use `std.testing.allocator` for leak detection
- SPDX header on every `.zig` file (CI-enforced via the `spdx` job)

**Architecture invariants — do not violate without a design conversation first:**
- **No runtime plugins / dynamic code loading.** The trusted computing base IS the binary. Contributions land at compile time, not at runtime.
- **No third-party Zig packages.** Zero runtime dependencies is the product promise. C interop is allowed for stable kernel ABIs only.
- **State tracker is bounded by the ceiling.** `memory_ceiling_mb` derives an entry-count cap for the state tracker (the dominant memory consumer); eviction fires before the cap is exceeded. The parser hot path is zero-alloc. `BudgetAllocator` exists in `engine/core/memory.zig` for components that need a hard per-component byte budget, but is not currently wired to a live consumer — if you add a new component with significant allocation, reach out before choosing an allocator strategy.
- **No runtime regex engine in the daemon.** Patterns are comptime-specialized. Runtime regex is an attack surface we don't carry.

## What we're intentionally NOT building

These come up regularly. They are *deliberate* choices, not omissions:

- A plugin system for filters or backends (see above — comptime contributions instead)
- A configuration server, dashboard auth provider, or user-management layer
- Cross-machine ban orchestration in v0.x (different product category; see roadmap)
- Windows support (out of scope; the firewall layer is Linux-kernel native)

Open a [Discussion](https://github.com/ul0gic/fail2zig/discussions) if
you want to argue for any of these — the list is not immutable, just
what we've decided against so far.

## Conduct

Be excellent to each other. Disrespectful behavior, harassment, or
bad-faith engagement gets you removed from the project — no formal
process, just judgment. Reports go to **devteam@corelift.io** and are
handled privately.

## License

By opening a pull request, you agree your contribution is licensed
**AGPL-3.0-or-later** — the same license as the rest of the project.
No CLA, no sign-off ceremony. `git blame` is the authorship record.

The trademark on the "fail2zig" name and logo is separate and not
granted by contributing — see [Trademark](README.md#trademark) in the
README.

---

That's it. Open the issue, write the PR, ship.
