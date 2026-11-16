# Effect recovery acceptance fixture

This manual verifier exercises persistence rollback and kernel-evidence orderings
that an ordinary log-load run cannot schedule reliably. It calls the production
Store and effect manager with the real nftables backend. It does not run in the
assembled suite or ship in the product.

Build into an isolated prefix:

```sh
zig build build-effect-recovery-fixture -Doptimize=ReleaseSafe --prefix .zig-cache/effect-recovery-bin
```

Every invocation takes a mode and a SQLite state path. Use a separate SQLite
backup copy of a stopped, daemon-created state for each invocation. Never give
this fixture the only copy or a state owned by a running daemon. The state must
have current-schema native effects, installed retry policies and live owners.
The fixture writes to the supplied state.

Run in a fresh rootless user/network namespace, with the original namespace
identity supplied for the harness safety check:

```sh
F2Z_NATIVE_PARENT_NETNS=$(readlink /proc/self/ns/net) \
  unshare --user --map-root-user --net \
  .zig-cache/effect-recovery-bin/bin/f2z-effect-recovery-fixture \
  reject /absolute/path/to/disposable/state.sqlite
```

The kernel must allow unprivileged user namespaces and nftables. No host firewall
or installed service is used. Keep each state, binary hash, output and its source
configuration together; daemon restart checks must preserve the original source
logpaths.

| Mode | Required state and proof |
|---|---|
| `reject` | At least one live scope. Attempts a live owner's generation change and a stale owner revision; both must leave the effect and owners unchanged. Captures a genuine empty owned kernel snapshot, then releases the selected scope's owners through Store. Trying to settle the new absence with the older observation must fail transactionally, leaving the pending intent and no observation receipt. |
| `legacy` | The same live input, but compile this fixture against the writer under investigation. It expects that writer to accept the older observation after owner release and then reject its own resulting row on read. The resulting state is suitable for the offline repair command and is intentionally malformed. A corrected writer must refuse this mode's settlement. |
| `drift` | A small state with at least two live scopes, including a permanent ban. Starts a real effect manager with kernel events subscribed, proves its cached snapshot predates the accepted observation, then removes the permanent element through an independent Inspector. The manager must recover to ready and a genuine kernel readback must find the ban restored. A final one-microsecond clock regression must be rejected. The fixture refuses if its stale-cache prerequisite is absent. |
| `rollback` | Exactly one eligible malformed absence among fewer than 64 scopes, produced by `legacy`. Injects the existing pre-commit Store fault, then checks that repair eligibility, observation count and effect snapshot revision are unchanged. |

The legacy comparison uses the same fixture source and an isolated archive of
the prior Store/runtime source. Its test API must expose `native_effect_runtime`
when building the `drift` comparison; changing that export does not change
product behavior. Preserve the archive and exact compile invocation with the
run evidence.

The normal executable owns offline recovery acceptance:

```sh
fail2zig repair-effect-evidence --config /absolute/path/to/disposable/config.toml --check
fail2zig repair-effect-evidence --config /absolute/path/to/disposable/config.toml --apply
```

Compare logical tables before and after repair, inspect the published backup and
restart the normal daemon in a new empty network namespace. A repair backup is a
faithful copy of the original malformed evidence; restoring it should reproduce
the original refusal. It is not a healthy-state backup.

These modes do not prove the equal-time differing-fingerprint pacing branch.
Freezing the entire wall clock makes a real dump's wall duration shorter than
its monotonic duration and fails an earlier observation-completeness check.
That non-qualifying setup is not a substitute for the required pacing proof.
