# CI and releases

Pull requests qualify changes before merge. Ordinary pushes to `main` do not
repeat the test suite. The required check remains **CI result**, and main must
require it against an up-to-date PR.

CI always checks source formatting, shell/YAML correctness, workflow security and
release refusal handling. Documentation-only changes skip compilation and product
execution. Unknown paths, product code, build files, tests, packaging and workflow
changes select full qualification. Independent source checks and product checks
run in parallel; a newer PR revision cancels the obsolete run.

Full qualification tests a stripped, baseline x86_64 musl ReleaseSafe executable.
The ordinary assembled suite runs unprivileged. Focused enforcement, shared-owner
unban, recovery and firewall readback cases run separately in private network
namespaces on disposable GitHub-hosted runners. Missing prerequisites fail that
job. Backend-specific firewall skips are accounted for across nftables, iptables
and ipset; a skipped enforcement suite is not a pass.

These hosted Ubuntu kernel checks do not establish Debian or non-x86 hardware
qualification. They do not replace additional release-specific upgrade or scale
checks when a product change requires them. Weekly workflow security checks and
Dependabot updates remain separate because advisories can change without a commit.
They are not a comprehensive advisory scan of vendored SQLite or the Zig compiler.

## Download a tested candidate

The full PR run uploads `tested-x86_64-<attempt>` containing `fail2zig` and
`SHA256SUMS`. Download that artifact from the Actions run and verify it before use:

```bash
sha256sum --check --strict SHA256SUMS
chmod u+x fail2zig
```

The run summary gives the binary SHA-256. `ci-qualification-<attempt>` records the
tested checkout, source tree, PR head/base, run attempt and binary digest, with its
own `qualification.sha256`. A checksum detects changed bytes; the release also
verifies which GitHub workflow, PR and source produced the evidence.

## Publish a release

1. Merge a release PR whose in-tree version is the intended plain release version
   and whose **full** CI succeeded. Record the resulting main commit and CI run ID.
2. Dispatch **Release** from `main` with `release_tag`, `source_commit` and
   `ci_run_id`. No locally built executables, existing draft, tag push or manually
   entered hash is required.
3. GitHub verifies the successful run and merged PR. The actual tested Git tree
   must equal the released source tree, even if squash or rebase changed the commit
   ID. A head-only checkout, stale base, docs-only run or stale attempt is refused.
4. GitHub builds all five release executables in parallel. The x86 executable must
   match the PR-tested SHA-256. The other four targets receive ELF/static-link
   validation; there is no independent second build of those four targets.
5. The workflow assembles the fixed package, generates `SHA256SUMS`, and attests its
   source and toolchain. The run summary prints every payload hash and the digest
   of `SHA256SUMS`. Download the verified package artifact for any additional
   qualification before approving publication.
6. Approve the existing `release` environment job. It creates the tag/draft,
   uploads the verified assets, publishes and checks a fresh download against the
   bound hashes. It neither compiles nor reruns product tests.

Publication credentials are available only to the publishing job. PR jobs have
read-only repository permissions and no publishing secrets. Keep the `release`
environment restricted to `main` with required reviewers, and keep
`RELEASE_PUBLICATION_ENABLED=true`. Approval applies to the package already built
in that run; no second dispatch is needed.

## Retry and evidence expiry

Use **Re-run failed jobs** for infrastructure failures. Successful jobs and their
outputs can be reused. A reused product job keeps the candidate artifact named
for the attempt that built it; the new qualification still names its tested hash.
Publication fills only missing draft assets; it never
replaces a conflicting asset or moves a tag. If publication completed before a
later download check failed, retry verifies the existing public release.

Artifacts are retained for 90 days, subject to repository retention limits. If PR
evidence is missing or expired, explicitly dispatch full **CI** on `main` and use
that run's exact source commit. There is no silent fallback that reruns the suite
during release. An older source that no longer has verifiable evidence must be
requalified through a current release PR or an explicitly selected main run.

The package still contains five executables, eight support files and
`SHA256SUMS`. Verify downloads using the manifest; provenance adds origin evidence.
The workflow no longer requires a developer-machine rebuild of all five targets.
