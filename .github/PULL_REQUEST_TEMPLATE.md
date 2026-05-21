<!--
Thanks for the contribution. Before opening, please:

- One purpose per PR. A bug fix is not a refactor + rename + unrelated cleanup.
- CI must be green. If main is broken, that's its own PR first.
- For filter contributions: include positive AND negative test cases.
- Commit message style: feat(scope): … / fix(scope): … / docs(scope): …
-->

## What this changes

<!-- One or two sentences. The diff shows what; you explain why. -->

## Related issue

<!-- Closes #N, or "n/a" if this is small enough to not warrant an issue. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (existing behavior changes — bumps minor version)
- [ ] Filter addition
- [ ] Documentation
- [ ] Build / CI / packaging
- [ ] Refactor (no behavior change)

## Verification

<!-- How did you check this works? Be concrete. -->

- [ ] `zig build` clean, no warnings
- [ ] `zig build test` passes (zero leaks under `std.testing.allocator`)
- [ ] `zig fmt --check engine/ client/ shared/ tests/` passes
- [ ] New tests added (for bug fixes: regression test that fails without the fix)
- [ ] Manual smoke test on a real system (if applicable)

## Notes for reviewers

<!-- Anything tricky, surprising, or worth a second look. -->
