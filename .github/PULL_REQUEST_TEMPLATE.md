## What this changes

## Related issue

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (existing behavior changes — bumps minor version)
- [ ] Filter addition
- [ ] Documentation
- [ ] Build / CI / packaging
- [ ] Refactor (no behavior change)

## Verification

- [ ] `zig build` clean, no warnings
- [ ] `zig build test` passes (zero leaks under `std.testing.allocator`)
- [ ] `zig fmt --check engine/ client/ shared/ tests/` passes
- [ ] New tests added (for bug fixes: regression test that fails without the fix)
- [ ] Manual smoke test on a real system (if applicable)

## Notes for reviewers
