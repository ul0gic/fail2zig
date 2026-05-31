#!/usr/bin/env bash
#
# scripts/setup-branch-protection.sh — apply branch protection to `main`.
#
# *** MAINTAINER / LEAD RUNS THIS — NOT an agent, NOT CI. ***
#
# This script changes repository settings (branch protection on `main`) via
# the GitHub REST API. It requires repo-ADMIN auth. It is intentionally NOT a
# workflow: branch protection is a repo setting, not something a committed
# workflow can (or should) self-apply.
#
# Usage:
#   gh auth login            # as a user with admin on the repo
#   scripts/setup-branch-protection.sh
#
# Override the target repo/branch via env if needed:
#   FAIL2ZIG_REPO=ul0gic/fail2zig FAIL2ZIG_BRANCH=main scripts/setup-branch-protection.sh
#
# Idempotent: re-running applies the same desired state (PUT replaces the
# whole protection object), so it is safe to run repeatedly. Run it again
# whenever the required status-check list changes (e.g. a new CI job).
#
# What it enforces on `main`:
#   - Require a pull request before merging (0 required approvals — solo
#     maintainer; green CI is the gate), dismiss stale approvals on new commits.
#   - Require the CI status checks below to pass, on the latest commit
#     (strict = branch must be up to date before merge).
#   - Require linear history (no merge commits onto main).
#   - Block force-pushes and branch deletion.
#   - Apply the rules to admins too (no silent bypass).
#
# Exit code: 0 on success, non-zero on any failure. Errors surface with a
# `branch-protection:` prefix.

set -euo pipefail

REPO="${FAIL2ZIG_REPO:-ul0gic/fail2zig}"
BRANCH="${FAIL2ZIG_BRANCH:-main}"

err() { echo "branch-protection: $*" >&2; }
info() { echo "branch-protection: $*"; }

# --- preflight ----------------------------------------------------------------

if ! command -v gh >/dev/null 2>&1; then
  err "the GitHub CLI (gh) is required but was not found on PATH"
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  err "not authenticated — run 'gh auth login' as a repo admin first"
  exit 1
fi

# Confirm the caller actually has admin on the repo; the protection API 403s
# otherwise, but failing early gives a clearer message.
perm="$(gh api "repos/${REPO}" --jq '.permissions.admin' 2>/dev/null || echo "false")"
if [ "${perm}" != "true" ]; then
  err "the authenticated user lacks admin on ${REPO} (need admin to set branch protection)"
  exit 1
fi

# --- required status checks ---------------------------------------------------
#
# These are the CI job *names* (the `name:` field of each job in
# .github/workflows/ci.yml). They run on `pull_request` to `main`, so they are
# valid required checks. Keep this list in lockstep with ci.yml job names.
#
# NOTE: the Scorecard job (.github/workflows/scorecard.yml, job "Scorecard
# analysis") is deliberately NOT required: it runs on push/schedule/
# branch_protection_rule, never on pull_request, so it can never report a
# status on a PR and would permanently block merges if required.
REQUIRED_CHECKS=(
  "zig fmt --check"
  "Build (native Debug)"
  "Tests (std.testing.allocator leak detection)"
  "Cross-compile x86_64-linux-musl"
  "Cross-compile aarch64-linux-musl"
  "Cross-compile arm-linux-musleabihf"
  "shellcheck"
  "yamllint"
  "zizmor"
  "SPDX headers"
)

# Build the JSON array of {context: "<name>"} for required_status_checks.checks.
checks_json="$(
  printf '%s\n' "${REQUIRED_CHECKS[@]}" | python3 -c '
import json, sys
checks = [{"context": line.rstrip("\n")} for line in sys.stdin if line.strip()]
print(json.dumps(checks))
'
)"

# --- assemble the protection payload -----------------------------------------

payload="$(python3 -c '
import json, sys
checks = json.loads(sys.argv[1])
body = {
    "required_status_checks": {
        # strict = the PR branch must be up to date with base before merging.
        "strict": True,
        "checks": checks,
    },
    # Enforce protection for admins as well — no bypass.
    "enforce_admins": True,
    "required_pull_request_reviews": {
        "required_approving_review_count": 0,
        # Stale approvals are dismissed when new commits land.
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": False,
    },
    # No team/user restrictions on who can push to the protected branch.
    "restrictions": None,
    "required_linear_history": True,
    "allow_force_pushes": False,
    "allow_deletions": False,
    "block_creations": False,
    "required_conversation_resolution": True,
}
print(json.dumps(body))
' "${checks_json}")"

# --- apply --------------------------------------------------------------------

info "applying branch protection to ${REPO}@${BRANCH}"
info "required checks: ${REQUIRED_CHECKS[*]}"

if printf '%s' "${payload}" | gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "repos/${REPO}/branches/${BRANCH}/protection" \
  --input - >/dev/null; then
  info "branch protection applied to ${BRANCH}"
else
  err "failed to apply branch protection (need repo admin + a valid token)"
  exit 1
fi

# --- verify -------------------------------------------------------------------

info "current protection summary:"
gh api "repos/${REPO}/branches/${BRANCH}/protection" --jq '
  "  enforce_admins:        \(.enforce_admins.enabled)",
  "  linear_history:        \(.required_linear_history.enabled)",
  "  force_pushes_blocked:  \(.allow_force_pushes.enabled | not)",
  "  deletions_blocked:     \(.allow_deletions.enabled | not)",
  "  required_reviews:      \(.required_pull_request_reviews.required_approving_review_count)",
  "  dismiss_stale:         \(.required_pull_request_reviews.dismiss_stale_reviews)",
  "  strict_checks:         \(.required_status_checks.strict)",
  "  required_checks:       \(.required_status_checks.checks | map(.context) | join(", "))"
'

info "done."
