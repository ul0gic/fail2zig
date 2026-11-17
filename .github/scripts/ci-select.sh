#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig contributors
# Does:  Decides whether CI runs the full product checks and writes the answer to GITHUB_OUTPUT.
# Holds: Every event but a pull request, and every pull request touching a path outside the listed documents, selects full checks.

set -euo pipefail
full=true
if [[ ${GITHUB_EVENT_NAME:?} == pull_request ]]; then
    # Why: Under set -e a malformed SHA ends the script here, before any output is written.
    [[ ${PR_BASE:?} =~ ^[0-9a-f]{40}$ && ${PR_HEAD:?} =~ ^[0-9a-f]{40}$ ]]
    changed=$(mktemp)
    trap 'rm -f "$changed"' EXIT
    # Why: --no-renames lists both sides of a rename, so moving source into docs/ still selects full checks.
    git diff --name-only --no-renames -z "$PR_BASE...$PR_HEAD" > "$changed"
    full=false
    while IFS= read -r -d '' path; do
        case "$path" in
            docs/*.md|README.md|CONTRIBUTING.md|CODE_OF_CONDUCT.md|SECURITY.md|CHANGELOG.md) ;;
            *) full=true ;;
        esac
    done < "$changed"
fi
printf 'full=%s\n' "$full" >> "${GITHUB_OUTPUT:?}"
printf 'Full product checks: %s\n' "$full"
