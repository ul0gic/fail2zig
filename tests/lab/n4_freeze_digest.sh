#!/bin/bash
# Sorted-manifest digest of the candidate: every tracked or new product/test/fixture path
# (project records, agent configuration, caches and build outputs excluded) plus the installed
# executable. Prints the manifest digest, the path count and the artifact digest.
set -eu
cd "$(dirname "$0")/../.."
manifest=$(git ls-files --cached --others --exclude-standard \
    | grep -v -E '^(\.project/|\.claude/|\.codex/|\.zig-cache/|zig-out/|\.github/)' \
    | LC_ALL=C sort \
    | while IFS= read -r path; do
        [ -f "$path" ] || continue
        printf '%s  %s\n' "$(sha256sum "$path" | cut -d' ' -f1)" "$path"
      done)
count=$(printf '%s\n' "$manifest" | wc -l)
digest=$(printf '%s\n' "$manifest" | sha256sum | cut -d' ' -f1)
echo "manifest_paths=$count"
echo "manifest_sha256=$digest"
if [ -f zig-out/bin/fail2zig ]; then
    echo "artifact_sha256=$(sha256sum zig-out/bin/fail2zig | cut -d' ' -f1)"
fi
if [ "${1:-}" = "--print" ]; then printf '%s\n' "$manifest"; fi
