#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig contributors
# Does:  Downloads pinned actionlint and zizmor releases and lints the workflow and action files with them.
# Holds: Each tool archive must match its pinned SHA-256 before it is unpacked or run.

set -euo pipefail
mode=${1:-all}
[[ $mode == all || $mode == security ]] || exit 2
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
fetch() {
    local url=$1 digest=$2 binary=$3
    curl --fail --silent --show-error --location --retry 3 "$url" -o "$scratch/$binary.tar.gz"
    printf '%s  %s\n' "$digest" "$scratch/$binary.tar.gz" | sha256sum --check --strict
    tar -xzf "$scratch/$binary.tar.gz" -C "$scratch" "$binary"
}
if [[ $mode == all ]]; then
    fetch https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz \
        8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 actionlint
    "$scratch/actionlint" .github/workflows/*.yml
fi
fetch https://github.com/zizmorcore/zizmor/releases/download/v1.25.2/zizmor-x86_64-unknown-linux-gnu.tar.gz \
    aa1facd105f0d83fe5c55b1adcd9d7417de5d83aa27471f91dc0b66cf3803577 zizmor
"$scratch/zizmor" --min-severity medium .github/workflows/ .github/actions/
