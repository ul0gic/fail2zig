#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig contributors
# Fixed release contract. No user-supplied commands, paths, or target lists.
set -euo pipefail

fail() { echo "release: $*" >&2; exit 1; }
targets=(x86_64-linux-musl aarch64-linux-musl arm-linux-musleabihf mips-linux-musleabi mipsel-linux-musleabi)
payloads=(COPYING.date-profile LICENSE SQLITE-NOTICE.md fail2zig.1 fail2zig.service fail2zig.toml.5 fail2zig.toml.example install.sh)

inputs() {
    [[ ${RELEASE_TAG:-} =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'expected a vMAJOR.MINOR.PATCH tag'
    [[ ${SOURCE_COMMIT:-} =~ ^[0-9a-f]{40}$ ]] || fail 'expected a full lowercase source SHA'
    [[ ${BINARY_SHA256:-} =~ ^[0-9a-f]{64}$ ]] || fail 'expected approved x86_64 SHA-256'
    [[ ${MANIFEST_SHA256:-} =~ ^[0-9a-f]{64}$ ]] || fail 'expected approved manifest SHA-256'
    [[ -n ${LAB_SCOPE:-} && ${#LAB_SCOPE} -le 2000 ]] || fail 'describe the hash-bound lab qualification (1-2000 characters)'
}

names() {
    local target
    for target in "${targets[@]}"; do printf 'fail2zig-%s-%s\n' "$RELEASE_TAG" "$target"; done
    printf '%s\n' "${payloads[@]}"
}

identity() {
    [[ $1 == "$SOURCE_COMMIT" && $2 == "$SOURCE_COMMIT" ]] || fail 'source checkout or tag moved'
}

# Resolve lightweight and annotated tags through GitHub, not a stale local ref.
remote_tag() {
    local object kind sha _depth
    object=$(gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$RELEASE_TAG")
    for _depth in 1 2 3 4 5; do
        kind=$(jq -er '.object.type' <<< "$object")
        sha=$(jq -er '.object.sha' <<< "$object")
        case "$kind" in
            commit) [[ $sha == "$SOURCE_COMMIT" ]] || fail 'remote tag moved'; return ;;
            tag) object=$(gh api "repos/$GITHUB_REPOSITORY/git/tags/$sha") ;;
            *) fail 'tag does not resolve to a commit' ;;
        esac
    done
    fail 'tag nesting exceeds release limit'
}

# Pure checks shared by API qualification and refusal fixtures.
evidence() {
    local run=$1 qualification=$2 workflow_id=$3
    jq -es --arg repo "$GITHUB_REPOSITORY" --arg sha "$SOURCE_COMMIT" --arg wid "$workflow_id" '
        length == 1 and (.[0] | .repository.full_name == $repo and .head_repository.full_name == $repo and
        (.workflow_id | tostring) == $wid and .path == ".github/workflows/ci.yml" and
        .head_sha == $sha and .status == "completed" and .conclusion == "success" and
        .head_branch == "main" and (.event == "push" or .event == "workflow_dispatch"))
    ' "$run" >/dev/null || fail 'CI run is not successful exact-source trusted CI'
    jq -es --slurpfile run "$run" --arg repo "$GITHUB_REPOSITORY" --arg sha "$SOURCE_COMMIT" '
        length == 1 and (.[0] | .schema == 1 and .repository == $repo and .workflow == ".github/workflows/ci.yml" and
        .source_commit == $sha and .route == "full" and .event == $run[0].event and
        .run_id == ($run[0].id | tostring) and .run_attempt == ($run[0].run_attempt | tostring))
    ' "$qualification" >/dev/null || fail 'missing full-route checkout qualification for this attempt'
}

qualify() {
    local workflow_id run_id scratch
    workflow_id=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml" --jq .id)
    scratch=$(mktemp -d)
    # gh run download writes only the named artifact into a fresh directory.
    gh api --method GET "repos/$GITHUB_REPOSITORY/actions/workflows/$workflow_id/runs" \
        -f head_sha="$SOURCE_COMMIT" -f status=success -f per_page=100 > "$scratch/runs.json"
    while read -r run_id; do
        gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id" > "$scratch/run.json"
        mkdir "$scratch/$run_id"
        if gh run download "$run_id" --repo "$GITHUB_REPOSITORY" --name ci-qualification --dir "$scratch/$run_id" &&
            (evidence "$scratch/run.json" "$scratch/$run_id/qualification.json" "$workflow_id"); then
            printf 'Qualified source %s with CI run %s\n' "$SOURCE_COMMIT" "$run_id"
            rm -rf "$scratch"
            return
        fi
    done < <(jq -r '.workflow_runs[] | select(.event == "push" or .event == "workflow_dispatch") | .id' "$scratch/runs.json")
    rm -rf "$scratch"
    fail 'no available successful full CI qualification for the exact source commit; dispatch full CI first'
}

package_check() {
    local dir=$1 approved=${2:-false} line filename scratch
    scratch=$(mktemp -d)
    { names; printf '%s\n' SHA256SUMS; } | LC_ALL=C sort > "$scratch/expected"
    find "$dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort > "$scratch/actual"
    [[ -z $(find "$dir" -mindepth 1 -maxdepth 1 ! -type f -print -quit) ]] || fail 'non-regular package entry'
    diff -u "$scratch/expected" "$scratch/actual" || fail 'package allowlist mismatch'
    : > "$scratch/manifest-files"
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line =~ ^[0-9a-f]{64}\ [\ \*][A-Za-z0-9._-]+$ ]] || fail 'malformed manifest line'
        filename=${line:66}
        printf '%s\n' "$filename" >> "$scratch/manifest-files"
    done < "$dir/SHA256SUMS"
    names | LC_ALL=C sort > "$scratch/expected"
    LC_ALL=C sort "$scratch/manifest-files" > "$scratch/actual"
    diff -u "$scratch/expected" "$scratch/actual" || fail 'manifest allowlist mismatch (including duplicates)'
    (cd "$dir" && sha256sum --check --strict SHA256SUMS) || fail 'payload checksum mismatch'
    if [[ $approved == true ]]; then
        printf '%s  %s/SHA256SUMS\n' "$MANIFEST_SHA256" "$dir" | sha256sum --check --strict
        printf '%s  %s/fail2zig-%s-x86_64-linux-musl\n' "$BINARY_SHA256" "$dir" "$RELEASE_TAG" | sha256sum --check --strict
    fi
    rm -rf "$scratch"
}

assemble() {
    local source=$1 dir=$2 target
    cp "$source/engine/compat/COPYING.date-profile" "$dir/COPYING.date-profile"
    cp "$source/LICENSE" "$source/SQLITE-NOTICE.md" "$dir/"
    cp "$source/docs/man/fail2zig.1" "$source/docs/man/fail2zig.toml.5" "$dir/"
    cp "$source/deploy/fail2zig.service" "$source/deploy/fail2zig.toml.example" "$dir/"
    cp "$source/scripts/install.sh" "$dir/"
    for target in "${targets[@]}"; do [[ -f "$dir/fail2zig-$RELEASE_TAG-$target" ]] || fail "missing $target"; done
    (cd "$dir" && names | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
    package_check "$dir"
}

compare() {
    local rebuilt=$1 approved=$2 name
    package_check "$rebuilt"
    package_check "$approved" true
    while read -r name; do cmp "$rebuilt/$name" "$approved/$name" || fail "unqualified rebuilt bytes: $name"; done < <(names)
    # All 13 payloads match. Preserve the approved manifest's ordering/formatting;
    # it is verified above, so its bound digest remains valid after publication.
    cp "$approved/SHA256SUMS" "$rebuilt/SHA256SUMS"
    package_check "$rebuilt" true
}

elf_check() {
    local dir=$1 target artifact expected description actual_version
    for target in "${targets[@]}"; do
        artifact="$dir/fail2zig-$RELEASE_TAG-$target"
        case "$target" in
            x86_64-*) expected='ELF 64-bit LSB.*x86-64' ;;
            aarch64-*) expected='ELF 64-bit LSB.*ARM aarch64' ;;
            arm-*) expected='ELF 32-bit LSB.*ARM' ;;
            mips-*) expected='ELF 32-bit MSB.*MIPS' ;;
            mipsel-*) expected='ELF 32-bit LSB.*MIPS' ;;
        esac
        description=$(file "$artifact")
        [[ $description =~ $expected && $description == *', stripped'* ]] || fail "wrong ELF/strip for $target"
        # Capture readelf first: a tool failure must not look like absent linkage.
        description=$(readelf -l "$artifact")
        [[ $description != *INTERP* ]] || fail "interpreter in $target"
        description=$(readelf -d "$artifact")
        [[ $description != *NEEDED* ]] || fail "dynamic dependency in $target"
    done
    artifact="$dir/fail2zig-$RELEASE_TAG-x86_64-linux-musl"
    chmod u+x "$artifact"
    actual_version=$("$artifact" --version)
    [[ $actual_version == "fail2zig ${RELEASE_TAG#v}" ]] || fail 'wrong executable version'
}

publication_guard() {
    [[ ${GITHUB_REF:-} == refs/heads/main ]] || fail 'release workflow must run from main'
    [[ ${PUBLICATION_ENABLED:-} == true ]] || fail 'publication is disabled until the maintainer configures the release environment'
    gh api "repos/$GITHUB_REPOSITORY/environments/release" | jq -e '
        any(.protection_rules[]?; .type == "required_reviewers" and (.reviewers | length) > 0)
    ' >/dev/null || fail 'release environment must require a reviewer'
}

inputs
command=${1:-}
shift || true
case "$command" in
    inputs) ;;
    identity) identity "$@" ;;
    tag) remote_tag ;;
    evidence) evidence "$@" ;;
    qualify) qualify ;;
    package) package_check "$@" ;;
    assemble) assemble "$@" ;;
    compare) compare "$@" ;;
    elf) elf_check "$@" ;;
    publication-guard) publication_guard ;;
    *) fail 'unknown release operation' ;;
esac
