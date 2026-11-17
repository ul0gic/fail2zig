#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig contributors
# Does:  Checks release inputs, CI qualification evidence and packages, and publishes the GitHub release through fixed operations.
# Holds: A release leaves draft only after its downloaded assets match the checked package bytes and the tag resolves to the source commit.

set -euo pipefail

fail() { echo "release: $*" >&2; exit 1; }
targets=(x86_64-linux-musl aarch64-linux-musl arm-linux-musleabihf mips-linux-musleabi mipsel-linux-musleabi)
payloads=(LICENSE SQLITE-NOTICE.md fail2zig.1 fail2zig.service fail2zig.toml.5 fail2zig.toml.example install.sh)

inputs() {
    [[ ${RELEASE_TAG:-} =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'expected a vMAJOR.MINOR.PATCH tag'
    [[ ${SOURCE_COMMIT:-} =~ ^[0-9a-f]{40}$ ]] || fail 'expected a full lowercase source SHA'
    [[ ${CI_RUN_ID:-} =~ ^[1-9][0-9]*$ ]] || fail 'expected the successful CI run ID'
}

names() {
    local target
    for target in "${targets[@]}"; do printf 'fail2zig-%s-%s\n' "$RELEASE_TAG" "$target"; done
    printf '%s\n' "${payloads[@]}"
}

identity() {
    [[ $1 == "$SOURCE_COMMIT" && $2 == "$SOURCE_COMMIT" ]] || fail 'source checkout or tag moved'
}

remote_tag() {
    local mode=${1:-required} object kind sha _depth
    object=$(gh api "repos/$GITHUB_REPOSITORY/git/matching-refs/tags/$RELEASE_TAG" |
        jq -ce --arg ref "refs/tags/$RELEASE_TAG" '[.[] | select(.ref == $ref)]')
    if [[ $(jq length <<< "$object") == 0 ]]; then
        [[ $mode == optional ]] || fail 'release tag is missing'
        return
    fi
    [[ $(jq length <<< "$object") == 1 ]] || fail 'ambiguous release tag'
    object=$(jq '.[0]' <<< "$object")
    for _depth in 1 2 3 4 5; do
        kind=$(jq -er '.object.type' <<< "$object")
        sha=$(jq -er '.object.sha' <<< "$object")
        [[ $sha =~ ^[0-9a-f]{40}$ ]] || fail 'invalid remote object'
        case "$kind" in
            commit) [[ $sha == "$SOURCE_COMMIT" ]] || fail 'remote tag moved'; return ;;
            tag) object=$(gh api "repos/$GITHUB_REPOSITORY/git/tags/$sha") ;;
            *) fail 'tag does not resolve to a commit' ;;
        esac
    done
    fail 'tag nesting exceeds release limit'
}

evidence() {
    local run=$1 qualification=$2 workflow_id=$3 tested=$4 source=$5 pr=$6
    jq -es --arg repo "$GITHUB_REPOSITORY" --arg wid "$workflow_id" --arg run "$CI_RUN_ID" '
        length == 1 and (.[0] | .repository.full_name == $repo and
        (.id | tostring) == $run and (.workflow_id | tostring) == $wid and .path == ".github/workflows/ci.yml" and
        .status == "completed" and .conclusion == "success" and
        (.event == "pull_request" or .event == "workflow_dispatch"))
    ' "$run" >/dev/null || fail 'CI run is not successful repository CI'
    jq -es --slurpfile run "$run" --slurpfile tested "$tested" --slurpfile source "$source" --slurpfile pr "$pr" \
        --arg repo "$GITHUB_REPOSITORY" --arg sha "$SOURCE_COMMIT" '
        length == 1 and (.[0] as $q |
          $q.schema == 2 and $q.repository == $repo and $q.workflow == ".github/workflows/ci.yml" and
          $q.route == "full" and $q.event == $run[0].event and
          $q.run_id == ($run[0].id | tostring) and $q.run_attempt == ($run[0].run_attempt | tostring) and
          ($q.binary_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
          $source[0].sha == $sha and $tested[0].sha == $q.source_commit and
          ($q.source_tree | type == "string" and test("^[0-9a-f]{40}$")) and
          $q.source_tree == $tested[0].tree.sha and $q.source_tree == $source[0].tree.sha and
          (if $q.event == "pull_request" then
             $pr[0].merged == true and $pr[0].merge_commit_sha == $sha and
             ($pr[0].number | tostring) == $q.pull_request and
             $pr[0].base.ref == "main" and $pr[0].base.repo.full_name == $repo and
             $pr[0].head.sha == $q.head_commit and $run[0].head_sha == $q.head_commit and
             $run[0].head_repository.full_name == $pr[0].head.repo.full_name and
             ($q.base_commit | type == "string" and test("^[0-9a-f]{40}$")) and
             [$tested[0].parents[].sha] == [$q.base_commit, $q.head_commit]
           else
             $run[0].head_branch == "main" and $run[0].head_repository.full_name == $repo and
             $run[0].head_sha == $sha and $q.source_commit == $sha and
             $q.pull_request == "" and $q.head_commit == "" and $q.base_commit == ""
           end))
    ' "$qualification" >/dev/null || fail 'CI evidence does not qualify the merged source tree'
}

qualification_package() {
    local dir=$1 manifest
    [[ $(find "$dir" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
       -z $(find "$dir" -mindepth 1 -maxdepth 1 ! -type f -print -quit) ]] || fail 'invalid qualification package'
    [[ -f $dir/qualification.json && -f $dir/qualification.sha256 &&
       $(stat -c %s "$dir/qualification.json") -le 16384 &&
       $(stat -c %s "$dir/qualification.sha256") -eq 85 ]] || fail 'invalid qualification sizes'
    manifest=$(cat "$dir/qualification.sha256")
    [[ $manifest =~ ^[0-9a-f]{64}\ \ qualification\.json$ &&
       $(wc -l < "$dir/qualification.sha256") == 1 ]] || fail 'invalid qualification digest'
    (cd "$dir" && sha256sum --check --strict qualification.sha256)
}

jobs_evidence() {
    local jobs=$1 run=$2
    jq -es --slurpfile run "$run" '
        length == 1 and (.[0] as $jobs |
          ($jobs | type == "array") and
          all($jobs[]; .run_id == $run[0].id and .head_sha == $run[0].head_sha and
            (.run_attempt | type == "number" and . >= 1 and . == floor) and .run_attempt <= $run[0].run_attempt) and
          all(["Select checks", "Source and workflow checks", "Product qualification", "CI result"][];
            . as $name | [$jobs[] | select(.name == $name)] as $matching |
            ($matching | length) > 0 and ($matching | map(.run_attempt) | max) as $latest |
            [$matching[] | select(.run_attempt == $latest)] as $current |
            ($current | length) == 1 and $current[0].status == "completed" and $current[0].conclusion == "success"))
    ' "$jobs" >/dev/null || fail 'required CI job did not succeed'
}

qualify() {
    local dir=$1 workflow_id attempt checkout pr_number artifact
    mkdir "$dir"
    workflow_id=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml" --jq .id)
    gh api "repos/$GITHUB_REPOSITORY/actions/runs/$CI_RUN_ID" > "$dir/run.json"
    attempt=$(jq -er '.run_attempt | select(type == "number" and . > 0) | tostring' "$dir/run.json")
    [[ $attempt =~ ^[1-9][0-9]*$ ]] || fail 'invalid CI attempt'
    gh api --paginate "repos/$GITHUB_REPOSITORY/actions/runs/$CI_RUN_ID/artifacts?per_page=100" \
        --jq ".artifacts[] | select(.name == \"ci-qualification-$attempt\")" > "$dir/artifacts.json"
    jq -es 'length == 1 and (.[0] | .expired == false and .size_in_bytes > 0 and .size_in_bytes < 65536)' \
        "$dir/artifacts.json" >/dev/null || fail 'missing, expired or oversized qualification artifact'
    artifact=$(jq -r .name "$dir/artifacts.json")
    mkdir "$dir/evidence"
    gh run download "$CI_RUN_ID" --repo "$GITHUB_REPOSITORY" --name "$artifact" --dir "$dir/evidence"
    qualification_package "$dir/evidence"
    checkout=$(jq -er '.source_commit | select(type == "string" and test("^[0-9a-f]{40}$"))' "$dir/evidence/qualification.json")
    gh api "repos/$GITHUB_REPOSITORY/git/commits/$checkout" > "$dir/tested.json"
    gh api "repos/$GITHUB_REPOSITORY/git/commits/$SOURCE_COMMIT" > "$dir/source.json"
    printf '{}\n' > "$dir/pr.json"
    if [[ $(jq -r .event "$dir/run.json") == pull_request ]]; then
        pr_number=$(jq -er '.pull_request | select(type == "string" and test("^[1-9][0-9]*$"))' "$dir/evidence/qualification.json")
        gh api "repos/$GITHUB_REPOSITORY/pulls/$pr_number" > "$dir/pr.json"
    fi
    evidence "$dir/run.json" "$dir/evidence/qualification.json" "$workflow_id" "$dir/tested.json" "$dir/source.json" "$dir/pr.json"
    gh api --paginate "repos/$GITHUB_REPOSITORY/actions/runs/$CI_RUN_ID/jobs?filter=all&per_page=100" \
        --jq '.jobs[]' | jq -s . > "$dir/jobs.json"
    jobs_evidence "$dir/jobs.json" "$dir/run.json"
    {
        printf 'binary_sha256=%s\n' "$(jq -r .binary_sha256 "$dir/evidence/qualification.json")"
        printf 'source_tree=%s\nci_attempt=%s\n' "$(jq -r .source_tree "$dir/evidence/qualification.json")" "$attempt"
        printf 'qualification_sha256=%s\n' "$(cut -d ' ' -f 1 "$dir/evidence/qualification.sha256")"
    } >> "${GITHUB_OUTPUT:?}"
}

provenance() {
    local source=$1 output=$2 repo_url
    [[ ${GITHUB_REF:-} == refs/heads/main && ${GITHUB_EVENT_NAME:-} == workflow_dispatch ]] || fail 'provenance requires main dispatch'
    [[ ${GITHUB_SHA:-} =~ ^[0-9a-f]{40}$ && ${SOURCE_TREE:-} =~ ^[0-9a-f]{40}$ ]] || fail 'invalid provenance source'
    [[ ${BINARY_SHA256:-} =~ ^[0-9a-f]{64}$ && ${MANIFEST_SHA256:-} =~ ^[0-9a-f]{64}$ &&
       ${QUALIFICATION_SHA256:-} =~ ^[0-9a-f]{64}$ && ${CI_ATTEMPT:-} =~ ^[1-9][0-9]*$ ]] || fail 'invalid provenance digests'
    repo_url="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY"
    jq -n --slurpfile zig "$source/.github/zig.json" \
        --arg repo_url "$repo_url" --arg ref "$GITHUB_REF" --arg workflow_commit "$GITHUB_SHA" \
        --arg source "$SOURCE_COMMIT" --arg tree "$SOURCE_TREE" --arg tag "$RELEASE_TAG" \
        --arg binary "$BINARY_SHA256" --arg manifest "$MANIFEST_SHA256" --arg qualification "$QUALIFICATION_SHA256" \
        --arg ci_run "$CI_RUN_ID" --arg ci_attempt "$CI_ATTEMPT" \
        --arg event "$GITHUB_EVENT_NAME" --arg repo_id "$GITHUB_REPOSITORY_ID" \
        --arg owner_id "$GITHUB_REPOSITORY_OWNER_ID" --arg runner "$RUNNER_ENVIRONMENT" \
        --arg run "$GITHUB_RUN_ID" --arg attempt "$GITHUB_RUN_ATTEMPT" '
        {
          buildDefinition: {
            buildType: "https://actions.github.io/buildtypes/workflow/v1",
            externalParameters: {
              inputs: {release_tag:$tag, source_commit:$source, ci_run_id:$ci_run},
              workflow: {ref:$ref, repository:$repo_url, path:".github/workflows/release.yml"}
            },
            internalParameters: {
              github: {event_name:$event, repository_id:$repo_id, repository_owner_id:$owner_id, runner_environment:$runner},
              qualification: {run_id:$ci_run, run_attempt:$ci_attempt, sha256:$qualification, source_tree:$tree},
              binary_sha256:$binary, manifest_sha256:$manifest
            },
            resolvedDependencies: [
              {uri:("git+" + $repo_url + "@" + $ref), digest:{gitCommit:$workflow_commit}},
              {uri:("git+" + $repo_url + "@" + $source), digest:{gitCommit:$source}},
              {uri:("https://ziglang.org/download/" + $zig[0].version + "/zig-x86_64-linux-" + $zig[0].version + ".tar.xz"),
               digest:{sha256:$zig[0].sha256}}
            ]
          },
          runDetails: {
            builder:{id:($repo_url + "/.github/workflows/release.yml@" + $ref)},
            metadata:{invocationId:($repo_url + "/actions/runs/" + $run + "/attempts/" + $attempt)}
          }
        }' > "$output"
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
        [[ ${BINARY_SHA256:-} =~ ^[0-9a-f]{64}$ && ${MANIFEST_SHA256:-} =~ ^[0-9a-f]{64}$ ]] || fail 'missing bound package digests'
        printf '%s  %s/SHA256SUMS\n' "$MANIFEST_SHA256" "$dir" | sha256sum --check --strict
        printf '%s  %s/fail2zig-%s-x86_64-linux-musl\n' "$BINARY_SHA256" "$dir" "$RELEASE_TAG" | sha256sum --check --strict
    fi
    rm -rf "$scratch"
}

assemble() {
    local source=$1 dir=$2 target
    cp "$source/LICENSE" "$source/SQLITE-NOTICE.md" "$dir/"
    cp "$source/docs/man/fail2zig.1" "$source/docs/man/fail2zig.toml.5" "$dir/"
    cp "$source/deploy/fail2zig.service" "$source/deploy/fail2zig.toml.example" "$dir/"
    cp "$source/scripts/install.sh" "$dir/"
    for target in "${targets[@]}"; do [[ -f "$dir/fail2zig-$RELEASE_TAG-$target" ]] || fail "missing $target"; done
    (cd "$dir" && names | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
    package_check "$dir"
    [[ ${BINARY_SHA256:-} =~ ^[0-9a-f]{64}$ ]] || fail 'missing tested x86 digest'
    printf '%s  %s/fail2zig-%s-x86_64-linux-musl\n' "$BINARY_SHA256" "$dir" "$RELEASE_TAG" | sha256sum --check --strict
    printf 'manifest_sha256=%s\n' "$(sha256sum "$dir/SHA256SUMS" | cut -d ' ' -f 1)" >> "${GITHUB_OUTPUT:?}"
}

compare() {
    local expected=$1 downloaded=$2 name
    package_check "$expected" true
    package_check "$downloaded" true
    while read -r name; do cmp "$expected/$name" "$downloaded/$name" || fail "published bytes differ: $name"; done < <(names)
    cmp "$expected/SHA256SUMS" "$downloaded/SHA256SUMS" || fail 'manifest bytes differ'
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
        # Why: Assigning first lets set -e stop on a readelf failure, which inside [[ ]] would read as absent linkage.
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

publish() {
    local dir=$1 source=$2 existing scratch name
    local missing=()
    publication_guard
    package_check "$dir" true
    remote_tag optional
    existing=$(gh api "repos/$GITHUB_REPOSITORY/git/matching-refs/tags/$RELEASE_TAG" |
        jq --arg ref "refs/tags/$RELEASE_TAG" '[.[] | select(.ref == $ref)] | length')
    if [[ $existing == 0 ]]; then
        gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs" -f "ref=refs/tags/$RELEASE_TAG" -f "sha=$SOURCE_COMMIT" >/dev/null
    fi
    remote_tag
    existing=$(gh release list --repo "$GITHUB_REPOSITORY" --limit 100 --json tagName,isDraft |
        jq -c --arg tag "$RELEASE_TAG" '[.[] | select(.tagName == $tag)]')
    if [[ $(jq length <<< "$existing") == 0 ]]; then
        gh release create "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --verify-tag --draft \
            --title "fail2zig $RELEASE_TAG" --notes-file "$source/RELEASE_NOTES.md"
    fi
    scratch=$(mktemp -d)
    gh release view "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --json assets,isDraft > "$scratch/release.json"
    if [[ $(jq -r .isDraft "$scratch/release.json") == true ]]; then
        while read -r name; do
            if ! jq -e --arg name "$name" 'any(.assets[]; .name == $name)' "$scratch/release.json" >/dev/null; then
                missing+=("$dir/$name")
            fi
        done < <(names; printf '%s\n' SHA256SUMS)
        if ((${#missing[@]})); then gh release upload "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" "${missing[@]}"; fi
    fi
    gh release download "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --dir "$scratch/downloaded"
    compare "$dir" "$scratch/downloaded"
    remote_tag
    if [[ $(jq -r .isDraft "$scratch/release.json") == true ]]; then
        gh release edit "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --draft=false --latest
    fi
    gh release download "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --dir "$scratch/public"
    compare "$dir" "$scratch/public"
    remote_tag
    rm -rf "$scratch"
}

inputs
command=${1:-}
shift || true
case "$command" in
    inputs) ;;
    identity) identity "$@" ;;
    tag) remote_tag "$@" ;;
    evidence) evidence "$@" ;;
    qualify) qualify "$@" ;;
    qualification-package) qualification_package "$@" ;;
    jobs-evidence) jobs_evidence "$@" ;;
    provenance) provenance "$@" ;;
    package) package_check "$@" ;;
    assemble) assemble "$@" ;;
    compare) compare "$@" ;;
    elf) elf_check "$@" ;;
    publication-guard) publication_guard ;;
    publish) publish "$@" ;;
    *) fail 'unknown release operation' ;;
esac
