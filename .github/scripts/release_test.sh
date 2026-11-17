#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig contributors
# Does:  Proves release.sh accepts valid release inputs and refuses tampered ones, and ci-select.sh routes only document-only changes short.
# Holds: Expected outcomes are fixed here, gh is a stub answering from fixtures, and every file lives in one temp directory removed on exit.

set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
helper="$root/release.sh"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export RELEASE_TAG=v1.2.3 SOURCE_COMMIT=1111111111111111111111111111111111111111 CI_RUN_ID=123
export GITHUB_REPOSITORY=owner/repo SOURCE_TREE=4444444444444444444444444444444444444444
export BINARY_SHA256 MANIFEST_SHA256 QUALIFICATION_SHA256 CI_ATTEMPT=1
BINARY_SHA256=$(printf x | sha256sum | cut -d ' ' -f 1)
MANIFEST_SHA256=$BINARY_SHA256
QUALIFICATION_SHA256=$BINARY_SHA256
passed=0
accept() { if "$@" > "$scratch/output" 2>&1; then passed=$((passed + 1)); else cat "$scratch/output"; exit 1; fi; }
refuse() { if "$@" > "$scratch/output" 2>&1; then echo "unexpected acceptance: $*" >&2; exit 1; else passed=$((passed + 1)); fi; }

accept env -u BINARY_SHA256 -u MANIFEST_SHA256 -u LAB_SCOPE bash "$helper" inputs
for tag in ../../bad v1.2.3-dev v1.2.3+diag; do refuse env RELEASE_TAG="$tag" bash "$helper" inputs; done
refuse env SOURCE_COMMIT=short bash "$helper" inputs
for run in '' 0 0123 abc '123/attempts/1'; do refuse env CI_RUN_ID="$run" bash "$helper" inputs; done
accept bash "$helper" identity "$SOURCE_COMMIT" "$SOURCE_COMMIT"
refuse bash "$helper" identity "$SOURCE_COMMIT" 2222222222222222222222222222222222222222
refuse bash "$helper" identity 2222222222222222222222222222222222222222 "$SOURCE_COMMIT"

head=3333333333333333333333333333333333333333
base=5555555555555555555555555555555555555555
checkout=2222222222222222222222222222222222222222
jq -n --arg head "$head" '{repository:{full_name:"owner/repo"},head_repository:{full_name:"contributor/fork"},
 workflow_id:42,path:".github/workflows/ci.yml",head_sha:$head,status:"completed",conclusion:"success",
 event:"pull_request",head_branch:"topic",id:123,run_attempt:1,pull_requests:[]}' > "$scratch/run"
jq -n --arg sha "$checkout" --arg tree "$SOURCE_TREE" --arg head "$head" --arg base "$base" --arg binary "$BINARY_SHA256" '
 {schema:2,repository:"owner/repo",workflow:".github/workflows/ci.yml",source_commit:$sha,source_tree:$tree,
 route:"full",event:"pull_request",run_id:"123",run_attempt:"1",head_commit:$head,base_commit:$base,
 pull_request:"129",binary_sha256:$binary}' > "$scratch/qualification"
jq -n --arg sha "$checkout" --arg tree "$SOURCE_TREE" --arg head "$head" --arg base "$base" '
 {sha:$sha,tree:{sha:$tree},parents:[{sha:$base},{sha:$head}]}' > "$scratch/tested"
jq -n --arg sha "$SOURCE_COMMIT" --arg tree "$SOURCE_TREE" '{sha:$sha,tree:{sha:$tree}}' > "$scratch/source"
jq -n --arg sha "$SOURCE_COMMIT" --arg head "$head" --arg base "$base" '
 {number:129,merged:true,merge_commit_sha:$sha,base:{ref:"main",sha:$base,repo:{full_name:"owner/repo"}},
 head:{sha:$head,repo:{full_name:"contributor/fork"}}}' > "$scratch/pr"
evidence() { bash "$helper" evidence "$1" "$2" 42 "$3" "$4" "$5"; }
accept evidence "$scratch/run" "$scratch/qualification" "$scratch/tested" "$scratch/source" "$scratch/pr"
for mutation in '.workflow_id=43' '.repository.full_name="wrong/repo"' '.head_repository.full_name="owner/repo"' \
    '.path=".github/workflows/lookalike.yml"' '.head_sha="wrong"' '.status="in_progress"' \
    '.conclusion="failure"' '.conclusion="cancelled"' '.event="push"' '.id=124' '.run_attempt=2'; do
    jq "$mutation" "$scratch/run" > "$scratch/bad"
    refuse evidence "$scratch/bad" "$scratch/qualification" "$scratch/tested" "$scratch/source" "$scratch/pr"
done
for mutation in '.route="docs"' '.source_commit="wrong"' '.source_tree="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
    '.run_attempt="2"' '.run_id="99"' '.repository="wrong/repo"' '.workflow="lookalike.yml"' \
    '.event="workflow_dispatch"' '.schema=1' 'del(.route)' '.head_commit="wrong"' '.base_commit="wrong"' \
    '.pull_request="130"' '.binary_sha256="bad"' '.binary_sha256=null'; do
    jq "$mutation" "$scratch/qualification" > "$scratch/bad"
    refuse evidence "$scratch/run" "$scratch/bad" "$scratch/tested" "$scratch/source" "$scratch/pr"
done
for mutation in '.sha="wrong"' '.tree.sha="wrong"' '.parents|=reverse' '.parents|=.[1:]' '.parents=[]'; do
    jq "$mutation" "$scratch/tested" > "$scratch/bad"
    refuse evidence "$scratch/run" "$scratch/qualification" "$scratch/bad" "$scratch/source" "$scratch/pr"
done
for mutation in '.sha="wrong"' '.tree.sha="wrong"'; do
    jq "$mutation" "$scratch/source" > "$scratch/bad"
    refuse evidence "$scratch/run" "$scratch/qualification" "$scratch/tested" "$scratch/bad" "$scratch/pr"
done
for mutation in '.merged=false' '.merge_commit_sha="wrong"' '.number=130' '.base.ref="other"' \
    '.base.repo.full_name="contributor/fork"' '.head.sha="wrong"' '.head.repo.full_name="wrong/fork"'; do
    jq "$mutation" "$scratch/pr" > "$scratch/bad"
    refuse evidence "$scratch/run" "$scratch/qualification" "$scratch/tested" "$scratch/source" "$scratch/bad"
done
jq '.head_repository.full_name="owner/repo"' "$scratch/run" > "$scratch/internal-run"
jq '.head.repo.full_name="owner/repo"' "$scratch/pr" > "$scratch/internal-pr"
accept evidence "$scratch/internal-run" "$scratch/qualification" "$scratch/tested" "$scratch/source" "$scratch/internal-pr"
for document in run qualification; do
    cat "$scratch/$document" "$scratch/$document" > "$scratch/bad"
    if [[ $document == run ]]; then
        refuse evidence "$scratch/bad" "$scratch/qualification" "$scratch/tested" "$scratch/source" "$scratch/pr"
    else
        refuse evidence "$scratch/run" "$scratch/bad" "$scratch/tested" "$scratch/source" "$scratch/pr"
    fi
done
printf 'malformed JSON' > "$scratch/bad"
refuse evidence "$scratch/run" "$scratch/bad" "$scratch/tested" "$scratch/source" "$scratch/pr"
refuse evidence "$scratch/run" "$scratch/missing" "$scratch/tested" "$scratch/source" "$scratch/pr"
jq --arg sha "$SOURCE_COMMIT" '.event="workflow_dispatch" | .head_branch="main" | .head_sha=$sha |
    .head_repository.full_name="owner/repo"' "$scratch/run" > "$scratch/dispatch"
jq --arg sha "$SOURCE_COMMIT" '.event="workflow_dispatch" | .source_commit=$sha |
    .head_commit="" | .base_commit="" | .pull_request=""' "$scratch/qualification" > "$scratch/dispatch-qualification"
printf '{}\n' > "$scratch/empty-pr"
accept evidence "$scratch/dispatch" "$scratch/dispatch-qualification" "$scratch/source" "$scratch/source" "$scratch/empty-pr"
for mutation in '.head_branch="topic"' '.head_repository.full_name="contributor/fork"' '.head_sha="wrong"'; do
    jq "$mutation" "$scratch/dispatch" > "$scratch/bad"
    refuse evidence "$scratch/bad" "$scratch/dispatch-qualification" "$scratch/source" "$scratch/source" "$scratch/empty-pr"
done
jq '.head_commit="3333333333333333333333333333333333333333"' "$scratch/dispatch-qualification" > "$scratch/bad"
refuse evidence "$scratch/dispatch" "$scratch/bad" "$scratch/source" "$scratch/source" "$scratch/empty-pr"

jq -n --arg head "$head" '["Select checks","Source and workflow checks","Product qualification","CI result"] |
    map({name:.,run_id:123,head_sha:$head,run_attempt:1,status:"completed",conclusion:"success"})' > "$scratch/jobs"
accept bash "$helper" jobs-evidence "$scratch/jobs" "$scratch/run"
jq '.run_attempt=2' "$scratch/run" > "$scratch/rerun"
jq '.[3].conclusion="cancelled" | . + [.[3] | .run_attempt=2 | .conclusion="success"]' \
    "$scratch/jobs" > "$scratch/reused-jobs"
accept bash "$helper" jobs-evidence "$scratch/reused-jobs" "$scratch/rerun"
jq '.[2].conclusion="failure" | . + [.[2] | .run_attempt=2 | .conclusion="success"]' \
    "$scratch/reused-jobs" > "$scratch/retried-jobs"
accept bash "$helper" jobs-evidence "$scratch/retried-jobs" "$scratch/rerun"
for mutation in 'map(select(.name!="Product qualification"))' '. + [.[0]]' \
    '.[0].conclusion="failure"' '.[0].conclusion="skipped"' '.[0].conclusion="cancelled"' \
    '.[0].status="in_progress"' '.[0].run_attempt=3' '.[0].run_attempt=0' '.[0].run_attempt=1.5' \
    '.[0].run_attempt="1"' '.[0].run_id=124' '.[0].head_sha="wrong"'; do
    jq "$mutation" "$scratch/reused-jobs" > "$scratch/bad"
    refuse bash "$helper" jobs-evidence "$scratch/bad" "$scratch/rerun"
done
for outcome in failure skipped cancelled; do
    jq --arg outcome "$outcome" '.[-1].conclusion=$outcome' "$scratch/retried-jobs" > "$scratch/bad"
    refuse bash "$helper" jobs-evidence "$scratch/bad" "$scratch/rerun"
done
cat "$scratch/jobs" "$scratch/jobs" > "$scratch/bad"
refuse bash "$helper" jobs-evidence "$scratch/bad" "$scratch/run"
printf '[]\n' > "$scratch/bad"
refuse bash "$helper" jobs-evidence "$scratch/bad" "$scratch/run"

mkdir "$scratch/receipt"
receipt_reset() {
    cp "$scratch/qualification" "$scratch/receipt/qualification.json"
    (cd "$scratch/receipt" && sha256sum qualification.json > qualification.sha256)
}
receipt_reset
accept bash "$helper" qualification-package "$scratch/receipt"
printf 'changed' >> "$scratch/receipt/qualification.json"
refuse bash "$helper" qualification-package "$scratch/receipt"
receipt_reset
touch "$scratch/receipt/extra"
refuse bash "$helper" qualification-package "$scratch/receipt"
rm "$scratch/receipt/extra"
mkdir "$scratch/receipt/nested"
refuse bash "$helper" qualification-package "$scratch/receipt"
rmdir "$scratch/receipt/nested"
rm "$scratch/receipt/qualification.json"
refuse bash "$helper" qualification-package "$scratch/receipt"
ln -s "$scratch/qualification" "$scratch/receipt/qualification.json"
refuse bash "$helper" qualification-package "$scratch/receipt"
rm "$scratch/receipt/qualification.json"
receipt_reset
cp "$scratch/receipt/qualification.sha256" "$scratch/saved-receipt-sum"
for name in ../qualification.json /qualification.json other.json; do
    printf '%s  %s\n' "$(cut -d ' ' -f 1 "$scratch/saved-receipt-sum")" "$name" > "$scratch/receipt/qualification.sha256"
    refuse bash "$helper" qualification-package "$scratch/receipt"
done
cat "$scratch/saved-receipt-sum" "$scratch/saved-receipt-sum" > "$scratch/receipt/qualification.sha256"
refuse bash "$helper" qualification-package "$scratch/receipt"
receipt_reset
printf '%*s' 16385 '' > "$scratch/receipt/qualification.json"
(cd "$scratch/receipt" && sha256sum qualification.json > qualification.sha256)
refuse bash "$helper" qualification-package "$scratch/receipt"

mkdir -p "$scratch/provenance-source/.github"
cp "$root/../zig.json" "$scratch/provenance-source/.github/zig.json"
provenance_fixture() {
    env GITHUB_SERVER_URL=https://github.com GITHUB_REF=refs/heads/main \
        GITHUB_SHA=7777777777777777777777777777777777777777 GITHUB_EVENT_NAME=workflow_dispatch \
        GITHUB_REPOSITORY_ID=123 GITHUB_REPOSITORY_OWNER_ID=456 RUNNER_ENVIRONMENT=github-hosted \
        GITHUB_RUN_ID=789 GITHUB_RUN_ATTEMPT=2 \
        bash "$helper" provenance "$scratch/provenance-source" "$scratch/predicate.json"
    jq -e --arg source "$SOURCE_COMMIT" --arg tree "$SOURCE_TREE" --arg binary "$BINARY_SHA256" \
        --arg manifest "$MANIFEST_SHA256" --arg qualification "$QUALIFICATION_SHA256" '
        .buildDefinition.externalParameters.inputs == {release_tag:"v1.2.3",source_commit:$source,ci_run_id:"123"} and
        .buildDefinition.internalParameters.qualification == {run_id:"123",run_attempt:"1",sha256:$qualification,source_tree:$tree} and
        .buildDefinition.internalParameters.binary_sha256 == $binary and
        .buildDefinition.internalParameters.manifest_sha256 == $manifest and
        .buildDefinition.resolvedDependencies[0].digest.gitCommit == "7777777777777777777777777777777777777777" and
        .buildDefinition.resolvedDependencies[1].digest.gitCommit == $source and
        .runDetails.builder.id == "https://github.com/owner/repo/.github/workflows/release.yml@refs/heads/main"
    ' "$scratch/predicate.json" >/dev/null
}
accept provenance_fixture

mkdir "$scratch/bin"
cat > "$scratch/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
    *environments/release*) printf '%s' "$ENVIRONMENT_FIXTURE" ;;
    *git/matching-refs/tags/*) [[ ${TAG_API_FAILURE:-false} == false ]] && printf '%s' "$TAG_FIXTURE" ;;
    *git/tags/*) printf '%s' "$ANNOTATED_FIXTURE" ;;
    *) exit 1 ;;
esac
STUB
chmod +x "$scratch/bin/gh"
export PATH="$scratch/bin:$PATH" TAG_FIXTURE ANNOTATED_FIXTURE ENVIRONMENT_FIXTURE
TAG_FIXTURE=$(jq -nc --arg sha "$SOURCE_COMMIT" '[{ref:"refs/tags/v1.2.3",object:{type:"commit",sha:$sha}}]')
accept bash "$helper" tag
accept env TAG_FIXTURE='[]' bash "$helper" tag optional
refuse env TAG_FIXTURE='[]' bash "$helper" tag
refuse env TAG_API_FAILURE=true bash "$helper" tag optional
refuse env TAG_FIXTURE='[{"ref":"refs/tags/v1.2.3","object":{"type":"commit","sha":"2222222222222222222222222222222222222222"}}]' \
    bash "$helper" tag
refuse env TAG_FIXTURE='[{"ref":"refs/tags/v1.2.30","object":{"type":"commit","sha":"1111111111111111111111111111111111111111"}}]' \
    bash "$helper" tag
ANNOTATED_FIXTURE=$(jq -nc --arg sha "$SOURCE_COMMIT" '{object:{type:"commit",sha:$sha}}')
TAG_FIXTURE='[{"ref":"refs/tags/v1.2.3","object":{"type":"tag","sha":"2222222222222222222222222222222222222222"}}]'
accept bash "$helper" tag
refuse env ANNOTATED_FIXTURE='{"object":{"type":"commit","sha":"2222222222222222222222222222222222222222"}}' bash "$helper" tag
refuse env ANNOTATED_FIXTURE='{"object":{"type":"tag","sha":"2222222222222222222222222222222222222222"}}' bash "$helper" tag
refuse env TAG_FIXTURE='[{"ref":"refs/tags/v1.2.3","object":{"type":"tree","sha":"2222222222222222222222222222222222222222"}}]' \
    bash "$helper" tag
ENVIRONMENT_FIXTURE='{"protection_rules":[{"type":"required_reviewers","reviewers":[{"type":"User"}]}]}'
accept env GITHUB_REF=refs/heads/main PUBLICATION_ENABLED=true bash "$helper" publication-guard
refuse env GITHUB_REF=refs/heads/main PUBLICATION_ENABLED=true ENVIRONMENT_FIXTURE='{"protection_rules":[]}' \
    bash "$helper" publication-guard
refuse env GITHUB_REF=refs/heads/main PUBLICATION_ENABLED=true \
    ENVIRONMENT_FIXTURE='{"protection_rules":[{"type":"required_reviewers","reviewers":[]}]}' bash "$helper" publication-guard
refuse env GITHUB_REF=refs/heads/topic PUBLICATION_ENABLED=true bash "$helper" publication-guard
refuse env GITHUB_REF=refs/heads/main PUBLICATION_ENABLED=false bash "$helper" publication-guard

mkdir "$scratch/approved" "$scratch/downloaded"
for name in LICENSE SQLITE-NOTICE.md fail2zig.1 fail2zig.service \
    fail2zig.toml.5 fail2zig.toml.example install.sh; do printf 'fixture %s\n' "$name" > "$scratch/approved/$name"; done
for target in x86_64-linux-musl aarch64-linux-musl arm-linux-musleabihf mips-linux-musleabi mipsel-linux-musleabi; do
    printf 'fixture %s\n' "$target" > "$scratch/approved/fail2zig-$RELEASE_TAG-$target"
done
(cd "$scratch/approved" && sha256sum ./* | sed 's#  ./#  #' > "$scratch/sums")
mv "$scratch/sums" "$scratch/approved/SHA256SUMS"
MANIFEST_SHA256=$(sha256sum "$scratch/approved/SHA256SUMS" | cut -d ' ' -f 1)
BINARY_SHA256=$(sha256sum "$scratch/approved/fail2zig-$RELEASE_TAG-x86_64-linux-musl" | cut -d ' ' -f 1)
cp "$scratch/approved/"* "$scratch/downloaded/"
accept bash "$helper" package "$scratch/approved" true
accept bash "$helper" compare "$scratch/approved" "$scratch/downloaded"
refuse env MANIFEST_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    bash "$helper" package "$scratch/approved" true
refuse env BINARY_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    bash "$helper" package "$scratch/approved" true
printf bad >> "$scratch/downloaded/install.sh"
refuse bash "$helper" compare "$scratch/approved" "$scratch/downloaded"
(cd "$scratch/downloaded" && sha256sum ./* | sed 's#  ./#  #' | sed '/  SHA256SUMS$/d' > "$scratch/sums")
mv "$scratch/sums" "$scratch/downloaded/SHA256SUMS"
refuse bash "$helper" compare "$scratch/approved" "$scratch/downloaded"
cp "$scratch/approved/"* "$scratch/downloaded/"
touch "$scratch/downloaded/extra"
refuse bash "$helper" package "$scratch/downloaded"
rm "$scratch/downloaded/extra" "$scratch/downloaded/LICENSE"
refuse bash "$helper" package "$scratch/downloaded"
ln -s "$scratch/approved/LICENSE" "$scratch/downloaded/LICENSE"
refuse bash "$helper" package "$scratch/downloaded"
rm "$scratch/downloaded/LICENSE"
cp "$scratch/approved/LICENSE" "$scratch/downloaded/LICENSE"
printf '%s\n' 'bad manifest' >> "$scratch/downloaded/SHA256SUMS"
refuse bash "$helper" package "$scratch/downloaded"
cp "$scratch/approved/SHA256SUMS" "$scratch/downloaded/SHA256SUMS"
head -1 "$scratch/approved/SHA256SUMS" >> "$scratch/downloaded/SHA256SUMS"
refuse bash "$helper" package "$scratch/downloaded"
tac "$scratch/approved/SHA256SUMS" > "$scratch/downloaded/SHA256SUMS"
refuse bash "$helper" compare "$scratch/approved" "$scratch/downloaded"

selector="$scratch/selector"
git init -q "$selector"
git -C "$selector" config user.name 'CI acceptance'
git -C "$selector" config user.email 'ci-acceptance@example.invalid'
# Why: Commits in the scratch repository must not depend on the host's signing setup or run its hooks.
git -C "$selector" config commit.gpgSign false
git -C "$selector" config core.hooksPath /dev/null
mkdir -p "$selector/docs" "$selector/engine"
printf 'guide\n' > "$selector/docs/guide.md"
printf 'source\n' > "$selector/engine/example.zig"
git -C "$selector" add .
git -C "$selector" commit -qm initial
selection_base=$(git -C "$selector" rev-parse HEAD)
select_expect() {
    local expected=$1 event=${2:-pull_request}
    : > "$scratch/selected"
    (cd "$selector" && env GITHUB_EVENT_NAME="$event" PR_BASE="$selection_base" \
        PR_HEAD="$(git rev-parse HEAD)" GITHUB_OUTPUT="$scratch/selected" bash "$root/ci-select.sh")
    test "$(cat "$scratch/selected")" = "full=$expected"
}
printf 'updated guide\n' >> "$selector/docs/guide.md"
git -C "$selector" commit -qam docs
accept select_expect false
accept select_expect true workflow_dispatch
git -C "$selector" checkout -q -B unknown "$selection_base"
printf 'unknown input\n' > "$selector/new-build-input"
git -C "$selector" add .
git -C "$selector" commit -qm unknown
accept select_expect true
git -C "$selector" checkout -q -B renamed "$selection_base"
git -C "$selector" mv engine/example.zig docs/example.md
git -C "$selector" commit -qm renamed
accept select_expect true
git -C "$selector" checkout -q -B release "$selection_base"
printf 'release qualification\n' > "$selector/RELEASE_NOTES.md"
git -C "$selector" add .
git -C "$selector" commit -qm release
accept select_expect true
: > "$scratch/selected"
refuse env GITHUB_EVENT_NAME=pull_request PR_BASE="$selection_base" \
    PR_HEAD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa GITHUB_OUTPUT="$scratch/selected" \
    bash "$root/ci-select.sh"
test ! -s "$scratch/selected"
printf 'release: %s acceptance/refusal checks passed\n' "$passed"
