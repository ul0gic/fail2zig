#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig contributors
# Bounded refusal fixtures; no network, builds, credentials, or publication.
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
helper="$root/release.sh"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export RELEASE_TAG=v1.2.3 SOURCE_COMMIT=1111111111111111111111111111111111111111
export BINARY_SHA256 MANIFEST_SHA256 LAB_SCOPE='fixture only' GITHUB_REPOSITORY=owner/repo
BINARY_SHA256=$(printf x | sha256sum | cut -d ' ' -f 1)
MANIFEST_SHA256=$BINARY_SHA256
passed=0
accept() { if "$@" > "$scratch/output" 2>&1; then passed=$((passed + 1)); else cat "$scratch/output"; exit 1; fi; }
refuse() { if "$@" > "$scratch/output" 2>&1; then echo "unexpected acceptance: $*" >&2; exit 1; else passed=$((passed + 1)); fi; }
accept bash "$helper" inputs
refuse env RELEASE_TAG=../../bad bash "$helper" inputs
refuse env RELEASE_TAG=v1.2.3-dev bash "$helper" inputs
refuse env SOURCE_COMMIT=short bash "$helper" inputs
refuse env BINARY_SHA256=bad bash "$helper" inputs
refuse env MANIFEST_SHA256=bad bash "$helper" inputs
refuse env LAB_SCOPE= bash "$helper" inputs
accept bash "$helper" identity "$SOURCE_COMMIT" "$SOURCE_COMMIT"
refuse bash "$helper" identity "$SOURCE_COMMIT" 2222222222222222222222222222222222222222
refuse bash "$helper" identity 2222222222222222222222222222222222222222 "$SOURCE_COMMIT"

jq -n --arg sha "$SOURCE_COMMIT" '{repository:{full_name:"owner/repo"},head_repository:{full_name:"owner/repo"},
 workflow_id:42,path:".github/workflows/ci.yml",head_sha:$sha,status:"completed",conclusion:"success",
 event:"push",head_branch:"main",id:123,run_attempt:1}' > "$scratch/run"
jq -n --arg sha "$SOURCE_COMMIT" '{schema:1,repository:"owner/repo",workflow:".github/workflows/ci.yml",
 source_commit:$sha,route:"full",event:"push",run_id:"123",run_attempt:"1"}' > "$scratch/qualification"
accept bash "$helper" evidence "$scratch/run" "$scratch/qualification" 42
for mutation in '.workflow_id=43' '.repository.full_name="wrong/repo"' '.head_repository.full_name="wrong/repo"' \
    '.path=".github/workflows/lookalike.yml"' '.head_sha="wrong"' '.status="in_progress"' \
    '.conclusion="failure"' '.conclusion="cancelled"' '.event="pull_request"' '.head_branch="other"'; do
    jq "$mutation" "$scratch/run" > "$scratch/bad-run"
    refuse bash "$helper" evidence "$scratch/bad-run" "$scratch/qualification" 42
done
for mutation in '.route="light"' '.source_commit="wrong"' '.run_attempt="2"' '.run_id="99"' \
    '.repository="wrong/repo"' '.workflow="lookalike.yml"' '.event="pull_request"' '.schema=2' 'del(.route)'; do
    jq "$mutation" "$scratch/qualification" > "$scratch/bad-qualification"
    refuse bash "$helper" evidence "$scratch/run" "$scratch/bad-qualification" 42
done
refuse bash "$helper" evidence "$scratch/run" "$scratch/missing" 42
jq '.event="workflow_dispatch"' "$scratch/run" > "$scratch/dispatch"
jq '.event="workflow_dispatch"' "$scratch/qualification" > "$scratch/dispatch-qualification"
accept bash "$helper" evidence "$scratch/dispatch" "$scratch/dispatch-qualification" 42
jq '.head_branch="topic"' "$scratch/dispatch" > "$scratch/bad-run"
refuse bash "$helper" evidence "$scratch/bad-run" "$scratch/dispatch-qualification" 42
cat "$scratch/run" "$scratch/run" > "$scratch/bad-run"
refuse bash "$helper" evidence "$scratch/bad-run" "$scratch/qualification" 42
cat "$scratch/qualification" "$scratch/qualification" > "$scratch/bad-qualification"
refuse bash "$helper" evidence "$scratch/run" "$scratch/bad-qualification" 42
printf 'malformed JSON' > "$scratch/bad-qualification"
refuse bash "$helper" evidence "$scratch/run" "$scratch/bad-qualification" 42
# No network: model current lightweight/annotated tags and publication settings.
mkdir "$scratch/bin"
cat > "$scratch/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
    *environments/release*) printf '%s' "$ENVIRONMENT_FIXTURE" ;;
    *git/ref/tags/*) printf '%s' "$TAG_FIXTURE" ;;
    *git/tags/*) printf '%s' "$ANNOTATED_FIXTURE" ;;
    *) exit 1 ;;
esac
STUB
chmod +x "$scratch/bin/gh"
export PATH="$scratch/bin:$PATH" TAG_FIXTURE ANNOTATED_FIXTURE ENVIRONMENT_FIXTURE
TAG_FIXTURE=$(jq -nc --arg sha "$SOURCE_COMMIT" '{object:{type:"commit",sha:$sha}}')
accept bash "$helper" tag
refuse env TAG_FIXTURE='{"object":{"type":"commit","sha":"wrong"}}' bash "$helper" tag
ANNOTATED_FIXTURE=$TAG_FIXTURE
TAG_FIXTURE='{"object":{"type":"tag","sha":"2222222222222222222222222222222222222222"}}'
accept bash "$helper" tag
refuse env ANNOTATED_FIXTURE='{"object":{"type":"commit","sha":"wrong"}}' bash "$helper" tag
refuse env ANNOTATED_FIXTURE="$TAG_FIXTURE" bash "$helper" tag
refuse env TAG_FIXTURE='{"object":{"type":"tree","sha":"wrong"}}' bash "$helper" tag
ENVIRONMENT_FIXTURE='{"protection_rules":[{"type":"required_reviewers","reviewers":[{"type":"User"}]}]}'
accept env GITHUB_REF=refs/heads/main PUBLICATION_ENABLED=true bash "$helper" publication-guard
refuse env GITHUB_REF=refs/heads/main PUBLICATION_ENABLED=true ENVIRONMENT_FIXTURE='{"protection_rules":[]}' \
    bash "$helper" publication-guard
refuse env GITHUB_REF=refs/heads/main PUBLICATION_ENABLED=true \
    ENVIRONMENT_FIXTURE='{"protection_rules":[{"type":"required_reviewers","reviewers":[]}]}' bash "$helper" publication-guard

mkdir "$scratch/approved" "$scratch/rebuilt"
for name in COPYING.date-profile LICENSE SQLITE-NOTICE.md fail2zig.1 fail2zig.service \
    fail2zig.toml.5 fail2zig.toml.example install.sh; do printf 'fixture %s\n' "$name" > "$scratch/approved/$name"; done
for target in x86_64-linux-musl aarch64-linux-musl arm-linux-musleabihf mips-linux-musleabi mipsel-linux-musleabi; do
    printf 'fixture %s\n' "$target" > "$scratch/approved/fail2zig-$RELEASE_TAG-$target"
done
(cd "$scratch/approved" && sha256sum ./* | sed 's#  ./#  #' > "$scratch/sums")
mv "$scratch/sums" "$scratch/approved/SHA256SUMS"
MANIFEST_SHA256=$(sha256sum "$scratch/approved/SHA256SUMS" | cut -d ' ' -f 1)
BINARY_SHA256=$(sha256sum "$scratch/approved/fail2zig-$RELEASE_TAG-x86_64-linux-musl" | cut -d ' ' -f 1)
cp "$scratch/approved/"* "$scratch/rebuilt/"
accept bash "$helper" package "$scratch/approved" true
accept bash "$helper" compare "$scratch/rebuilt" "$scratch/approved"
refuse env MANIFEST_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    bash "$helper" package "$scratch/approved" true
refuse env BINARY_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    bash "$helper" package "$scratch/approved" true
printf bad >> "$scratch/rebuilt/install.sh"
refuse bash "$helper" compare "$scratch/rebuilt" "$scratch/approved"
# Even self-consistent replacement payload/checksums must not replace approved bytes.
(cd "$scratch/rebuilt" && sha256sum ./* | sed 's#  ./#  #' | sed '/  SHA256SUMS$/d' > "$scratch/sums")
mv "$scratch/sums" "$scratch/rebuilt/SHA256SUMS"
refuse bash "$helper" compare "$scratch/rebuilt" "$scratch/approved"
cp "$scratch/approved/"* "$scratch/rebuilt/"
touch "$scratch/rebuilt/extra"
refuse bash "$helper" package "$scratch/rebuilt"
rm "$scratch/rebuilt/extra" "$scratch/rebuilt/LICENSE"
refuse bash "$helper" package "$scratch/rebuilt"
ln -s "$scratch/approved/LICENSE" "$scratch/rebuilt/LICENSE"
refuse bash "$helper" package "$scratch/rebuilt"
rm "$scratch/rebuilt/LICENSE"
cp "$scratch/approved/LICENSE" "$scratch/rebuilt/LICENSE"
printf '%s\n' 'bad manifest' >> "$scratch/rebuilt/SHA256SUMS"
refuse bash "$helper" package "$scratch/rebuilt"
cp "$scratch/approved/SHA256SUMS" "$scratch/rebuilt/SHA256SUMS"
head -1 "$scratch/approved/SHA256SUMS" >> "$scratch/rebuilt/SHA256SUMS"
refuse bash "$helper" package "$scratch/rebuilt"
# Manifest ordering is semantically irrelevant, but approved digest is retained.
tac "$scratch/approved/SHA256SUMS" > "$scratch/rebuilt/SHA256SUMS"
accept bash "$helper" compare "$scratch/rebuilt" "$scratch/approved"
cmp "$scratch/rebuilt/SHA256SUMS" "$scratch/approved/SHA256SUMS"
refuse env GITHUB_REF=refs/heads/topic PUBLICATION_ENABLED=true bash "$helper" publication-guard
refuse env GITHUB_REF=refs/heads/main PUBLICATION_ENABLED=false bash "$helper" publication-guard
printf 'release: %s acceptance/refusal fixtures passed\n' "$passed"
