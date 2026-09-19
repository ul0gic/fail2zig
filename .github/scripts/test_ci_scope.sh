#!/usr/bin/env bash
# Exercise actual git diffs and the same gate used by the workflow.
set -euo pipefail
router=$(cd "$(dirname "$0")" && pwd)/ci_scope.sh
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cd "$scratch"
git init -q
git config user.name 'CI fixture'
git config user.email ci@example.invalid
mkdir docs engine
printf 'original\n' > README.md
printf 'original\n' > docs/one.md
printf 'original\n' > engine/one.zig
git add .
git commit -qm base
base=$(git rev-parse HEAD)
export GITHUB_EVENT_PATH=$scratch/event.json GITHUB_OUTPUT=$scratch/output GITHUB_EVENT_NAME=push
count=0
expect_route() {
    local wanted=$1
    : > "$GITHUB_OUTPUT"
    bash "$router" classify >/dev/null
    [[ $(cat "$GITHUB_OUTPUT") == "route=$wanted" ]] || { echo "Wrong route: wanted $wanted" >&2; exit 1; }
    count=$((count + 1))
}
event() {
    jq -n --arg before "$base" --arg after "$(git rev-parse HEAD)" \
        '{before:$before, after:$after}' > "$GITHUB_EVENT_PATH"
}
commit_case() {
    git add -- README.md docs engine .github 2>/dev/null || git add -- README.md docs engine
    git commit -qm fixture
    event
}
reset_case() { git reset --hard -q "$base"; git clean -fdq docs engine .github; }
# Empty diff, unknown/missing and malformed event data are full.
event; expect_route full
printf '{}' > "$GITHUB_EVENT_PATH"; expect_route full
printf 'invalid' > "$GITHUB_EVENT_PATH"; expect_route full
rm "$GITHUB_EVENT_PATH"; expect_route full
printf 'docs\n' >> README.md; commit_case; expect_route light
GITHUB_EVENT_NAME=workflow_dispatch expect_route full
jq '.before = "0000000000000000000000000000000000000000"' "$GITHUB_EVENT_PATH" > missing.json
mv missing.json "$GITHUB_EVENT_PATH"; expect_route full
jq -n '{before:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",after:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}' > "$GITHUB_EVENT_PATH"
expect_route full
reset_case
mkdir -p .github/ISSUE_TEMPLATE
printf 'name: Request\n' > .github/ISSUE_TEMPLATE/feature.yml
commit_case; expect_route light
reset_case
printf 'changed\n' >> README.md
printf 'changed\n' >> engine/one.zig
commit_case; expect_route full
reset_case
rm docs/one.md; commit_case; expect_route full
reset_case
git mv docs/one.md docs/two.md; commit_case; expect_route full
reset_case
printf 'unusual\n' > 'docs/space name.md'; commit_case; expect_route light
reset_case
printf 'unusual\n' > $'docs/line\nname.md'; commit_case; expect_route full
reset_case
printf 'script\n' > docs/example.sh; commit_case; expect_route full
reset_case
mkdir -p .github/workflows
printf 'name: CI\n' > .github/workflows/ci.yml; commit_case; expect_route full
reset_case
mkdir -p .github/ISSUE_TEMPLATE/nested
printf 'name: nested\n' > .github/ISSUE_TEMPLATE/nested/form.yml; commit_case; expect_route full
reset_case
rm docs/one.md
ln -s ../engine/one.zig docs/one.md; commit_case; expect_route full
# PR comparison uses merge-base; unrelated new changes on the base are excluded.
reset_case
printf 'changed\n' >> README.md; commit_case
head=$(git rev-parse HEAD)
git checkout -q --detach "$base"
printf 'other change\n' >> engine/one.zig
git commit -qam base-advance
jq -n --arg base "$(git rev-parse HEAD)" --arg head "$head" \
    '{pull_request:{base:{sha:$base},head:{sha:$head}}}' > "$GITHUB_EVENT_PATH"
GITHUB_EVENT_NAME=pull_request expect_route light

# Every job, including the matrix's aggregate outcome, must match the route.
full='["fmt","build-native","test","components","fuzz","release-target","shellcheck","yamllint","zizmor","spdx"]'
for route in full light; do
    good=$(jq -n --arg route "$route" --argjson full "$full" '
        reduce (["scope","community"] + $full)[] as $key ({};
          .[$key] = {result:(if $route == "light" and ($full | index($key)) != null then "skipped" else "success" end)}) |
        .scope.outputs.route = $route')
    CI_NEEDS=$good bash "$router" gate
    for job in $(jq -r 'keys[]' <<< "$good"); do
        for result in failure cancelled skipped success; do
            [[ $result != "$(jq -r --arg job "$job" '.[$job].result' <<< "$good")" ]] || continue
            bad=$(jq --arg job "$job" --arg result "$result" '.[$job].result=$result' <<< "$good")
            if CI_NEEDS=$bad bash "$router" gate 2>/dev/null; then echo "Gate accepted $route/$job/$result" >&2; exit 1; fi
            count=$((count + 1))
        done
        bad=$(jq --arg job "$job" 'del(.[$job])' <<< "$good")
        if CI_NEEDS=$bad bash "$router" gate 2>/dev/null; then exit 1; fi
    done
    for bad in '' '{}' 'invalid' "$good $good" "$(jq '.scope.outputs.route="unknown"' <<< "$good")" \
        "$(jq '.extra={result:"success"}' <<< "$good")"; do
        if CI_NEEDS=$bad bash "$router" gate 2>/dev/null; then exit 1; fi
    done
done
# Qualification rejects a different checkout even when every job passed.
export CI_NEEDS
CI_NEEDS=$(jq '.scope.outputs.route="full" | with_entries(.value.result="success")' <<< "$good")
export GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REPOSITORY=fixture/repo GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1
export GITHUB_SHA
GITHUB_SHA=$(git rev-parse HEAD)
bash "$router" qualification
jq -e --arg sha "$GITHUB_SHA" '.source_commit==$sha and .route=="full" and .schema==1' qualification.json >/dev/null
if GITHUB_SHA=$base bash "$router" qualification; then exit 1; fi
if GITHUB_EVENT_NAME=pull_request bash "$router" qualification; then exit 1; fi
printf 'CI scope fixtures passed (%s route/result cases plus malformed, missing and qualification refusals).\n' "$count"
