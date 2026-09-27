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
mkdir docs engine client tests
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
    [[ $(sed -n 's/^route=//p' "$GITHUB_OUTPUT") == "$wanted" ]] || { echo "Wrong route: wanted $wanted" >&2; exit 1; }
    count=$((count + 1))
}
event() {
    jq -n --arg before "$base" --arg after "$(git rev-parse HEAD)" \
        '{before:$before, after:$after}' > "$GITHUB_EVENT_PATH"
}
commit_case() {
    git add -- README.md docs engine client tests .github 2>/dev/null || git add -- README.md docs engine client tests
    git commit -qm fixture
    event
}
reset_case() { git reset --hard -q "$base"; git clean -fdq docs engine client tests .github; mkdir -p docs engine client tests; }
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

# Explicit narrow PR mapping; shared and unknown paths remain full.
pr_event() {
    jq -n --arg base "$base" --arg head "$(git rev-parse HEAD)" \
        '{pull_request:{base:{sha:$base},head:{sha:$head}}}' > "$GITHUB_EVENT_PATH"
}
reset_case
printf 'client\n' > client/format.zig; commit_case
expect_route full # code pushes never use PR scoping
pr_event
GITHUB_EVENT_NAME=pull_request expect_route scoped
[[ $(sed -n 's/^targets=//p' "$GITHUB_OUTPUT") == 'test-smoke test-cli-entry test-client-format test-native-cli' ]]
printf 'client\n' > client/args.zig; commit_case; pr_event
GITHUB_EVENT_NAME=pull_request expect_route scoped
[[ $(sed -n 's/^targets=//p' "$GITHUB_OUTPUT") == 'test-smoke test-cli-entry test-client-format test-native-cli' ]]
reset_case
mkdir -p engine/filters
printf 'filter\n' > engine/filters/sshd.zig; commit_case; pr_event
GITHUB_EVENT_NAME=pull_request expect_route scoped
[[ $(sed -n 's/^targets=//p' "$GITHUB_OUTPUT") == 'test-smoke test-ci-fuzz test-native-detection' ]]
for path in engine/store/records.zig engine/runtime/new.zig engine/unknown.zig; do
    reset_case
    mkdir -p "$(dirname "$path")"
    printf 'shared\n' > "$path"; commit_case; pr_event
    GITHUB_EVENT_NAME=pull_request expect_route full
done
reset_case
printf 'docs\n' >> README.md; commit_case; pr_event
GITHUB_EVENT_NAME=pull_request expect_route light
GITHUB_EVENT_NAME=workflow_dispatch expect_route full

# Every job, including the matrix's aggregate outcome, must match the route.
full='["lint","test","components","fuzz","release-target"]'
for route in full light scoped; do
    good=$(jq -n --arg route "$route" --argjson full "$full" '
        reduce (["scope"] + $full)[] as $key ({};
          .[$key] = {result:(if ($route == "light" and ($full | index($key)) != null) or ($route == "scoped" and (["components","fuzz","release-target"] | index($key)) != null) then "skipped" else "success" end)}) |
        .scope.outputs.route = $route |
        if $route == "scoped" then .scope.outputs.targets="test-smoke test-client-format" else . end')
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
# Scoped targets cannot inject shell syntax, unknown flags, duplicates or omit smoke.
for selection in 'test-smoke --help' 'test-client-format' 'test-smoke test-smoke' 'test-smoke test-client-format;id' ''; do
    bad=$(jq --arg targets "$selection" '.scope.outputs.targets=$targets' <<< "$good")
    if CI_NEEDS=$bad bash "$router" gate 2>/dev/null; then echo 'Invalid target plan accepted' >&2; exit 1; fi
done
# Exercise allowlisted dispatch with a local stub, never a real Zig build.
mkdir -p stub-bin
cat > stub-bin/zig <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${CI_STUB_LOG:?}"
STUB
chmod +x stub-bin/zig
export CI_STUB_LOG=$scratch/zig.calls
PATH="$scratch/stub-bin:$PATH" CI_TARGETS='test-smoke test-client-format' bash "$router" run-scoped
[[ $(wc -l < "$CI_STUB_LOG") == 2 ]]
[[ $(head -n 1 "$CI_STUB_LOG") == 'build test-smoke -Doptimize=ReleaseSafe -j2 --summary all' ]]
[[ $(tail -n 1 "$CI_STUB_LOG") == 'build test-client-format -Doptimize=ReleaseSafe -j2 --summary all' ]]
if PATH="$scratch/stub-bin:$PATH" CI_TARGETS='test-smoke --help' bash "$router" run-scoped 2>/dev/null; then exit 1; fi
[[ $(wc -l < "$CI_STUB_LOG") == 2 ]]
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
