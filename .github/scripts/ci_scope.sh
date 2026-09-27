#!/usr/bin/env bash
# Conservative CI routing and fail-closed result aggregation. Requires git and jq.
set -euo pipefail

full_jobs='["lint","test","components","fuzz","release-target"]'

comparison() {
    local head
    [[ -f ${GITHUB_EVENT_PATH:-} ]] || return 1
    case ${GITHUB_EVENT_NAME:-} in
        pull_request)
            base=$(jq -er '.pull_request.base.sha' "$GITHUB_EVENT_PATH") || return 1
            head=$(jq -er '.pull_request.head.sha' "$GITHUB_EVENT_PATH") || return 1
            ;;
        push)
            base=$(jq -er '.before' "$GITHUB_EVENT_PATH") || return 1
            head=$(jq -er '.after' "$GITHUB_EVENT_PATH") || return 1
            ;;
        *) return 1 ;;
    esac
    [[ $base =~ ^[0-9a-f]{40}$ && $head =~ ^[0-9a-f]{40}$ ]] || return 1
    [[ $base != 0000000000000000000000000000000000000000 ]] || return 1
    git cat-file -e "$base^{commit}" 2>/dev/null || return 1
    git cat-file -e "$head^{commit}" 2>/dev/null || return 1
    if [[ $GITHUB_EVENT_NAME == pull_request ]]; then
        base=$(git merge-base "$base" "$head") || return 1
    fi
    tip=$head
}

light_path() {
    case $1 in
        /*|*'/../'*|../*|*'/./'*|*//*|*$'\n'*|*$'\r'*) return 1 ;;
        README.md|CONTRIBUTING.md|CHANGELOG.md|RELEASE_NOTES.md|SECURITY.md|CODE_OF_CONDUCT.md|.github/PULL_REQUEST_TEMPLATE.md) return 0 ;;
        docs/*.md) return 0 ;;
        .github/ISSUE_TEMPLATE/*)
            local name=${1#.github/ISSUE_TEMPLATE/}
            [[ $name != */* && $name == *.@(yml|yaml|md) ]] ;;
        *) return 1 ;;
    esac
}

# Narrow PR mapping. Unknown paths deliberately select the full maintained gate.
# Space-separated build steps are constants here, never derived from path text.
scoped_path() {
    case $1 in
        client/*|tests/component/client_format_tests.zig|tests/integration/cli_entry_test.zig)
            echo 'test-client-format test-cli-entry test-native-cli' ;;
        engine/cli/rule_test.zig|tests/component/native_rule_test_tests.zig)
            echo 'test-native-rule-test test-native-rules' ;;
        engine/filters/*|engine/core/parser.zig|tests/component/native_detection_tests.zig)
            echo 'test-native-detection test-ci-fuzz' ;;
        engine/core/native_rules.zig|tests/component/native_rule_tests.zig)
            echo 'test-native-rules test-native-consumer-plan test-ci-fuzz' ;;
        *) return 1 ;;
    esac
}

classify() {
    local status path count=0 all_light=true targets='' selected
    [[ ${GITHUB_EVENT_NAME:-} != workflow_dispatch ]] || { echo full; return; }
    comparison || { echo full; return; }
    local diff
    diff=$(mktemp)
    trap 'rm -f "$diff"' RETURN
    git diff --name-status --no-renames -z "$base" "$tip" -- > "$diff" || { echo full; return; }
    while IFS= read -r -d '' status; do
        IFS= read -r -d '' path || { echo full; return; }
        # Deletions, renames and type changes remain conservative.
        [[ $status == A || $status == M ]] || { echo full; return; }
        case $path in
            /*|*'/../'*|../*|*'/./'*|*//*|*$'\n'*|*$'\r'*) echo full; return ;;
        esac
        count=$((count + 1))
        if light_path "$path"; then continue; fi
        all_light=false
        [[ ${GITHUB_EVENT_NAME:-} == pull_request ]] || { echo full; return; }
        selected=$(scoped_path "$path") || { echo full; return; }
        targets+=" $selected"
    done < "$diff"
    if ((count == 0)); then echo full
    elif $all_light; then echo light
    else
        # Stable deduplication also avoids rerunning a component for two changed paths.
        printf 'scoped|test-smoke'
        printf '%s\n' "$targets" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ' | sed 's/^/ /;s/ $/\n/'
    fi
}

validate_targets() {
    local target seen=' '
    [[ ${CI_TARGETS:-} == test-smoke\ * ]] || return 1
    [[ $CI_TARGETS != *$'\n'* && $CI_TARGETS != *$'\r'* ]] || return 1
    read -r -a targets <<< "$CI_TARGETS"
    for target in "${targets[@]}"; do
        case $target in
            test-smoke|test-client-format|test-cli-entry|test-native-cli|test-native-rule-test|test-native-rules|test-native-consumer-plan|test-native-detection|test-ci-fuzz) ;;
            *) return 1 ;;
        esac
        [[ $seen != *" $target "* ]] || return 1
        seen+="$target "
    done
}

gate() {
    jq -es --argjson full "$full_jobs" '
      length == 1 and (.[0] | type == "object" and
      (keys == (["scope"] + $full | sort)) and
      (.scope.outputs.route as $route |
        ($route == "full" or $route == "light" or $route == "scoped") and
        all(to_entries[];
          .value.result == (if ($route == "light" and (.key as $k | $full | index($k)) != null) or
                               ($route == "scoped" and (.key as $k | ["components","fuzz","release-target"] | index($k)) != null)
                            then "skipped" else "success" end))))
    ' <<< "${CI_NEEDS:-}" >/dev/null || {
        echo 'CI failed: missing, malformed, failed, cancelled or unexpectedly skipped checks.' >&2
        return 1
    }
    if [[ $(jq -r '.scope.outputs.route' <<< "$CI_NEEDS") == scoped ]]; then
        CI_TARGETS=$(jq -er '.scope.outputs.targets' <<< "$CI_NEEDS") validate_targets
    fi
}

case ${1:-} in
    classify)
        selection=$(classify)
        route=${selection%%|*}
        if [[ $route == scoped ]]; then
            printf 'targets=%s\n' "${selection#*|}" >> "${GITHUB_OUTPUT:?}"
        fi
        printf 'route=%s\n' "$route" >> "${GITHUB_OUTPUT:?}"
        printf 'CI route: %s\n' "$route"
        ;;
    whitespace)
        if comparison; then git diff --check "$base" "$tip" --;
        else git show --format= --check HEAD --; fi
        ;;
    run-scoped)
        validate_targets || { echo 'Invalid scoped build targets' >&2; exit 2; }
        # Separate invocations serialize any steps sharing zig-out/bin.
        for target in "${targets[@]}"; do
            zig build "$target" -Doptimize=ReleaseSafe -j2 --summary all
        done
        ;;
    gate) gate ;;
    qualification)
        gate
        [[ $(jq -r '.scope.outputs.route' <<< "$CI_NEEDS") == full ]]
        [[ ${GITHUB_EVENT_NAME:-} == workflow_dispatch ||
           ( ${GITHUB_EVENT_NAME:-} == push && ${GITHUB_REF:-} == refs/heads/main ) ]]
        actual=$(git rev-parse HEAD)
        [[ $actual == "${GITHUB_SHA:?}" && $actual =~ ^[0-9a-f]{40}$ ]]
        jq -n --arg repository "${GITHUB_REPOSITORY:?}" --arg source_commit "$actual" \
            --arg event "$GITHUB_EVENT_NAME" --arg run_id "${GITHUB_RUN_ID:?}" \
            --arg run_attempt "${GITHUB_RUN_ATTEMPT:?}" \
            '{schema:1, repository:$repository, workflow:".github/workflows/ci.yml",
              source_commit:$source_commit, route:"full", event:$event,
              run_id:$run_id, run_attempt:$run_attempt}' > qualification.json
        ;;
    *) echo 'Usage: ci_scope.sh classify|whitespace|run-scoped|gate|qualification' >&2; exit 2 ;;
esac
