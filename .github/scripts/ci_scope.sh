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

classify() {
    local status path count=0
    # A dispatch is deliberately full, including after a docs-only commit.
    [[ ${GITHUB_EVENT_NAME:-} != workflow_dispatch ]] || { echo full; return; }
    comparison || { echo full; return; }
    local diff
    diff=$(mktemp)
    trap 'rm -f "$diff"' RETURN
    git diff --name-status --no-renames -z "$base" "$tip" -- > "$diff" || { echo full; return; }
    while IFS= read -r -d '' status; do
        IFS= read -r -d '' path || { echo full; return; }
        # Renames become deletion/addition pairs. Both deletions and type changes
        # must run full even if all names happen to be documentation.
        [[ $status == A || $status == M ]] || { echo full; return; }
        light_path "$path" || { echo full; return; }
        count=$((count + 1))
    done < "$diff"
    if ((count > 0)); then echo light; else echo full; fi
}

gate() {
    jq -es --argjson full "$full_jobs" '
      length == 1 and (.[0] | type == "object" and
      (keys == (["scope"] + $full | sort)) and
      (.scope.outputs.route as $route |
        ($route == "full" or $route == "light") and
        all(to_entries[];
          .value.result == (if $route == "light" and (.key as $k | $full | index($k)) != null
                            then "skipped" else "success" end))))
    ' <<< "${CI_NEEDS:-}" >/dev/null || {
        echo 'CI failed: missing, malformed, failed, cancelled or unexpectedly skipped checks.' >&2
        return 1
    }
}

case ${1:-} in
    classify)
        route=$(classify)
        printf 'route=%s\n' "$route" >> "${GITHUB_OUTPUT:?}"
        printf 'CI route: %s\n' "$route"
        ;;
    whitespace)
        if comparison; then git diff --check "$base" "$tip" --;
        else git show --format= --check HEAD --; fi
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
    *) echo 'Usage: ci_scope.sh classify|whitespace|gate|qualification' >&2; exit 2 ;;
esac
