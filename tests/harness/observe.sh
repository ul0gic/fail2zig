#!/usr/bin/env bash

set -euo pipefail

interval_ms=1000
duration_s=0
output="/dev/stdout"
while [ $# -gt 0 ]; do
    case "$1" in
        --interval-ms) interval_ms="$2"; shift 2 ;;
        --output)      output="$2"; shift 2 ;;
        --duration-s)  duration_s="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

interval_s=$(awk -v ms="$interval_ms" 'BEGIN{printf "%.3f", ms/1000.0}')

if [ "$output" != "/dev/stdout" ]; then
    mkdir -p "$(dirname "$output")"
    : > "$output"
    exec 3>"$output"
else
    exec 3>&1
fi

now_ms() { date +%s%3N; }

find_pid() { pgrep -f '^/usr/local/bin/fail2zig' | head -1 || true; }

pid="$(find_pid)"
if [ -z "$pid" ]; then
    echo '{"event":"error","msg":"fail2zig daemon not running"}' >&3
    exit 1
fi

sample_metrics() {
    local ts; ts="$(now_ms)"
    local txt
    txt="$(curl -sS --max-time 1 http://127.0.0.1:9100/metrics 2>/dev/null || true)"
    if [ -z "$txt" ]; then return; fi
    local lp lm bt ub ab pe
    lp=$(echo "$txt" | awk '/^fail2zig_lines_parsed_total /{print $2; exit}')
    lm=$(echo "$txt" | awk '/^fail2zig_lines_matched_total /{print $2; exit}')
    bt=$(echo "$txt" | awk '/^fail2zig_bans_total /{print $2; exit}')
    ub=$(echo "$txt" | awk '/^fail2zig_unbans_total /{print $2; exit}')
    ab=$(echo "$txt" | awk '/^fail2zig_active_bans /{print $2; exit}')
    pe=$(echo "$txt" | awk '/^fail2zig_parse_errors_total /{print $2; exit}')
    printf '{"ts_ms":%d,"source":"metrics","lines_parsed":%s,"lines_matched":%s,"bans_total":%s,"unbans_total":%s,"active_bans":%s,"parse_errors":%s}\n' \
        "$ts" "${lp:-0}" "${lm:-0}" "${bt:-0}" "${ub:-0}" "${ab:-0}" "${pe:-0}" >&3
}

sample_proc() {
    local ts; ts="$(now_ms)"
    [ -r "/proc/$pid/status" ] || return
    local rss vmpeak threads fd_count
    rss=$(sudo awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    vmpeak=$(sudo awk '/^VmPeak:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    threads=$(sudo awk '/^Threads:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    fd_count=$(sudo ls "/proc/$pid/fd/" 2>/dev/null | wc -l)
    printf '{"ts_ms":%d,"source":"proc","rss_kb":%s,"vmpeak_kb":%s,"threads":%s,"fd_count":%s}\n' \
        "$ts" "${rss:-0}" "${vmpeak:-0}" "${threads:-0}" "${fd_count:-0}" >&3
}

sample_nft() {
    local ts; ts="$(now_ms)"
    local count
    count=$(sudo nft -j list set inet fail2zig banned_ipv4 2>/dev/null | \
            grep -oE '"val":' | wc -l || true)
    printf '{"ts_ms":%d,"source":"nft","banned_ipv4_count":%s}\n' \
        "$ts" "${count:-0}" >&3
}

trap 'printf "{\"event\":\"stopped\",\"ts_ms\":%d}\n" "$(now_ms)" >&3; exit 0' INT TERM

start_ms="$(now_ms)"
samples=0
while :; do
    sample_metrics
    sample_proc
    sample_nft
    samples=$((samples + 1))
    if [ "$duration_s" != "0" ]; then
        now="$(now_ms)"
        if [ $(( now - start_ms )) -ge $(( duration_s * 1000 )) ]; then
            printf '{"event":"duration_reached","samples":%d,"ts_ms":%d}\n' \
                "$samples" "$now" >&3
            exit 0
        fi
    fi
    sleep "$interval_s"
done
