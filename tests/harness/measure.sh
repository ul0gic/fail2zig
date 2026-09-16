#!/usr/bin/env bash

set -euo pipefail

client_bin="/usr/local/bin/fail2zig"
metrics_url="http://127.0.0.1:9100/metrics"
reset_sh="$(dirname "$0")/reset.sh"

usage() {
    cat >&2 <<EOF
Usage: $0 <subcommand> [args]

Subcommands:
  ban-latency             [--iterations N]
  memory-per-ban          [--n N]
  sustained-throughput    [--rate-lines-s N] [--duration-s N]
  cold-start-with-state   [--entries N]
EOF
    exit 2
}

now_ms() { date +%s%3N; }

daemon_pid() { pgrep -f '^/usr/local/bin/fail2zig' | head -1 || true; }

metric() {
    curl -sS --max-time 1 "$metrics_url" 2>/dev/null | \
        awk -v k="$1" '$1==k{print $2; exit}'
}

require_daemon() {
    if [ -z "$(daemon_pid)" ]; then
        echo '{"error":"daemon not running"}'
        exit 1
    fi
}

cmd_ban_latency() {
    local iterations=100
    while [ $# -gt 0 ]; do
        case "$1" in
            --iterations) iterations="$2"; shift 2 ;;
            *) usage ;;
        esac
    done
    require_daemon

    local samples=()
    for i in $(seq 1 "$iterations"); do
        local ip="192.0.2.$(( (i % 250) + 1 ))"
        sudo "$client_bin" unban "$ip" >/dev/null 2>&1 || true
        local t0; t0="$(date +%s%N)"
        logger -t "sshd[$$]" -p auth.info "Invalid user a from $ip port 11111"
        logger -t "sshd[$$]" -p auth.info "Invalid user b from $ip port 22222"
        logger -t "sshd[$$]" -p auth.info "Invalid user c from $ip port 33333"
        local deadline=$(( $(date +%s) + 5 ))
        local found=0
        while [ "$(date +%s)" -lt "$deadline" ]; do
            if sudo nft list set inet fail2zig banned_ipv4 2>/dev/null | \
                grep -q " $ip "; then
                found=1; break
            fi
        done
        local t1; t1="$(date +%s%N)"
        if [ "$found" = "1" ]; then
            samples+=( $(( (t1 - t0) / 1000 )) )
        fi
    done

    printf '{"subcommand":"ban-latency","iterations":%d,"samples":%d' \
        "$iterations" "${#samples[@]}"
    if [ "${#samples[@]}" -gt 0 ]; then
        local sorted
        mapfile -t sorted < <(printf '%s\n' "${samples[@]}" | sort -n)
        local n="${#sorted[@]}"
        local p50_idx=$(( n / 2 ))
        local p95_idx=$(( n * 95 / 100 )); [ "$p95_idx" -ge "$n" ] && p95_idx=$(( n - 1 ))
        local p99_idx=$(( n * 99 / 100 )); [ "$p99_idx" -ge "$n" ] && p99_idx=$(( n - 1 ))
        local sum=0
        for v in "${sorted[@]}"; do sum=$(( sum + v )); done
        printf ',"mean_us":%d,"p50_us":%s,"p95_us":%s,"p99_us":%s,"max_us":%s' \
            $(( sum / n )) "${sorted[$p50_idx]}" "${sorted[$p95_idx]}" \
            "${sorted[$p99_idx]}" "${sorted[-1]}"
    fi
    printf '}\n'
}

cmd_memory_per_ban() {
    local n=1000
    while [ $# -gt 0 ]; do
        case "$1" in
            --n) n="$2"; shift 2 ;;
            *) usage ;;
        esac
    done

    bash "$reset_sh" >/dev/null

    require_daemon
    local pid; pid="$(daemon_pid)"
    local rss_before; rss_before="$(sudo awk '/^VmRSS:/{print $2}' "/proc/$pid/status")"

    for i in $(seq 1 "$n"); do
        local octet=$(( (i - 1) % 250 + 1 ))
        local block=$(( (i - 1) / 250 ))
        local ip
        case "$block" in
            0) ip="203.0.113.$octet" ;;
            1) ip="198.51.100.$octet" ;;
            *) ip="192.0.2.$octet" ;;
        esac
        logger -t "sshd[$$]" -p auth.info "Invalid user a from $ip port 10000"
        logger -t "sshd[$$]" -p auth.info "Invalid user b from $ip port 20000"
        logger -t "sshd[$$]" -p auth.info "Invalid user c from $ip port 30000"
    done
    for _ in $(seq 1 50); do
        local ab; ab="$(metric fail2zig_active_bans)"
        if [ -n "$ab" ] && [ "$ab" -ge "$n" ]; then break; fi
        sleep 0.2
    done

    local rss_after; rss_after="$(sudo awk '/^VmRSS:/{print $2}' "/proc/$pid/status")"
    local delta_kb=$(( rss_after - rss_before ))
    local bytes_per_ban=$(( delta_kb * 1024 / n ))
    local ab; ab="$(metric fail2zig_active_bans)"

    printf '{"subcommand":"memory-per-ban","requested_bans":%d,"active_bans_observed":%s,"rss_before_kb":%s,"rss_after_kb":%s,"rss_delta_kb":%d,"bytes_per_ban":%d}\n' \
        "$n" "${ab:-0}" "$rss_before" "$rss_after" "$delta_kb" "$bytes_per_ban"
}

cmd_sustained_throughput() {
    local rate=1000
    local duration=10
    while [ $# -gt 0 ]; do
        case "$1" in
            --rate-lines-s) rate="$2"; shift 2 ;;
            --duration-s)   duration="$2"; shift 2 ;;
            *) usage ;;
        esac
    done
    require_daemon

    local lp0; lp0="$(metric fail2zig_lines_parsed_total)"
    local t0; t0="$(date +%s)"
    local total_sent=0
    local delay_us=$(( 1000000 / rate ))

    while [ $(( $(date +%s) - t0 )) -lt "$duration" ]; do
        logger -t "sshd[$$]" -p auth.info "sshd info: probe line ${total_sent}"
        total_sent=$(( total_sent + 1 ))
        if [ "$delay_us" -gt 100 ]; then usleep "$delay_us" 2>/dev/null || true; fi
    done

    sleep 1
    local lp1; lp1="$(metric fail2zig_lines_parsed_total)"
    local elapsed=$(( $(date +%s) - t0 ))
    local parsed_delta=$(( lp1 - lp0 ))
    local observed_rate=0
    [ "$elapsed" -gt 0 ] && observed_rate=$(( parsed_delta / elapsed ))

    printf '{"subcommand":"sustained-throughput","requested_rate_lines_s":%d,"duration_s":%d,"lines_sent":%d,"lines_parsed_delta":%d,"observed_rate_lines_s":%d}\n' \
        "$rate" "$duration" "$total_sent" "$parsed_delta" "$observed_rate"
}

cmd_cold_start_with_state() {
    local entries=1000
    while [ $# -gt 0 ]; do
        case "$1" in
            --entries) entries="$2"; shift 2 ;;
            *) usage ;;
        esac
    done

    bash "$reset_sh" >/dev/null
    require_daemon

    for i in $(seq 1 "$entries"); do
        local octet=$(( (i - 1) % 250 + 1 ))
        local block=$(( (i - 1) / 250 ))
        local ip
        case "$block" in
            0) ip="203.0.113.$octet" ;;
            1) ip="198.51.100.$octet" ;;
            2) ip="192.0.2.$octet" ;;
            *) ip="100.64.$(( block - 3 )).$octet" ;;
        esac
        logger -t "sshd[$$]" -p auth.info "Invalid user a from $ip port 10000"
        logger -t "sshd[$$]" -p auth.info "Invalid user b from $ip port 20000"
        logger -t "sshd[$$]" -p auth.info "Invalid user c from $ip port 30000"
    done
    for _ in $(seq 1 100); do
        local ab; ab="$(metric fail2zig_active_bans)"
        [ -n "$ab" ] && [ "$ab" -ge "$entries" ] && break
        sleep 0.3
    done

    sudo systemctl stop fail2zig
    local t0; t0="$(date +%s%N)"
    sudo systemctl start fail2zig
    for _ in $(seq 1 200); do
        if curl -sS --max-time 1 "$metrics_url" >/dev/null 2>&1; then break; fi
        sleep 0.05
    done
    local t1; t1="$(date +%s%N)"
    local elapsed_ms=$(( (t1 - t0) / 1000000 ))
    local ab_after; ab_after="$(metric fail2zig_active_bans)"

    printf '{"subcommand":"cold-start-with-state","requested_entries":%d,"active_bans_after_restart":%s,"cold_start_ms":%d}\n' \
        "$entries" "${ab_after:-0}" "$elapsed_ms"
}

[ $# -lt 1 ] && usage
sub="$1"; shift
case "$sub" in
    ban-latency)           cmd_ban_latency "$@" ;;
    memory-per-ban)        cmd_memory_per_ban "$@" ;;
    sustained-throughput)  cmd_sustained_throughput "$@" ;;
    cold-start-with-state) cmd_cold_start_with_state "$@" ;;
    *) usage ;;
esac
