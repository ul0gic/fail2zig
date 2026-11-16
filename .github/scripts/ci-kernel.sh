#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig contributors
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && $EUID != 0 ]] || {
    echo 'kernel CI requires an unprivileged GitHub-hosted runner' >&2
    exit 1
}
for tool in nft iptables ip6tables iptables-save ip6tables-save ipset unshare timeout; do command -v "$tool" >/dev/null; done
parent=$(readlink /proc/self/ns/net)
mkdir -p kernel-results
run_suite() {
    local name=$1 binary=$2 backend=$3 skips=$4 log
    log="kernel-results/$name.log"
    timeout --signal=TERM --kill-after=10s 240s sudo -n env -i \
        PATH=/usr/sbin:/usr/bin:/sbin:/bin \
        F2Z_NATIVE_PARENT_NETNS="$parent" F2Z_NATIVE_DAEMON_ENFORCEMENT=1 \
        F2Z_NATIVE_FIREWALL_TRANSPORT="$backend" \
        unshare --net -- "$PWD/zig-out/bin/$binary" 2>&1 | tee "$log"
    if [[ $skips == 0 ]]; then
        ! grep -q 'SKIP' "$log"
        grep -Eq 'All [1-9][0-9]* tests passed\.' "$log"
    else
        test "$(grep -c 'SKIP' "$log")" = "$skips"
        grep -Eq "[1-9][0-9]* passed; $skips skipped; 0 failed\\." "$log"
    fi
}
run_suite admin admin-tests nftables 0
run_suite daemon native-daemon-tests nftables 0
run_suite firewall-nftables native-firewall-tests nftables 2
run_suite firewall-iptables native-firewall-tests iptables 2
run_suite firewall-ipset native-firewall-tests ipset 1
