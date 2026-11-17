#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig contributors
# Does:  Runs the admin, daemon and firewall kernel test binaries as root on an unprivileged GitHub-hosted runner.
# Holds: Each suite runs in its own new network namespace with a cleared environment and passes only with its exact SKIP count.

set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && $EUID != 0 ]] || {
    echo 'kernel CI requires an unprivileged GitHub-hosted runner' >&2
    exit 1
}
for tool in nft iptables ip6tables iptables-save ip6tables-save ipset unshare timeout; do command -v "$tool" >/dev/null; done
parent=$(readlink /proc/self/ns/net)
mkdir -p kernel-results
{ uname -a; dpkg-query -W nftables iptables ipset; } > kernel-results/environment.log
run_suite() {
    local name=$1 binary=$2 backend=$3 skips=$4 log
    log="kernel-results/$name.log"
    if ! timeout --signal=TERM --kill-after=10s 240s sudo -n env -i \
        PATH=/usr/sbin:/usr/bin:/sbin:/bin \
        F2Z_NATIVE_PARENT_NETNS="$parent" F2Z_NATIVE_DAEMON_ENFORCEMENT=1 \
        F2Z_NATIVE_FIREWALL_TRANSPORT="$backend" \
        unshare --net -- "$PWD/zig-out/bin/$binary" 2>&1 | tee "$log"; then
        return 1
    fi
    if [[ $skips == 0 ]]; then
        if grep -q 'SKIP' "$log"; then return 1; fi
        grep -Eq 'All [1-9][0-9]* tests passed\.' "$log" || return 1
    else
        test "$(grep -c 'SKIP' "$log")" = "$skips" || return 1
        grep -Eq "[1-9][0-9]* passed; $skips skipped; 0 failed\\." "$log" || return 1
    fi
}
status=0
run_suite admin admin-tests nftables 0 || status=1
run_suite daemon native-daemon-tests nftables 0 || status=1
run_suite firewall-nftables native-firewall-tests nftables 2 || status=1
run_suite firewall-iptables native-firewall-tests iptables 2 || status=1
run_suite firewall-ipset native-firewall-tests ipset 1 || status=1
exit "$status"
