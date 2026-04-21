// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Shell-completion scripts for fail2zig-client.
//!
//! Three supported shells: bash, zsh, fish. Each `generate*()` returns a
//! static string at comptime — no allocation needed. The scripts cover:
//!   - subcommands: status, ban, unban, list, jails, reload, version,
//!                  completions, help
//!   - global flags: --socket, --output, --no-color, --timeout, --help,
//!                   --version
//!   - flag values: --output completes to `table json plain`; the
//!                  `completions` subcommand's first positional completes
//!                  to `bash zsh fish`.
//!
//! Install instructions are included as comments at the top of each script.

const std = @import("std");

pub fn generateBash() []const u8 {
    return bash_script;
}

pub fn generateZsh() []const u8 {
    return zsh_script;
}

pub fn generateFish() []const u8 {
    return fish_script;
}

// ============================================================================
// Scripts
// ============================================================================

const bash_script =
    \\#!/usr/bin/env bash
    \\# bash completion for fail2zig-client
    \\#
    \\# Install:
    \\#   fail2zig-client completions bash > /etc/bash_completion.d/fail2zig-client
    \\# or for current user:
    \\#   fail2zig-client completions bash > ~/.local/share/bash-completion/completions/fail2zig-client
    \\
    \\_fail2zig_client_completions() {
    \\    local cur prev words cword
    \\    _init_completion || return
    \\
    \\    local subcommands="status ban unban list jails reload version completions help"
    \\    local global_flags="--socket --output --no-color --timeout --help --version"
    \\
    \\    # Flag-value completion for the previous word.
    \\    case "$prev" in
    \\        --output)
    \\            COMPREPLY=( $(compgen -W "table json plain" -- "$cur") )
    \\            return 0 ;;
    \\        --socket)
    \\            _filedir
    \\            return 0 ;;
    \\        --timeout)
    \\            COMPREPLY=( $(compgen -W "1000 3000 5000 10000 30000" -- "$cur") )
    \\            return 0 ;;
    \\        --jail)
    \\            COMPREPLY=( $(compgen -W "sshd nginx postfix dovecot" -- "$cur") )
    \\            return 0 ;;
    \\    esac
    \\
    \\    # Find the primary command (first non-flag after program name).
    \\    local cmd=""
    \\    local i=1
    \\    while [ $i -lt $cword ]; do
    \\        local w="${words[i]}"
    \\        case "$w" in
    \\            --socket|--output|--timeout)
    \\                i=$((i + 2)) ;;
    \\            -*)
    \\                i=$((i + 1)) ;;
    \\            *)
    \\                cmd="$w"
    \\                break ;;
    \\        esac
    \\    done
    \\
    \\    if [ -z "$cmd" ]; then
    \\        COMPREPLY=( $(compgen -W "$subcommands $global_flags" -- "$cur") )
    \\        return 0
    \\    fi
    \\
    \\    case "$cmd" in
    \\        status|jails|reload|version)
    \\            COMPREPLY=( $(compgen -W "$global_flags" -- "$cur") ) ;;
    \\        ban)
    \\            COMPREPLY=( $(compgen -W "--jail --duration $global_flags" -- "$cur") ) ;;
    \\        unban)
    \\            COMPREPLY=( $(compgen -W "--jail $global_flags" -- "$cur") ) ;;
    \\        list)
    \\            COMPREPLY=( $(compgen -W "--jail $global_flags" -- "$cur") ) ;;
    \\        completions)
    \\            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ) ;;
    \\        help)
    \\            COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") ) ;;
    \\    esac
    \\}
    \\
    \\complete -F _fail2zig_client_completions fail2zig-client
    \\
;

const zsh_script =
    \\#compdef fail2zig-client
    \\# zsh completion for fail2zig-client
    \\#
    \\# Install:
    \\#   fail2zig-client completions zsh > /usr/share/zsh/site-functions/_fail2zig-client
    \\# or for current user, place in any directory in $fpath and reload:
    \\#   fail2zig-client completions zsh > ~/.zfunc/_fail2zig-client
    \\
    \\_fail2zig_client() {
    \\    local -a commands global_flags
    \\    commands=(
    \\        'status:Show daemon status'
    \\        'ban:Manually ban an IP'
    \\        'unban:Manually unban an IP'
    \\        'list:List active bans'
    \\        'jails:List configured jails'
    \\        'reload:Trigger config reload'
    \\        'version:Show client and daemon version'
    \\        'completions:Generate shell completion script'
    \\        'help:Show help for a command'
    \\    )
    \\
    \\    global_flags=(
    \\        '--socket[Unix socket path]:socket path:_files'
    \\        '--output[Output format]:format:(table json plain)'
    \\        '--no-color[Disable color output]'
    \\        '--timeout[Command timeout in ms]:timeout:(1000 3000 5000 10000 30000)'
    \\        '--help[Show help]'
    \\        '-h[Show help]'
    \\        '--version[Show version]'
    \\        '-V[Show version]'
    \\    )
    \\
    \\    _arguments -C \
    \\        $global_flags \
    \\        '1: :->command' \
    \\        '*:: :->args'
    \\
    \\    case $state in
    \\        command)
    \\            _describe -t commands 'fail2zig-client command' commands ;;
    \\        args)
    \\            case $words[1] in
    \\                ban)
    \\                    _arguments \
    \\                        '--jail[Target jail]:jail name:' \
    \\                        '--duration[Ban duration in seconds]:seconds:' \
    \\                        $global_flags \
    \\                        '1:ip address:' ;;
    \\                unban)
    \\                    _arguments \
    \\                        '--jail[Target jail]:jail name:' \
    \\                        $global_flags \
    \\                        '1:ip address:' ;;
    \\                list)
    \\                    _arguments \
    \\                        '--jail[Filter by jail]:jail name:' \
    \\                        $global_flags ;;
    \\                completions)
    \\                    _arguments '1:shell:(bash zsh fish)' ;;
    \\                help)
    \\                    _describe -t commands 'subcommand' commands ;;
    \\                *)
    \\                    _arguments $global_flags ;;
    \\            esac ;;
    \\    esac
    \\}
    \\
    \\_fail2zig_client "$@"
    \\
;

const fish_script =
    \\# fish completion for fail2zig-client
    \\#
    \\# Install:
    \\#   fail2zig-client completions fish > ~/.config/fish/completions/fail2zig-client.fish
    \\
    \\# Helper: returns 0 if no primary command has been given yet.
    \\function __fail2zig_client_needs_command
    \\    set -l tokens (commandline -opc)
    \\    set -l skip_next 0
    \\    for i in (seq 2 (count $tokens))
    \\        set -l t $tokens[$i]
    \\        if test $skip_next -eq 1
    \\            set skip_next 0
    \\            continue
    \\        end
    \\        switch $t
    \\            case --socket --output --timeout
    \\                set skip_next 1
    \\            case '-*'
    \\                continue
    \\            case '*'
    \\                return 1
    \\        end
    \\    end
    \\    return 0
    \\end
    \\
    \\function __fail2zig_client_using_command
    \\    set -l cmd $argv[1]
    \\    set -l tokens (commandline -opc)
    \\    set -l skip_next 0
    \\    for i in (seq 2 (count $tokens))
    \\        set -l t $tokens[$i]
    \\        if test $skip_next -eq 1
    \\            set skip_next 0
    \\            continue
    \\        end
    \\        switch $t
    \\            case --socket --output --timeout
    \\                set skip_next 1
    \\            case '-*'
    \\                continue
    \\            case $cmd
    \\                return 0
    \\        end
    \\    end
    \\    return 1
    \\end
    \\
    \\# Primary subcommands
    \\complete -c fail2zig-client -f -n '__fail2zig_client_needs_command' -a 'status'       -d 'Show daemon status'
    \\complete -c fail2zig-client -f -n '__fail2zig_client_needs_command' -a 'ban'          -d 'Manually ban an IP'
    \\complete -c fail2zig-client -f -n '__fail2zig_client_needs_command' -a 'unban'        -d 'Manually unban an IP'
    \\complete -c fail2zig-client -f -n '__fail2zig_client_needs_command' -a 'list'         -d 'List active bans'
    \\complete -c fail2zig-client -f -n '__fail2zig_client_needs_command' -a 'jails'        -d 'List configured jails'
    \\complete -c fail2zig-client -f -n '__fail2zig_client_needs_command' -a 'reload'       -d 'Reload config'
    \\complete -c fail2zig-client -f -n '__fail2zig_client_needs_command' -a 'version'      -d 'Show version'
    \\complete -c fail2zig-client -f -n '__fail2zig_client_needs_command' -a 'completions'  -d 'Generate completion script'
    \\complete -c fail2zig-client -f -n '__fail2zig_client_needs_command' -a 'help'         -d 'Show help'
    \\
    \\# Global flags
    \\complete -c fail2zig-client -l socket   -r -d 'Unix socket path'
    \\complete -c fail2zig-client -l output   -x -a 'table json plain' -d 'Output format'
    \\complete -c fail2zig-client -l no-color     -d 'Disable color output'
    \\complete -c fail2zig-client -l timeout  -x -a '1000 3000 5000 10000 30000' -d 'Command timeout (ms)'
    \\complete -c fail2zig-client -s h -l help    -d 'Show help'
    \\complete -c fail2zig-client -s V -l version -d 'Show version'
    \\
    \\# Subcommand-specific flags
    \\complete -c fail2zig-client -n '__fail2zig_client_using_command ban'   -l jail     -x -d 'Target jail'
    \\complete -c fail2zig-client -n '__fail2zig_client_using_command ban'   -l duration -x -d 'Ban duration (seconds)'
    \\complete -c fail2zig-client -n '__fail2zig_client_using_command unban' -l jail     -x -d 'Target jail'
    \\complete -c fail2zig-client -n '__fail2zig_client_using_command list'  -l jail     -x -d 'Filter by jail'
    \\
    \\# `completions` subcommand: shell argument
    \\complete -c fail2zig-client -f -n '__fail2zig_client_using_command completions' -a 'bash zsh fish'
    \\
;

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "completions: bash starts with shebang and installs complete -F" {
    const s = generateBash();
    try testing.expect(std.mem.startsWith(u8, s, "#!/usr/bin/env bash"));
    try testing.expect(std.mem.indexOf(u8, s, "complete -F") != null);
    try testing.expect(std.mem.indexOf(u8, s, "fail2zig-client") != null);
    try testing.expect(std.mem.indexOf(u8, s, "table json plain") != null);
    try testing.expect(std.mem.indexOf(u8, s, "status") != null);
    try testing.expect(std.mem.indexOf(u8, s, "ban") != null);
    try testing.expect(std.mem.indexOf(u8, s, "Install:") != null);
}

test "completions: bash covers all subcommands" {
    const s = generateBash();
    const subs = [_][]const u8{ "status", "ban", "unban", "list", "jails", "reload", "version", "completions", "help" };
    for (subs) |sub| {
        try testing.expect(std.mem.indexOf(u8, s, sub) != null);
    }
}

test "completions: bash covers --output values" {
    const s = generateBash();
    try testing.expect(std.mem.indexOf(u8, s, "--output)") != null);
    try testing.expect(std.mem.indexOf(u8, s, "table json plain") != null);
}

test "completions: zsh has #compdef header" {
    const s = generateZsh();
    try testing.expect(std.mem.startsWith(u8, s, "#compdef fail2zig-client"));
    try testing.expect(std.mem.indexOf(u8, s, "_arguments") != null);
    try testing.expect(std.mem.indexOf(u8, s, "(table json plain)") != null);
    try testing.expect(std.mem.indexOf(u8, s, "(bash zsh fish)") != null);
    try testing.expect(std.mem.indexOf(u8, s, "Install:") != null);
}

test "completions: zsh covers all subcommands in command list" {
    const s = generateZsh();
    const subs = [_][]const u8{ "status:", "ban:", "unban:", "list:", "jails:", "reload:", "version:", "completions:", "help:" };
    for (subs) |sub| {
        try testing.expect(std.mem.indexOf(u8, s, sub) != null);
    }
}

test "completions: fish uses complete -c syntax" {
    const s = generateFish();
    try testing.expect(std.mem.indexOf(u8, s, "complete -c fail2zig-client") != null);
    try testing.expect(std.mem.indexOf(u8, s, "table json plain") != null);
    try testing.expect(std.mem.indexOf(u8, s, "bash zsh fish") != null);
    try testing.expect(std.mem.indexOf(u8, s, "Install:") != null);
}

test "completions: fish has all subcommands" {
    const s = generateFish();
    const subs = [_][]const u8{ "status", "ban", "unban", "list", "jails", "reload", "version", "completions", "help" };
    for (subs) |sub| {
        try testing.expect(std.mem.indexOf(u8, s, sub) != null);
    }
}

test "completions: fish references global flags" {
    const s = generateFish();
    try testing.expect(std.mem.indexOf(u8, s, "-l socket") != null);
    try testing.expect(std.mem.indexOf(u8, s, "-l output") != null);
    try testing.expect(std.mem.indexOf(u8, s, "-l no-color") != null);
    try testing.expect(std.mem.indexOf(u8, s, "-l timeout") != null);
}
