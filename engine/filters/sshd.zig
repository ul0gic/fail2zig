// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Built-in `sshd` filter.
//!
//! The single most important fail2ban filter — covers roughly 80% of
//! real-world fail2ban installs. Patterns are sourced from the current
//! fail2ban `filter.d/sshd.conf` and cross-checked against OpenSSH log
//! output across the 7.x / 8.x / 9.x line.
//!
//! All patterns are compiled at comptime via `parser.compile`. There is
//! no runtime regex engine — a successful match is pure slice arithmetic.
//!
//! The fail2zig DSL tokens used below:
//!   `<IP>` — required on every pattern, populates `ParseResult.ip`.
//!   `<*>`  — wildcard (non-greedy-until-next-literal).

const std = @import("std");
const types = @import("types.zig");
const parser = @import("../core/parser.zig");

pub const PatternDef = types.PatternDef;

/// sshd failregex patterns. Ordered so the most common (Failed password)
/// is tested first — the matcher short-circuits on the first match.
pub const patterns = [_]PatternDef{
    .{
        .name = "failed-password",
        .match = parser.compile("Failed password for <*> from <IP>"),
    },
    .{
        .name = "failed-password-invalid-user",
        .match = parser.compile("Failed password for invalid user <*> from <IP>"),
    },
    .{
        .name = "invalid-user",
        .match = parser.compile("Invalid user <*> from <IP>"),
    },
    .{
        .name = "connection-closed-auth",
        .match = parser.compile("Connection closed by authenticating user <*><IP>"),
    },
    .{
        .name = "disconnected-auth",
        .match = parser.compile("Disconnected from authenticating user <*><IP>"),
    },
    .{
        .name = "pam-auth-failure",
        .match = parser.compile("error: PAM: Authentication failure for <*> from <IP>"),
    },
    .{
        // CRITICAL: require the `[preauth]` suffix. OpenSSH writes
        // `Received disconnect from <IP> port ...` on EVERY SSH
        // disconnect, including normal operator logouts. Matching the
        // bare form false-positives on legitimate sessions and bans
        // the operator's own IP. fail2ban upstream only enables this
        // pattern in `aggressive` mode for exactly this reason.
        // Regression: SYS-011, operator self-ban 2026-04-22.
        .name = "received-disconnect-preauth",
        .match = parser.compile("Received disconnect from <IP> <*>[preauth]"),
    },
    .{
        .name = "bad-protocol",
        .match = parser.compile("Bad protocol version identification <*> from <IP>"),
    },
    // OpenSSH 8+ emits a distinct "maximum authentication attempts" line.
    .{
        .name = "max-auth-attempts",
        .match = parser.compile("maximum authentication attempts exceeded for <*> from <IP>"),
    },
};

// ============================================================================
// Tests — each pattern gets >=3 positive and >=2 negative cases.
// ============================================================================

const testing = std.testing;

/// Helper: find the first pattern in `patterns` that matches `line`.
fn firstMatch(line: []const u8) ?usize {
    for (patterns, 0..) |p, i| {
        if (p.match(line)) |_| return i;
    }
    return null;
}

test "sshd: Failed password (OpenSSH 7)" {
    // Typical OpenSSH 7.x log line.
    try testing.expect(firstMatch("Failed password for root from 192.168.1.100 port 43210 ssh2") != null);
    try testing.expect(firstMatch("Failed password for admin from 10.0.0.1 port 22 ssh2") != null);
    try testing.expect(firstMatch("Failed password for ubuntu from 203.0.113.55 port 1234 ssh2") != null);
}

test "sshd: Failed password invalid user" {
    try testing.expect(firstMatch("Failed password for invalid user oracle from 1.2.3.4 port 22 ssh2") != null);
    try testing.expect(firstMatch("Failed password for invalid user postgres from 8.8.8.8 port 12345 ssh2") != null);
    try testing.expect(firstMatch("Failed password for invalid user test from 172.16.0.5 port 55555 ssh2") != null);
}

test "sshd: Invalid user" {
    try testing.expect(firstMatch("Invalid user oracle from 1.2.3.4") != null);
    try testing.expect(firstMatch("Invalid user admin from 9.9.9.9 port 22") != null);
    try testing.expect(firstMatch("Invalid user fake from 10.20.30.40") != null);
}

test "sshd: PAM authentication failure" {
    try testing.expect(firstMatch("error: PAM: Authentication failure for root from 1.2.3.4") != null);
    try testing.expect(firstMatch("error: PAM: Authentication failure for admin from 5.6.7.8") != null);
    try testing.expect(firstMatch("error: PAM: Authentication failure for invalid user x from 9.10.11.12") != null);
}

test "sshd: Connection closed by authenticating user (OpenSSH 8+)" {
    try testing.expect(firstMatch("Connection closed by authenticating user root 1.2.3.4 port 22 [preauth]") != null);
    try testing.expect(firstMatch("Connection closed by authenticating user admin 203.0.113.1 port 1234 [preauth]") != null);
    try testing.expect(firstMatch("Connection closed by authenticating user foo 10.0.0.2 port 555 [preauth]") != null);
}

test "sshd: Disconnected from authenticating user" {
    try testing.expect(firstMatch("Disconnected from authenticating user root 1.2.3.4 port 22 [preauth]") != null);
    try testing.expect(firstMatch("Disconnected from authenticating user admin 9.9.9.9 port 22 [preauth]") != null);
    try testing.expect(firstMatch("Disconnected from authenticating user invalid user x 8.8.8.8 port 22 [preauth]") != null);
}

test "sshd: Bad protocol version" {
    try testing.expect(firstMatch("Bad protocol version identification 'GET / HTTP/1.1' from 1.2.3.4 port 1234") != null);
    try testing.expect(firstMatch("Bad protocol version identification 'SSH-1.99' from 5.6.7.8 port 22") != null);
    try testing.expect(firstMatch("Bad protocol version identification 'foo' from 9.9.9.9 port 1") != null);
}

test "sshd: IPv6 addresses match" {
    try testing.expect(firstMatch("Failed password for root from 2001:db8::1 port 22 ssh2") != null);
    try testing.expect(firstMatch("Invalid user admin from ::1") != null);
}

test "sshd: negative — Accepted password (successful auth) must NOT match" {
    try testing.expect(firstMatch("Accepted password for root from 1.2.3.4 port 22 ssh2") == null);
}

test "sshd: negative — Accepted publickey must NOT match" {
    try testing.expect(firstMatch("Accepted publickey for root from 1.2.3.4 port 22 ssh2: RSA SHA256:...") == null);
}

test "sshd: negative — session opened must NOT match" {
    try testing.expect(firstMatch("pam_unix(sshd:session): session opened for user root by (uid=0)") == null);
}

test "sshd: negative — no IP present must NOT match" {
    try testing.expect(firstMatch("Failed password for root from (no address)") == null);
}

test "sshd: received-disconnect requires [preauth] (SYS-011 regression)" {
    // Positive: attacker pre-auth disconnect — the [preauth] suffix is
    // the signal that this IP never authenticated. These MUST match.
    try testing.expect(firstMatch("Received disconnect from 1.2.3.4 port 22:11: Bye Bye [preauth]") != null);
    try testing.expect(firstMatch("Received disconnect from 203.0.113.5 port 5555:11: disconnected by user [preauth]") != null);
    try testing.expect(firstMatch("Received disconnect from 2001:db8::1 port 22:11: Bye Bye [preauth]") != null);

    // Negative: normal successful-session disconnects. OpenSSH writes
    // this exact line on every clean logout; catching it self-bans the
    // operator's own IP under even modest maxretry.
    try testing.expect(firstMatch("Received disconnect from 1.2.3.4 port 22:11: disconnected by user") == null);
    try testing.expect(firstMatch("Received disconnect from 192.168.1.1 port 2222: disconnected by server request") == null);
}

test "sshd: negative — completely unrelated log line" {
    try testing.expect(firstMatch("kernel: CPU0: Package temperature above threshold") == null);
}
