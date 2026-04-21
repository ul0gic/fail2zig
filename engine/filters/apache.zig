// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Built-in Apache filters.
//!
//! Three filter sets mirror fail2ban's apache-* family:
//!   * `apache_auth`       — 401 basic-auth failures, bad credentials
//!   * `apache_badbots`    — well-known scraping / scanning user-agents
//!   * `apache_overflows`  — invalid URI / oversized request attacks
//!
//! Apache error-log shape:
//!   `[Tue Apr 21 12:00:00.000 2026] [authz_core:error] [pid 1:tid 2] [client <IP>:PORT] msg`

const std = @import("std");
const types = @import("types.zig");
const parser = @import("../core/parser.zig");

pub const PatternDef = types.PatternDef;

/// `apache-auth` — authentication failures.
pub const auth_patterns = [_]PatternDef{
    // [client 1.2.3.4] user x: authentication failure
    .{
        .name = "auth-failure",
        .match = parser.compile("<*>[client <IP>:<*>] user <*>authentication failure"),
    },
    // [client 1.2.3.4] user x not found
    .{
        .name = "user-not-found",
        .match = parser.compile("<*>[client <IP>:<*>] user <*>not found"),
    },
    // [client 1.2.3.4] AH01617: user x: password mismatch
    .{
        .name = "password-mismatch",
        .match = parser.compile("<*>[client <IP>:<*>] <*>password mismatch"),
    },
};

/// `apache-badbots` — known abusive user-agents (access log).
pub const badbots_patterns = [_]PatternDef{
    .{
        .name = "ahrefs",
        .match = parser.compile("<IP> <*>AhrefsBot"),
    },
    .{
        .name = "semrush",
        .match = parser.compile("<IP> <*>SemrushBot"),
    },
    .{
        .name = "mj12",
        .match = parser.compile("<IP> <*>MJ12bot"),
    },
    .{
        .name = "dot",
        .match = parser.compile("<IP> <*>DotBot"),
    },
    // Bots probing wp-login / xmlrpc (access log 404).
    .{
        .name = "wp-login-404",
        .match = parser.compile("<IP> <*>wp-login"),
    },
    .{
        .name = "xmlrpc-404",
        .match = parser.compile("<IP> <*>xmlrpc"),
    },
};

/// `apache-overflows` — malformed / oversized requests (error log).
pub const overflows_patterns = [_]PatternDef{
    .{
        .name = "invalid-uri",
        .match = parser.compile("<*>[client <IP>:<*>] Invalid URI in request"),
    },
    .{
        .name = "request-line-too-long",
        .match = parser.compile("<*>[client <IP>:<*>] request failed: URI too long"),
    },
    .{
        .name = "request-header-too-long",
        .match = parser.compile("<*>[client <IP>:<*>] request failed: error reading the headers"),
    },
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn firstMatchIn(patterns: []const PatternDef, line: []const u8) ?usize {
    for (patterns, 0..) |p, i| {
        if (p.match(line)) |_| return i;
    }
    return null;
}

test "apache-auth: authentication failure" {
    try testing.expect(firstMatchIn(&auth_patterns, "[Tue Apr 21 12:00:00.000 2026] [auth_basic:error] [pid 1:tid 2] [client 1.2.3.4:12345] user admin: authentication failure") != null);
    try testing.expect(firstMatchIn(&auth_patterns, "[Tue Apr 21 12:00:00 2026] [error] [client 203.0.113.50:80] user foo: authentication failure for \"/admin\"") != null);
    try testing.expect(firstMatchIn(&auth_patterns, "[error] [client 10.0.0.1:22] user bar: authentication failure for \"/dashboard\"") != null);
}

test "apache-auth: user not found" {
    try testing.expect(firstMatchIn(&auth_patterns, "[error] [client 1.2.3.4:22] user doesntexist not found: /admin") != null);
    try testing.expect(firstMatchIn(&auth_patterns, "[error] [client 9.9.9.9:1234] user ghost not found: /private") != null);
    try testing.expect(firstMatchIn(&auth_patterns, "[error] [client 8.8.8.8:80] user fake not found in htpasswd") != null);
}

test "apache-auth: password mismatch" {
    try testing.expect(firstMatchIn(&auth_patterns, "[error] [client 1.2.3.4:22] AH01617: user admin: password mismatch: /secret") != null);
    try testing.expect(firstMatchIn(&auth_patterns, "[error] [client 203.0.113.1:80] user foo: password mismatch") != null);
}

test "apache-auth: negative — successful auth" {
    try testing.expect(firstMatchIn(&auth_patterns, "[notice] [client 1.2.3.4:22] user admin authenticated successfully") == null);
}

test "apache-auth: negative — unrelated info log" {
    try testing.expect(firstMatchIn(&auth_patterns, "[notice] mod_ssl: ServerName set") == null);
}

test "apache-badbots: AhrefsBot" {
    try testing.expect(firstMatchIn(&badbots_patterns, "1.2.3.4 - - [21/Apr/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0 (compatible; AhrefsBot/7.0)\"") != null);
    try testing.expect(firstMatchIn(&badbots_patterns, "203.0.113.1 - - [21/Apr/2026] \"GET /robots.txt HTTP/1.1\" 200 0 \"-\" \"AhrefsBot\"") != null);
    try testing.expect(firstMatchIn(&badbots_patterns, "8.8.8.8 - - [21/Apr/2026] \"HEAD / HTTP/1.1\" 200 0 \"-\" \"AhrefsBot/7\"") != null);
}

test "apache-badbots: SemrushBot" {
    try testing.expect(firstMatchIn(&badbots_patterns, "1.2.3.4 - - [21/Apr/2026] \"GET / HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0 (compatible; SemrushBot/7)\"") != null);
    try testing.expect(firstMatchIn(&badbots_patterns, "203.0.113.1 - - [21/Apr/2026] \"GET / HTTP/1.1\" 200 0 \"-\" \"SemrushBot\"") != null);
}

test "apache-badbots: MJ12bot" {
    try testing.expect(firstMatchIn(&badbots_patterns, "1.2.3.4 - - [21/Apr/2026] \"GET / HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0 (compatible; MJ12bot/v1.4.8)\"") != null);
    try testing.expect(firstMatchIn(&badbots_patterns, "10.0.0.1 - - [21/Apr/2026] \"GET / HTTP/1.1\" 200 0 \"-\" \"MJ12bot\"") != null);
}

test "apache-badbots: wp-login probe" {
    try testing.expect(firstMatchIn(&badbots_patterns, "1.2.3.4 - - [21/Apr/2026:12:00:00 +0000] \"GET /wp-login.php HTTP/1.1\" 404 162") != null);
    try testing.expect(firstMatchIn(&badbots_patterns, "203.0.113.50 - - [21/Apr/2026] \"POST /wp-login.php HTTP/1.1\" 404 0") != null);
}

test "apache-badbots: negative — regular browser" {
    try testing.expect(firstMatchIn(&badbots_patterns, "1.2.3.4 - - [21/Apr/2026] \"GET / HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0 (X11; Linux x86_64) Firefox/125\"") == null);
}

test "apache-badbots: negative — search engine crawler (allowed)" {
    try testing.expect(firstMatchIn(&badbots_patterns, "1.2.3.4 - - [21/Apr/2026] \"GET / HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0 (compatible; Googlebot/2.1)\"") == null);
}

test "apache-overflows: invalid URI" {
    try testing.expect(firstMatchIn(&overflows_patterns, "[error] [pid 1:tid 2] [client 1.2.3.4:12345] Invalid URI in request GET %00 HTTP/1.1") != null);
    try testing.expect(firstMatchIn(&overflows_patterns, "[error] [client 9.9.9.9:80] Invalid URI in request FOO bar") != null);
    try testing.expect(firstMatchIn(&overflows_patterns, "[error] [client 10.1.2.3:443] Invalid URI in request GET \\x00\\x01") != null);
}

test "apache-overflows: URI too long" {
    try testing.expect(firstMatchIn(&overflows_patterns, "[error] [client 1.2.3.4:80] request failed: URI too long") != null);
    try testing.expect(firstMatchIn(&overflows_patterns, "[error] [client 203.0.113.1:80] request failed: URI too long (longer than 8190)") != null);
}

test "apache-overflows: negative — successful request" {
    try testing.expect(firstMatchIn(&overflows_patterns, "[notice] [client 1.2.3.4:80] GET /index.html HTTP/1.1") == null);
}

test "apache-overflows: negative — SSL handshake" {
    try testing.expect(firstMatchIn(&overflows_patterns, "[error] [client 1.2.3.4:443] SSL handshake failed") == null);
}
