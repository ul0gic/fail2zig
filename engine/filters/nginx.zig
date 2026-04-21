//! Built-in nginx filters.
//!
//! Three distinct filter sets:
//!   * `nginx_http_auth`    — basic-auth 401 failures
//!   * `nginx_limit_req`    — request-rate limit violations
//!   * `nginx_botsearch`    — 404s against well-known attack paths
//!
//! Nginx access logs have the canonical format:
//!   `<IP> - user [timestamp] "METHOD /path HTTP/1.1" STATUS SIZE "ref" "UA"`
//!
//! Error logs have the shape:
//!   `TIMESTAMP [error] PID#TID: *CONNID message, client: <IP>, server: ..., request: "..."`

const std = @import("std");
const types = @import("types.zig");
const parser = @import("../core/parser.zig");

pub const PatternDef = types.PatternDef;

/// `nginx-http-auth` — basic authentication failures.
pub const http_auth_patterns = [_]PatternDef{
    // Error log variant: "no user/password was provided for basic authentication ... client: <IP>"
    .{
        .name = "no-user-password",
        .match = parser.compile("<*>no user/password was provided for basic authentication<*>client: <IP>"),
    },
    // Error log variant: "user \"x\": was not found ... client: <IP>"
    .{
        .name = "user-not-found",
        .match = parser.compile("<*>was not found in<*>client: <IP>"),
    },
    // Error log variant: "user \"x\": password mismatch ... client: <IP>"
    .{
        .name = "password-mismatch",
        .match = parser.compile("<*>password mismatch<*>client: <IP>"),
    },
};

/// `nginx-limit-req` — rate-limit violations.
pub const limit_req_patterns = [_]PatternDef{
    .{
        .name = "limit-req-zone",
        .match = parser.compile("<*>limiting requests, excess:<*>by zone<*>client: <IP>"),
    },
    // Connection-rate variant emitted by limit_conn_zone.
    .{
        .name = "limit-conn-zone",
        .match = parser.compile("<*>limiting connections by zone<*>client: <IP>"),
    },
};

/// `nginx-botsearch` — bots probing known attack paths in access logs.
pub const botsearch_patterns = [_]PatternDef{
    // Access log 404 for wp-login.php.
    .{
        .name = "wp-login",
        .match = parser.compile("<IP> <*>wp-login"),
    },
    .{
        .name = "xmlrpc",
        .match = parser.compile("<IP> <*>xmlrpc"),
    },
    .{
        .name = "phpmyadmin",
        .match = parser.compile("<IP> <*>phpmyadmin"),
    },
    .{
        .name = "env-file",
        .match = parser.compile("<IP> <*>.env"),
    },
    .{
        .name = "git-folder",
        .match = parser.compile("<IP> <*>/.git"),
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

test "nginx-http-auth: no user/password" {
    try testing.expect(firstMatchIn(&http_auth_patterns, "2026/04/21 12:00:00 [error] 1234#0: *1 no user/password was provided for basic authentication, client: 1.2.3.4, server: example.com") != null);
    try testing.expect(firstMatchIn(&http_auth_patterns, "[error] 1#0: *5 no user/password was provided for basic authentication, client: 203.0.113.50, server: _") != null);
    try testing.expect(firstMatchIn(&http_auth_patterns, "2026/04/21 [error] no user/password was provided for basic authentication, client: 10.0.0.1, server: app") != null);
}

test "nginx-http-auth: user not found" {
    try testing.expect(firstMatchIn(&http_auth_patterns, "[error] 1#0: *2 user \"foo\": was not found in \"/etc/nginx/.htpasswd\", client: 1.2.3.4") != null);
    try testing.expect(firstMatchIn(&http_auth_patterns, "[error] user \"bar\": was not found in \"...\", client: 8.8.8.8") != null);
    try testing.expect(firstMatchIn(&http_auth_patterns, "[error] user \"x\": was not found in \"/.htpasswd\", client: 172.16.0.2") != null);
}

test "nginx-http-auth: password mismatch" {
    try testing.expect(firstMatchIn(&http_auth_patterns, "[error] user \"foo\": password mismatch, client: 1.2.3.4, server: _") != null);
    try testing.expect(firstMatchIn(&http_auth_patterns, "[error] password mismatch, client: 9.9.9.9, server: app") != null);
    try testing.expect(firstMatchIn(&http_auth_patterns, "[error] user \"x\": password mismatch, client: 10.1.2.3, server: _") != null);
}

test "nginx-http-auth: negative — successful request" {
    try testing.expect(firstMatchIn(&http_auth_patterns, "1.2.3.4 - user [21/Apr/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 1024 \"-\" \"curl/7.0\"") == null);
}

test "nginx-http-auth: negative — connection refused" {
    try testing.expect(firstMatchIn(&http_auth_patterns, "[error] 1#0: *1 connect() failed (111: Connection refused) while connecting to upstream, client: 1.2.3.4") == null);
}

test "nginx-limit-req: matches limit_req zone violation" {
    try testing.expect(firstMatchIn(&limit_req_patterns, "[error] 1#0: *1 limiting requests, excess: 0.500 by zone \"one\", client: 1.2.3.4") != null);
    try testing.expect(firstMatchIn(&limit_req_patterns, "[error] limiting requests, excess: 10 by zone \"req_zone\", client: 203.0.113.1") != null);
    try testing.expect(firstMatchIn(&limit_req_patterns, "[error] 3#0: *5 limiting requests, excess: 2.000 by zone \"api\", client: 10.0.0.10") != null);
}

test "nginx-limit-req: matches limit_conn zone violation" {
    try testing.expect(firstMatchIn(&limit_req_patterns, "[error] 1#0: *1 limiting connections by zone \"addr\", client: 5.6.7.8") != null);
}

test "nginx-limit-req: negative — normal 200 response" {
    try testing.expect(firstMatchIn(&limit_req_patterns, "1.2.3.4 - - [21/Apr/2026] \"GET / HTTP/1.1\" 200 1024 \"-\" \"Mozilla\"") == null);
}

test "nginx-limit-req: negative — unrelated error" {
    try testing.expect(firstMatchIn(&limit_req_patterns, "[error] upstream timed out, client: 1.2.3.4") == null);
}

test "nginx-botsearch: wp-login probe" {
    try testing.expect(firstMatchIn(&botsearch_patterns, "1.2.3.4 - - [21/Apr/2026:12:00:00 +0000] \"GET /wp-login.php HTTP/1.1\" 404 162") != null);
    try testing.expect(firstMatchIn(&botsearch_patterns, "203.0.113.50 - - [21/Apr/2026:12:00:00 +0000] \"POST /wordpress/wp-login.php HTTP/1.1\" 404 500") != null);
    try testing.expect(firstMatchIn(&botsearch_patterns, "8.8.8.8 - - [21/Apr/2026:12:00:00 +0000] \"GET /blog/wp-login.php?action=register HTTP/1.1\" 404 0") != null);
}

test "nginx-botsearch: xmlrpc probe" {
    try testing.expect(firstMatchIn(&botsearch_patterns, "1.2.3.4 - - [21/Apr/2026] \"POST /xmlrpc.php HTTP/1.1\" 404 162") != null);
    try testing.expect(firstMatchIn(&botsearch_patterns, "10.0.0.5 - - [21/Apr/2026] \"GET /wp/xmlrpc.php HTTP/1.1\" 404 0") != null);
}

test "nginx-botsearch: phpmyadmin probe" {
    try testing.expect(firstMatchIn(&botsearch_patterns, "1.2.3.4 - - [21/Apr/2026] \"GET /phpmyadmin/ HTTP/1.1\" 404 0") != null);
    try testing.expect(firstMatchIn(&botsearch_patterns, "9.9.9.9 - - [21/Apr/2026] \"GET /admin/phpmyadmin/index.php HTTP/1.1\" 404 0") != null);
}

test "nginx-botsearch: .env probe" {
    try testing.expect(firstMatchIn(&botsearch_patterns, "5.6.7.8 - - [21/Apr/2026] \"GET /.env HTTP/1.1\" 404 0") != null);
    try testing.expect(firstMatchIn(&botsearch_patterns, "1.2.3.4 - - [21/Apr/2026] \"GET /app/.env HTTP/1.1\" 404 0") != null);
}

test "nginx-botsearch: .git probe" {
    try testing.expect(firstMatchIn(&botsearch_patterns, "5.6.7.8 - - [21/Apr/2026] \"GET /.git/config HTTP/1.1\" 404 0") != null);
    try testing.expect(firstMatchIn(&botsearch_patterns, "1.2.3.4 - - [21/Apr/2026] \"GET /repo/.git/HEAD HTTP/1.1\" 404 0") != null);
}

test "nginx-botsearch: negative — normal homepage fetch" {
    try testing.expect(firstMatchIn(&botsearch_patterns, "1.2.3.4 - - [21/Apr/2026] \"GET / HTTP/1.1\" 200 1024 \"-\" \"curl\"") == null);
}

test "nginx-botsearch: negative — non-probe 404" {
    try testing.expect(firstMatchIn(&botsearch_patterns, "1.2.3.4 - - [21/Apr/2026] \"GET /missing.html HTTP/1.1\" 404 162") == null);
}
