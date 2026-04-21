//! Built-in filter registry.
//!
//! Maps filter names (the canonical strings operators use in
//! `filter = <name>` directives) to their comptime-compiled pattern
//! arrays. Every registered name is a pointer into `.rodata` — the
//! registry itself has zero runtime state.
//!
//! Naming convention matches fail2ban's filter.d files so operators
//! migrating `filter = sshd` (and friends) get a zero-config path.
//! Where fail2ban uses hyphens (e.g. `nginx-http-auth`), we accept
//! BOTH the hyphenated form and the underscore form (e.g.
//! `nginx_http_auth`) to smooth over TOML key conventions.

const std = @import("std");
const types = @import("types.zig");
const sshd = @import("sshd.zig");
const nginx = @import("nginx.zig");
const apache = @import("apache.zig");
const mail = @import("mail.zig");
const misc = @import("misc.zig");

pub const PatternDef = types.PatternDef;

/// One entry in the registry table. `patterns` points at a static array
/// compiled once at build time.
pub const Entry = struct {
    name: []const u8,
    patterns: []const PatternDef,
};

/// Full registry. Every filter fail2zig ships with is listed here.
/// Order is alphabetical for stable `--list-filters` output.
pub const entries = [_]Entry{
    .{ .name = "apache-auth", .patterns = &apache.auth_patterns },
    .{ .name = "apache-badbots", .patterns = &apache.badbots_patterns },
    .{ .name = "apache-overflows", .patterns = &apache.overflows_patterns },
    .{ .name = "courier", .patterns = &mail.courier_patterns },
    .{ .name = "dovecot", .patterns = &mail.dovecot_patterns },
    .{ .name = "mysqld-auth", .patterns = &misc.mysqld_auth_patterns },
    .{ .name = "named-refused", .patterns = &misc.named_refused_patterns },
    .{ .name = "nginx-botsearch", .patterns = &nginx.botsearch_patterns },
    .{ .name = "nginx-http-auth", .patterns = &nginx.http_auth_patterns },
    .{ .name = "nginx-limit-req", .patterns = &nginx.limit_req_patterns },
    .{ .name = "postfix", .patterns = &mail.postfix_patterns },
    .{ .name = "proftpd", .patterns = &misc.proftpd_patterns },
    .{ .name = "recidive", .patterns = &misc.recidive_patterns },
    .{ .name = "sshd", .patterns = &sshd.patterns },
    .{ .name = "vsftpd", .patterns = &misc.vsftpd_patterns },
};

/// Look up a filter by name. Accepts hyphenated (`nginx-http-auth`) or
/// underscore (`nginx_http_auth`) forms interchangeably. Returns null
/// for unknown names — the caller warns and falls back to an empty
/// pattern set.
pub fn get(name: []const u8) ?[]const PatternDef {
    for (entries) |e| {
        if (namesEqual(e.name, name)) return e.patterns;
    }
    return null;
}

/// Case-sensitive equality that treats `-` and `_` as identical.
fn namesEqual(canonical: []const u8, query: []const u8) bool {
    if (canonical.len != query.len) return false;
    for (canonical, query) |a, b| {
        const na: u8 = if (a == '_') '-' else a;
        const nb: u8 = if (b == '_') '-' else b;
        if (na != nb) return false;
    }
    return true;
}

/// Write one filter name per line to `writer`. Ordered as declared in
/// `entries` (alphabetical). Intended for a future `fail2zig
/// --list-filters` CLI flag; exported now so integration tests and
/// future CLI surface can share a single source of truth.
pub fn listFilters(writer: anytype) !void {
    for (entries) |e| {
        try writer.print("{s}\n", .{e.name});
    }
}

/// Total number of registered filters. Handy for tests that assert
/// coverage when new filters are added.
pub const registered_count: usize = entries.len;

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "registry: sshd resolves" {
    const p = get("sshd").?;
    try testing.expect(p.len > 0);
}

test "registry: nginx-http-auth resolves (hyphen)" {
    const p = get("nginx-http-auth").?;
    try testing.expect(p.len > 0);
}

test "registry: nginx_http_auth resolves (underscore form)" {
    const p = get("nginx_http_auth").?;
    try testing.expect(p.len > 0);
}

test "registry: apache-badbots resolves" {
    const p = get("apache-badbots").?;
    try testing.expect(p.len > 0);
}

test "registry: postfix resolves" {
    const p = get("postfix").?;
    try testing.expect(p.len > 0);
}

test "registry: dovecot resolves" {
    const p = get("dovecot").?;
    try testing.expect(p.len > 0);
}

test "registry: courier resolves" {
    const p = get("courier").?;
    try testing.expect(p.len > 0);
}

test "registry: recidive resolves" {
    const p = get("recidive").?;
    try testing.expect(p.len > 0);
}

test "registry: vsftpd resolves" {
    const p = get("vsftpd").?;
    try testing.expect(p.len > 0);
}

test "registry: proftpd resolves" {
    const p = get("proftpd").?;
    try testing.expect(p.len > 0);
}

test "registry: mysqld-auth resolves" {
    const p = get("mysqld-auth").?;
    try testing.expect(p.len > 0);
}

test "registry: named-refused resolves" {
    const p = get("named-refused").?;
    try testing.expect(p.len > 0);
}

test "registry: unknown filter returns null" {
    try testing.expect(get("nonexistent") == null);
    try testing.expect(get("") == null);
    try testing.expect(get("sshdx") == null);
}

test "registry: listFilters writes all names" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try listFilters(buf.writer());

    // Every declared entry appears once.
    for (entries) |e| {
        try testing.expect(std.mem.indexOf(u8, buf.items, e.name) != null);
    }
    // Line count equals entries.len.
    var line_count: usize = 0;
    for (buf.items) |c| {
        if (c == '\n') line_count += 1;
    }
    try testing.expectEqual(entries.len, line_count);
}

test "registry: registered_count matches entries length" {
    try testing.expectEqual(entries.len, registered_count);
}

test "registry: every registered name is unique" {
    var i: usize = 0;
    while (i < entries.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < entries.len) : (j += 1) {
            try testing.expect(!std.mem.eql(u8, entries[i].name, entries[j].name));
        }
    }
}

test "registry: at least 15 filters registered" {
    // The build plan says "15+ filters". If someone removes one the
    // build must fail so the plan's acceptance criterion is visible.
    try testing.expect(registered_count >= 15);
}
