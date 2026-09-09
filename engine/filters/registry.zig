// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const parser = @import("../core/parser.zig");
const types = @import("types.zig");
const sshd = @import("sshd.zig");
const nginx = @import("nginx.zig");
const apache = @import("apache.zig");
const mail = @import("mail.zig");
const misc = @import("misc.zig");

pub const PatternDef = types.PatternDef;

pub const Entry = struct {
    name: []const u8,
    patterns: []const PatternDef,
};

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

pub fn get(name: []const u8) ?[]const PatternDef {
    for (entries) |e| {
        if (namesEqual(e.name, name)) return e.patterns;
    }
    return null;
}

pub const FilterMatcher = struct {
    patterns: []const PatternDef,

    pub fn match(self: FilterMatcher, line: []const u8) ?parser.ParseResult {
        for (self.patterns) |p| {
            if (p.match(line)) |r| return r;
        }
        return null;
    }

    pub fn patternCount(self: FilterMatcher) usize {
        return self.patterns.len;
    }
};

pub fn matcherForFilter(name: []const u8) ?FilterMatcher {
    const patterns = get(name) orelse return null;
    return .{ .patterns = patterns };
}

fn namesEqual(canonical: []const u8, query: []const u8) bool {
    if (canonical.len != query.len) return false;
    for (canonical, query) |a, b| {
        const na: u8 = if (a == '_') '-' else a;
        const nb: u8 = if (b == '_') '-' else b;
        if (na != nb) return false;
    }
    return true;
}

pub fn listFilters(writer: anytype) !void {
    for (entries) |e| {
        try writer.print("{s}\n", .{e.name});
    }
}

pub const registered_count: usize = entries.len;

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

test "registry: matcherForFilter resolves sshd and applies its patterns (SYS-020)" {
    const m = matcherForFilter("sshd").?;
    try testing.expect(m.patternCount() == sshd.patterns.len);

    try testing.expect(m.match("Failed password for root from 1.2.3.4 port 22 ssh2") != null);
    try testing.expect(m.match("Invalid user oracle from 203.0.113.5 port 22") != null);

    try testing.expect(m.match("Server listening on 0.0.0.0 port 22.") == null);
    try testing.expect(m.match("Server listening on :: port 22.") == null);

    try testing.expect(m.match("Accepted password for root from 1.2.3.4 port 22 ssh2") == null);
    try testing.expect(m.match("Accepted publickey for root from 1.2.3.4 port 22 ssh2: RSA SHA256:x") == null);
}

test "registry: matcherForFilter accepts hyphen/underscore forms" {
    try testing.expect(matcherForFilter("nginx-http-auth") != null);
    try testing.expect(matcherForFilter("nginx_http_auth") != null);
}

test "registry: matcherForFilter fails closed on unknown filter (SYS-020)" {
    try testing.expect(matcherForFilter("nonexistent") == null);
    try testing.expect(matcherForFilter("") == null);
    try testing.expect(matcherForFilter("custom-app") == null);
}

test "registry: FilterMatcher returns first-match result in declaration order" {
    const m = matcherForFilter("sshd").?;
    const r = m.match("Failed password for admin from 10.0.0.1 port 22 ssh2").?;
    try testing.expectEqual(@as(u32, 0x0A000001), r.ip.ipv4);
}

test "registry: listFilters writes all names" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try listFilters(buf.writer());

    for (entries) |e| {
        try testing.expect(std.mem.indexOf(u8, buf.items, e.name) != null);
    }
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
    try testing.expect(registered_count >= 15);
}
