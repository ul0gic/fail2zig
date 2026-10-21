// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const parser = @import("../core/parser.zig");
const types = @import("types.zig");
const sshd = @import("sshd.zig");
const nginx = @import("nginx.zig");
const apache = @import("apache.zig");
const mail = @import("mail.zig");
const misc = @import("misc.zig");
const portsentry = @import("portsentry.zig");

pub const PatternDef = types.PatternDef;

pub const Entry = struct {
    name: []const u8,
    patterns: []const PatternDef,
    whole_record: bool = false,
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
    .{ .name = "portsentry", .patterns = &portsentry.patterns, .whole_record = true },
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

pub fn requiresWholeRecord(name: []const u8) bool {
    for (entries) |entry| {
        if (namesEqual(entry.name, name)) return entry.whole_record;
    }
    return false;
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
