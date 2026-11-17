// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Parses iptables and ipset output into this installation's entries and builds the arguments of its fixed scoped rules.
// Holds: An iptables chain reads as owned only with its marked RETURN rule and one marked jump that is the first INPUT rule.

const std = @import("std");
const shared = @import("shared");
const nft = @import("nftables.zig");
const canonical_scope = @import("scope.zig");
const mem = @import("std").mem;
const CanonicalScope = @import("inspection.zig").CanonicalScope;
const Entry = @import("inspection.zig").Entry;
const Error = @import("inspection.zig").Error;
const Inspector = @import("inspection.zig").Inspector;
const ScopedRuleMetadata = @import("inspection.zig").ScopedRuleMetadata;
const reservedName = @import("inspection.zig").reservedName;
const scoped_comment_bytes = @import("inspection.zig").scoped_comment_bytes;
const scoped_comment_prefix = @import("inspection.zig").scoped_comment_prefix;
const subjectAddress = @import("inspection.zig").subjectAddress;
const Builder = @import("inspection_builder.zig").Builder;
const ScopedGroup = @import("inspection_builder.zig").ScopedGroup;
const collectScopedGroup = @import("inspection_builder.zig").collectScopedGroup;
const finishScopedGroups = @import("inspection_builder.zig").finishScopedGroups;

pub fn scanSavedTables(output: []const u8) Error!void {
    if (output.len != 0 and output[output.len - 1] != '\n') return error.Incomplete;
    var lines = mem.tokenizeScalar(u8, output, '\n');
    var in_table = false;
    while (lines.next()) |line| {
        if (line[0] == '#') continue;
        if (line[0] == '*') {
            if (in_table or line.len < 2) return error.Incomplete;
            in_table = true;
        } else if (mem.eql(u8, line, "COMMIT")) {
            if (!in_table) return error.Incomplete;
            in_table = false;
        } else if (line[0] == ':') {
            if (!in_table) return error.Incomplete;
            const end = mem.indexOfScalar(u8, line, ' ') orelse return error.Incomplete;
            if (reservedName(line[1..end])) return error.ForeignState;
        } else if (mem.startsWith(u8, line, "-A ")) {
            if (!in_table) return error.Incomplete;
            const tokens = try Tokens.parse(line);
            for (tokens.values[0..tokens.count]) |token| if (reservedName(token)) return error.ForeignState;
        } else return error.UnknownState;
    }
    if (in_table) return error.Incomplete;
}

pub const Tokens = struct {
    values: [32][]const u8 = undefined,
    count: usize = 0,
    pub fn parse(line: []const u8) Error!Tokens {
        var out: Tokens = .{};
        var at: usize = 0;
        while (at < line.len) {
            if (line[at] == ' ' or line[at] == '\t') {
                at += 1;
                continue;
            }
            if (out.count == out.values.len) return error.LimitExceeded;
            const quoted = line[at] == '"';
            if (quoted) at += 1;
            const begin = at;
            while (at < line.len and (if (quoted) line[at] != '"' else line[at] != ' ' and line[at] != '\t')) : (at += 1) {
                if (line[at] == '\\' or line[at] < 32 or (!quoted and line[at] == '"')) return error.UnknownState;
            }
            out.values[out.count] = line[begin..at];
            out.count += 1;
            if (quoted) {
                if (at == line.len) return error.Incomplete;
                at += 1;
                if (at < line.len and line[at] != ' ' and line[at] != '\t') return error.UnknownState;
            }
        }
        return out;
    }
    fn is(self: Tokens, expected: []const []const u8) bool {
        if (self.count != expected.len) return false;
        for (expected, self.values[0..self.count]) |a, b| if (!mem.eql(u8, a, b)) return false;
        return true;
    }
};

fn hostAddress(text: []const u8, v6: bool) Error!shared.IpAddress {
    var host = text;
    if (mem.indexOfScalar(u8, text, '/')) |slash| {
        if (!mem.eql(u8, text[slash..], if (v6) "/128" else "/32")) return error.UnsupportedScope;
        host = text[0..slash];
    }
    const address = shared.IpAddress.parse(host) catch return error.UnknownState;
    if ((address == .ipv6) != v6) return error.UnknownState;
    return address;
}

fn scopedSubjectText(scope: CanonicalScope, buf: *[64]u8) Error![]const u8 {
    return std.fmt.bufPrint(buf, "{}/{}", .{ subjectAddress(scope.subject), scope.subject.prefix }) catch error.LimitExceeded;
}

fn scopedPortText(port: canonical_scope.PortRange, buf: *[16]u8) Error![]const u8 {
    return if (port.first == port.last)
        std.fmt.bufPrint(buf, "{d}", .{port.first}) catch error.LimitExceeded
    else
        std.fmt.bufPrint(buf, "{d}:{d}", .{ port.first, port.last }) catch error.LimitExceeded;
}

fn scopedProtocolText(protocol: canonical_scope.Protocol) Error![]const u8 {
    return switch (protocol) {
        .tcp => "tcp",
        .udp => "udp",
        .icmp_v4 => "icmp",
        .icmp_v6 => "ipv6-icmp",
        .all => error.UnsupportedScope,
    };
}

pub const FixedScopedOperation = enum { insert, delete };

pub fn buildFixedScopedArgv(
    argv: *[24][]const u8,
    subject_buf: *[64]u8,
    port_buf: *[16]u8,
    comment_buf: *[scoped_comment_bytes]u8,
    binary: []const u8,
    chain: []const u8,
    metadata: ScopedRuleMetadata,
    operation: FixedScopedOperation,
) Error![]const []const u8 {
    const part = nft.scopeRulePart(metadata.scope, metadata.part) catch return error.UnsupportedScope;
    const comment = try metadata.encodeComment();
    comment_buf.* = comment;
    const subject = try scopedSubjectText(metadata.scope, subject_buf);
    var count: usize = 0;
    const append = struct {
        fn value(values: *[24][]const u8, at: *usize, text: []const u8) Error!void {
            if (at.* == values.len) return error.LimitExceeded;
            values[at.*] = text;
            at.* += 1;
        }
    }.value;
    try append(argv, &count, binary);
    try append(argv, &count, "-w");
    try append(argv, &count, "1");
    try append(argv, &count, if (operation == .insert) "-I" else "-D");
    try append(argv, &count, chain);
    if (operation == .insert) try append(argv, &count, "1");
    try append(argv, &count, "-s");
    try append(argv, &count, subject);
    if (part.protocol) |protocol| {
        const protocol_text = try scopedProtocolText(protocol);
        try append(argv, &count, "-p");
        try append(argv, &count, protocol_text);
        if (protocol == .tcp or protocol == .udp) {
            try append(argv, &count, "-m");
            try append(argv, &count, protocol_text);
        }
    }
    if (part.port) |port| {
        try append(argv, &count, "--dport");
        try append(argv, &count, try scopedPortText(port, port_buf));
    }
    try append(argv, &count, "-m");
    try append(argv, &count, "comment");
    try append(argv, &count, "--comment");
    try append(argv, &count, comment_buf);
    try append(argv, &count, "-j");
    try append(argv, &count, "DROP");
    return argv[0..count];
}

pub fn fixedScopedMetadata(tokens: Tokens, chain: []const u8, v6: bool) Error!?ScopedRuleMetadata {
    if (tokens.count < 10 or !mem.eql(u8, tokens.values[tokens.count - 6], "-m") or
        !mem.eql(u8, tokens.values[tokens.count - 5], "comment") or
        !mem.eql(u8, tokens.values[tokens.count - 4], "--comment") or
        !mem.startsWith(u8, tokens.values[tokens.count - 3], scoped_comment_prefix) or
        !mem.eql(u8, tokens.values[tokens.count - 2], "-j") or
        !mem.eql(u8, tokens.values[tokens.count - 1], "DROP")) return null;
    const metadata = try ScopedRuleMetadata.decodeComment(tokens.values[tokens.count - 3]);
    if ((metadata.scope.subject.family == .v6) != v6) return error.ForeignState;
    var argv: [24][]const u8 = undefined;
    var subject_buf: [64]u8 = undefined;
    var port_buf: [16]u8 = undefined;
    var comment_buf: [scoped_comment_bytes]u8 = undefined;
    // Why: Only the arguments after the chain are compared, so this binary path never reaches the comparison.
    const expected = try buildFixedScopedArgv(&argv, &subject_buf, &port_buf, &comment_buf, if (v6) "/usr/sbin/ip6tables" else "/usr/sbin/iptables", chain, metadata, .delete);
    if (tokens.count != expected.len - 3 or !mem.eql(u8, tokens.values[0], "-A") or !mem.eql(u8, tokens.values[1], chain)) return error.ForeignState;
    for (tokens.values[2..tokens.count], expected[5..]) |actual, wanted| if (!mem.eql(u8, actual, wanted)) return error.ForeignState;
    return metadata;
}

pub const FixedScopedVariants = struct {
    const max_variants = 8;
    const Variant = struct { deadline_us: ?i64, counts: [nft.max_scope_rule_parts]u16 = @splat(0) };
    variants: [max_variants]Variant = undefined,
    len: usize = 0,
    pub fn note(self: *FixedScopedVariants, deadline_us: ?i64, part: u8) void {
        for (self.variants[0..self.len]) |*variant| if (variant.deadline_us == deadline_us) {
            variant.counts[part] +|= 1;
            return;
        };
        if (self.len == max_variants) return;
        self.variants[self.len] = .{ .deadline_us = deadline_us };
        self.variants[self.len].counts[part] = 1;
        self.len += 1;
    }
    pub fn count(self: *const FixedScopedVariants, deadline_us: ?i64, part: usize) u16 {
        for (self.variants[0..self.len]) |variant| if (variant.deadline_us == deadline_us) return variant.counts[part];
        return 0;
    }
};

pub fn parseIptables(builder: *Builder, output: []const u8, v6: bool) Error!bool {
    if (output.len == 0 or output[output.len - 1] != '\n') return error.Incomplete;
    var name_buf: [28]u8 = undefined;
    const name = builder.installation.name(&name_buf);
    var marker_buf: [44]u8 = undefined;
    const marker = builder.installation.marker(&marker_buf);
    var chain = false;
    var mark = false;
    var jump_count: usize = 0;
    var rules: usize = 0;
    var policy_seen = [_]bool{ false, false, false };
    var lookup = false;
    var input_rules: usize = 0;
    var scoped = std.ArrayList(ScopedGroup).init(builder.allocator);
    defer scoped.deinit();
    var lines = mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        rules += 1;
        if (rules > builder.limits.max_messages) return error.LimitExceeded;
        const t = try Tokens.parse(line);
        if (t.count < 2) return error.UnknownState;
        if (mem.eql(u8, t.values[0], "-P")) {
            if (t.count != 3) return error.UnknownState;
            const index: usize = if (mem.eql(u8, t.values[1], "INPUT")) 0 else if (mem.eql(u8, t.values[1], "FORWARD")) 1 else if (mem.eql(u8, t.values[1], "OUTPUT")) 2 else return error.UnknownState;
            if (policy_seen[index] or (!mem.eql(u8, t.values[2], "ACCEPT") and !mem.eql(u8, t.values[2], "DROP"))) return error.UnknownState;
            policy_seen[index] = true;
            continue;
        }
        if (mem.eql(u8, t.values[0], "-N")) {
            if (t.count != 2) return error.UnknownState;
            if (mem.eql(u8, t.values[1], name)) {
                if (chain) return error.UnknownState;
                chain = true;
            }
            continue;
        }
        if (!mem.eql(u8, t.values[0], "-A")) return error.UnknownState;
        if (mem.eql(u8, t.values[1], "INPUT")) input_rules += 1;
        if (mem.eql(u8, t.values[1], name)) {
            if (!chain or mark) return error.ForeignState;
            if (t.is(&.{ "-A", name, "-m", "comment", "--comment", marker, "-j", "RETURN" })) {
                mark = true;
                continue;
            }
            if (try fixedScopedMetadata(t, name, v6)) |metadata| {
                try collectScopedGroup(&scoped, metadata, builder.limits);
                continue;
            }
            if (builder.installation.transport == .iptables) {
                if (t.count != 6 or !mem.eql(u8, t.values[2], "-s") or !mem.eql(u8, t.values[4], "-j") or !mem.eql(u8, t.values[5], "DROP")) return error.ForeignState;
                try builder.add(.{ .address = try hostAddress(t.values[3], v6) });
            } else {
                var set_buf: [31]u8 = undefined;
                const set = try setName(name, v6, &set_buf);
                if (!t.is(&.{ "-A", name, "-m", "set", "--match-set", set, "src", "-j", "DROP" })) return error.ForeignState;
                if (lookup) return error.ForeignState;
                lookup = true;
                builder.topology.update(line);
            }
        } else {
            var references = false;
            for (t.values[2..t.count], 2..) |value, index| {
                if ((mem.eql(u8, value, "-j") or mem.eql(u8, value, "-g")) and index + 1 < t.count and mem.eql(u8, t.values[index + 1], name)) references = true;
            }
            if (references) {
                if (!t.is(&.{ "-A", "INPUT", "-m", "comment", "--comment", marker, "-j", name })) return error.ForeignState;
                jump_count += 1;
                // Why: A rule ahead of the jump could accept a banned source first, so the jump must be the first INPUT rule.
                if (input_rules != 1) return error.ForeignState;
            }
        }
    }
    // Why: iptables -S prints the three built-in filter policies, so output missing one is cut short.
    if (!policy_seen[0] or !policy_seen[1] or !policy_seen[2]) return error.Incomplete;
    if (!chain) {
        if (mark or jump_count != 0) return error.ForeignState;
        return false;
    }
    if (!mark or jump_count != 1) return error.ForeignState;
    if (builder.installation.transport == .ipset and !lookup) return error.ForeignState;
    try finishScopedGroups(builder, scoped.items);
    builder.topology.update(marker);
    return true;
}

pub fn setName(name: []const u8, v6: bool, buf: *[31]u8) Error![]const u8 {
    return std.fmt.bufPrint(buf, "{s}_{s}", .{ name, if (v6) "6" else "4" }) catch error.LimitExceeded;
}

pub fn parseIpset(builder: *Builder, output: []const u8, v6: bool) Error!bool {
    if (output.len != 0 and output[output.len - 1] != '\n') return error.Incomplete;
    var name_buf: [28]u8 = undefined;
    var set_buf: [31]u8 = undefined;
    const name = try setName(builder.installation.name(&name_buf), v6, &set_buf);
    var created = false;
    var lines = mem.splitScalar(u8, output, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        count += 1;
        if (count > builder.limits.max_messages) return error.LimitExceeded;
        const t = try Tokens.parse(line);
        if (t.count < 2) return error.UnknownState;
        if (!mem.eql(u8, t.values[1], name)) continue;
        if (mem.eql(u8, t.values[0], "create")) {
            if (created or t.count < 5 or !mem.eql(u8, t.values[2], "hash:ip")) return error.ForeignState;
            var family = false;
            var timeout = false;
            var at: usize = 3;
            while (at < t.count) : (at += 2) {
                if (at + 1 >= t.count) return error.UnknownState;
                const key = t.values[at];
                const value = t.values[at + 1];
                if (mem.eql(u8, key, "family")) {
                    if (family or !mem.eql(u8, value, if (v6) "inet6" else "inet")) return error.ForeignState;
                    family = true;
                } else if (mem.eql(u8, key, "timeout")) {
                    if (timeout or !mem.eql(u8, value, "0")) return error.ForeignState;
                    timeout = true;
                } else if (mem.eql(u8, key, "hashsize") or mem.eql(u8, key, "maxelem") or mem.eql(u8, key, "bucketsize") or mem.eql(u8, key, "initval")) {
                    _ = std.fmt.parseInt(u64, value, 0) catch return error.UnknownState;
                } else return error.ForeignState;
            }
            if (!family or !timeout) return error.ForeignState;
            created = true;
        } else if (mem.eql(u8, t.values[0], "add")) {
            if (!created or (t.count != 3 and t.count != 5)) return error.UnknownState;
            var remaining: ?u64 = null;
            if (t.count == 5) {
                if (!mem.eql(u8, t.values[3], "timeout")) return error.UnknownState;
                const seconds = std.fmt.parseInt(u64, t.values[4], 10) catch return error.UnknownState;
                if (seconds != 0) remaining = std.math.mul(u64, seconds, 1000) catch return error.UnknownState;
            }
            try builder.add(.{ .address = try hostAddress(t.values[2], v6), .remaining_ms = remaining });
        } else return error.UnknownState;
    }
    return created;
}

pub fn readTools(self: *Inspector, builder: *Builder, timer: *std.time.Timer) Error!void {
    defer self.live_bytes = 0;
    var presence: [2]bool = undefined;
    for ([_][]const u8{ self.iptables_path, self.ip6tables_path }, 0..) |binary, index| {
        self.live_bytes = builder.entries.capacity * @sizeOf(Entry);
        const result = try self.run(&.{ binary, "-w", "1", "-S" }, timer);
        defer result.deinit(self.allocator);
        builder.transient_bytes = result.stdout.len + result.stderr.len;
        defer builder.transient_bytes = 0;
        presence[index] = try parseIptables(builder, result.stdout, index == 1);
    }
    if (presence[0] != presence[1]) return error.ForeignState;
    if (self.installation.transport == .ipset) {
        self.live_bytes = builder.entries.capacity * @sizeOf(Entry);
        const result = try self.run(&.{ self.ipset_path, "save" }, timer);
        defer result.deinit(self.allocator);
        builder.transient_bytes = result.stdout.len + result.stderr.len;
        defer builder.transient_bytes = 0;
        for (0..2) |index| {
            if (try parseIpset(builder, result.stdout, index == 1) != presence[index]) return error.ForeignState;
        }
    }
    builder.present = presence[0];
}
