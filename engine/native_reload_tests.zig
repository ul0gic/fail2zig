// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const config = @import("config/native.zig");
const reload = @import("native_reload.zig");

const t = std.testing;

const base =
    \\[global]
    \\native_ingestion = true
    \\state_file = "/var/lib/fail2zig/state.sqlite"
    \\socket_path = "/run/fail2zig/fail2zig.sock"
    \\metrics_enabled = false
    \\log_level = "info"
    \\[defaults]
    \\banaction = "log-only"
    \\maxretry = 3
    \\findtime = 600
    \\bantime = 60
    \\[jails.sshd]
    \\filter = "sshd"
    \\source = "file"
    \\timestamp = "undated"
    \\logpath = ["/var/log/auth.log"]
    \\
;

fn parse(arena: std.mem.Allocator, text: []const u8) !config.Config {
    const cfg = try config.Config.parse(arena, text);
    try config.validate(&cfg);
    return cfg;
}

fn edited(arena: std.mem.Allocator, from: []const u8, to: []const u8) ![]const u8 {
    return std.mem.replaceOwned(u8, arena, base, from, to);
}

test "native reload: identical proposals are no-ops" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const current = try parse(a, base);
    const proposed = try parse(a, base);
    const out = reload.classify(&current, &proposed, 64);
    try t.expectEqual(reload.Kind.noop, out.kind);
    try t.expectEqual(@as(u8, 0), out.reason_count);
    try t.expectEqual(@as(u8, 0), out.policy_count);
}

test "native reload: retry policy and log level changes are live with exact policies" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const current = try parse(a, base);
    const text = try edited(a, "maxretry = 3", "maxretry = 2");
    const text2 = try std.mem.replaceOwned(u8, a, text, "log_level = \"info\"", "log_level = \"debug\"");
    const proposed = try parse(a, text2);
    const out = reload.classify(&current, &proposed, 64);
    try t.expectEqual(reload.Kind.live, out.kind);
    try t.expectEqual(config.LogLevel.debug, out.log_level.?);
    try t.expectEqual(@as(u8, 1), out.policy_count);
    try t.expectEqualStrings("sshd", out.policySlice()[0].jail);
    try t.expectEqual(@as(u16, 2), out.policySlice()[0].next.maxretry);
    try t.expectEqual(@as(u32, 64), out.policySlice()[0].next.max_subjects);
}

test "native reload: generation-bound jail keys, added/removed jails and globals require restart" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const current = try parse(a, base);
    const cases = [_][2][]const u8{
        .{ "filter = \"sshd\"", "filter = \"vsftpd\"" },
        .{ "logpath = [\"/var/log/auth.log\"]", "logpath = [\"/var/log/secure\"]" },
        .{ "timestamp = \"undated\"", "timestamp = \"iso8601\"" },
        .{ "findtime = 600", "findtime = 300" },
        .{ "state_file = \"/var/lib/fail2zig/state.sqlite\"", "state_file = \"/var/lib/fail2zig/other.sqlite\"" },
        .{ "banaction = \"log-only\"", "banaction = \"nftables\"" },
        .{ "socket_path = \"/run/fail2zig/fail2zig.sock\"", "socket_path = \"/run/fail2zig/b.sock\"" },
    };
    for (cases) |pair| {
        const proposed = try parse(a, try edited(a, pair[0], pair[1]));
        const out = reload.classify(&current, &proposed, 64);
        try t.expectEqual(reload.Kind.restart_required, out.kind);
        try t.expect(out.reason_count >= 1);
        try t.expectEqual(@as(u8, 0), out.policy_count);
    }
    const added = try parse(a, try std.mem.concat(a, u8, &.{ base, "[jails.vsftpd]\nfilter = \"vsftpd\"\nsource = \"file\"\ntimestamp = \"undated\"\nlogpath = [\"/var/log/vsftpd.log\"]\n" }));
    const out = reload.classify(&current, &added, 64);
    try t.expectEqual(reload.Kind.restart_required, out.kind);
    try t.expect(std.mem.indexOf(u8, out.reasonSlice()[0].slice(), "set size") != null);
    // A restart-required proposal never carries live policy changes even if some keys were live.
    const mixed = try parse(a, try std.mem.replaceOwned(u8, a, try edited(a, "maxretry = 3", "maxretry = 2"), "filter = \"sshd\"", "filter = \"vsftpd\""));
    const mixed_out = reload.classify(&current, &mixed, 64);
    try t.expectEqual(reload.Kind.restart_required, mixed_out.kind);
    try t.expectEqual(@as(u8, 0), mixed_out.policy_count);
}

test "native reload: internal-source policy changes and invalid policies are not live" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const with_recidive = try std.mem.concat(a, u8, &.{ base, "[jails.recidive]\nfilter = \"recidive\"\nsource = \"internal\"\nbantime = 600\n" });
    const current = try parse(a, with_recidive);
    const proposed = try parse(a, try std.mem.replaceOwned(u8, a, with_recidive, "bantime = 600\n", "bantime = 1200\n"));
    const out = reload.classify(&current, &proposed, 64);
    try t.expectEqual(reload.Kind.restart_required, out.kind);
    try t.expect(std.mem.indexOf(u8, out.reasonSlice()[0].slice(), "internal source generation") != null);
    const base_cfg = try parse(a, base);
    const permanent = try parse(a, try edited(a, "bantime = 60", "bantime = \"permanent\"\nbantime_increment_enabled = true"));
    const bad = reload.classify(&base_cfg, &permanent, 64);
    try t.expectEqual(reload.Kind.rejected, bad.kind);
}

test "native reload: digests and generation identities are deterministic and clock-distinct" {
    const d1 = reload.digestBytes("a");
    try t.expectEqualSlices(u8, &d1, &reload.digestBytes("a"));
    try t.expect(!std.mem.eql(u8, &reload.generationId(d1, 1), &reload.generationId(d1, 2)));
    try t.expectEqualSlices(u8, &reload.generationId(d1, 1), &reload.generationId(d1, 1));
    const policy = @import("core/native_retry.zig").Policy{ .maxretry = 3, .window_us = 1_000_000, .duration = .{ .finite_us = 1_000_000 }, .max_subjects = 4 };
    const g = [_]u8{1} ** 32;
    try t.expectEqualSlices(u8, &try reload.jailDigest("sshd", policy, g), &try reload.jailDigest("sshd", policy, g));
    try t.expect(!std.mem.eql(u8, &try reload.jailDigest("sshd", policy, g), &try reload.jailDigest("vsftpd", policy, g)));
}
