// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");

const shared = @import("shared");
const engine = @import("engine");

const commands = engine.commands_mod;
const journald = engine.journald_source_mod;
const config_mod = engine.config_mod;
const firewall = engine.firewall;
const state = engine.state_mod;
const tracker_map = engine.tracker_map_mod;

const persist = struct {
    pub const saveAll = @import("../../engine/core/persist.zig").saveAll;
    pub const loadFull = @import("../../engine/core/persist.zig").loadFull;
    pub const seedMap = @import("../../engine/core/persist.zig").seedMap;
    pub const seedLifetimes = @import("../../engine/core/persist.zig").seedLifetimes;
};

const testing = std.testing;

const ResolvedDescriptor = struct {
    name: []const u8,
    descriptor: []const u8,
};

fn resolveDescriptor(
    arena: std.mem.Allocator,
    jail: config_mod.JailConfig,
    logpath_exists: bool,
    journalctl_present: bool,
    filter_journald_supported: bool,
) !ResolvedDescriptor {
    const resolved = journald.resolveSource(
        jail.source,
        logpath_exists,
        journalctl_present,
        filter_journald_supported,
    );
    const desc = switch (resolved) {
        .journald => try std.fmt.allocPrint(arena, "journald ({s})", .{jail.filter}),
        .file => if (jail.logpath.len == 0)
            try arena.dupe(u8, "file")
        else if (jail.logpath.len == 1)
            try arena.dupe(u8, jail.logpath[0])
        else
            try std.mem.join(arena, ", ", jail.logpath),
        .fail => try arena.dupe(u8, "unavailable"),
    };
    return .{ .name = jail.name, .descriptor = desc };
}

const DescriptorTable = struct {
    entries: []const ResolvedDescriptor,
    fn lookup(ctx: ?*anyopaque, jail_name: []const u8) ?[]const u8 {
        const self: *const DescriptorTable = @ptrCast(@alignCast(ctx.?));
        for (self.entries) |e| {
            if (std.mem.eql(u8, jail_name, e.name)) return e.descriptor;
        }
        return null;
    }
};

test "integration: SYS-017 a journald-resolved jail reports journald, never its config logpath" {
    const a = testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(a);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables, .source = .auto, .filter = "sshd", .logpath = &.{"/var/log/auth.log"} },
        .{ .name = "nginx", .enabled = true, .banaction = .nftables, .source = .file, .filter = "nginx", .logpath = &.{"/var/log/nginx/error.log"} },
    };

    var descs = [_]ResolvedDescriptor{
        try resolveDescriptor(arena, jails[0], false, true, true),
        try resolveDescriptor(arena, jails[1], true, true, true),
    };
    try testing.expectEqualStrings("journald (sshd)", descs[0].descriptor);
    try testing.expectEqualStrings("/var/log/nginx/error.log", descs[1].descriptor);

    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var trackers = tracker_map.TrackerMap.init(a);
    defer trackers.deinit();
    var backend: firewall.Backend = .{ .nftables = firewall.nftables.NftablesBackend{} };
    defer backend.deinit();
    var table = DescriptorTable{ .entries = &descs };

    var ctx = commands.Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &backend,
        .source_descriptor = .{ .ctx = @ptrCast(&table), .lookup = DescriptorTable.lookup },
    };

    const resp = try commands.Context.dispatch(@ptrCast(&ctx), .{ .list_jails = {} }, a);
    defer resp.deinit(a);
    const body = resp.ok.payload;

    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"journald (sshd)\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "/var/log/auth.log") == null);
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"/var/log/nginx/error.log\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"unknown\"") == null);
}

test "integration: SYS-017 a file jail whose log is ABSENT still reports its path, never unknown" {
    const a = testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(a);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var jails = [_]config_mod.JailConfig{
        .{ .name = "mail", .enabled = true, .banaction = .nftables, .source = .file, .filter = "mail", .logpath = &.{"/var/log/mail.log"} },
    };
    var descs = [_]ResolvedDescriptor{
        try resolveDescriptor(arena, jails[0], false, true, true),
    };
    try testing.expectEqualStrings("/var/log/mail.log", descs[0].descriptor);

    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var trackers = tracker_map.TrackerMap.init(a);
    defer trackers.deinit();
    var backend: firewall.Backend = .{ .nftables = firewall.nftables.NftablesBackend{} };
    defer backend.deinit();
    var table = DescriptorTable{ .entries = &descs };

    var ctx = commands.Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &backend,
        .source_descriptor = .{ .ctx = @ptrCast(&table), .lookup = DescriptorTable.lookup },
    };
    const resp = try commands.Context.dispatch(@ptrCast(&ctx), .{ .list_jails = {} }, a);
    defer resp.deinit(a);
    const body = resp.ok.payload;

    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"/var/log/mail.log\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"unknown\"") == null);
    try testing.expect(std.mem.indexOf(u8, body, "\"source_healthy\"") == null);
}

fn tIp(s: []const u8) shared.IpAddress {
    return shared.IpAddress.parse(s) catch unreachable;
}
fn tJail(s: []const u8) shared.JailId {
    return shared.JailId.fromSlice(s) catch unreachable;
}

test "integration: BUG-006 persisted lifetime survives restart and stays >= active bans" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    const path = try std.fmt.allocPrint(a, "{s}/state.bin", .{dir});
    defer a.free(path);

    {
        var tm = tracker_map.TrackerMap.init(a);
        defer tm.deinit();
        const sshd = try tm.addTracker("sshd", .{ .max_entries = 16, .maxretry = 1, .findtime = 600, .bantime = 600 });
        sshd.lifetime_bans = 9;
        _ = try sshd.recordAttempt(tIp("203.0.113.5"), tJail("sshd"), 1_000);
        sshd.map.getPtr(tIp("203.0.113.5")).?.ban_state = .banned;
        try testing.expectEqual(@as(u32, 1), tm.totalActiveBans());
        try persist.saveAll(&tm, path);
    }

    var tm2 = tracker_map.TrackerMap.init(a);
    defer tm2.deinit();
    _ = try tm2.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm2.ensureLegacy(.{ .max_entries = 16 });

    const loaded = try persist.loadFull(a, path);
    defer loaded.deinit(a);
    try persist.seedMap(&tm2, loaded.entries, null, null);
    persist.seedLifetimes(&tm2, loaded.lifetimes);

    const sshd2 = tm2.get("sshd").?;
    try testing.expectEqual(@as(u64, 9), sshd2.lifetime_bans);
    try testing.expectEqual(@as(u32, 1), tm2.totalActiveBans());
    try testing.expect(sshd2.lifetime_bans >= tm2.totalActiveBans());
}

test "integration: BUG-006 restored bans do not re-increment the lifetime (no double-count)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    const path = try std.fmt.allocPrint(a, "{s}/state.bin", .{dir});
    defer a.free(path);

    {
        var tm = tracker_map.TrackerMap.init(a);
        defer tm.deinit();
        const sshd = try tm.addTracker("sshd", .{ .max_entries = 16, .maxretry = 1, .findtime = 600, .bantime = 600 });
        sshd.lifetime_bans = 3;
        inline for (.{ "10.0.0.1", "10.0.0.2", "10.0.0.3" }) |ip_s| {
            _ = try sshd.recordAttempt(tIp(ip_s), tJail("sshd"), 1_000);
            sshd.map.getPtr(tIp(ip_s)).?.ban_state = .banned;
        }
        try testing.expectEqual(@as(u32, 3), tm.totalActiveBans());
        try persist.saveAll(&tm, path);
    }

    var round: u32 = 0;
    while (round < 2) : (round += 1) {
        var tm = tracker_map.TrackerMap.init(a);
        defer tm.deinit();
        _ = try tm.addTracker("sshd", .{ .max_entries = 16 });
        _ = try tm.ensureLegacy(.{ .max_entries = 16 });
        const loaded = try persist.loadFull(a, path);
        defer loaded.deinit(a);
        try persist.seedMap(&tm, loaded.entries, null, null);
        persist.seedLifetimes(&tm, loaded.lifetimes);

        const sshd = tm.get("sshd").?;
        try testing.expectEqual(@as(u32, 3), tm.totalActiveBans());
        try testing.expectEqual(@as(u64, 3), sshd.lifetime_bans);

        try persist.saveAll(&tm, path);
    }
}
