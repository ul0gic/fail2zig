// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const state_mod = @import("state.zig");
const tracker_map_mod = @import("tracker_map.zig");
const metrics_mod = @import("metrics.zig");
const shared = @import("shared");

pub const BanApplyFn = *const fn (
    ctx: *anyopaque,
    ip: shared.IpAddress,
    jail: shared.JailId,
    remaining: u64,
) anyerror!void;

pub fn reconcileRestoredBans(
    allocator: std.mem.Allocator,
    tracker: *state_mod.StateTracker,
    metrics: ?*metrics_mod.Metrics,
    now: shared.Timestamp,
    applyFn: BanApplyFn,
    ctx: *anyopaque,
) !u32 {
    var per_jail = std.StringHashMap(u32).init(allocator);
    defer per_jail.deinit();

    var reinstalled: u32 = 0;
    var it = tracker.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.ban_state != .banned or !kv.value_ptr.enforced) continue;
        const expiry = kv.value_ptr.ban_expiry orelse continue;
        if (expiry <= now) continue;
        const remaining: u64 = @intCast(expiry - now);
        applyFn(ctx, kv.key_ptr.*, kv.value_ptr.jail, remaining) catch continue;
        reinstalled += 1;

        const jail_name = kv.value_ptr.jail.slice();
        const gop = try per_jail.getOrPut(jail_name);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
    }

    if (metrics) |m| {
        m.setActiveBans(reinstalled);
        var jit = per_jail.iterator();
        while (jit.next()) |entry| {
            m.jailSetActiveBans(entry.key_ptr.*, entry.value_ptr.*);
        }
    }

    return reinstalled;
}

pub fn reconcileAllRestoredBans(
    allocator: std.mem.Allocator,
    map: *const tracker_map_mod.TrackerMap,
    metrics: ?*metrics_mod.Metrics,
    now: shared.Timestamp,
    applyFn: BanApplyFn,
    ctx: *anyopaque,
) !u32 {
    var per_jail = std.StringHashMap(u32).init(allocator);
    defer per_jail.deinit();

    var reinstalled: u32 = 0;
    var it = map.iterator();
    while (it.next()) |kv| {
        const tracker = kv.value_ptr.*;
        var tit = tracker.iterator();
        while (tit.next()) |entry| {
            if (entry.value_ptr.ban_state != .banned or !entry.value_ptr.enforced) continue;
            const expiry = entry.value_ptr.ban_expiry orelse continue;
            if (expiry <= now) continue;
            const remaining: u64 = @intCast(expiry - now);
            applyFn(ctx, entry.key_ptr.*, entry.value_ptr.jail, remaining) catch continue;
            reinstalled += 1;

            const jail_name = entry.value_ptr.jail.slice();
            const gop = try per_jail.getOrPut(jail_name);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* += 1;
        }
    }

    if (metrics) |m| {
        m.setActiveBans(reinstalled);
        var jit = per_jail.iterator();
        while (jit.next()) |entry| {
            m.jailSetActiveBans(entry.key_ptr.*, entry.value_ptr.*);
        }
    }

    return reinstalled;
}
