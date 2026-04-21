//! State-tracker → firewall-backend reconciliation on daemon startup.
//!
//! The scaffold installer (`nftables.zig::sendScaffold`) always leaves
//! the backend in a clean state — empty sets, no active bans. The
//! state tracker, however, may hold bans that were active when the
//! previous instance exited and were persisted to disk. Without an
//! explicit reconciliation step those bans would be visible via the
//! IPC `list` command but silently un-enforced at the kernel layer
//! until a fresh ban decision fires.
//!
//! This module is the bridge. It walks the tracker once, calls a
//! caller-supplied `applyFn` for every entry whose ban is both
//! active (`.banned`) and still in-window (`ban_expiry > now`), and
//! optionally syncs the `active_bans` gauges in `Metrics`.
//!
//! Extracted from `main.zig` so the logic is testable without
//! spinning up the whole daemon. The `applyFn` callback means unit
//! tests can pass a recording closure; production code passes a
//! thin wrapper around `Backend.ban`.

const std = @import("std");
const state_mod = @import("state.zig");
const metrics_mod = @import("metrics.zig");
const shared = @import("shared");

/// Callback invoked for each restored ban entry. Typically calls
/// `backend.ban(ip, jail, remaining)` in production; record-and-return
/// in tests.
///
/// Returning an error causes the entry to be counted as a failure
/// (no metrics bump, no reinstalled++ tick) but does not abort the
/// loop — other entries still get a chance.
pub const BanApplyFn = *const fn (
    ctx: *anyopaque,
    ip: shared.IpAddress,
    jail: shared.JailId,
    remaining: u64,
) anyerror!void;

/// Walk `tracker`, invoke `applyFn` for each `.banned` entry with a
/// future `ban_expiry`, and (if `metrics` is non-null) set the
/// `active_bans` gauges to the reconciled count. Returns the number
/// of entries successfully reinstalled.
///
/// `allocator` backs a short-lived `StringHashMap(u32)` for per-jail
/// counting; it's freed before returning.
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
        if (kv.value_ptr.ban_state != .banned) continue;
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

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const persist_mod = @import("persist.zig");

const RecordedCall = struct {
    ip: shared.IpAddress,
    jail_str: [64]u8 = undefined,
    jail_len: u8 = 0,
    remaining: u64,

    fn jailSlice(self: *const RecordedCall) []const u8 {
        return self.jail_str[0..self.jail_len];
    }
};

const Recorder = struct {
    calls: std.ArrayList(RecordedCall),

    fn init(alloc: std.mem.Allocator) Recorder {
        return .{ .calls = std.ArrayList(RecordedCall).init(alloc) };
    }

    fn deinit(self: *Recorder) void {
        self.calls.deinit();
    }
};

fn recordApply(ctx: *anyopaque, ip: shared.IpAddress, jail: shared.JailId, remaining: u64) anyerror!void {
    const rec: *Recorder = @ptrCast(@alignCast(ctx));
    var call = RecordedCall{ .ip = ip, .remaining = remaining };
    const js = jail.slice();
    @memcpy(call.jail_str[0..js.len], js);
    call.jail_len = @intCast(js.len);
    try rec.calls.append(call);
}

fn makeIpV4(a: u8, b: u8, c: u8, d: u8) shared.IpAddress {
    return .{ .ipv4 = (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | @as(u32, d) };
}

test "reconcile: banned entries applied, expired + monitoring skipped (SYS-007)" {
    const alloc = testing.allocator;

    var tracker = try state_mod.StateTracker.init(alloc, .{ .max_entries = 16 });
    defer tracker.deinit();

    const sshd_jail = try shared.JailId.fromSlice("sshd");
    const now: shared.Timestamp = 1_000_000;

    // Seed via the same public path the daemon uses at startup
    // (persist.seed -> StateTracker). Covers the production codepath.
    const entries = [_]persist_mod.StateEntry{
        // One active ban, future expiry — must reconcile.
        .{
            .ip = makeIpV4(203, 0, 113, 1),
            .jail = sshd_jail,
            .attempt_count = 3,
            .ban_count = 1,
            .first_attempt = now - 120,
            .last_attempt = now - 60,
            .ban_expiry = now + 120,
        },
        // Expired ban (ban_expiry in the past) — must skip.
        .{
            .ip = makeIpV4(203, 0, 113, 2),
            .jail = sshd_jail,
            .attempt_count = 3,
            .ban_count = 1,
            .first_attempt = now - 400,
            .last_attempt = now - 200,
            .ban_expiry = now - 10,
        },
        // Monitoring only (ban_expiry null) — must skip.
        .{
            .ip = makeIpV4(203, 0, 113, 3),
            .jail = sshd_jail,
            .attempt_count = 1,
            .ban_count = 0,
            .first_attempt = now - 10,
            .last_attempt = now - 5,
            .ban_expiry = null,
        },
    };
    try persist_mod.seed(&tracker, &entries);

    var rec = Recorder.init(alloc);
    defer rec.deinit();
    var metrics = metrics_mod.Metrics.init();
    _ = metrics.registerJail("sshd");

    const count = try reconcileRestoredBans(
        alloc,
        &tracker,
        &metrics,
        now,
        recordApply,
        @ptrCast(&rec),
    );

    try testing.expectEqual(@as(u32, 1), count);
    try testing.expectEqual(@as(usize, 1), rec.calls.items.len);
    const call = rec.calls.items[0];
    const banned_ip = makeIpV4(203, 0, 113, 1);
    try testing.expect(shared.IpAddress.eql(call.ip, banned_ip));
    try testing.expectEqualStrings("sshd", call.jailSlice());
    // Remaining must equal ban_expiry - now.
    try testing.expectEqual(@as(u64, 120), call.remaining);

    // Metrics synced: active_bans gauge reflects reconciled count, but
    // bans_total (the monotonic counter) stays at 0 — reloads aren't
    // fresh ban events and shouldn't inflate the lifetime total.
    const snap = metrics.snapshot();
    try testing.expectEqual(@as(u32, 1), snap.active_bans);
    try testing.expectEqual(@as(u64, 0), snap.bans_total);
}

test "reconcile: empty tracker returns 0, metrics untouched (SYS-007)" {
    const alloc = testing.allocator;
    var tracker = try state_mod.StateTracker.init(alloc, .{ .max_entries = 16 });
    defer tracker.deinit();

    var rec = Recorder.init(alloc);
    defer rec.deinit();
    var metrics = metrics_mod.Metrics.init();

    const count = try reconcileRestoredBans(
        alloc,
        &tracker,
        &metrics,
        1_000_000,
        recordApply,
        @ptrCast(&rec),
    );

    try testing.expectEqual(@as(u32, 0), count);
    try testing.expectEqual(@as(usize, 0), rec.calls.items.len);
    try testing.expectEqual(@as(u32, 0), metrics.snapshot().active_bans);
}

const FailFirst = struct {
    first: bool = true,
    count: u32 = 0,

    fn apply(ctx: *anyopaque, ip: shared.IpAddress, jail: shared.JailId, remaining: u64) anyerror!void {
        _ = ip;
        _ = jail;
        _ = remaining;
        const self: *FailFirst = @ptrCast(@alignCast(ctx));
        if (self.first) {
            self.first = false;
            return error.Faked;
        }
        self.count += 1;
    }
};

test "reconcile: callback errors are non-fatal, loop continues (SYS-007)" {
    // If applyFn errors on one entry (e.g. backend returns AlreadyBanned,
    // or a real transient netlink error), reconcile keeps going for the
    // rest. Only successful applies count toward the return value.
    const alloc = testing.allocator;

    var tracker = try state_mod.StateTracker.init(alloc, .{ .max_entries = 16 });
    defer tracker.deinit();

    const sshd_jail = try shared.JailId.fromSlice("sshd");
    const now: shared.Timestamp = 1_000_000;

    const entries = [_]persist_mod.StateEntry{
        .{
            .ip = makeIpV4(203, 0, 113, 10),
            .jail = sshd_jail,
            .attempt_count = 3,
            .ban_count = 1,
            .first_attempt = now - 120,
            .last_attempt = now - 30,
            .ban_expiry = now + 60,
        },
        .{
            .ip = makeIpV4(203, 0, 113, 11),
            .jail = sshd_jail,
            .attempt_count = 3,
            .ban_count = 1,
            .first_attempt = now - 120,
            .last_attempt = now - 30,
            .ban_expiry = now + 60,
        },
    };
    try persist_mod.seed(&tracker, &entries);

    var ff = FailFirst{};
    const count = try reconcileRestoredBans(
        alloc,
        &tracker,
        null,
        now,
        FailFirst.apply,
        @ptrCast(&ff),
    );

    try testing.expectEqual(@as(u32, 1), count);
    try testing.expectEqual(@as(u32, 1), ff.count);
}
