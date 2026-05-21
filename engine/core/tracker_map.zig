// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Per-jail collection of `StateTracker` instances.
//!
//! Each jail owns its own `StateTracker` so per-jail `maxretry`,
//! `findtime`, `bantime`, and `bantime_increment` overrides actually
//! take effect (ISSUE-007). The map is keyed by jail name (the same
//! string the config layer hands us — owned by the config arena and
//! outlives the map). Trackers are heap-allocated so their pointers
//! stay stable as the map grows.
//!
//! Eviction is naturally jail-local: a hot jail filling its tracker
//! cannot starve another jail's records.
//!
//! Threading: single-threaded, owned by the event loop. Callers in a
//! multi-threaded harness must serialize externally.

const std = @import("std");
const shared = @import("shared");

const state_mod = @import("state.zig");

const StateTracker = state_mod.StateTracker;
const IpAddress = shared.IpAddress;
const JailId = shared.JailId;
const Timestamp = shared.Timestamp;

/// Synthetic jail used as a landing zone for persisted entries whose
/// jail name no longer matches any configured jail. The legacy
/// state-file shim writes here too — entries from v0.1.0 single-tracker
/// files that pre-date per-jail routing are funneled into this tracker
/// so the daemon can still reconcile them with the firewall on the
/// next checkpoint.
pub const legacy_jail_name: []const u8 = "__legacy__";

pub const Error = error{
    OutOfMemory,
    UnknownJail,
};

pub const TrackerMap = struct {
    allocator: std.mem.Allocator,
    /// Owns the inner trackers. Keys are slices into the config arena
    /// (or, for the legacy tracker, the constant `legacy_jail_name`).
    map: std.StringHashMap(*StateTracker),

    pub fn init(allocator: std.mem.Allocator) TrackerMap {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap(*StateTracker).init(allocator),
        };
    }

    pub fn deinit(self: *TrackerMap) void {
        var it = self.map.valueIterator();
        while (it.next()) |tp| {
            tp.*.deinit();
            self.allocator.destroy(tp.*);
        }
        self.map.deinit();
        self.* = undefined;
    }

    /// Insert a freshly-initialized tracker for `name`. Returns
    /// `error.OutOfMemory` if the map cannot grow or the heap
    /// allocation fails.
    pub fn addTracker(
        self: *TrackerMap,
        name: []const u8,
        cfg: state_mod.Config,
    ) Error!*StateTracker {
        const tp = self.allocator.create(StateTracker) catch
            return error.OutOfMemory;
        errdefer self.allocator.destroy(tp);
        tp.* = StateTracker.init(self.allocator, cfg) catch
            return error.OutOfMemory;
        errdefer tp.deinit();
        self.map.put(name, tp) catch return error.OutOfMemory;
        return tp;
    }

    /// Lookup the tracker for `name`. Returns null when the jail isn't
    /// known — callers should log + drop rather than fall through.
    pub fn get(self: *const TrackerMap, name: []const u8) ?*StateTracker {
        return self.map.get(name);
    }

    /// Same as `get` but takes a `JailId` for convenience at call sites
    /// that already hold one.
    pub fn getByJail(self: *const TrackerMap, jail: JailId) ?*StateTracker {
        return self.map.get(jail.slice());
    }

    /// Lookup-or-fall-back-to-legacy. The legacy tracker MUST be present
    /// in the map (added via `ensureLegacy`) before this is called.
    pub fn getOrLegacy(self: *const TrackerMap, name: []const u8) ?*StateTracker {
        if (self.map.get(name)) |t| return t;
        return self.map.get(legacy_jail_name);
    }

    /// Ensure the synthetic legacy tracker exists. Idempotent.
    pub fn ensureLegacy(self: *TrackerMap, cfg: state_mod.Config) Error!*StateTracker {
        if (self.map.get(legacy_jail_name)) |t| return t;
        return try self.addTracker(legacy_jail_name, cfg);
    }

    pub fn count(self: *const TrackerMap) usize {
        return self.map.count();
    }

    pub fn iterator(self: *const TrackerMap) std.StringHashMap(*StateTracker).Iterator {
        return self.map.iterator();
    }

    /// Sum of active (`.banned`) entries across every tracker. Used by
    /// `status` and metrics gauges.
    pub fn totalActiveBans(self: *const TrackerMap) u32 {
        var n: u32 = 0;
        var it = self.map.valueIterator();
        while (it.next()) |tp| {
            var inner = tp.*.iterator();
            while (inner.next()) |kv| {
                if (kv.value_ptr.ban_state == .banned) n += 1;
            }
        }
        return n;
    }

    /// Sum of live entries across all trackers (banned + monitoring).
    pub fn totalEntries(self: *const TrackerMap) usize {
        var n: usize = 0;
        var it = self.map.valueIterator();
        while (it.next()) |tp| {
            n += tp.*.stats().entry_count;
        }
        return n;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "tracker_map: init/deinit empty map leaves no leak" {
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();
    try testing.expectEqual(@as(usize, 0), tm.count());
}

test "tracker_map: addTracker installs and get returns it" {
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();

    const t = try tm.addTracker("sshd", .{
        .max_entries = 64,
        .maxretry = 3,
        .findtime = 600,
        .bantime = 600,
    });
    try testing.expect(t == tm.get("sshd").?);
    try testing.expectEqual(@as(usize, 1), tm.count());
    try testing.expect(tm.get("nginx") == null);
}

test "tracker_map: separate trackers honor distinct configs" {
    // The core promise of ISSUE-007: each jail has its own thresholds.
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();

    const aggressive = try tm.addTracker("aggressive", .{
        .max_entries = 32,
        .maxretry = 1,
        .findtime = 600,
        .bantime = 60,
    });
    const lenient = try tm.addTracker("lenient", .{
        .max_entries = 32,
        .maxretry = 5,
        .findtime = 600,
        .bantime = 60,
    });

    try testing.expectEqual(@as(u32, 1), aggressive.config.maxretry);
    try testing.expectEqual(@as(u32, 5), lenient.config.maxretry);
}

test "tracker_map: totalActiveBans aggregates across trackers" {
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();

    const a = try tm.addTracker("a", .{ .max_entries = 32, .maxretry = 1, .findtime = 600, .bantime = 60 });
    const b = try tm.addTracker("b", .{ .max_entries = 32, .maxretry = 1, .findtime = 600, .bantime = 60 });

    const jail_a = try JailId.fromSlice("a");
    const jail_b = try JailId.fromSlice("b");

    // Two bans in a, one in b.
    _ = try a.recordAttempt(try IpAddress.parse("1.1.1.1"), jail_a, 1_000);
    _ = try a.recordAttempt(try IpAddress.parse("1.1.1.2"), jail_a, 1_000);
    _ = try b.recordAttempt(try IpAddress.parse("2.2.2.1"), jail_b, 1_000);

    try testing.expectEqual(@as(u32, 3), tm.totalActiveBans());
    try testing.expectEqual(@as(usize, 3), tm.totalEntries());
}

test "tracker_map: ensureLegacy is idempotent" {
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();

    const first = try tm.ensureLegacy(.{ .max_entries = 8 });
    const second = try tm.ensureLegacy(.{ .max_entries = 8 });
    try testing.expect(first == second);
    try testing.expectEqual(@as(usize, 1), tm.count());
}

test "tracker_map: getOrLegacy falls back when jail missing" {
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();

    _ = try tm.ensureLegacy(.{ .max_entries = 8 });
    _ = try tm.addTracker("sshd", .{ .max_entries = 8 });

    try testing.expect(tm.getOrLegacy("sshd").? == tm.get("sshd").?);
    try testing.expect(tm.getOrLegacy("unknown").? == tm.get(legacy_jail_name).?);
}

// ---------- ISSUE-007: per-jail threshold regression tests ----------

test "tracker_map: ISSUE-007 — per-jail maxretry actually takes effect" {
    // The exact spec test #1 from the issue: defaults maxretry=5,
    // jails.aggressive maxretry=1. One match on aggressive bans;
    // it would take five on the default-shaped jail.
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();

    const aggressive = try tm.addTracker("aggressive", .{
        .max_entries = 32,
        .maxretry = 1,
        .findtime = 600,
        .bantime = 60,
    });
    const defaulty = try tm.addTracker("defaulty", .{
        .max_entries = 32,
        .maxretry = 5,
        .findtime = 600,
        .bantime = 60,
    });

    const ip = try IpAddress.parse("1.2.3.4");
    const j_agg = try JailId.fromSlice("aggressive");
    const j_def = try JailId.fromSlice("defaulty");

    // 1 match against aggressive -> ban decision fires.
    const dec_agg = (try aggressive.recordAttempt(ip, j_agg, 1_000)).?;
    try testing.expect(IpAddress.eql(dec_agg.ip, ip));

    // 4 matches against defaulty -> no ban yet.
    try testing.expect((try defaulty.recordAttempt(ip, j_def, 2_000)) == null);
    try testing.expect((try defaulty.recordAttempt(ip, j_def, 2_010)) == null);
    try testing.expect((try defaulty.recordAttempt(ip, j_def, 2_020)) == null);
    try testing.expect((try defaulty.recordAttempt(ip, j_def, 2_030)) == null);

    // 5th match crosses the default jail's threshold.
    const dec_def = (try defaulty.recordAttempt(ip, j_def, 2_040)).?;
    try testing.expect(IpAddress.eql(dec_def.ip, ip));
}

test "tracker_map: ISSUE-007 — cross-jail IP state is isolated" {
    // Spec test #2: same IP triggers in jail A; jail B's tracker is
    // untouched. A ban in A does not preempt B's independent threshold.
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();

    const a = try tm.addTracker("a", .{
        .max_entries = 32,
        .maxretry = 2,
        .findtime = 600,
        .bantime = 60,
    });
    const b = try tm.addTracker("b", .{
        .max_entries = 32,
        .maxretry = 3,
        .findtime = 600,
        .bantime = 60,
    });

    const ip = try IpAddress.parse("9.9.9.9");
    const j_a = try JailId.fromSlice("a");
    const j_b = try JailId.fromSlice("b");

    // Two attempts in A -> ban.
    _ = try a.recordAttempt(ip, j_a, 1_000);
    const dec_a = (try a.recordAttempt(ip, j_a, 1_010)).?;
    try testing.expect(IpAddress.eql(dec_a.ip, ip));

    // Two attempts in B with a threshold of 3 -> still monitoring.
    _ = try b.recordAttempt(ip, j_b, 1_000);
    _ = try b.recordAttempt(ip, j_b, 1_010);
    try testing.expect(b.get(ip).?.ban_state == .monitoring);
    try testing.expect(a.get(ip).?.ban_state == .banned);

    // Third attempt in B finally crosses its own threshold.
    const dec_b = (try b.recordAttempt(ip, j_b, 1_020)).?;
    try testing.expect(IpAddress.eql(dec_b.ip, ip));
}

test "tracker_map: ISSUE-007 — per-jail bantime_increment escalates independently" {
    // Spec test #3: a per-jail bantime_increment factor applies to that
    // jail's ban escalation curve; a sibling jail with no escalation
    // keeps a flat bantime.
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();

    const fast = try tm.addTracker("fast", .{
        .max_entries = 32,
        .maxretry = 1,
        .findtime = 600,
        .bantime = 100,
        .bantime_increment = .{
            .enabled = true,
            .multiplier = 1.0,
            .factor = 4.0,
            .formula = .exponential,
            .max_bantime = 100_000,
        },
    });
    const flat = try tm.addTracker("flat", .{
        .max_entries = 32,
        .maxretry = 1,
        .findtime = 600,
        .bantime = 100,
    });

    const ip = try IpAddress.parse("4.4.4.4");
    const j_fast = try JailId.fromSlice("fast");
    const j_flat = try JailId.fromSlice("flat");

    // First ban in `fast`.
    const d1 = (try fast.recordAttempt(ip, j_fast, 1_000)).?;
    try testing.expectEqual(@as(shared.Duration, 100), d1.duration);
    // Recidive in `fast`: 100 * 4^1 = 400.
    fast.clearBan(ip);
    const d2 = (try fast.recordAttempt(ip, j_fast, 2_000)).?;
    try testing.expectEqual(@as(shared.Duration, 400), d2.duration);

    // Meanwhile `flat` (no escalation) keeps the flat 100s bantime.
    const d_flat1 = (try flat.recordAttempt(ip, j_flat, 5_000)).?;
    try testing.expectEqual(@as(shared.Duration, 100), d_flat1.duration);
    flat.clearBan(ip);
    const d_flat2 = (try flat.recordAttempt(ip, j_flat, 6_000)).?;
    try testing.expectEqual(@as(shared.Duration, 100), d_flat2.duration);
}

test "tracker_map: ISSUE-007 — total memory stays within sum of per-jail budgets" {
    // Spec test #5: each tracker is initialized with a bounded
    // `max_entries`; the map's total is the sum. Filling each tracker
    // past its cap exercises the eviction path independently, never
    // exceeding the per-jail ceiling.
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();

    const per_jail_cap: u32 = 4;
    const jail_count: u32 = 3;
    const names = [_][]const u8{ "j0", "j1", "j2" };
    for (names) |n| {
        _ = try tm.addTracker(n, .{
            .max_entries = per_jail_cap,
            .maxretry = 100,
            .findtime = 10_000,
            .bantime = 60,
            .eviction_policy = .drop_oldest_unbanned,
        });
    }

    // Push per_jail_cap+2 unique IPs into each tracker -> eviction kicks in.
    var jdx: u32 = 0;
    while (jdx < jail_count) : (jdx += 1) {
        const tracker = tm.get(names[jdx]).?;
        const jail = try JailId.fromSlice(names[jdx]);
        var i: u32 = 0;
        while (i < per_jail_cap + 2) : (i += 1) {
            const ip: IpAddress = .{ .ipv4 = (10 << 24) | (jdx << 16) | i };
            _ = try tracker.recordAttempt(ip, jail, @as(Timestamp, 1_000) + @as(Timestamp, i));
        }
        // Each tracker must stay at-or-under its own ceiling.
        try testing.expect(tracker.stats().entry_count <= per_jail_cap);
    }

    // Total is bounded by sum of per-jail caps.
    try testing.expect(tm.totalEntries() <= per_jail_cap * jail_count);
}
