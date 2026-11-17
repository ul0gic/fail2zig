// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const types = shared.types;
const RuntimeIgnoreEntry = @import("../store/ignore_entries.zig").RuntimeIgnoreEntry;

pub const max_entries_per_part: usize = 128;
pub const distinct_bound: usize = 128;

pub const Source = enum(u3) { config = 1, runtime = 2, both = 3, self = 4 };

pub const Item = struct {
    entry: types.IgnoreEntry,
    source: Source,
    expires_us: ?i64 = null,
    expired: bool = false,
};

pub fn configuredEntries(configured: []const []const u8, default_duration_s: ?u64, out: []types.TimedEntry) error{InvalidStaticIgnore}!usize {
    var count: usize = 0;
    for (configured) |literal| {
        const parsed = types.TimedEntry.parse(literal, default_duration_s) catch {
            if (std.mem.indexOfAny(u8, literal, &std.ascii.whitespace) == null) continue;
            return error.InvalidStaticIgnore;
        };
        if (count == out.len) return error.InvalidStaticIgnore;
        out[count] = parsed;
        count += 1;
    }
    return count;
}

pub const EffectiveIgnore = struct {
    entries: []const Item,
    configured_count: u16,
    runtime_count: u16,
    over_bound: bool,
    next_deadline_us: ?i64,

    pub fn build(
        allocator: std.mem.Allocator,
        configured: []const []const u8,
        deadlines: []const ?i64,
        runtime: []const RuntimeIgnoreEntry,
        self: []const shared.IpAddress,
        now_us: i64,
    ) error{ InvalidStaticIgnore, IgnoreCapacityExceeded, OutOfMemory }!*EffectiveIgnore {
        if (configured.len > max_entries_per_part or runtime.len > max_entries_per_part) return error.IgnoreCapacityExceeded;
        if (deadlines.len != 0 and deadlines.len != configured.len) return error.InvalidStaticIgnore;
        const scratch = try allocator.alloc(Item, configured.len + runtime.len + self.len);
        defer allocator.free(scratch);
        var count: usize = 0;
        for (configured, 0..) |literal, index| {
            const parsed = types.TimedEntry.parse(literal, null) catch return error.InvalidStaticIgnore;
            scratch[count] = timedItem(parsed.entry, .config, if (deadlines.len == 0) null else deadlines[index], now_us);
            count += 1;
        }
        for (runtime) |stored| {
            scratch[count] = timedItem(stored.entry, .runtime, stored.expires_us, now_us);
            count += 1;
        }
        for (self) |address| {
            scratch[count] = .{ .entry = hostEntry(address), .source = .self };
            count += 1;
        }
        std.sort.pdq(Item, scratch[0..count], {}, itemLessThan);

        var distinct: usize = 0;
        next: for (scratch[0..count]) |item| {
            var prior = distinct;
            while (prior > 0 and scratch[prior - 1].entry.order(item.entry) == .eq) : (prior -= 1) {
                if (merge(&scratch[prior - 1], item)) continue :next;
            }
            scratch[distinct] = item;
            distinct += 1;
        }

        var configured_count: u16 = 0;
        var runtime_count: u16 = 0;
        var self_count: usize = 0;
        var next_deadline_us: ?i64 = null;
        for (scratch[0..distinct]) |item| {
            switch (item.source) {
                .config => configured_count += 1,
                .runtime => runtime_count += 1,
                .both => {
                    configured_count += 1;
                    runtime_count += 1;
                },
                .self => self_count += 1,
            }
            if (item.expired) continue;
            if (item.expires_us) |deadline| next_deadline_us = if (next_deadline_us) |current| @min(current, deadline) else deadline;
        }

        const entries = try allocator.alloc(Item, distinct);
        errdefer allocator.free(entries);
        @memcpy(entries, scratch[0..distinct]);
        const result = try allocator.create(EffectiveIgnore);
        result.* = .{
            .entries = entries,
            .configured_count = configured_count,
            .runtime_count = runtime_count,
            .over_bound = distinct - self_count > distinct_bound,
            .next_deadline_us = next_deadline_us,
        };
        return result;
    }

    pub fn deinit(self: *EffectiveIgnore, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        allocator.destroy(self);
    }

    pub fn check(self: *const EffectiveIgnore, ip: shared.IpAddress) ?*const Item {
        for (self.entries) |*item| {
            if (item.expired) continue;
            if (item.entry.contains(ip)) return item;
        }
        return null;
    }

    pub fn covering(self: *const EffectiveIgnore, entry: types.IgnoreEntry, out: []*const Item) usize {
        var found: usize = 0;
        for (self.entries) |*item| {
            if (found == out.len) break;
            if (item.source == .runtime or item.expired) continue;
            if (item.entry.order(entry) == .eq) continue;
            if (item.entry.prefix <= entry.prefix and item.entry.contains(entry.network())) {
                out[found] = item;
                found += 1;
            }
        }
        return found;
    }

    fn timedItem(entry: types.IgnoreEntry, source: Source, expires_us: ?i64, now_us: i64) Item {
        const expired = if (expires_us) |deadline| deadline <= now_us else false;
        return .{ .entry = entry, .source = source, .expires_us = expires_us, .expired = expired };
    }

    fn hostEntry(address: shared.IpAddress) types.IgnoreEntry {
        var bytes = [_]u8{0} ** 16;
        return switch (address) {
            .ipv4 => |bits| blk: {
                std.mem.writeInt(u32, bytes[0..4], bits, .big);
                break :blk .{ .family = .v4, .address = bytes, .prefix = 32 };
            },
            .ipv6 => |bits| blk: {
                std.mem.writeInt(u128, &bytes, bits, .big);
                break :blk .{ .family = .v6, .address = bytes, .prefix = 128 };
            },
        };
    }

    fn merge(prior: *Item, item: Item) bool {
        if (prior.source == item.source and sameDeadline(prior.expires_us, item.expires_us)) return true;
        if (prior.source == .self or item.source == .self) return false;
        if (prior.expires_us != null or item.expires_us != null) return false;
        prior.source = @enumFromInt(@intFromEnum(prior.source) | @intFromEnum(item.source));
        return true;
    }

    fn sameDeadline(a: ?i64, b: ?i64) bool {
        const left = a orelse return b == null;
        const right = b orelse return false;
        return left == right;
    }

    fn itemLessThan(_: void, a: Item, b: Item) bool {
        return a.entry.order(b.entry) == .lt;
    }
};
