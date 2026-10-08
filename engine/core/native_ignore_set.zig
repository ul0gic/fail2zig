// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const types = shared.types;

pub const max_entries_per_part: usize = 128;
pub const distinct_bound: usize = 128;

pub const Source = enum(u2) { config = 1, runtime = 2, both = 3 };

pub const Item = struct {
    entry: types.IgnoreEntry,
    source: Source,
};

pub const EffectiveIgnore = struct {
    entries: []const Item,
    configured_count: u16,
    runtime_count: u16,
    over_bound: bool,

    pub fn build(
        allocator: std.mem.Allocator,
        configured: []const []const u8,
        runtime: []const types.IgnoreEntry,
    ) error{ InvalidStaticIgnore, IgnoreCapacityExceeded, OutOfMemory }!*EffectiveIgnore {
        if (configured.len > max_entries_per_part or runtime.len > max_entries_per_part) return error.IgnoreCapacityExceeded;
        var scratch: [2 * max_entries_per_part]Item = undefined;
        var count: usize = 0;
        for (configured) |literal| {
            const entry = types.IgnoreEntry.parse(literal) catch return error.InvalidStaticIgnore;
            scratch[count] = .{ .entry = entry, .source = .config };
            count += 1;
        }
        for (runtime) |entry| {
            scratch[count] = .{ .entry = entry, .source = .runtime };
            count += 1;
        }
        std.sort.pdq(Item, scratch[0..count], {}, itemLessThan);

        var distinct: usize = 0;
        for (scratch[0..count]) |item| {
            if (distinct > 0 and scratch[distinct - 1].entry.order(item.entry) == .eq) {
                const merged = @intFromEnum(scratch[distinct - 1].source) | @intFromEnum(item.source);
                scratch[distinct - 1].source = @enumFromInt(merged);
            } else {
                scratch[distinct] = item;
                distinct += 1;
            }
        }

        var configured_count: u16 = 0;
        var runtime_count: u16 = 0;
        for (scratch[0..distinct]) |item| {
            if (item.source != .runtime) configured_count += 1;
            if (item.source != .config) runtime_count += 1;
        }

        const entries = try allocator.alloc(Item, distinct);
        errdefer allocator.free(entries);
        @memcpy(entries, scratch[0..distinct]);
        const self = try allocator.create(EffectiveIgnore);
        self.* = .{
            .entries = entries,
            .configured_count = configured_count,
            .runtime_count = runtime_count,
            .over_bound = distinct > distinct_bound,
        };
        return self;
    }

    pub fn deinit(self: *EffectiveIgnore, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        allocator.destroy(self);
    }

    pub fn check(self: *const EffectiveIgnore, ip: shared.IpAddress) ?*const Item {
        for (self.entries) |*item| {
            if (item.entry.contains(ip)) return item;
        }
        return null;
    }

    pub fn covering(self: *const EffectiveIgnore, entry: types.IgnoreEntry, out: []*const Item) usize {
        var found: usize = 0;
        for (self.entries) |*item| {
            if (found == out.len) break;
            if (item.source == .runtime) continue;
            if (item.entry.order(entry) == .eq) continue;
            if (item.entry.prefix <= entry.prefix and item.entry.contains(entry.network())) {
                out[found] = item;
                found += 1;
            }
        }
        return found;
    }

    fn itemLessThan(_: void, a: Item, b: Item) bool {
        return a.entry.order(b.entry) == .lt;
    }
};
