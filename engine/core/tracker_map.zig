// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");

const state_mod = @import("state.zig");

const StateTracker = state_mod.StateTracker;
const IpAddress = shared.IpAddress;
const JailId = shared.JailId;
const Timestamp = shared.Timestamp;

pub const legacy_jail_name: []const u8 = "__legacy__";

pub const Error = error{
    OutOfMemory,
    UnknownJail,
};

pub const TrackerMap = struct {
    allocator: std.mem.Allocator,
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

    pub fn get(self: *const TrackerMap, name: []const u8) ?*StateTracker {
        return self.map.get(name);
    }

    pub fn getByJail(self: *const TrackerMap, jail: JailId) ?*StateTracker {
        return self.map.get(jail.slice());
    }

    pub fn getOrLegacy(self: *const TrackerMap, name: []const u8) ?*StateTracker {
        if (self.map.get(name)) |t| return t;
        return self.map.get(legacy_jail_name);
    }

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

    pub fn totalEntries(self: *const TrackerMap) usize {
        var n: usize = 0;
        var it = self.map.valueIterator();
        while (it.next()) |tp| {
            n += tp.*.stats().entry_count;
        }
        return n;
    }
};
