// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");

const AtomicCounter = struct {
    value: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn init(v: u64) AtomicCounter {
        return .{ .value = std.atomic.Value(u64).init(v) };
    }

    fn inc(self: *AtomicCounter) void {
        _ = self.value.fetchAdd(1, .monotonic);
    }

    fn load(self: *AtomicCounter) u64 {
        return self.value.load(.monotonic);
    }

    fn store(self: *AtomicCounter, v: u64) void {
        self.value.store(v, .monotonic);
    }
};

const MutexCounter = struct {
    mutex: std.Thread.Mutex = .{},
    value: u64 = 0,

    fn init(v: u64) MutexCounter {
        return .{ .value = v };
    }

    fn inc(self: *MutexCounter) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.value += 1;
    }

    fn load(self: *MutexCounter) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.value;
    }

    fn store(self: *MutexCounter, v: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.value = v;
    }
};

const Counter = if (@bitSizeOf(usize) >= 64) AtomicCounter else MutexCounter;

pub const max_jails: usize = 64;

pub const max_jail_name_len: usize = 64;

const counter_order: std.builtin.AtomicOrder = .monotonic;

pub const PerJail = struct {
    name_buf: [max_jail_name_len]u8 = [_]u8{0} ** max_jail_name_len,
    name_len: u8 = 0,
    lines_parsed: Counter = .{},
    lines_matched: Counter = .{},
    bans_total: Counter = .{},
    unbans_total: Counter = .{},
    active_bans: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    parse_errors: Counter = .{},

    pub fn name(self: *const PerJail) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const PerJailSnapshot = struct {
    name_buf: [max_jail_name_len]u8,
    name_len: u8,
    lines_parsed: u64,
    lines_matched: u64,
    bans_total: u64,
    unbans_total: u64,
    active_bans: u32,
    parse_errors: u64,

    pub fn name(self: *const PerJailSnapshot) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const Snapshot = struct {
    lines_parsed: u64 = 0,
    lines_matched: u64 = 0,
    bans_total: u64 = 0,
    unbans_total: u64 = 0,
    active_bans: u32 = 0,
    parse_errors: u64 = 0,
    memory_bytes_used: u64 = 0,
    jails: [max_jails]PerJailSnapshot = undefined,
    jails_len: usize = 0,

    pub fn perJail(self: *const Snapshot) []const PerJailSnapshot {
        return self.jails[0..self.jails_len];
    }
};

pub const Metrics = struct {
    lines_parsed: Counter = .{},
    lines_matched: Counter = .{},
    bans_total: Counter = .{},
    unbans_total: Counter = .{},
    active_bans: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    parse_errors: Counter = .{},
    memory_bytes_used: Counter = .{},

    jails: [max_jails]PerJail = [_]PerJail{.{}} ** max_jails,
    jails_len: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    pub fn init() Metrics {
        return .{};
    }

    pub fn incrementParsed(self: *Metrics) void {
        self.lines_parsed.inc();
    }

    pub fn incrementMatched(self: *Metrics) void {
        self.lines_matched.inc();
    }

    pub fn incrementBans(self: *Metrics) void {
        self.bans_total.inc();
        _ = self.active_bans.fetchAdd(1, counter_order);
    }

    pub fn incrementUnbans(self: *Metrics) void {
        self.unbans_total.inc();
        const prev = self.active_bans.load(counter_order);
        if (prev > 0) {
            _ = self.active_bans.fetchSub(1, counter_order);
        }
    }

    pub fn incrementParseErrors(self: *Metrics) void {
        self.parse_errors.inc();
    }

    pub fn setMemoryBytes(self: *Metrics, bytes: u64) void {
        self.memory_bytes_used.store(bytes);
    }

    pub fn setActiveBans(self: *Metrics, count: u32) void {
        self.active_bans.store(count, counter_order);
    }

    pub fn setBansTotal(self: *Metrics, count: u64) void {
        self.bans_total.store(count);
    }

    pub fn registerJail(self: *Metrics, name: []const u8) ?usize {
        if (name.len == 0 or name.len > max_jail_name_len) return null;
        const live = self.jails_len.load(.acquire);
        for (self.jails[0..live], 0..) |*slot, i| {
            if (slot.name_len == name.len and
                std.mem.eql(u8, slot.name_buf[0..slot.name_len], name))
            {
                return i;
            }
        }
        if (live >= max_jails) return null;
        var slot = &self.jails[live];
        @memcpy(slot.name_buf[0..name.len], name);
        slot.name_len = @intCast(name.len);
        self.jails_len.store(live + 1, .release);
        return live;
    }

    pub fn jailIndex(self: *const Metrics, name: []const u8) ?usize {
        const live = self.jails_len.load(.acquire);
        for (self.jails[0..live], 0..) |*slot, i| {
            if (slot.name_len == name.len and
                std.mem.eql(u8, slot.name_buf[0..slot.name_len], name))
            {
                return i;
            }
        }
        return null;
    }

    pub fn jailIncrementParsed(self: *Metrics, jail: []const u8) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].lines_parsed.inc();
        }
    }

    pub fn jailIncrementMatched(self: *Metrics, jail: []const u8) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].lines_matched.inc();
        }
    }

    pub fn jailIncrementBans(self: *Metrics, jail: []const u8) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].bans_total.inc();
            _ = self.jails[i].active_bans.fetchAdd(1, counter_order);
        }
    }

    pub fn jailSetActiveBans(self: *Metrics, jail: []const u8, count: u32) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].active_bans.store(count, counter_order);
        }
    }

    pub fn jailSetBansTotal(self: *Metrics, jail: []const u8, count: u64) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].bans_total.store(count);
        }
    }

    pub fn jailIncrementUnbans(self: *Metrics, jail: []const u8) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].unbans_total.inc();
            const prev = self.jails[i].active_bans.load(counter_order);
            if (prev > 0) {
                _ = self.jails[i].active_bans.fetchSub(1, counter_order);
            }
        }
    }

    pub fn jailIncrementParseErrors(self: *Metrics, jail: []const u8) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].parse_errors.inc();
        }
    }

    pub fn snapshot(self: *Metrics) Snapshot {
        var s = Snapshot{};
        s.lines_parsed = self.lines_parsed.load();
        s.lines_matched = self.lines_matched.load();
        s.bans_total = self.bans_total.load();
        s.unbans_total = self.unbans_total.load();
        s.active_bans = self.active_bans.load(counter_order);
        s.parse_errors = self.parse_errors.load();
        s.memory_bytes_used = self.memory_bytes_used.load();

        const live = self.jails_len.load(.acquire);
        s.jails_len = live;
        for (self.jails[0..live], 0..) |*slot, i| {
            s.jails[i] = .{
                .name_buf = slot.name_buf,
                .name_len = slot.name_len,
                .lines_parsed = slot.lines_parsed.load(),
                .lines_matched = slot.lines_matched.load(),
                .bans_total = slot.bans_total.load(),
                .unbans_total = slot.unbans_total.load(),
                .active_bans = slot.active_bans.load(counter_order),
                .parse_errors = slot.parse_errors.load(),
            };
        }
        return s;
    }
};
