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

const testing = std.testing;

test "metrics: init produces zeroed counters" {
    var m = Metrics.init();
    const s = m.snapshot();
    try testing.expectEqual(@as(u64, 0), s.lines_parsed);
    try testing.expectEqual(@as(u64, 0), s.bans_total);
    try testing.expectEqual(@as(u32, 0), s.active_bans);
    try testing.expectEqual(@as(usize, 0), s.jails_len);
}

test "metrics: incrementParsed / incrementBans move the global counters" {
    var m = Metrics.init();
    m.incrementParsed();
    m.incrementParsed();
    m.incrementBans();
    m.incrementParseErrors();

    const s = m.snapshot();
    try testing.expectEqual(@as(u64, 2), s.lines_parsed);
    try testing.expectEqual(@as(u64, 1), s.bans_total);
    try testing.expectEqual(@as(u32, 1), s.active_bans);
    try testing.expectEqual(@as(u64, 1), s.parse_errors);
}

test "metrics: incrementUnbans saturates at zero" {
    var m = Metrics.init();
    m.incrementUnbans();
    m.incrementUnbans();
    const s = m.snapshot();
    try testing.expectEqual(@as(u32, 0), s.active_bans);
    try testing.expectEqual(@as(u64, 2), s.unbans_total);
}

test "metrics: registerJail and jailIndex round-trip" {
    var m = Metrics.init();
    const idx_sshd = m.registerJail("sshd").?;
    const idx_nginx = m.registerJail("nginx").?;
    try testing.expectEqual(@as(usize, 0), idx_sshd);
    try testing.expectEqual(@as(usize, 1), idx_nginx);

    try testing.expectEqual(@as(usize, 0), m.jailIndex("sshd").?);
    try testing.expectEqual(@as(usize, 1), m.jailIndex("nginx").?);
    try testing.expectEqual(@as(?usize, null), m.jailIndex("unknown"));
}

test "metrics: registerJail rejects empty and overlong names" {
    var m = Metrics.init();
    try testing.expectEqual(@as(?usize, null), m.registerJail(""));
    const too_long = [_]u8{'a'} ** (max_jail_name_len + 1);
    try testing.expectEqual(@as(?usize, null), m.registerJail(&too_long));
}

test "metrics: registerJail dedupes duplicate registration" {
    var m = Metrics.init();
    const a = m.registerJail("sshd").?;
    const b = m.registerJail("sshd").?;
    try testing.expectEqual(a, b);
    try testing.expectEqual(@as(usize, 1), m.snapshot().jails_len);
}

test "metrics: per-jail counters increment independently" {
    var m = Metrics.init();
    _ = m.registerJail("sshd").?;
    _ = m.registerJail("nginx").?;
    m.jailIncrementParsed("sshd");
    m.jailIncrementParsed("sshd");
    m.jailIncrementParsed("nginx");
    m.jailIncrementBans("sshd");

    const s = m.snapshot();
    try testing.expectEqual(@as(usize, 2), s.jails_len);
    for (s.perJail()) |pj| {
        if (std.mem.eql(u8, pj.name(), "sshd")) {
            try testing.expectEqual(@as(u64, 2), pj.lines_parsed);
            try testing.expectEqual(@as(u64, 1), pj.bans_total);
        } else if (std.mem.eql(u8, pj.name(), "nginx")) {
            try testing.expectEqual(@as(u64, 1), pj.lines_parsed);
            try testing.expectEqual(@as(u64, 0), pj.bans_total);
        }
    }
}

test "metrics: max_jails ceiling prevents registration beyond cap" {
    var m = Metrics.init();
    var i: usize = 0;
    while (i < max_jails) : (i += 1) {
        var buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "jail{d}", .{i});
        try testing.expect(m.registerJail(name) != null);
    }
    try testing.expectEqual(@as(?usize, null), m.registerJail("overflow"));
}

test "metrics: snapshot is a stable by-value copy" {
    var m = Metrics.init();
    m.incrementParsed();
    const s1 = m.snapshot();
    m.incrementParsed();
    const s2 = m.snapshot();
    try testing.expectEqual(@as(u64, 1), s1.lines_parsed);
    try testing.expectEqual(@as(u64, 2), s2.lines_parsed);
}

test "metrics: setMemoryBytes updates the memory gauge" {
    var m = Metrics.init();
    m.setMemoryBytes(12345);
    try testing.expectEqual(@as(u64, 12345), m.snapshot().memory_bytes_used);
    m.setMemoryBytes(67890);
    try testing.expectEqual(@as(u64, 67890), m.snapshot().memory_bytes_used);
}

test "metrics: BUG-006 setBansTotal / jailSetBansTotal seed the lifetime counters" {
    var m = Metrics.init();
    _ = m.registerJail("sshd");
    m.setBansTotal(100);
    m.jailSetBansTotal("sshd", 60);
    var s = m.snapshot();
    try testing.expectEqual(@as(u64, 100), s.bans_total);
    try testing.expectEqual(@as(u64, 60), s.perJail()[0].bans_total);

    m.incrementBans();
    m.jailIncrementBans("sshd");
    s = m.snapshot();
    try testing.expectEqual(@as(u64, 101), s.bans_total);
    try testing.expectEqual(@as(u64, 61), s.perJail()[0].bans_total);
}

test "metrics: concurrent incrementParsed across 4 threads sums correctly" {
    var m = Metrics.init();
    const Worker = struct {
        fn run(metrics: *Metrics) void {
            var i: u32 = 0;
            while (i < 1000) : (i += 1) {
                metrics.incrementParsed();
            }
        }
    };

    var ths: [4]std.Thread = undefined;
    for (&ths) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{&m});
    }
    for (ths) |t| t.join();

    try testing.expectEqual(@as(u64, 4000), m.snapshot().lines_parsed);
}

test "metrics: concurrent mixed operations preserve totals" {
    var m = Metrics.init();
    _ = m.registerJail("sshd").?;

    const Worker = struct {
        fn run(metrics: *Metrics) void {
            var i: u32 = 0;
            while (i < 500) : (i += 1) {
                metrics.incrementParsed();
                metrics.incrementMatched();
                metrics.incrementBans();
                metrics.incrementUnbans();
                metrics.jailIncrementParsed("sshd");
            }
        }
    };

    var ths: [4]std.Thread = undefined;
    for (&ths) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{&m});
    }
    for (ths) |t| t.join();

    const s = m.snapshot();
    try testing.expectEqual(@as(u64, 2000), s.lines_parsed);
    try testing.expectEqual(@as(u64, 2000), s.lines_matched);
    try testing.expectEqual(@as(u64, 2000), s.bans_total);
    try testing.expectEqual(@as(u64, 2000), s.unbans_total);
    try testing.expectEqual(@as(u64, 2000), s.perJail()[0].lines_parsed);
    try testing.expectEqual(@as(u32, 0), s.active_bans);
}

test "MutexCounter: single-threaded init/inc/load/store" {
    var c = MutexCounter.init(0);
    try testing.expectEqual(@as(u64, 0), c.load());

    var i: u64 = 0;
    while (i < 7) : (i += 1) c.inc();
    try testing.expectEqual(@as(u64, 7), c.load());

    c.store(123456789);
    try testing.expectEqual(@as(u64, 123456789), c.load());

    var seeded = MutexCounter.init(42);
    try testing.expectEqual(@as(u64, 42), seeded.load());
}

test "MutexCounter: 4 threads x 1000 inc serialize to exactly 4000" {
    var c = MutexCounter.init(0);
    const Worker = struct {
        fn run(counter: *MutexCounter) void {
            var i: u32 = 0;
            while (i < 1000) : (i += 1) counter.inc();
        }
    };

    var ths: [4]std.Thread = undefined;
    for (&ths) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{&c});
    }
    for (ths) |t| t.join();

    try testing.expectEqual(@as(u64, 4000), c.load());
}

test "AtomicCounter: single-threaded init/inc/load/store" {
    var c = AtomicCounter.init(0);
    try testing.expectEqual(@as(u64, 0), c.load());

    var i: u64 = 0;
    while (i < 7) : (i += 1) c.inc();
    try testing.expectEqual(@as(u64, 7), c.load());

    c.store(123456789);
    try testing.expectEqual(@as(u64, 123456789), c.load());

    var seeded = AtomicCounter.init(42);
    try testing.expectEqual(@as(u64, 42), seeded.load());
}

test "AtomicCounter: 4 threads x 1000 inc sum to exactly 4000" {
    var c = AtomicCounter.init(0);
    const Worker = struct {
        fn run(counter: *AtomicCounter) void {
            var i: u32 = 0;
            while (i < 1000) : (i += 1) counter.inc();
        }
    };

    var ths: [4]std.Thread = undefined;
    for (&ths) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{&c});
    }
    for (ths) |t| t.join();

    try testing.expectEqual(@as(u64, 4000), c.load());
}
