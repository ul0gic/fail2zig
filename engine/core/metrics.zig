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
    failures_counted: Counter = .{},
    ignored_detections: Counter = .{},
    pool_evictions: Counter = .{},
    source_state: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

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
    failures_counted: u64,
    ignored_detections: u64,
    pool_evictions: u64,
    source_state: u8,

    pub fn name(self: *const PerJailSnapshot) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const NativeHealth = struct {
    storage_healthy: bool = false,
    committed_records: u64 = 0,
    worker_stalled: bool = false,
    worker_busy: bool = false,
    worker_heartbeat_age_ms: u64 = 0,
    worker_busy_age_ms: u64 = 0,
    clock_uncertain: bool = false,
    expiry_overdue: bool = false,
    expiry_uncertain: bool = false,
};

pub const Snapshot = struct {
    lines_parsed: u64 = 0,
    lines_matched: u64 = 0,
    bans_total: u64 = 0,
    unbans_total: u64 = 0,
    active_bans: u32 = 0,
    parse_errors: u64 = 0,
    memory_bytes_used: u64 = 0,
    state_file_bytes: u64 = 0,
    state_file_pages: u64 = 0,
    pool_sample_available: bool = false,
    pool_sample_pending: bool = true,
    pool_sample_as_of_us: ?i64 = null,
    pool_tracked: u32 = 0,
    pool_banned: u32 = 0,
    pool_tracking_limit: u32 = 0,
    pool_ban_limit: u32 = 0,
    native: NativeHealth = .{},
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
    state_file_bytes: Counter = .{},
    state_file_pages: Counter = .{},
    pool_sample_available: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    pool_sample_pending: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    pool_sample_as_of_us: Counter = .{},
    pool_tracked: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    pool_banned: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

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

    pub fn setStateFile(self: *Metrics, bytes: u64, pages: u64) void {
        self.state_file_bytes.store(bytes);
        self.state_file_pages.store(pages);
    }

    pub fn setPoolSample(self: *Metrics, available: bool, pending: bool, as_of_us: ?i64) void {
        self.pool_sample_as_of_us.store(@bitCast(as_of_us orelse @as(i64, 0)));
        self.pool_sample_available.store(available, counter_order);
        self.pool_sample_pending.store(pending, counter_order);
    }

    pub fn setPoolOccupancy(self: *Metrics, tracked: u32, banned: u32) void {
        self.pool_tracked.store(tracked, counter_order);
        self.pool_banned.store(banned, counter_order);
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

    pub fn jailSetFailuresCounted(self: *Metrics, jail: []const u8, count: u64) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].failures_counted.store(count);
        }
    }

    pub fn jailSetIgnoredDetections(self: *Metrics, jail: []const u8, count: u64) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].ignored_detections.store(count);
        }
    }

    pub fn jailSetPoolEvictions(self: *Metrics, jail: []const u8, count: u64) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].pool_evictions.store(count);
        }
    }

    pub fn jailSetSourceState(self: *Metrics, jail: []const u8, state: u8) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].source_state.store(state, counter_order);
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
        s.state_file_bytes = self.state_file_bytes.load();
        s.state_file_pages = self.state_file_pages.load();
        s.pool_sample_available = self.pool_sample_available.load(counter_order);
        s.pool_sample_pending = self.pool_sample_pending.load(counter_order);
        s.pool_sample_as_of_us = if (s.pool_sample_available) @as(i64, @bitCast(self.pool_sample_as_of_us.load())) else null;
        s.pool_tracked = self.pool_tracked.load(counter_order);
        s.pool_banned = self.pool_banned.load(counter_order);

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
                .failures_counted = slot.failures_counted.load(),
                .ignored_detections = slot.ignored_detections.load(),
                .pool_evictions = slot.pool_evictions.load(),
                .source_state = slot.source_state.load(counter_order),
            };
        }
        return s;
    }
};

const Kind = enum { gauge, counter };

fn family(writer: anytype, name: []const u8, kind: Kind, help: []const u8) !void {
    try writer.print("# HELP {s} {s}\n# TYPE {s} {s}\n", .{ name, help, name, @tagName(kind) });
}

fn sample(writer: anytype, name: []const u8, kind: Kind, help: []const u8, value: u64) !void {
    try family(writer, name, kind, help);
    try writer.print("{s} {d}\n", .{ name, value });
}

fn writeLabelValue(writer: anytype, value: []const u8) !void {
    for (value) |c| switch (c) {
        '\\' => try writer.writeAll("\\\\"),
        '"' => try writer.writeAll("\\\""),
        '\n' => try writer.writeAll("\\n"),
        else => try writer.writeByte(c),
    };
}

const JailSeries = struct {
    name: []const u8,
    kind: Kind,
    help: []const u8,
    field: std.meta.FieldEnum(PerJailSnapshot),
};

const jail_series = [_]JailSeries{
    .{ .name = "fail2zig_jail_bans_active", .kind = .gauge, .help = "Live bans owned by the jail", .field = .active_bans },
    .{ .name = "fail2zig_jail_bans_total", .kind = .counter, .help = "Bans the jail has issued", .field = .bans_total },
    .{ .name = "fail2zig_jail_failures_counted_total", .kind = .counter, .help = "Failures counted toward a ban", .field = .failures_counted },
    .{ .name = "fail2zig_jail_ignored_detections_total", .kind = .counter, .help = "Detections dropped by the ignore list", .field = .ignored_detections },
    .{ .name = "fail2zig_jail_source_state", .kind = .gauge, .help = "Log source state: 0 ok, 1 paused, 2 missing, 3 blocked", .field = .source_state },
    .{ .name = "fail2zig_jail_pool_evictions_total", .kind = .counter, .help = "Idle subjects evicted from the shared pool", .field = .pool_evictions },
};

pub fn renderPrometheus(snapshot: *const Snapshot, writer: anytype) !void {
    const n = snapshot.native;
    try sample(writer, "fail2zig_up", .gauge, "1 when the daemon is running", 1);
    try sample(writer, "fail2zig_native_storage_healthy", .gauge, "1 when storage is healthy", @intFromBool(n.storage_healthy));
    try sample(writer, "fail2zig_native_committed_records", .gauge, "Records committed by the storage worker", n.committed_records);
    try sample(writer, "fail2zig_native_worker_stalled", .gauge, "1 when the storage worker is stalled", @intFromBool(n.worker_stalled));
    try sample(writer, "fail2zig_native_worker_busy", .gauge, "1 when the storage worker is busy", @intFromBool(n.worker_busy));
    try sample(writer, "fail2zig_native_worker_heartbeat_age_ms", .gauge, "Milliseconds since the storage worker heartbeat", n.worker_heartbeat_age_ms);
    try sample(writer, "fail2zig_native_worker_busy_age_ms", .gauge, "Milliseconds the storage worker has been busy", n.worker_busy_age_ms);
    try sample(writer, "fail2zig_native_clock_uncertain", .gauge, "1 when the wall clock is uncertain", @intFromBool(n.clock_uncertain));
    try sample(writer, "fail2zig_native_expiry_overdue", .gauge, "1 when a ban expiry is overdue", @intFromBool(n.expiry_overdue));
    try sample(writer, "fail2zig_native_expiry_uncertain", .gauge, "1 when ban expiry is uncertain", @intFromBool(n.expiry_uncertain));
    try sample(writer, "fail2zig_state_file_bytes", .gauge, "State file size in bytes", snapshot.state_file_bytes);
    try sample(writer, "fail2zig_state_file_pages", .gauge, "State file size in pages", snapshot.state_file_pages);
    try sample(writer, "fail2zig_pool_sample_available", .gauge, "1 when a completed retry pool sample is available", @intFromBool(snapshot.pool_sample_available));
    try sample(writer, "fail2zig_pool_sample_pending", .gauge, "1 while retry pool sampling awaits catch-up", @intFromBool(snapshot.pool_sample_pending));
    if (snapshot.pool_sample_available) {
        try sample(writer, "fail2zig_pool_tracked", .gauge, "Tracked subjects in the last completed sample; retained while pending", snapshot.pool_tracked);
        try sample(writer, "fail2zig_pool_banned", .gauge, "Banned subjects in the last completed sample; retained while pending", snapshot.pool_banned);
        if (snapshot.pool_sample_as_of_us) |as_of| {
            try family(writer, "fail2zig_pool_sample_as_of_seconds", .gauge, "Processing-clock time of the completed retry pool sample");
            const magnitude = @abs(as_of);
            try writer.print("fail2zig_pool_sample_as_of_seconds {s}{d}.{d:0>6}\n", .{ if (as_of < 0) "-" else "", magnitude / std.time.us_per_s, magnitude % std.time.us_per_s });
        }
    }
    if (snapshot.pool_sample_available) {
        try sample(writer, "fail2zig_pool_tracking_limit", .gauge, "Tracking pool bound", snapshot.pool_tracking_limit);
        try sample(writer, "fail2zig_pool_ban_limit", .gauge, "Ban pool bound", snapshot.pool_ban_limit);
    }

    const jails = snapshot.perJail();
    inline for (jail_series) |series| {
        try family(writer, series.name, series.kind, series.help);
        for (jails) |*jail| {
            try writer.print("{s}{{jail=\"", .{series.name});
            try writeLabelValue(writer, jail.name());
            try writer.print("\"}} {d}\n", .{@field(jail, @tagName(series.field))});
        }
    }
}
