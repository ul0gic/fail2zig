// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const build_options = @import("build_options");
const native_time = @import("native_time.zig");

pub const Clock = if (build_options.diag) VirtualClock else SystemClock;

pub const SystemClock = struct {
    timer: std.time.Timer,

    pub fn init() error{TimerUnsupported}!SystemClock {
        return .{ .timer = try std.time.Timer.start() };
    }
    pub inline fn wallUs(_: *SystemClock) i64 {
        return std.time.microTimestamp();
    }
    pub inline fn wallS(_: *SystemClock) i64 {
        return std.time.timestamp();
    }
    pub inline fn monotonicNs(self: *SystemClock) u64 {
        return self.timer.read();
    }
    pub inline fn monotonicMs(self: *SystemClock) u64 {
        return self.timer.read() / std.time.ns_per_ms;
    }
    pub inline fn rate(_: *SystemClock) u32 {
        return 1;
    }
};

pub const VirtualClock = struct {
    mutex: std.Thread.Mutex = .{},
    origin_real_ns: u64,
    origin_wall_us: i64,
    rate_value: u32,
    offset_ns: u64 = 0,
    last_real_ns: u64,
    regression_count: u64 = 0,
    origin: Origin,

    pub const max_rate: u32 = 1000;
    pub const max_advance_us: u64 = 366 * std.time.us_per_day;
    pub const Origin = enum { real, floor };
    pub const Mode = enum { real, accelerated, step };
    pub const Snapshot = struct { mode: Mode, rate: u32, wall_us: i64, monotonic_ns: u64, real_wall_us: i64, regressions: u64 };
    pub const InitError = error{ TimerUnsupported, InvalidDiagClockRate, InvalidDiagClockOrigin };

    pub fn init() InitError!VirtualClock {
        const real = realNs() orelse return error.TimerUnsupported;
        const selected_rate: u32 = if (std.posix.getenv("F2Z_DIAG_CLOCK_RATE")) |text| std.fmt.parseInt(u32, text, 10) catch return error.InvalidDiagClockRate else 1;
        if (selected_rate > max_rate) return error.InvalidDiagClockRate;
        const origin_text = std.posix.getenv("F2Z_DIAG_CLOCK_ORIGIN") orelse "real";
        const origin = std.meta.stringToEnum(Origin, origin_text) orelse return error.InvalidDiagClockOrigin;
        return .{ .origin_real_ns = real, .origin_wall_us = std.time.microTimestamp(), .rate_value = selected_rate, .last_real_ns = real, .origin = origin };
    }

    pub fn raiseOriginTo(self: *VirtualClock, floor_us: i64) i64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const current = self.wallLocked(self.sampleLocked());
        if (floor_us <= current) return current;
        self.origin_wall_us +|= floor_us - current;
        return floor_us;
    }
    pub fn wallUs(self: *VirtualClock) i64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.wallLocked(self.sampleLocked());
    }
    pub fn wallS(self: *VirtualClock) i64 {
        return @divFloor(self.wallUs(), std.time.us_per_s);
    }
    pub fn monotonicNs(self: *VirtualClock) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.sampleLocked();
    }
    pub fn monotonicMs(self: *VirtualClock) u64 {
        return self.monotonicNs() / std.time.ns_per_ms;
    }
    pub fn rate(self: *VirtualClock) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.rate_value;
    }
    pub fn mode(self: *VirtualClock) Mode {
        return modeFor(self.rate());
    }
    pub fn loopWaitNs(self: *VirtualClock, real_wait_ns: u64) u64 {
        const current = self.rate();
        if (current <= 1) return real_wait_ns;
        return @max(real_wait_ns / current, std.time.ns_per_ms);
    }
    pub fn setRate(self: *VirtualClock, next: u32) error{OutOfRange}!void {
        if (next > max_rate) return error.OutOfRange;
        self.mutex.lock();
        defer self.mutex.unlock();
        self.offset_ns = self.sampleLocked();
        self.origin_real_ns = self.last_real_ns;
        self.rate_value = next;
    }
    pub fn advance(self: *VirtualClock, us: u64) error{ NotStepMode, OutOfRange }!void {
        if (us == 0 or us > max_advance_us) return error.OutOfRange;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.rate_value != 0) return error.NotStepMode;
        self.offset_ns = self.sampleLocked() +| us * std.time.ns_per_us;
        self.origin_real_ns = self.last_real_ns;
    }
    pub fn snapshot(self: *VirtualClock) Snapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        const virtual = self.sampleLocked();
        return .{ .mode = modeFor(self.rate_value), .rate = self.rate_value, .wall_us = self.wallLocked(virtual), .monotonic_ns = virtual, .real_wall_us = std.time.microTimestamp(), .regressions = self.regression_count };
    }

    fn modeFor(value: u32) Mode {
        return switch (value) {
            0 => .step,
            1 => .real,
            else => .accelerated,
        };
    }
    fn wallLocked(self: *const VirtualClock, virtual_ns: u64) i64 {
        return self.origin_wall_us +| @as(i64, @intCast(virtual_ns / std.time.ns_per_us));
    }
    fn sampleLocked(self: *VirtualClock) u64 {
        if (realNs()) |real| {
            if (real >= self.last_real_ns) self.last_real_ns = real else self.regression_count +|= 1;
        } else self.regression_count +|= 1;
        return self.offset_ns +| (self.last_real_ns - self.origin_real_ns) *| self.rate_value;
    }
    fn realNs() ?u64 {
        const now = std.time.Instant.now() catch return null;
        const seconds = std.math.cast(u64, now.timestamp.sec) orelse return null;
        const nanos = std.math.cast(u64, now.timestamp.nsec) orelse return null;
        return seconds *| std.time.ns_per_s +| nanos;
    }
};

pub fn wallRead(context: ?*anyopaque) i64 {
    return fromContext(context).wallUs();
}
pub fn wallTimestamp(context: ?*anyopaque) anyerror!native_time.Timestamp {
    return .{ .us = fromContext(context).wallUs() };
}
pub fn monotonicMsRead(context: ?*anyopaque) u64 {
    return fromContext(context).monotonicMs();
}
pub fn monotonicNsRead(context: ?*anyopaque) ?u64 {
    return fromContext(context).monotonicNs();
}
fn fromContext(context: ?*anyopaque) *Clock {
    return @ptrCast(@alignCast(context.?));
}
