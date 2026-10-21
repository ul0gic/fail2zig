// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const time = @import("native_time.zig");

pub const version: u16 = 2;
pub const future_tolerance_us: i64 = 60 * 1_000_000;
pub const Policy = enum { timestamped, undated };

pub fn binding(parent: [32]u8, policy: Policy, window_us: i64) ![32]u8 {
    if (window_us < 0) return error.InvalidWindow;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("fail2zig-source-time\x00");
    hash.update(&parent);
    var numbers: [18]u8 = undefined;
    std.mem.writeInt(u16, numbers[0..2], version, .little);
    std.mem.writeInt(i64, numbers[2..10], future_tolerance_us, .little);
    std.mem.writeInt(i64, numbers[10..18], window_us, .little);
    hash.update(&numbers);
    hash.update(@tagName(policy));
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}
pub const Reason = enum { missing, malformed, out_of_range, unsupported_precision, future };
pub const Input = union(enum) { parsed: time.Timestamp, rejected: Reason };
pub const Origin = enum { event, receipt, clock_adjusted };
pub const Evidence = struct {
    encoding_replaced: bool = false,
    timestamp: time.Timestamp,
    origin: Origin,
    original: ?time.Timestamp,
    receipt: time.Timestamp,
    inferred_year: ?u16 = null,
};
pub const Rejection = struct {
    encoding_replaced: bool = false,
    reason: Reason,
    original: ?time.Timestamp = null,
    receipt: ?time.Timestamp = null,
    inferred_year: ?u16 = null,
};
pub const Result = union(enum) {
    eligible: Evidence,
    obsolete: Evidence,
    rejected: Rejection,

    pub fn encodingReplaced(self: Result) bool {
        return switch (self) {
            inline else => |value| value.encoding_replaced,
        };
    }

    pub fn withEncodingReplacement(self: Result) Result {
        var result = self;
        switch (result) {
            inline else => |*value| value.encoding_replaced = true,
        }
        return result;
    }

    fn marked(self: Result, comptime value: []const u8) []const u8 {
        return if (self.encodingReplaced()) value ++ "-encoding-replaced" else value;
    }

    pub fn disposition(self: Result) []const u8 {
        return switch (self) {
            .eligible => |value| switch (value.origin) {
                .event => self.marked("time-eligible-event"),
                .receipt => self.marked("time-eligible-receipt"),
                .clock_adjusted => self.marked("time-eligible-clock-adjusted"),
            },
            .obsolete => |value| switch (value.origin) {
                .event => self.marked("time-obsolete-event"),
                .receipt => self.marked("time-obsolete-receipt"),
                .clock_adjusted => self.marked("time-obsolete-clock-adjusted"),
            },
            .rejected => |value| switch (value.reason) {
                .missing => self.marked("time-rejected-missing"),
                .malformed => self.marked("time-rejected-malformed"),
                .out_of_range => self.marked("time-rejected-range"),
                .unsupported_precision => self.marked("time-rejected-precision"),
                .future => self.marked("time-rejected-future"),
            },
        };
    }
};

pub fn parseField(format: time.Format, field: ?[]const u8, context: time.Context) !Input {
    const bytes = field orelse return .{ .rejected = .missing };
    if (bytes.len == 0) return .{ .rejected = .missing };
    const value = time.parse(format, bytes, context) catch |err| switch (err) {
        error.InvalidTimestamp => return .{ .rejected = .malformed },
        error.TimeOutOfRange => return .{ .rejected = .out_of_range },
        error.UnsupportedPrecision => return .{ .rejected = .unsupported_precision },
        error.MissingYear, error.MissingTimezone => return error.SourceTimeContextRequired,
    };
    return .{ .parsed = value };
}

pub fn evaluate(policy: Policy, input: Input, receipt: ?time.Timestamp, now: time.Timestamp, window_us: i64) !Result {
    if (window_us < 0) return error.InvalidWindow;
    if (policy == .timestamped and input == .rejected) return .{ .rejected = .{ .reason = input.rejected } };
    const observed = receipt orelse return error.MissingReceiptTime;
    if (observed.us > now.us) return error.ReceiptClockReversed;
    const evidence: Evidence = switch (policy) {
        .timestamped => switch (input) {
            .rejected => unreachable,
            .parsed => |timestamp| blk: {
                const ahead = @as(i128, timestamp.us) - observed.us;
                if (ahead > future_tolerance_us) return .{ .rejected = .{ .reason = .future, .original = timestamp, .receipt = observed } };
                break :blk .{
                    .timestamp = if (ahead > 0) observed else timestamp,
                    .origin = if (ahead > 0) .clock_adjusted else .event,
                    .original = timestamp,
                    .receipt = observed,
                };
            },
        },
        .undated => .{ .timestamp = observed, .origin = .receipt, .original = null, .receipt = observed },
    };
    return switch (try time.age(evidence.timestamp, now, window_us)) {
        .eligible => .{ .eligible = evidence },
        .obsolete => .{ .obsolete = evidence },
        .future => unreachable,
    };
}

pub const Counters = struct {
    pub const Kind = enum { eligible, obsolete, missing, malformed, future };
    eligible: u64 = 0,
    obsolete: u64 = 0,
    missing: u64 = 0,
    malformed: u64 = 0,
    receipt: u64 = 0,
    adjusted: u64 = 0,
    future: u64 = 0,

    pub fn validate(self: Counters) !void {
        const valid = try add(self.eligible, self.obsolete);
        const rejected = try add(try add(self.missing, self.malformed), self.future);
        _ = try add(valid, rejected);
        if (try add(self.receipt, self.adjusted) > valid) return error.InvalidTimeCounters;
    }

    pub fn advanced(self: Counters, result: Result) !Counters {
        return switch (result) {
            .eligible => |evidence| self.counted(.eligible, evidence.origin),
            .obsolete => |evidence| self.counted(.obsolete, evidence.origin),
            .rejected => |value| self.counted(switch (value.reason) {
                .missing => .missing,
                .future => .future,
                else => .malformed,
            }, .event),
        };
    }

    pub fn counted(self: Counters, kind: Kind, origin: Origin) !Counters {
        try self.validate();
        if (origin != .event and kind != .eligible and kind != .obsolete) return error.InvalidTimeCounters;
        var next = self;
        switch (kind) {
            .eligible => next.eligible = try add(next.eligible, 1),
            .obsolete => next.obsolete = try add(next.obsolete, 1),
            .missing => next.missing = try add(next.missing, 1),
            .malformed => next.malformed = try add(next.malformed, 1),
            .future => next.future = try add(next.future, 1),
        }
        if (origin == .receipt) next.receipt = try add(next.receipt, 1);
        if (origin == .clock_adjusted) next.adjusted = try add(next.adjusted, 1);
        try next.validate();
        return next;
    }

    fn add(a: u64, b: u64) !u64 {
        const value = std.math.add(u64, a, b) catch return error.TimeCounterLimit;
        if (value > std.math.maxInt(i64)) return error.TimeCounterLimit;
        return value;
    }
};

pub const Notice = struct {
    totals: Counters,
    missing_since_notice: u64,
    malformed_since_notice: u64,
    future_since_notice: u64,
};

pub const Health = struct {
    committed: Counters = .{},
    reported_missing: u64 = 0,
    reported_malformed: u64 = 0,
    reported_future: u64 = 0,
    last_notice_ms: ?u64 = null,

    pub fn init(restored: Counters) !Health {
        try restored.validate();
        return .{ .committed = restored, .reported_missing = restored.missing, .reported_malformed = restored.malformed, .reported_future = restored.future };
    }

    pub fn publish(self: *Health, committed: Counters) void {
        self.committed = committed;
    }

    pub fn snapshot(self: *const Health) Counters {
        return self.committed;
    }

    pub fn nextNotice(self: *Health, now_ms: u64) ?Notice {
        const missing = self.committed.missing -| self.reported_missing;
        const malformed = self.committed.malformed -| self.reported_malformed;
        const future = self.committed.future -| self.reported_future;
        if (missing == 0 and malformed == 0 and future == 0) return null;
        if (self.last_notice_ms) |last| if (now_ms < last or now_ms - last < 60_000) return null;
        const notice = Notice{ .totals = self.committed, .missing_since_notice = missing, .malformed_since_notice = malformed, .future_since_notice = future };
        self.reported_missing = self.committed.missing;
        self.reported_malformed = self.committed.malformed;
        self.reported_future = self.committed.future;
        self.last_notice_ms = now_ms;
        return notice;
    }
};
