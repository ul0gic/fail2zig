// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Native admission of event time. Rejection is a durable record disposition,
//! not an acknowledgment by itself. Callers commit its counters and cursor
//! together, then publish health. No receipt-time fallback for timestamped input.
const std = @import("std");
const time = @import("native_time.zig");

/// Include this version in native source configuration/checkpoint bindings.
pub const version: u16 = 2;
pub const future_tolerance_us: i64 = 60 * 1_000_000;
pub const Policy = enum { timestamped, undated };

/// Bind effective source configuration to the native time semantics. The parent
/// must include extraction/codec/context options; receipt/processing clocks are
/// per-occurrence values and intentionally do not change this identity.
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
    /// Effective detection time; original remains available for diagnosis.
    timestamp: time.Timestamp,
    origin: Origin,
    original: ?time.Timestamp,
    receipt: time.Timestamp,
    /// Present only when native syslog inference selected the original year.
    inferred_year: ?u16 = null,
};
pub const Rejection = struct {
    reason: Reason,
    original: ?time.Timestamp = null,
    receipt: ?time.Timestamp = null,
    inferred_year: ?u16 = null,
};
pub const Result = union(enum) {
    eligible: Evidence,
    obsolete: Evidence,
    rejected: Rejection,

    pub fn disposition(self: Result) []const u8 {
        return switch (self) {
            .eligible => |value| switch (value.origin) {
                .event => "time-eligible-event",
                .receipt => "time-eligible-receipt",
                .clock_adjusted => "time-eligible-clock-adjusted",
            },
            .obsolete => |value| switch (value.origin) {
                .event => "time-obsolete-event",
                .receipt => "time-obsolete-receipt",
                .clock_adjusted => "time-obsolete-clock-adjusted",
            },
            .rejected => |value| switch (value.reason) {
                .missing => "time-rejected-missing",
                .malformed => "time-rejected-malformed",
                .out_of_range => "time-rejected-range",
                .unsupported_precision => "time-rejected-precision",
                .future => "time-rejected-future",
            },
        };
    }
};

/// The source extractor distinguishes absent/empty fields from malformed ones.
/// Configuration/context failures must not silently discard an entire source.
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

/// receipt is supplied by the ingestion owner, not sampled here. Retries of an
/// already observed occurrence must retain that observation time. Source capture
/// and restart provenance belong to the native session/coordinator integration.
pub fn evaluate(policy: Policy, input: Input, receipt: ?time.Timestamp, now: time.Timestamp, window_us: i64) !Result {
    if (window_us < 0) return error.InvalidWindow;
    if (policy == .timestamped and input == .rejected) return .{ .rejected = .{ .reason = input.rejected } };
    // Every timed record needs its original receipt boundary. Comparing future
    // time only against a later retry clock would eventually admit bad dates.
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
        // observed <= now and effective <= observed were checked above.
        .future => unreachable,
    };
}

/// Values fit nonnegative SQLite INTEGERs. Counter staging is allocation-free
/// and cannot mutate the committed owner on failure. Baselines are not records.
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

    /// Classification-only adapters need no lossy timestamp conversion to count
    /// their outcome. Receipt origin is meaningful only for dated evidence.
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

/// One owner per source/jail generation. The coordinator supplies monotonic ms
/// and routes notices to its logger. No input text, database writes or allocations
/// are needed to read health or emit a deferred warning during idle periods.
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

    /// Only call after durable publication with previously validated counters.
    /// A failed transaction must leave both these counters and notices unchanged.
    pub fn publish(self: *Health, committed: Counters) void {
        self.committed = committed;
    }

    pub fn snapshot(self: *const Health) Counters {
        return self.committed;
    }

    /// First new rejection warns immediately; subsequent ones aggregate for at
    /// least 60 seconds. Lifetime counters stay visible even after a notice.
    /// A reversed monotonic sample cannot trigger an early warning or underflow.
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

test "time admission: missing and malformed have no receipt fallback or evidence" {
    const now = time.Timestamp{ .us = 1_000_000_000 };
    for ([_]?[]const u8{ null, "", "not-a-date", "2026-02-30T00:00:00Z" }) |field| {
        const input = try parseField(.iso8601, field, .{});
        const result = try evaluate(.timestamped, input, now, now, 600_000_000);
        try std.testing.expect(result == .rejected);
        const counters = try (Counters{}).advanced(result);
        try std.testing.expectEqual(@as(u64, 1), counters.missing + counters.malformed);
        try std.testing.expectEqual(@as(u64, 0), counters.eligible + counters.receipt);
    }
    try std.testing.expectEqual(Reason.out_of_range, (try parseField(.epoch_seconds, "9223372036854.775808", .{})).rejected);
    try std.testing.expectEqual(Reason.unsupported_precision, (try parseField(.epoch_seconds, "1.0000001", .{})).rejected);
    try std.testing.expectError(error.SourceTimeContextRequired, parseField(.syslog, "Jan  1 00:00:00", .{}));
    try std.testing.expectError(error.SourceTimeContextRequired, parseField(.iso8601, "2026-01-01T00:00:00", .{}));
    try std.testing.expectError(error.InvalidWindow, evaluate(.timestamped, .{ .rejected = .missing }, now, now, -1));
}

test "time admission: explicit undated receipt stays fixed across delayed retries" {
    const receipt = time.Timestamp{ .us = 500_000_000 };
    const input = Input{ .rejected = .missing };
    const initial = try evaluate(.undated, input, receipt, .{ .us = 1_000_000_000 }, 600_000_000);
    try std.testing.expectEqual(Origin.receipt, initial.eligible.origin);
    try std.testing.expectEqual(receipt.us, initial.eligible.timestamp.us);
    const retried = try evaluate(.undated, input, receipt, .{ .us = 1_200_000_000 }, 600_000_000);
    try std.testing.expectEqual(receipt.us, retried.obsolete.timestamp.us);
    try std.testing.expectError(error.MissingReceiptTime, evaluate(.undated, input, null, receipt, 0));
    try std.testing.expectEqual(Origin.clock_adjusted, (try evaluate(.timestamped, .{ .parsed = .{ .us = receipt.us + 1 } }, receipt, receipt, 0)).eligible.origin);
    const exact = try evaluate(.timestamped, .{ .parsed = .{ .us = 400_000_000 } }, .{ .us = 1_000_000_000 }, .{ .us = 1_000_000_000 }, 600_000_000);
    try std.testing.expectEqual(Origin.event, exact.eligible.origin);
}

test "time admission: counters reject overflow and inconsistent restored values" {
    const counters = Counters{ .eligible = std.math.maxInt(i64) };
    try std.testing.expectError(error.TimeCounterLimit, counters.advanced(.{ .rejected = .{ .reason = .missing } }));
    try std.testing.expectEqual(@as(u64, std.math.maxInt(i64)), counters.eligible);
    try std.testing.expectError(error.InvalidTimeCounters, (Counters{ .receipt = 1 }).validate());
    try std.testing.expectError(error.TimeCounterLimit, (Counters{ .missing = std.math.maxInt(u64) }).validate());
}

test "time admission: warnings aggregate committed rejections and remain readable without storage" {
    var health = try Health.init(.{});
    const missing = try health.snapshot().advanced(.{ .rejected = .{ .reason = .missing } });
    try std.testing.expect(health.nextNotice(0) == null); // preparation is not publication
    health.publish(missing);
    try std.testing.expectEqual(@as(u64, 1), health.nextNotice(0).?.missing_since_notice);
    health.publish(try health.snapshot().advanced(.{ .rejected = .{ .reason = .malformed } }));
    try std.testing.expect(health.nextNotice(59_999) == null);
    try std.testing.expectEqual(@as(u64, 1), health.nextNotice(60_000).?.malformed_since_notice);
    try std.testing.expect(health.nextNotice(120_000) == null);
    health.publish(try health.snapshot().advanced(.{ .rejected = .{ .reason = .missing } }));
    try std.testing.expect(health.nextNotice(1) == null);
    try std.testing.expectEqual(@as(u64, 1), health.nextNotice(120_000).?.missing_since_notice);
    try std.testing.expectEqual(@as(u64, 2), health.snapshot().missing);
    var restored = try Health.init(health.snapshot());
    try std.testing.expectEqualDeep(health.snapshot(), restored.snapshot());
    try std.testing.expect(restored.nextNotice(0) == null); // no replayed rejection event
}

test "future time: inclusive tolerance preserves original and effective timestamps exactly" {
    // Include values beyond binary64 integer precision and both signed extremes.
    for ([_]i64{ std.math.minInt(i64), -1_000_000_000, 1_000_000_000, 9007199254740993, std.math.maxInt(i64) - future_tolerance_us - 1 }) |base| {
        const receipt = time.Timestamp{ .us = base };
        for ([_]i64{ 0, 1, future_tolerance_us - 1, future_tolerance_us, future_tolerance_us + 1 }) |delta| {
            const original = time.Timestamp{ .us = base + delta };
            const result = try evaluate(.timestamped, .{ .parsed = original }, receipt, receipt, 0);
            if (delta > future_tolerance_us) {
                try std.testing.expectEqual(Reason.future, result.rejected.reason);
                try std.testing.expectEqual(original.us, result.rejected.original.?.us);
                try std.testing.expectEqual(receipt.us, result.rejected.receipt.?.us);
                try std.testing.expectEqualStrings("time-rejected-future", result.disposition());
            } else {
                try std.testing.expectEqual(receipt.us, result.eligible.timestamp.us);
                try std.testing.expectEqual(original.us, result.eligible.original.?.us);
                try std.testing.expectEqual(receipt.us, result.eligible.receipt.us);
                try std.testing.expectEqual(if (delta == 0) Origin.event else Origin.clock_adjusted, result.eligible.origin);
            }
        }
    }
    const widest = try evaluate(.timestamped, .{ .parsed = .{ .us = std.math.maxInt(i64) } }, .{ .us = std.math.minInt(i64) }, .{ .us = std.math.maxInt(i64) }, 0);
    try std.testing.expectEqual(Reason.future, widest.rejected.reason);
}

test "future time: retry clocks cannot extend the window or admit an excessive future date" {
    const receipt = time.Timestamp{ .us = 1_000_000_000 };
    const original = time.Timestamp{ .us = receipt.us + future_tolerance_us };
    const first = try evaluate(.timestamped, .{ .parsed = original }, receipt, receipt, 600_000_000);
    const endpoint = try evaluate(.timestamped, .{ .parsed = original }, receipt, .{ .us = receipt.us + 600_000_000 }, 600_000_000);
    try std.testing.expectEqualDeep(first, endpoint);
    const expired = try evaluate(.timestamped, .{ .parsed = original }, receipt, .{ .us = receipt.us + 600_000_001 }, 600_000_000);
    try std.testing.expectEqualDeep(first.eligible, expired.obsolete);
    try std.testing.expectEqualStrings("time-obsolete-clock-adjusted", expired.disposition());
    const too_far = time.Timestamp{ .us = original.us + 1 };
    const rejected = try evaluate(.timestamped, .{ .parsed = too_far }, receipt, receipt, 600_000_000);
    const later = try evaluate(.timestamped, .{ .parsed = too_far }, receipt, .{ .us = receipt.us + 1000_000_000 }, 600_000_000);
    try std.testing.expectEqualDeep(rejected, later);
    try std.testing.expectEqual(Reason.future, later.rejected.reason);
    try std.testing.expectError(error.MissingReceiptTime, evaluate(.timestamped, .{ .parsed = receipt }, null, receipt, 0));
    try std.testing.expectError(error.ReceiptClockReversed, evaluate(.timestamped, .{ .parsed = receipt }, receipt, .{ .us = receipt.us - 1 }, 0));
    try std.testing.expectError(error.ReceiptClockReversed, evaluate(.undated, .{ .rejected = .missing }, receipt, .{ .us = receipt.us - 1 }, 0));
}

test "future time: adjusted and rejected counters remain distinct and warnings wait for publication" {
    const receipt = time.Timestamp{ .us = 1000_000_000 };
    const adjusted = try evaluate(.timestamped, .{ .parsed = .{ .us = receipt.us + 1 } }, receipt, receipt, 0);
    var counts = try (Counters{}).advanced(adjusted);
    try std.testing.expectEqualDeep(Counters{ .eligible = 1, .adjusted = 1 }, counts);
    const rejected = try evaluate(.timestamped, .{ .parsed = .{ .us = receipt.us + future_tolerance_us + 1 } }, receipt, receipt, 0);
    var health = try Health.init(counts);
    counts = try counts.advanced(rejected);
    try std.testing.expect(health.nextNotice(0) == null);
    health.publish(counts);
    const notice = health.nextNotice(0).?;
    try std.testing.expectEqual(@as(u64, 1), notice.future_since_notice);
    try std.testing.expectEqual(@as(u64, 0), notice.missing_since_notice + notice.malformed_since_notice);
    health.publish(try counts.advanced(rejected));
    try std.testing.expect(health.nextNotice(59_999) == null);
    try std.testing.expectEqual(@as(u64, 1), health.nextNotice(60_000).?.future_since_notice);
    var restored = try Health.init(health.snapshot());
    try std.testing.expect(restored.nextNotice(0) == null);
    try std.testing.expectEqual(@as(u64, 2), restored.snapshot().future);
    try std.testing.expectError(error.InvalidTimeCounters, (Counters{ .eligible = 1, .receipt = 1, .adjusted = 1 }).validate());
    try std.testing.expectError(error.InvalidTimeCounters, (Counters{}).counted(.future, .clock_adjusted));
    try std.testing.expectError(error.TimeCounterLimit, (Counters{ .future = std.math.maxInt(i64) }).advanced(adjusted));
}
