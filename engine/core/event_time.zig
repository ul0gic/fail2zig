// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Source event-time normalization. No wall-clock reads or integer truncation of timestamps.
const std = @import("std");

/// Bind this policy change into source/checkpoint configuration fingerprints.
pub const policy_version: u16 = 2;

pub const Error = error{ NonFiniteTime, InvalidWindow };
pub const EventTime = struct {
    seconds: f64,
    pub fn init(seconds: f64) Error!EventTime {
        if (!std.math.isFinite(seconds)) return error.NonFiniteTime;
        return .{ .seconds = seconds };
    }
    pub fn bits(self: EventTime) u64 {
        return @bitCast(self.seconds);
    }
    pub fn fromBits(value: u64) Error!EventTime {
        return init(@bitCast(value));
    }
};
pub const Mode = enum { startup, live, replay };
pub const Input = union(enum) {
    parsed: EventTime,
    missing,
    invalid,
    /// A configured date pattern matched an empty timestamp, unlike no match.
    optional_empty,
};
pub const Origin = enum { parsed, recent_context, optional_now, missing_now, invalid_now, live_correction };
pub const Disposition = enum { accepted, obsolete, undated, rejected };
pub const Result = struct {
    disposition: Disposition,
    raw: ?EventTime = null,
    effective: ?EventTime = null,
    stored: ?EventTime = null,
    origin: ?Origin = null,
    diagnostic: bool = false,
    rejection: ?@import("source_time_policy.zig").Reason = null,
};
pub const Context = struct {
    last_date: ?EventTime = null,
    /// Valid past event times use the retry window in every mode. The remaining
    /// legacy future-time branches await their native policy conversion.
    pub fn normalize(self: *Context, input: Input, now: EventTime, window: f64, mode: Mode, check_findtime: bool) Error!Result {
        if (!std.math.isFinite(window) or window < 0) return error.InvalidWindow;
        _ = try EventTime.init(now.seconds);
        const check = check_findtime and mode != .replay;
        var result: Result = .{ .disposition = .accepted };
        var date: ?EventTime = null;
        switch (input) {
            .parsed => |value| {
                _ = try EventTime.init(value.seconds);
                if (value.seconds <= now.seconds) {
                    const oldest = now.seconds - window;
                    if (!std.math.isFinite(oldest)) return error.NonFiniteTime;
                    const obsolete = value.seconds < oldest;
                    self.last_date = value;
                    // Receipt time, startup/live mode and legacy replay switches
                    // cannot turn expired evidence into a fresh attempt.
                    return .{
                        .disposition = if (obsolete) .obsolete else .accepted,
                        .raw = value,
                        .effective = value,
                        .stored = if (obsolete) null else value,
                        .origin = .parsed,
                    };
                }
                date = value;
                self.last_date = value;
                result.raw = value;
                result.origin = .parsed;
            },
            .missing, .invalid, .optional_empty => {
                // This adapter describes timestamped input. Optional-empty is
                // still missing time, not authorization for an undated source.
                // No borrowing another record's date or receipt-time fallback.
                return .{ .disposition = .rejected, .diagnostic = true, .rejection = if (input == .invalid) .malformed else .missing };
            },
        }
        if (date == null) {
            result.disposition = .undated;
            return result;
        }
        if (check) {
            if (mode == .live) {
                // Python int(date-now) also rejects a nonfinite intermediate,
                // even when both input timestamps are individually finite.
                const delta = date.?.seconds - now.seconds;
                if (!std.math.isFinite(delta)) return error.NonFiniteTime;
                // Truncate only the deviation, matching int(date-now), never the date.
                if (@abs(@trunc(delta)) > 60) {
                    date = now;
                    self.last_date = now;
                    result.origin = .live_correction;
                    result.diagnostic = true;
                }
            } else if (date.?.seconds < now.seconds - window) {
                result.disposition = .obsolete;
                result.effective = date;
                return result;
            }
        }
        result.effective = date;
        result.stored = if (check and date.?.seconds > now.seconds) now else date;
        return result;
    }
};

test "source event time preserves fractional boundaries and future storage clamp" {
    var context: Context = .{};
    const now = try EventTime.init(1000.25);
    const equality = try context.normalize(.{ .parsed = try EventTime.init(400.25) }, now, 600, .startup, true);
    try std.testing.expectEqual(Disposition.accepted, equality.disposition);
    const old = try context.normalize(.{ .parsed = try EventTime.init(400.249) }, now, 600, .startup, true);
    try std.testing.expectEqual(Disposition.obsolete, old.disposition);
    const inside = try context.normalize(.{ .parsed = try EventTime.init(1061.249) }, now, 600, .live, true);
    try std.testing.expectEqual(@as(f64, 1061.249), inside.effective.?.seconds);
    try std.testing.expectEqual(now.seconds, inside.stored.?.seconds);
    const corrected = try context.normalize(.{ .parsed = try EventTime.init(1061.25) }, now, 600, .live, true);
    try std.testing.expectEqual(Origin.live_correction, corrected.origin.?);
    try std.testing.expectEqual(now.seconds, corrected.effective.?.seconds);
    const replay = try context.normalize(.{ .parsed = try EventTime.init(1.125) }, now, 600, .replay, true);
    try std.testing.expectEqual(Disposition.obsolete, replay.disposition);
    try std.testing.expectEqual(@as(f64, 1.125), replay.effective.?.seconds);
    try std.testing.expect(replay.stored == null);
}

test "event age: past timestamps remain authoritative across all modes and legacy switches" {
    for ([_]Mode{ .startup, .live, .replay }) |mode| {
        for ([_]bool{ true, false }) |check_findtime| {
            for ([_]f64{ 399.999, 400, 700.125, 939.5, 1000 }) |seconds| {
                var context = Context{};
                const result = try context.normalize(.{ .parsed = try EventTime.init(seconds) }, try EventTime.init(1000), 600, mode, check_findtime);
                try std.testing.expectEqual(if (seconds < 400) Disposition.obsolete else .accepted, result.disposition);
                try std.testing.expectEqual(seconds, result.raw.?.seconds);
                try std.testing.expectEqual(seconds, result.effective.?.seconds);
                try std.testing.expectEqual(seconds, context.last_date.?.seconds);
                try std.testing.expectEqual(Origin.parsed, result.origin.?);
                try std.testing.expect(!result.diagnostic);
                if (seconds < 400) try std.testing.expect(result.stored == null) else try std.testing.expectEqual(seconds, result.stored.?.seconds);
            }
        }
    }
}

test "event age: zero window and epoch zero are explicit and invalid arithmetic cannot mutate context" {
    var context = Context{};
    const zero = try context.normalize(.{ .parsed = try EventTime.init(0) }, try EventTime.init(600), 600, .live, true);
    try std.testing.expectEqual(Disposition.accepted, zero.disposition);
    try std.testing.expectEqual(@as(f64, 0), zero.stored.?.seconds);
    const current = try context.normalize(.{ .parsed = try EventTime.init(600) }, try EventTime.init(600), 0, .live, true);
    try std.testing.expectEqual(Disposition.accepted, current.disposition);
    const old = try context.normalize(.{ .parsed = try EventTime.init(599.999) }, try EventTime.init(600), 0, .live, true);
    try std.testing.expectEqual(Disposition.obsolete, old.disposition);
    const previous = context.last_date.?.bits();
    try std.testing.expectError(error.NonFiniteTime, context.normalize(.{ .parsed = try EventTime.init(-1.0e308) }, try EventTime.init(-1.0e308), 1.0e308, .live, true));
    try std.testing.expectEqual(previous, context.last_date.?.bits());
    try std.testing.expectError(error.InvalidWindow, context.normalize(.{ .parsed = try EventTime.init(1) }, try EventTime.init(2), -1, .live, true));
    try std.testing.expectEqual(previous, context.last_date.?.bits());
}
test "time admission: staged adapter cannot borrow dates or rejuvenate rejected input" {
    for ([_]Mode{ .startup, .live, .replay }) |mode| {
        for ([_]bool{ true, false }) |check| {
            for ([_]?EventTime{ null, .{ .seconds = 0 }, .{ .seconds = 999.5 } }) |last| {
                for ([_]Input{ .missing, .invalid, .optional_empty }) |input| {
                    var context = Context{ .last_date = last };
                    const result = try context.normalize(input, try EventTime.init(1000), 600, mode, check);
                    try std.testing.expectEqual(Disposition.rejected, result.disposition);
                    try std.testing.expectEqual(if (input == .invalid) @import("source_time_policy.zig").Reason.malformed else .missing, result.rejection.?);
                    try std.testing.expect(result.diagnostic);
                    try std.testing.expect(result.raw == null and result.effective == null and result.stored == null and result.origin == null);
                    try std.testing.expectEqualDeep(last, context.last_date);
                }
            }
        }
    }
}
test "event-time transport rejects nonfinite values and preserves bits" {
    for ([_]f64{ 0, -0.0, 1000.123456789, -1.5 }) |value| {
        const time = try EventTime.init(value);
        try std.testing.expectEqual(time.bits(), (try EventTime.fromBits(time.bits())).bits());
    }
    try std.testing.expectError(error.NonFiniteTime, EventTime.init(std.math.inf(f64)));
    try std.testing.expectError(error.NonFiniteTime, EventTime.init(std.math.nan(f64)));
}

test "live normalization rejects overflowed finite-input deviation" {
    var context: Context = .{};
    try std.testing.expectError(error.NonFiniteTime, context.normalize(.{ .parsed = try EventTime.init(1.0e308) }, try EventTime.init(-1.0e308), 600, .live, true));
}
