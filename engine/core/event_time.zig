// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Source event-time normalization. No wall-clock reads or integer truncation of timestamps.
const std = @import("std");

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
pub const Disposition = enum { accepted, obsolete, undated };
pub const Result = struct {
    disposition: Disposition,
    raw: ?EventTime = null,
    effective: ?EventTime = null,
    stored: ?EventTime = null,
    origin: ?Origin = null,
    diagnostic: bool = false,
};
pub const Context = struct {
    last_date: ?EventTime = null,
    /// Replay explicitly opts out of findtime checks; startup uses restore semantics.
    pub fn normalize(self: *Context, input: Input, now: EventTime, window: f64, mode: Mode, check_findtime: bool) Error!Result {
        if (!std.math.isFinite(window) or window < 0) return error.InvalidWindow;
        _ = try EventTime.init(now.seconds);
        const check = check_findtime and mode != .replay;
        var result: Result = .{ .disposition = .accepted };
        var date: ?EventTime = null;
        switch (input) {
            .parsed => |value| {
                _ = try EventTime.init(value.seconds);
                date = value;
                self.last_date = value;
                result.raw = value;
                result.origin = .parsed;
            },
            .missing, .invalid, .optional_empty => {
                result.diagnostic = input == .invalid or input == .missing;
                if (self.last_date) |last| {
                    _ = try EventTime.init(last.seconds);
                    // Python's reference also tests truthiness: epoch zero is not reused.
                    if (last.seconds != 0 and last.seconds > now.seconds - 60) {
                        date = last;
                        result.origin = .recent_context;
                    }
                }
                if (date == null) {
                    if (input == .optional_empty) {
                        date = now;
                        result.origin = .optional_now;
                    } else if (check and mode == .live) {
                        date = now;
                        result.origin = if (input == .invalid) .invalid_now else .missing_now;
                    }
                }
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
    try std.testing.expectEqual(@as(f64, 1.125), replay.stored.?.seconds);
}
test "missing invalid and optional dates retain explicit provenance" {
    var context: Context = .{};
    const now = try EventTime.init(1000);
    try std.testing.expectEqual(Disposition.undated, (try context.normalize(.missing, now, 600, .startup, true)).disposition);
    const invalid = try context.normalize(.invalid, now, 600, .live, true);
    try std.testing.expect(invalid.diagnostic);
    try std.testing.expectEqual(Origin.invalid_now, invalid.origin.?);
    context.last_date = try EventTime.init(940);
    try std.testing.expectEqual(Disposition.undated, (try context.normalize(.missing, now, 600, .startup, true)).disposition);
    context.last_date = try EventTime.init(940.001);
    try std.testing.expectEqual(Origin.recent_context, (try context.normalize(.missing, now, 600, .startup, true)).origin.?);
    context.last_date = null;
    try std.testing.expectEqual(Origin.optional_now, (try context.normalize(.optional_empty, now, 600, .startup, true)).origin.?);
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
