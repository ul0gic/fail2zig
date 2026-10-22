// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");

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
                return .{ .disposition = .rejected, .diagnostic = true, .rejection = if (input == .invalid) .malformed else .missing };
            },
        }
        if (date == null) {
            result.disposition = .undated;
            return result;
        }
        if (check) {
            if (mode == .live) {
                const delta = date.?.seconds - now.seconds;
                if (!std.math.isFinite(delta)) return error.NonFiniteTime;
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
