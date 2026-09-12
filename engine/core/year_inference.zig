// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Explicit classic-syslog year inference. Only fixed UTC offsets are admitted;
//! no local timezone, mutable previous date, allocation or retry clock is used.
const std = @import("std");
const time = @import("native_time.zig");
pub const version: u16 = 1;
pub const Inferred = struct { timestamp: time.Timestamp, year: u16 };

/// Find the local calendar year with bounded binary search over admitted years.
/// Parsing Jan 1 reuses the checked calendar conversion; wider offset arithmetic
/// keeps extreme receipt values from overflowing before range rejection.
pub fn receiptYear(receipt: time.Timestamp, offset_seconds: i32) !u16 {
    if (offset_seconds < -86340 or offset_seconds > 86340 or @mod(offset_seconds, 60) != 0) return error.InvalidTimeContext;
    const local = @as(i128, receipt.us) + @as(i128, offset_seconds) * 1_000_000;
    if (local < -62135596800000000 or local > 253402300799999999) return error.TimeOutOfRange;
    var low: u16 = 1;
    var high: u16 = 9999;
    while (low < high) {
        const middle = low + (high - low + 1) / 2;
        const start = try time.parse(.syslog, "Jan  1 00:00:00", .{ .year = middle, .offset_seconds = 0 });
        if (start.us <= local) low = middle else high = middle - 1;
    }
    return low;
}

/// Select the closest valid candidate among the receipt's local year and its
/// neighbors. Admission runs afterwards: a future rejection cannot cause this
/// selection to fall back to a more convenient year. Equal distance is rejected.
pub fn infer(field: []const u8, receipt: time.Timestamp, offset_seconds: i32) !Inferred {
    const reference = try receiptYear(receipt, offset_seconds);
    // A leap year validates syntax/calendar independently of candidate years.
    _ = try time.parse(.syslog, field, .{ .year = 2000, .offset_seconds = offset_seconds });
    var best: ?Inferred = null;
    var distance: u128 = std.math.maxInt(u128);
    var tied = false;
    const first = if (reference > 1) reference - 1 else reference;
    const last = if (reference < 9999) reference + 1 else reference;
    var year = first;
    while (true) {
        const candidate: ?time.Timestamp = time.parse(.syslog, field, .{ .year = year, .offset_seconds = offset_seconds }) catch |err| switch (err) {
            error.InvalidTimestamp => null, // Feb 29 in a non-leap candidate.
            else => return err,
        };
        if (candidate) |timestamp| {
            const delta = @abs(@as(i128, timestamp.us) - receipt.us);
            if (delta < distance) {
                best = .{ .timestamp = timestamp, .year = year };
                distance = delta;
                tied = false;
            } else if (delta == distance) tied = true;
        }
        if (year == last) break;
        year += 1;
    }
    if (tied) return error.AmbiguousYear;
    return best orelse error.InvalidTimestamp;
}

fn iso(field: []const u8) !time.Timestamp {
    return time.parse(.iso8601, field, .{});
}

test "year inference: nearest local year handles New Year offsets leap days and past centuries" {
    const Case = struct { receipt: []const u8, field: []const u8, offset: i32 = 0, expected: []const u8, year: u16 };
    for ([_]Case{
        .{ .receipt = "2026-01-01T00:00:10Z", .field = "Dec 31 23:59:59", .expected = "2025-12-31T23:59:59Z", .year = 2025 },
        .{ .receipt = "2025-12-31T23:59:50Z", .field = "Jan  1 00:00:00", .expected = "2026-01-01T00:00:00Z", .year = 2026 },
        .{ .receipt = "2025-12-31T23:45:00Z", .field = "Jan  1 05:15:00", .offset = 19800, .expected = "2025-12-31T23:45:00Z", .year = 2026 },
        .{ .receipt = "2026-01-01T02:00:00Z", .field = "Dec 31 21:00:00", .offset = -18000, .expected = "2026-01-01T02:00:00Z", .year = 2025 },
        .{ .receipt = "2025-03-01T00:00:00Z", .field = "Feb 29 00:00:00", .expected = "2024-02-29T00:00:00Z", .year = 2024 },
        .{ .receipt = "2000-03-01T00:00:00Z", .field = "Feb 29 00:00:00", .expected = "2000-02-29T00:00:00Z", .year = 2000 },
        .{ .receipt = "1969-12-31T23:59:59Z", .field = "Jan  1 00:00:00", .expected = "1970-01-01T00:00:00Z", .year = 1970 },
        .{ .receipt = "0001-01-01T00:00:00Z", .field = "Jan  1 00:00:00", .expected = "0001-01-01T00:00:00Z", .year = 1 },
        .{ .receipt = "9999-12-31T23:59:59Z", .field = "Dec 31 23:59:59", .expected = "9999-12-31T23:59:59Z", .year = 9999 },
    }) |case| {
        const value = try infer(case.field, try iso(case.receipt), case.offset);
        try std.testing.expectEqual(case.year, value.year);
        try std.testing.expectEqual((try iso(case.expected)).us, value.timestamp.us);
    }
}

test "year inference: ties invalid calendars and out of range receipts cannot invent a date" {
    try std.testing.expectError(error.AmbiguousYear, infer("Jan  1 00:00:00", try iso("2025-07-02T12:00:00Z"), 0));
    // One microsecond either side of the midpoint chooses the corresponding year.
    const middle = try iso("2025-07-02T12:00:00Z");
    try std.testing.expectEqual(@as(u16, 2025), (try infer("Jan  1 00:00:00", .{ .us = middle.us - 1 }, 0)).year);
    try std.testing.expectEqual(@as(u16, 2026), (try infer("Jan  1 00:00:00", .{ .us = middle.us + 1 }, 0)).year);
    for ([_][]const u8{ "", "Feb 30 00:00:00", "Apr 31 00:00:00", "Jan  1 24:00:00", "Jan  1 00:00:60", "jan  1 00:00:00", "Jan  1 00:00:00x" }) |bad|
        try std.testing.expectError(error.InvalidTimestamp, infer(bad, middle, 0));
    for ([_][]const u8{ "2026-03-01T00:00:00Z", "1900-03-01T00:00:00Z", "2100-03-01T00:00:00Z" }) |stamp|
        try std.testing.expectError(error.InvalidTimestamp, infer("Feb 29 00:00:00", try iso(stamp), 0));
    for ([_]i64{ std.math.minInt(i64), std.math.maxInt(i64) }) |stamp|
        try std.testing.expectError(error.TimeOutOfRange, infer("Jan  1 00:00:00", .{ .us = stamp }, 0));
    try std.testing.expectError(error.TimeOutOfRange, receiptYear(try iso("0001-01-01T00:00:00Z"), -60));
    try std.testing.expectError(error.TimeOutOfRange, receiptYear(try iso("9999-12-31T23:59:59Z"), 60));
    for ([_]i32{ -86400, 86400, 1 }) |offset|
        try std.testing.expectError(error.InvalidTimeContext, infer("Jan  1 00:00:00", middle, offset));
}

test "year inference: every admitted year boundary resolves without unsigned epoch assumptions" {
    for (1..10000) |year| {
        const y: u16 = @intCast(year);
        const start = try time.parse(.syslog, "Jan  1 00:00:00", .{ .year = y, .offset_seconds = 0 });
        try std.testing.expectEqual(y, try receiptYear(start, 0));
        if (year > 1) try std.testing.expectEqual(y - 1, try receiptYear(.{ .us = start.us - 1 }, 0));
    }
}
