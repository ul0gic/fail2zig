// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Bounded timestamp values and field parsing. This layer never invents a year,
//! timezone or receipt time and does not decide how ingestion handles bad dates.
const std = @import("std");

pub const Error = error{ InvalidTimestamp, TimeOutOfRange, MissingYear, MissingTimezone, UnsupportedPrecision };
pub const Timestamp = struct {
    us: i64,

    pub fn fromSeconds(seconds: i64) Error!Timestamp {
        return .{ .us = std.math.mul(i64, seconds, 1_000_000) catch return error.TimeOutOfRange };
    }

    pub fn fromJournal(microseconds: u64) Error!Timestamp {
        return .{ .us = std.math.cast(i64, microseconds) orelse return error.TimeOutOfRange };
    }

    pub fn encode(self: Timestamp) [8]u8 {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(i64, &bytes, self.us, .little);
        return bytes;
    }

    pub fn decode(bytes: *const [8]u8) Timestamp {
        return .{ .us = std.mem.readInt(i64, bytes, .little) };
    }
};

pub const Format = enum { epoch_seconds, iso8601, syslog, common_log };
pub const Context = struct {
    year: ?u16 = null,
    offset_seconds: ?i32 = null,
};
pub const Age = enum { eligible, obsolete, future };

/// Inclusive past window; the caller must decide what to do with .future.
/// Wider intermediate arithmetic avoids overflow at signed epoch boundaries.
pub fn age(event: Timestamp, now: Timestamp, window_us: i64) error{InvalidWindow}!Age {
    if (window_us < 0) return error.InvalidWindow;
    if (event.us > now.us) return .future;
    return if (@as(i128, now.us) - event.us <= window_us) .eligible else .obsolete;
}

/// Parse one complete timestamp field, not an arbitrary regex or an unbounded
/// search through a message. Fractions must be exactly representable in µs.
pub fn parse(format: Format, field: []const u8, context: Context) Error!Timestamp {
    if (field.len == 0 or field.len > 64) return error.InvalidTimestamp;
    return switch (format) {
        .epoch_seconds => epoch(field),
        .iso8601 => iso(field, context),
        .syslog => syslog(field, context),
        .common_log => commonLog(field),
    };
}

fn number(bytes: []const u8) Error!i64 {
    if (bytes.len == 0) return error.InvalidTimestamp;
    var result: i64 = 0;
    for (bytes) |c| {
        if (c < '0' or c > '9') return error.InvalidTimestamp;
        result = std.math.mul(i64, result, 10) catch return error.TimeOutOfRange;
        result = std.math.add(i64, result, c - '0') catch return error.TimeOutOfRange;
    }
    return result;
}

fn fraction(bytes: []const u8) Error!i64 {
    if (bytes.len > 6) return error.UnsupportedPrecision;
    var value = try number(bytes);
    for (bytes.len..6) |_| value *= 10;
    return value;
}

fn epoch(field: []const u8) Error!Timestamp {
    const negative = field[0] == '-';
    const text = if (negative) field[1..] else field;
    const dot = std.mem.indexOfScalar(u8, text, '.') orelse text.len;
    const whole = try number(text[0..dot]);
    const part = if (dot < text.len) try fraction(text[dot + 1 ..]) else 0;
    var value = @as(i128, whole) * 1_000_000 + part;
    if (negative) value = -value;
    return .{ .us = std.math.cast(i64, value) orelse return error.TimeOutOfRange };
}

fn month(text: []const u8) Error!i64 {
    const names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    for (names, 1..) |name, value| if (std.mem.eql(u8, name, text)) return @intCast(value);
    return error.InvalidTimestamp;
}

fn zone(text: []const u8, colon: bool) Error!i32 {
    if (text.len != (if (colon) @as(usize, 6) else 5)) return error.InvalidTimestamp;
    if (text[0] != '+' and text[0] != '-') return error.InvalidTimestamp;
    if (colon and text[3] != ':') return error.InvalidTimestamp;
    const hours = try number(text[1..3]);
    const minutes = try number(text[if (colon) @as(usize, 4) else 3..]);
    if (hours > 23 or minutes > 59) return error.InvalidTimestamp;
    // An unknown offset must not be silently interpreted as UTC.
    if (text[0] == '-' and hours == 0 and minutes == 0) return error.MissingTimezone;
    const value: i32 = @intCast(hours * 3600 + minutes * 60);
    return if (text[0] == '-') -value else value;
}

fn calendar(year: i64, mon: i64, day: i64, clock: []const u8, microseconds: i64, offset: i32) Error!Timestamp {
    if (year < 1 or year > 9999 or mon < 1 or mon > 12 or clock.len != 8) return error.InvalidTimestamp;
    if (offset < -86340 or offset > 86340) return error.InvalidTimestamp;
    if (clock[2] != ':' or clock[5] != ':') return error.InvalidTimestamp;
    const hour = try number(clock[0..2]);
    const minute = try number(clock[3..5]);
    const second = try number(clock[6..8]);
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidTimestamp;
    const leap = @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
    const lengths = [_]i64{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const index: usize = @intCast(mon - 1);
    const max_day = lengths[index] + @as(i64, if (mon == 2 and leap) 1 else 0);
    if (day < 1 or day > max_day) return error.InvalidTimestamp;
    const prior_year = year - 1;
    var days = prior_year * 365 + @divFloor(prior_year, 4) - @divFloor(prior_year, 100) + @divFloor(prior_year, 400) - 719162;
    for (lengths[0..index]) |n| days += n;
    if (mon > 2 and leap) days += 1;
    days += day - 1;
    const seconds = days * 86400 + hour * 3600 + minute * 60 + second - offset;
    // Validated calendar and offset ranges are comfortably within i64 µs.
    return .{ .us = seconds * 1_000_000 + microseconds };
}

fn iso(text: []const u8, context: Context) Error!Timestamp {
    if (text.len < 19) return error.InvalidTimestamp;
    if (text[4] != '-' or text[7] != '-' or (text[10] != 'T' and text[10] != ' ')) return error.InvalidTimestamp;
    var end: usize = 19;
    var microseconds: i64 = 0;
    if (end < text.len and text[end] == '.') {
        const start = end + 1;
        end = start;
        while (end < text.len and std.ascii.isDigit(text[end])) : (end += 1) {}
        microseconds = try fraction(text[start..end]);
    }
    const suffix = text[end..];
    const offset = if (suffix.len == 0)
        context.offset_seconds orelse return error.MissingTimezone
    else if (std.mem.eql(u8, suffix, "Z"))
        @as(i32, 0)
    else
        try zone(suffix, true);
    return calendar(try number(text[0..4]), try number(text[5..7]), try number(text[8..10]), text[11..19], microseconds, offset);
}

fn syslog(text: []const u8, context: Context) Error!Timestamp {
    if (text.len != 15 or text[3] != ' ' or text[6] != ' ') return error.InvalidTimestamp;
    const day = try number(if (text[4] == ' ') text[5..6] else text[4..6]);
    return calendar(context.year orelse return error.MissingYear, try month(text[0..3]), day, text[7..15], 0, context.offset_seconds orelse return error.MissingTimezone);
}

fn commonLog(text: []const u8) Error!Timestamp {
    if (text.len != 26 or text[2] != '/' or text[6] != '/' or text[11] != ':' or text[20] != ' ') return error.InvalidTimestamp;
    return calendar(try number(text[7..11]), try month(text[3..6]), try number(text[0..2]), text[12..20], 0, try zone(text[21..], false));
}

test "native time: signed microseconds preserve boundaries without floats" {
    for ([_]i64{ std.math.minInt(i64), -1, 0, 1, 9007199254740993, std.math.maxInt(i64) }) |value| {
        const timestamp = Timestamp{ .us = value };
        try std.testing.expectEqual(value, Timestamp.decode(&timestamp.encode()).us);
    }
    try std.testing.expectEqual(@as(i64, 9007199254740993), (try Timestamp.fromJournal(9007199254740993)).us);
    try std.testing.expectError(error.TimeOutOfRange, Timestamp.fromJournal(@as(u64, std.math.maxInt(i64)) + 1));
    try std.testing.expectError(error.TimeOutOfRange, Timestamp.fromSeconds(std.math.maxInt(i64)));
    try std.testing.expectEqual(@as(i64, -1), (try parse(.epoch_seconds, "-0.000001", .{})).us);
    try std.testing.expectEqual(std.math.minInt(i64), (try parse(.epoch_seconds, "-9223372036854.775808", .{})).us);
    try std.testing.expectEqual(std.math.maxInt(i64), (try parse(.epoch_seconds, "9223372036854.775807", .{})).us);
    try std.testing.expectError(error.TimeOutOfRange, parse(.epoch_seconds, "9223372036854.775808", .{}));
    try std.testing.expectError(error.TimeOutOfRange, parse(.epoch_seconds, "-9223372036854.775809", .{}));
    for ([_][]const u8{ "", "-", "+1", "1e3", " 1", "1.", "1.2x", "1..2" }) |bad|
        try std.testing.expectError(error.InvalidTimestamp, parse(.epoch_seconds, bad, .{}));
    try std.testing.expectError(error.UnsupportedPrecision, parse(.epoch_seconds, "1.0000001", .{}));
}

test "native time: common service fields and calendar validation" {
    const Case = struct { format: Format, field: []const u8, us: i64, context: Context = .{} };
    for ([_]Case{
        .{ .format = .iso8601, .field = "1970-01-01T00:00:00Z", .us = 0 },
        .{ .format = .iso8601, .field = "1969-12-31T23:59:59.999999Z", .us = -1 },
        .{ .format = .iso8601, .field = "1970-01-01T02:30:00.123456+02:30", .us = 123456 },
        .{ .format = .iso8601, .field = "1969-12-31 19:00:00-05:00", .us = 0 },
        .{ .format = .iso8601, .field = "2000-02-29T00:00:00Z", .us = 951782400000000 },
        .{ .format = .iso8601, .field = "0001-01-01T00:00:00Z", .us = -62135596800000000 },
        .{ .format = .iso8601, .field = "9999-12-31T23:59:59.999999Z", .us = 253402300799999999 },
        .{ .format = .common_log, .field = "10/Oct/2000:13:55:36 -0700", .us = 971211336000000 },
        .{ .format = .syslog, .field = "Jan  1 00:00:00", .us = 0, .context = .{ .year = 1970, .offset_seconds = 0 } },
    }) |case| try std.testing.expectEqual(case.us, (try parse(case.format, case.field, case.context)).us);
    for ([_][]const u8{
        "1900-02-29T00:00:00Z",      "2100-02-29T00:00:00Z",      "2000-04-31T00:00:00Z",
        "2026-00-01T00:00:00Z",      "2026-13-01T00:00:00Z",      "0000-01-01T00:00:00Z",
        "2026-01-00T00:00:00Z",      "2026-01-01T24:00:00Z",      "2026-01-01T00:60:00Z",
        "2026-01-01T00:00:60Z",      "2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00+01:60",
        "2026-01-01T00:00:00Zextra", "2026-01-01T00:00:00.Z",
    }) |bad| try std.testing.expectError(error.InvalidTimestamp, parse(.iso8601, bad, .{}));
}

test "native time: context and future policy cannot be silently inferred" {
    try std.testing.expectError(error.MissingYear, parse(.syslog, "Jan  1 00:00:00", .{}));
    try std.testing.expectError(error.MissingTimezone, parse(.syslog, "Jan  1 00:00:00", .{ .year = 1970 }));
    try std.testing.expectError(error.MissingTimezone, parse(.iso8601, "1970-01-01T00:00:00", .{}));
    try std.testing.expectError(error.MissingTimezone, parse(.iso8601, "1970-01-01T00:00:00-00:00", .{ .offset_seconds = 0 }));
    try std.testing.expectEqual(@as(i64, 0), (try parse(.iso8601, "1970-01-01T01:00:00", .{ .offset_seconds = 3600 })).us);
    const now = Timestamp{ .us = 1000 };
    try std.testing.expectEqual(.eligible, try age(.{ .us = 400 }, now, 600));
    try std.testing.expectEqual(.obsolete, try age(.{ .us = 399 }, now, 600));
    try std.testing.expectEqual(.future, try age(.{ .us = 1001 }, now, 600));
    try std.testing.expectEqual(.eligible, try age(now, now, 0));
    try std.testing.expectError(error.InvalidWindow, age(now, now, -1));
    try std.testing.expectEqual(.obsolete, try age(.{ .us = std.math.minInt(i64) }, .{ .us = std.math.maxInt(i64) }, std.math.maxInt(i64)));
}

test "native time: complete Gregorian cycle agrees with standard library dates" {
    // Independent inverse conversion covers every day, including the three
    // non-leap century boundaries, rather than repeating this parser's formula.
    for (10957..10957 + 146097) |day| {
        const year_day = (std.time.epoch.EpochDay{ .day = @intCast(day) }).calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        var field: [32]u8 = undefined;
        const value = try std.fmt.bufPrint(&field, "{d:0>4}-{d:0>2}-{d:0>2}T00:00:00Z", .{
            year_day.year, @intFromEnum(month_day.month), @as(u8, month_day.day_index) + 1,
        });
        try std.testing.expectEqual(@as(i64, @intCast(day)) * 86400 * 1_000_000, (try parse(.iso8601, value, .{})).us);
    }
}
