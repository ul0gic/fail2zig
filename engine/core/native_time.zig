// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
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

pub fn age(event: Timestamp, now: Timestamp, window_us: i64) error{InvalidWindow}!Age {
    if (window_us < 0) return error.InvalidWindow;
    if (event.us > now.us) return .future;
    return if (@as(i128, now.us) - event.us <= window_us) .eligible else .obsolete;
}

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
    // ISO numeric zones accept both basic (+HHMM) and extended (+HH:MM) forms.
    const offset = if (suffix.len == 0)
        context.offset_seconds orelse return error.MissingTimezone
    else if (std.mem.eql(u8, suffix, "Z"))
        @as(i32, 0)
    else
        try zone(suffix, suffix.len != 5);
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
