// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Bounded arithmetic duration language. Never evaluates configuration as code.
const std = @import("std");
pub const Error = error{ InvalidDuration, NonFiniteDuration, TooComplex, NegativeDuration, PrecisionLoss, Overflow };
pub const Duration = union(enum) {
    finite: f64,
    permanent,
    legacy_unknown,
    pub fn nativeSeconds(self: Duration) Error!u64 {
        const value = switch (self) {
            .finite => |v| v,
            else => return error.InvalidDuration,
        };
        if (!std.math.isFinite(value)) return error.NonFiniteDuration;
        if (value < 0) return error.NegativeDuration;
        if (@trunc(value) != value) return error.PrecisionLoss;
        if (value >= 18446744073709551616.0) return error.Overflow;
        return @intFromFloat(value);
    }
};
/// -2 is historical unknown only when reading state, never a configured ban duration.
pub fn parse(text: []const u8, allow_history_unknown: bool) Error!Duration {
    const value = try expression(text);
    if (value == -1) return .permanent;
    if (value == -2 and allow_history_unknown) return .legacy_unknown;
    if (value < 0) return error.NegativeDuration;
    return .{ .finite = value };
}
pub fn expression(text: []const u8) Error!f64 {
    if (text.len > 4096) return error.TooComplex;
    var normalized: [32768]u8 = undefined;
    var stream = std.io.fixedBufferStream(&normalized);
    var i: usize = 0;
    while (i < text.len) {
        if (std.ascii.isAlphabetic(text[i])) {
            const start = i;
            while (i < text.len and std.ascii.isAlphabetic(text[i])) : (i += 1) {}
            if (start == 0 or (!std.ascii.isDigit(text[start - 1]) and !std.ascii.isWhitespace(text[start - 1]))) return error.InvalidDuration;
            const multiplier = unit(text[start..i]) orelse return error.InvalidDuration;
            stream.writer().print("*{d} ", .{@as(u64, @intFromFloat(multiplier))}) catch return error.TooComplex;
        } else {
            stream.writer().writeByte(text[i]) catch return error.TooComplex;
            i += 1;
        }
    }
    var parser: Parser = .{ .text = stream.getWritten() };
    const value = try parser.sum(0);
    parser.space();
    if (parser.pos != parser.text.len) return error.InvalidDuration;
    return checked(value);
}
fn checked(value: f64) Error!f64 {
    if (!std.math.isFinite(value)) return error.NonFiniteDuration;
    return value;
}
const Parser = struct {
    text: []const u8,
    pos: usize = 0,
    fn space(self: *Parser) void {
        while (self.pos < self.text.len and std.ascii.isWhitespace(self.text[self.pos])) self.pos += 1;
    }
    fn sum(self: *Parser, depth: usize) Error!f64 {
        var value = try self.product(depth);
        while (true) {
            self.space();
            if (self.pos == self.text.len or self.text[self.pos] == ')') return value;
            const c = self.text[self.pos];
            if (c == '+' or c == '-') {
                self.pos += 1;
                const rhs = try self.product(depth);
                value = try checked(if (c == '+') value + rhs else value - rhs);
            } else if (std.ascii.isDigit(c)) {
                // Reference unit sequences and whitespace-separated numbers imply addition.
                value = try checked(value + try self.product(depth));
            } else return value;
        }
    }
    fn product(self: *Parser, depth: usize) Error!f64 {
        var value = try self.unary(depth);
        while (true) {
            self.space();
            if (self.pos == self.text.len) return value;
            const c = self.text[self.pos];
            if (c != '*' and c != '/' and c != '%') return value;
            self.pos += 1;
            const floor_div = c == '/' and self.pos < self.text.len and self.text[self.pos] == '/';
            if (floor_div) self.pos += 1;
            const rhs = try self.unary(depth);
            value = try checked(switch (c) {
                '*' => value * rhs,
                '/' => if (floor_div) @floor(value / rhs) else value / rhs,
                '%' => if (rhs == 0) return error.InvalidDuration else @mod(value, rhs),
                else => unreachable,
            });
        }
    }
    fn unary(self: *Parser, depth: usize) Error!f64 {
        if (depth >= 32) return error.TooComplex;
        self.space();
        if (self.pos < self.text.len and (self.text[self.pos] == '+' or self.text[self.pos] == '-')) {
            const negative = self.text[self.pos] == '-';
            self.pos += 1;
            const value = try self.unary(depth + 1);
            return if (negative) -value else value;
        }
        return self.power(depth);
    }
    fn power(self: *Parser, depth: usize) Error!f64 {
        var value = try self.atom(depth);
        self.space();
        if (self.pos + 1 < self.text.len and std.mem.eql(u8, self.text[self.pos .. self.pos + 2], "**")) {
            self.pos += 2;
            value = try checked(std.math.pow(f64, value, try self.unary(depth + 1)));
        }
        return value;
    }
    fn atom(self: *Parser, depth: usize) Error!f64 {
        self.space();
        if (self.pos == self.text.len) return error.InvalidDuration;
        if (self.text[self.pos] == '(') {
            if (depth >= 32) return error.TooComplex;
            self.pos += 1;
            const value = try self.sum(depth + 1);
            self.space();
            if (self.pos == self.text.len or self.text[self.pos] != ')') return error.InvalidDuration;
            self.pos += 1;
            return value;
        }
        const start = self.pos;
        while (self.pos < self.text.len and (std.ascii.isDigit(self.text[self.pos]) or self.text[self.pos] == '.')) self.pos += 1;
        if (self.pos == start) return error.InvalidDuration;
        const numeric = self.text[start..self.pos];
        // Do not round an integer token before checked conversion to legacy u64.
        if (std.mem.indexOfScalar(u8, numeric, '.') == null) {
            const integer = std.fmt.parseInt(u64, numeric, 10) catch return error.Overflow;
            if (integer > 9007199254740992) return error.PrecisionLoss;
        }
        var value = std.fmt.parseFloat(f64, numeric) catch return error.InvalidDuration;
        value = try checked(value);
        return value;
    }
};
fn unit(value: []const u8) ?f64 {
    const Group = struct { aliases: []const []const u8, multiplier: f64 };
    const groups = [_]Group{
        .{ .aliases = &.{ "d", "dd", "da", "day", "days" }, .multiplier = 86400 },
        .{ .aliases = &.{ "w", "ww", "we", "wee", "week", "weeks" }, .multiplier = 604800 },
        .{ .aliases = &.{ "mo", "mon", "month", "months" }, .multiplier = 2629800 },
        .{ .aliases = &.{ "y", "yy", "ye", "yea", "year", "years" }, .multiplier = 31557600 },
        .{ .aliases = &.{ "s", "ss", "se", "sec", "second", "seconds" }, .multiplier = 1 },
        .{ .aliases = &.{ "m", "mm", "mi", "min", "minute", "minutes" }, .multiplier = 60 },
        .{ .aliases = &.{ "h", "hh", "ho", "hou", "hour", "hours" }, .multiplier = 3600 },
    };
    for (groups) |group| for (group.aliases) |alias| {
        if (std.ascii.eqlIgnoreCase(value, alias)) return group.multiplier;
    };
    return null;
}
test "duration expressions units precedence and permanent tags" {
    const Case = struct { text: []const u8, value: f64 };
    for ([_]Case{
        .{ .text = "1d12h", .value = 129600 },
        .{ .text = "1hour+30min", .value = 5400 },
        .{ .text = "1year-6mo", .value = 15778800 },
        .{ .text = "1.5 min", .value = 90 },
        .{ .text = "(2+3)*60", .value = 300 },
        .{ .text = "2**3**2", .value = 512 },
        .{ .text = "-2**2", .value = -4 },
        .{ .text = "7//2", .value = 3 },
        .{ .text = "7%3", .value = 1 },
        .{ .text = "2h**2", .value = 25920000 },
    }) |case| try std.testing.expectEqual(case.value, try expression(case.text));
    try std.testing.expect((try parse("-1", false)) == .permanent);
    try std.testing.expect((try parse("-2", true)) == .legacy_unknown);
    try std.testing.expectError(error.NegativeDuration, parse("-2", false));
}
test "duration rejects code invalid values and lossy native conversion" {
    try std.testing.expectError(error.InvalidDuration, expression("print(1)"));
    try std.testing.expectError(error.NonFiniteDuration, expression("1/0"));
    try std.testing.expectError(error.InvalidDuration, expression("1fortnight"));
    try std.testing.expectError(error.PrecisionLoss, (try parse("0.5", false)).nativeSeconds());
    try std.testing.expectError(error.Overflow, parse("18446744073709551616", false));
    try std.testing.expectError(error.PrecisionLoss, parse("9007199254740993", false));
    try std.testing.expectEqual(@as(u64, 3600), try (try parse("1h", false)).nativeSeconds());
}
