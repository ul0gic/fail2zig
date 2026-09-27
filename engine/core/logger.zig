// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");

pub const Level = enum(u2) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,

    pub fn tag(self: Level) []const u8 {
        return switch (self) {
            .debug => "debug",
            .info => "info",
            .warn => "warn",
            .err => "err",
        };
    }
};

pub const Field = struct {
    key: []const u8,
    value: Value,

    pub const Value = union(enum) {
        string: []const u8,
        int: i64,
        uint: u64,
        boolean: bool,
        float: f64,
    };

    pub fn str(key: []const u8, value: []const u8) Field {
        return .{ .key = key, .value = .{ .string = value } };
    }
    pub fn int(key: []const u8, value: i64) Field {
        return .{ .key = key, .value = .{ .int = value } };
    }
    pub fn uint(key: []const u8, value: u64) Field {
        return .{ .key = key, .value = .{ .uint = value } };
    }
    pub fn boolean(key: []const u8, value: bool) Field {
        return .{ .key = key, .value = .{ .boolean = value } };
    }
    pub fn float(key: []const u8, value: f64) Field {
        return .{ .key = key, .value = .{ .float = value } };
    }
};

pub const max_line_bytes: usize = 4096;

pub const Logger = struct {
    writer: std.io.AnyWriter,
    min_level: Level,
    component: []const u8,
    mutex: std.Thread.Mutex,

    pub fn init(writer: std.io.AnyWriter, component: []const u8, min_level: Level) Logger {
        return .{
            .writer = writer,
            .min_level = min_level,
            .component = component,
            .mutex = .{},
        };
    }

    pub fn shouldLog(self: *const Logger, level: Level) bool {
        return @intFromEnum(level) >= @intFromEnum(self.min_level);
    }

    pub fn debug(
        self: *Logger,
        comptime fmt: []const u8,
        args: anytype,
        fields: []const Field,
    ) void {
        self.log(.debug, fmt, args, fields);
    }
    pub fn info(
        self: *Logger,
        comptime fmt: []const u8,
        args: anytype,
        fields: []const Field,
    ) void {
        self.log(.info, fmt, args, fields);
    }
    pub fn warn(
        self: *Logger,
        comptime fmt: []const u8,
        args: anytype,
        fields: []const Field,
    ) void {
        self.log(.warn, fmt, args, fields);
    }
    pub fn err(
        self: *Logger,
        comptime fmt: []const u8,
        args: anytype,
        fields: []const Field,
    ) void {
        self.log(.err, fmt, args, fields);
    }

    pub fn log(
        self: *Logger,
        level: Level,
        comptime fmt: []const u8,
        args: anytype,
        fields: []const Field,
    ) void {
        if (!self.shouldLog(level)) return;

        var buf: [max_line_bytes]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const w = fbs.writer();

        writeLine(w, level, self.component, fmt, args, fields) catch {
            fbs.reset();
            writeLine(w, .err, self.component, "log truncated", .{}, &.{}) catch return;
        };

        const bytes = fbs.getWritten();

        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.writer.writeAll(bytes) catch return;
    }
};

fn writeLine(
    w: anytype,
    level: Level,
    component: []const u8,
    comptime fmt: []const u8,
    args: anytype,
    fields: []const Field,
) !void {
    try w.writeByte('{');

    try w.writeAll("\"ts\":\"");
    try writeIso8601(w, std.time.timestamp());
    try w.writeAll("\",");

    try w.writeAll("\"level\":\"");
    try w.writeAll(level.tag());
    try w.writeAll("\",");

    try w.writeAll("\"component\":\"");
    try writeEscaped(w, component);
    try w.writeAll("\",");

    try w.writeAll("\"msg\":\"");
    var msg_buf: [1024]u8 = undefined;
    var msg_fbs = std.io.fixedBufferStream(&msg_buf);
    try std.fmt.format(msg_fbs.writer(), fmt, args);
    try writeEscaped(w, msg_fbs.getWritten());
    try w.writeAll("\"");

    for (fields) |f| {
        try w.writeByte(',');
        try w.writeByte('"');
        try writeEscaped(w, f.key);
        try w.writeAll("\":");
        try writeFieldValue(w, f.value);
    }

    try w.writeAll("}\n");
}

fn writeFieldValue(w: anytype, v: Field.Value) !void {
    switch (v) {
        .string => |s| {
            try w.writeByte('"');
            try writeEscaped(w, s);
            try w.writeByte('"');
        },
        .int => |n| try std.fmt.format(w, "{d}", .{n}),
        .uint => |n| try std.fmt.format(w, "{d}", .{n}),
        .boolean => |b| try w.writeAll(if (b) "true" else "false"),
        .float => |f| try std.fmt.format(w, "{d}", .{f}),
    }
}

fn writeEscaped(w: anytype, s: []const u8) !void {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0x00...0x08, 0x0B, 0x0C, 0x0E...0x1F => {
                try std.fmt.format(w, "\\u{x:0>4}", .{c});
            },
            else => try w.writeByte(c),
        }
    }
}

fn writeIso8601(w: anytype, epoch_seconds: i64) !void {
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(@max(epoch_seconds, 0)) };
    const day = es.getEpochDay();
    const ymd = day.calculateYearDay();
    const month_day = ymd.calculateMonthDay();
    const time = es.getDaySeconds();
    const h = time.getHoursIntoDay();
    const m = time.getMinutesIntoHour();
    const s = time.getSecondsIntoMinute();

    try std.fmt.format(w, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        ymd.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        h,
        m,
        s,
    });
}
