// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Operational logger for the fail2zig daemon.
//!
//! This is for fail2zig's OWN logs — startup messages, errors, metrics.
//! It is NOT the log ingestion layer that parses third-party logs.
//!
//! Design invariants:
//!   * Zero allocation per log call. Output is formatted into a
//!     stack-allocated 4 KB buffer and written in one go.
//!   * JSON line-per-log (ndjson). Fields are quoted, escapes
//!     minimal but correct for `\"` and `\\`.
//!   * Thread-safe via `std.Thread.Mutex` around the final write.
//!   * Configurable minimum level — messages below it are dropped
//!     before any formatting work.

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

/// One structured key-value pair to attach to a log line. Values are
/// emitted as JSON scalars or strings depending on the variant.
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
    /// Writer that receives one ndjson line per call. Stderr is the
    /// default in production. Tests inject an `std.ArrayList(u8).Writer`.
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

    /// Emit a log line at `level`. Silently drops if below min_level.
    /// Silently truncates if the formatted line would exceed
    /// `max_line_bytes` — we never allocate to make room.
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
            // Formatting produced more bytes than our fixed buffer.
            // Fall back to a minimal error record so we still emit
            // *something* rather than dropping silently.
            fbs.reset();
            writeLine(w, .err, self.component, "log truncated", .{}, &.{}) catch return;
        };

        const bytes = fbs.getWritten();

        self.mutex.lock();
        defer self.mutex.unlock();
        // A single write is intentional — one ndjson line per syscall.
        _ = self.writer.writeAll(bytes) catch return;
    }
};

// ============================================================================
// JSON emit helpers (file-private)
// ============================================================================

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
    // Format the message into a small scratch buffer so we can emit it
    // as a correctly-escaped JSON string. Reusing the line buffer in
    // place is possible but wrappers around `std.fmt.format` make this
    // cleaner and the ~256 byte msg is plenty for log messages.
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

/// JSON-escape a string. We only emit the mandatory minimum: `"`, `\`,
/// and control bytes below 0x20 go through `\uXXXX`. Multibyte UTF-8 is
/// passed through unchanged — valid UTF-8 is valid JSON per RFC 8259.
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

/// Very small ISO-8601 formatter for a unix epoch timestamp. Emits the
/// `YYYY-MM-DDTHH:MM:SSZ` form (UTC). No fractional seconds. Stable
/// across architectures because we use the raw epoch math.
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

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn parseLine(allocator: std.mem.Allocator, json: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, json, .{});
}

test "Logger: emits valid JSON at info level" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    var logger = Logger.init(buf.writer().any(), "test", .info);

    logger.info("hello {s}", .{"world"}, &.{
        Field.str("kind", "greeting"),
        Field.int("n", 42),
    });

    const line = std.mem.trimRight(u8, buf.items, "\n");
    var parsed = try parseLine(testing.allocator, line);
    defer parsed.deinit();
    const obj = parsed.value.object;

    try testing.expectEqualStrings("info", obj.get("level").?.string);
    try testing.expectEqualStrings("test", obj.get("component").?.string);
    try testing.expectEqualStrings("hello world", obj.get("msg").?.string);
    try testing.expectEqualStrings("greeting", obj.get("kind").?.string);
    try testing.expectEqual(@as(i64, 42), obj.get("n").?.integer);
    try testing.expect(obj.get("ts") != null);
}

test "Logger: filters below min_level" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    var logger = Logger.init(buf.writer().any(), "test", .warn);

    logger.debug("not shown", .{}, &.{});
    logger.info("not shown either", .{}, &.{});
    logger.warn("shown", .{}, &.{});
    logger.err("also shown", .{}, &.{});

    // Count newlines — should be exactly 2.
    var nl_count: usize = 0;
    for (buf.items) |c| if (c == '\n') {
        nl_count += 1;
    };
    try testing.expectEqual(@as(usize, 2), nl_count);
}

test "Logger: escapes quotes and backslashes" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    var logger = Logger.init(buf.writer().any(), "esc", .debug);

    logger.info("quote=\" backslash=\\ newline=\n", .{}, &.{});

    const line = std.mem.trimRight(u8, buf.items, "\n");
    var parsed = try parseLine(testing.allocator, line);
    defer parsed.deinit();
    const msg = parsed.value.object.get("msg").?.string;
    // Parsed msg should have literal chars back.
    try testing.expect(std.mem.indexOf(u8, msg, "quote=\"") != null);
    try testing.expect(std.mem.indexOf(u8, msg, "backslash=\\") != null);
    try testing.expect(std.mem.indexOf(u8, msg, "newline=\n") != null);
}

test "Logger: emits bool, uint, float fields" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    var logger = Logger.init(buf.writer().any(), "t", .debug);

    logger.debug("m", .{}, &.{
        Field.boolean("ok", true),
        Field.uint("count", 1_234_567),
        Field.float("ratio", 3.14),
    });

    const line = std.mem.trimRight(u8, buf.items, "\n");
    var parsed = try parseLine(testing.allocator, line);
    defer parsed.deinit();
    const obj = parsed.value.object;
    try testing.expectEqual(true, obj.get("ok").?.bool);
    try testing.expectEqual(@as(i64, 1_234_567), obj.get("count").?.integer);
    // Float parse tolerance — JSON parses small floats exactly.
    try testing.expectEqual(@as(f64, 3.14), obj.get("ratio").?.float);
}

test "Logger: each call emits exactly one newline-terminated line" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    var logger = Logger.init(buf.writer().any(), "nl", .debug);

    logger.info("a", .{}, &.{});
    logger.info("b", .{}, &.{});
    logger.info("c", .{}, &.{});

    var lines: usize = 0;
    for (buf.items) |c| if (c == '\n') {
        lines += 1;
    };
    try testing.expectEqual(@as(usize, 3), lines);
    try testing.expectEqual(@as(u8, '\n'), buf.items[buf.items.len - 1]);
}

test "Logger: ts is ISO 8601 UTC" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    var logger = Logger.init(buf.writer().any(), "t", .info);
    logger.info("x", .{}, &.{});

    const line = std.mem.trimRight(u8, buf.items, "\n");
    var parsed = try parseLine(testing.allocator, line);
    defer parsed.deinit();
    const ts = parsed.value.object.get("ts").?.string;
    try testing.expectEqual(@as(usize, 20), ts.len);
    try testing.expectEqual(@as(u8, 'T'), ts[10]);
    try testing.expectEqual(@as(u8, 'Z'), ts[19]);
}

test "Logger: respects shouldLog across boundary" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    var logger = Logger.init(buf.writer().any(), "t", .info);
    try testing.expect(!logger.shouldLog(.debug));
    try testing.expect(logger.shouldLog(.info));
    try testing.expect(logger.shouldLog(.warn));
    try testing.expect(logger.shouldLog(.err));
}

test "Logger: thread-safe concurrent writes do not interleave bytes" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    var logger = Logger.init(buf.writer().any(), "mt", .info);

    const Worker = struct {
        fn run(l: *Logger, n: usize) void {
            var i: usize = 0;
            while (i < n) : (i += 1) {
                l.info("hello from worker {d}", .{i}, &.{});
            }
        }
    };

    const n_per: usize = 50;
    var t1 = try std.Thread.spawn(.{}, Worker.run, .{ &logger, n_per });
    var t2 = try std.Thread.spawn(.{}, Worker.run, .{ &logger, n_per });
    t1.join();
    t2.join();

    // Every line must parse as valid JSON — interleaving would break it.
    var it = std.mem.splitScalar(u8, buf.items, '\n');
    var count: usize = 0;
    while (it.next()) |line| {
        if (line.len == 0) continue;
        count += 1;
        var parsed = try parseLine(testing.allocator, line);
        defer parsed.deinit();
        try testing.expectEqualStrings("info", parsed.value.object.get("level").?.string);
    }
    try testing.expectEqual(@as(usize, 2 * n_per), count);
}
