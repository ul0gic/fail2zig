// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{
    BufferTooSmall,
    OutOfMemory,
};

pub const Line = struct {
    bytes: []const u8,
    truncated: bool,
};

pub const default_capacity: usize = 64 * 1024;
pub const default_max_line_len: usize = 4096;

pub const LineBuffer = struct {
    allocator: Allocator,
    buf: []u8,
    read_head: usize,
    write_head: usize,
    max_line_len: usize,
    skipping_overlong: bool,
    pending_truncation: bool,

    pub fn init(
        allocator: Allocator,
        capacity: usize,
        max_line_len: usize,
    ) Error!LineBuffer {
        if (max_line_len == 0 or capacity < max_line_len) return error.BufferTooSmall;
        const buf = allocator.alloc(u8, capacity) catch return error.OutOfMemory;
        return .{
            .allocator = allocator,
            .buf = buf,
            .read_head = 0,
            .write_head = 0,
            .max_line_len = max_line_len,
            .skipping_overlong = false,
            .pending_truncation = false,
        };
    }

    pub fn initDefault(allocator: Allocator) Error!LineBuffer {
        return init(allocator, default_capacity, default_max_line_len);
    }

    pub fn deinit(self: *LineBuffer) void {
        self.allocator.free(self.buf);
        self.* = undefined;
    }

    pub fn len(self: *const LineBuffer) usize {
        return self.write_head - self.read_head;
    }

    pub fn writableLen(self: *const LineBuffer) usize {
        return self.buf.len - self.write_head;
    }

    pub fn reset(self: *LineBuffer) void {
        self.read_head = 0;
        self.write_head = 0;
        self.skipping_overlong = false;
        self.pending_truncation = false;
    }

    pub fn append(self: *LineBuffer, data: []const u8) Error!void {
        if (data.len == 0) return;

        if (self.writableLen() < data.len) self.compact();

        if (!self.skipping_overlong and
            !self.pending_truncation and
            self.len() >= self.max_line_len and
            std.mem.indexOfScalar(u8, self.buf[self.read_head..self.write_head], '\n') == null)
        {
            self.write_head = self.read_head + self.max_line_len;
            self.skipping_overlong = true;
            self.pending_truncation = true;
        }

        if (self.skipping_overlong) {
            if (std.mem.indexOfScalar(u8, data, '\n')) |nl| {
                const remainder = data[nl + 1 ..];
                self.skipping_overlong = false;
                if (remainder.len > 0) return self.append(remainder);
                return;
            }
            return;
        }

        if (self.writableLen() < data.len) {
            return error.BufferTooSmall;
        }
        @memcpy(self.buf[self.write_head .. self.write_head + data.len], data);
        self.write_head += data.len;
    }

    pub fn nextLine(self: *LineBuffer) ?Line {
        if (self.pending_truncation) {
            const end = self.read_head + self.max_line_len;
            if (end <= self.write_head) {
                const line: Line = .{
                    .bytes = self.buf[self.read_head..end],
                    .truncated = true,
                };
                self.read_head = end;
                self.pending_truncation = false;
                self.maybeCompact();
                return line;
            }
            return null;
        }

        const slice = self.buf[self.read_head..self.write_head];
        const nl = std.mem.indexOfScalar(u8, slice, '\n') orelse return null;

        const raw = slice[0..nl];
        var truncated = false;
        var line_bytes: []const u8 = raw;
        if (raw.len > self.max_line_len) {
            line_bytes = raw[0..self.max_line_len];
            truncated = true;
        }
        const line: Line = .{ .bytes = line_bytes, .truncated = truncated };
        self.read_head += nl + 1;
        self.maybeCompact();
        return line;
    }

    pub fn maybeCompact(self: *LineBuffer) void {
        if (self.read_head > self.buf.len / 2) self.compact();
    }

    pub fn compact(self: *LineBuffer) void {
        if (self.read_head == 0) return;
        const live = self.write_head - self.read_head;
        if (live > 0) {
            std.mem.copyForwards(u8, self.buf[0..live], self.buf[self.read_head..self.write_head]);
        }
        self.read_head = 0;
        self.write_head = live;
    }
};

const testing = std.testing;

test "LineBuffer: init validates capacity" {
    try testing.expectError(
        error.BufferTooSmall,
        LineBuffer.init(testing.allocator, 100, 200),
    );
    try testing.expectError(
        error.BufferTooSmall,
        LineBuffer.init(testing.allocator, 100, 0),
    );
}

test "LineBuffer: single complete line" {
    var lb = try LineBuffer.init(testing.allocator, 128, 64);
    defer lb.deinit();

    try lb.append("hello\n");
    const line = lb.nextLine().?;
    try testing.expectEqualStrings("hello", line.bytes);
    try testing.expectEqual(false, line.truncated);
    try testing.expect(lb.nextLine() == null);
}

test "LineBuffer: multiple lines in one append" {
    var lb = try LineBuffer.init(testing.allocator, 256, 64);
    defer lb.deinit();

    try lb.append("one\ntwo\nthree\n");
    try testing.expectEqualStrings("one", lb.nextLine().?.bytes);
    try testing.expectEqualStrings("two", lb.nextLine().?.bytes);
    try testing.expectEqualStrings("three", lb.nextLine().?.bytes);
    try testing.expect(lb.nextLine() == null);
}

test "LineBuffer: partial line reassembled across appends" {
    var lb = try LineBuffer.init(testing.allocator, 256, 64);
    defer lb.deinit();

    try lb.append("hel");
    try testing.expect(lb.nextLine() == null);
    try lb.append("lo ");
    try testing.expect(lb.nextLine() == null);
    try lb.append("world\n");
    const line = lb.nextLine().?;
    try testing.expectEqualStrings("hello world", line.bytes);
}

test "LineBuffer: empty line preserved" {
    var lb = try LineBuffer.init(testing.allocator, 128, 64);
    defer lb.deinit();

    try lb.append("\n\nfoo\n");
    try testing.expectEqualStrings("", lb.nextLine().?.bytes);
    try testing.expectEqualStrings("", lb.nextLine().?.bytes);
    try testing.expectEqualStrings("foo", lb.nextLine().?.bytes);
}

test "LineBuffer: overlong line delivered truncated" {
    var lb = try LineBuffer.init(testing.allocator, 256, 16);
    defer lb.deinit();

    try lb.append("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
    const line = lb.nextLine().?;
    try testing.expectEqual(true, line.truncated);
    try testing.expectEqual(@as(usize, 16), line.bytes.len);
    try testing.expect(std.mem.eql(u8, line.bytes, "AAAAAAAAAAAAAAAA"));
    try testing.expect(lb.nextLine() == null);
}

test "LineBuffer: truncation followed by next valid line" {
    var lb = try LineBuffer.init(testing.allocator, 256, 16);
    defer lb.deinit();

    try lb.append("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nshort\n");
    const first = lb.nextLine().?;
    try testing.expectEqual(true, first.truncated);
    try testing.expectEqual(@as(usize, 16), first.bytes.len);

    const second = lb.nextLine().?;
    try testing.expectEqual(false, second.truncated);
    try testing.expectEqualStrings("short", second.bytes);
}

test "LineBuffer: overlong split across appends still truncates correctly" {
    var lb = try LineBuffer.init(testing.allocator, 64, 16);
    defer lb.deinit();

    try lb.append("AAAAAAAAAAAA");
    try lb.append("BBBBBBBBBBBBBBBBBBBB");
    try lb.append("\n");

    const line = lb.nextLine().?;
    try testing.expectEqual(true, line.truncated);
    try testing.expectEqual(@as(usize, 16), line.bytes.len);
    try testing.expectEqualStrings("AAAAAAAAAAAABBBB", line.bytes);
}

test "LineBuffer: compaction moves data to start" {
    var lb = try LineBuffer.init(testing.allocator, 64, 16);
    defer lb.deinit();

    try lb.append("one\ntwo\nthree\n");
    _ = lb.nextLine().?;
    _ = lb.nextLine().?;
    lb.compact();
    try testing.expectEqual(@as(usize, 0), lb.read_head);
    try testing.expectEqualStrings("three", lb.nextLine().?.bytes);
}

test "LineBuffer: reset clears state" {
    var lb = try LineBuffer.init(testing.allocator, 64, 16);
    defer lb.deinit();

    try lb.append("partial line without newline");
    lb.reset();
    try testing.expectEqual(@as(usize, 0), lb.len());
    try testing.expect(lb.nextLine() == null);

    try lb.append("fresh\n");
    try testing.expectEqualStrings("fresh", lb.nextLine().?.bytes);
}

test "LineBuffer: writableLen decreases as data is appended" {
    var lb = try LineBuffer.init(testing.allocator, 64, 16);
    defer lb.deinit();

    try testing.expectEqual(@as(usize, 64), lb.writableLen());
    try lb.append("hello");
    try testing.expectEqual(@as(usize, 59), lb.writableLen());
    try lb.append("\n");
    _ = lb.nextLine();
    try testing.expectEqual(@as(usize, 0), lb.len());
}

test "LineBuffer: delivered slices point into buffer (zero-copy)" {
    var lb = try LineBuffer.init(testing.allocator, 64, 16);
    defer lb.deinit();

    try lb.append("stable\n");
    const line = lb.nextLine().?;
    const buf_start = @intFromPtr(lb.buf.ptr);
    const buf_end = buf_start + lb.buf.len;
    const line_start = @intFromPtr(line.bytes.ptr);
    try testing.expect(line_start >= buf_start and line_start < buf_end);
}
