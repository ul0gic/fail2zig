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
