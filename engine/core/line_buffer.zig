// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Zero-copy line buffer for log ingestion.
//!
//! `LineBuffer` accumulates bytes produced by the log watcher and hands
//! out complete lines as slices into its internal fixed buffer. No
//! allocation occurs per line; callers must consume each returned slice
//! before the next call that mutates the buffer (`append`, `nextLine`,
//! `compact`, `reset`).
//!
//! Truncation policy: a single line that exceeds `max_line_len` is
//! delivered as a truncated slice of exactly `max_line_len` bytes with
//! `truncated = true`. The remainder of that overlong line is skipped up
//! to and including the next `\n` — we never fragment one logical line
//! into two false positives.
//!
//! The buffer compacts itself (memmoves the live data to the start)
//! when the read head passes the midpoint. This keeps the amortized
//! memory move cost O(1) per byte without ever allocating.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{
    BufferTooSmall,
    OutOfMemory,
};

/// Result of a successful `nextLine` call.
pub const Line = struct {
    /// Slice into the internal buffer. Valid until the next mutating
    /// call on the `LineBuffer`.
    bytes: []const u8,
    /// True when the line exceeded `max_line_len` and `bytes` is the
    /// leading `max_line_len` bytes — callers may want to flag the
    /// event for monitoring.
    truncated: bool,
};

pub const default_capacity: usize = 64 * 1024;
pub const default_max_line_len: usize = 4096;

pub const LineBuffer = struct {
    allocator: Allocator,
    buf: []u8,
    /// Live data is `buf[read_head..write_head]`.
    read_head: usize,
    write_head: usize,
    max_line_len: usize,
    /// When true we are inside an overlong-line skip: bytes are consumed
    /// silently until the next `\n`.
    skipping_overlong: bool,
    /// When true, `nextLine()` should immediately deliver the first
    /// `max_line_len` bytes of the live region as a truncated line.
    /// Set when an overlong line is detected; cleared after delivery.
    pending_truncation: bool,

    /// Create a buffer with the given total capacity and max line
    /// length. `max_line_len` must fit within `capacity`.
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

    /// Convenience: 64KB capacity, 4KB max line.
    pub fn initDefault(allocator: Allocator) Error!LineBuffer {
        return init(allocator, default_capacity, default_max_line_len);
    }

    pub fn deinit(self: *LineBuffer) void {
        self.allocator.free(self.buf);
        self.* = undefined;
    }

    /// Bytes currently buffered (not yet returned as a line).
    pub fn len(self: *const LineBuffer) usize {
        return self.write_head - self.read_head;
    }

    /// Remaining writable bytes without compaction.
    pub fn writableLen(self: *const LineBuffer) usize {
        return self.buf.len - self.write_head;
    }

    /// Reset all state, reusing the buffer. Used on log rotation.
    pub fn reset(self: *LineBuffer) void {
        self.read_head = 0;
        self.write_head = 0;
        self.skipping_overlong = false;
        self.pending_truncation = false;
    }

    /// Append `data` to the buffer. Compacts first if needed. Returns
    /// `error.BufferTooSmall` only when the incoming chunk plus the
    /// currently-buffered partial line together exceed the total
    /// capacity — in practice this happens only if the caller is feeding
    /// an unbounded line with no `\n`, which the overlong-skip state
    /// machine should prevent once engaged.
    pub fn append(self: *LineBuffer, data: []const u8) Error!void {
        if (data.len == 0) return;

        // Make room by compacting if the write head is near the end.
        if (self.writableLen() < data.len) self.compact();

        // If the caller keeps pushing bytes that can never form a line
        // (no `\n` in sight AND the partial line is already bigger than
        // max_line_len), engage the overlong-skip state: drop everything
        // up to the next newline and surface a single truncated line.
        if (!self.skipping_overlong and
            !self.pending_truncation and
            self.len() >= self.max_line_len and
            std.mem.indexOfScalar(u8, self.buf[self.read_head..self.write_head], '\n') == null)
        {
            // Leave the first max_line_len bytes in place so nextLine can
            // deliver a truncated line. Drop anything beyond; subsequent
            // input is skipped until newline.
            self.write_head = self.read_head + self.max_line_len;
            self.skipping_overlong = true;
            self.pending_truncation = true;
        }

        if (self.skipping_overlong) {
            // Consume `data` silently until (and including) a newline.
            if (std.mem.indexOfScalar(u8, data, '\n')) |nl| {
                // Everything up to and including `\n` is discarded. Any
                // remainder re-enters normal buffering.
                const remainder = data[nl + 1 ..];
                self.skipping_overlong = false;
                if (remainder.len > 0) return self.append(remainder);
                return;
            }
            // No newline yet — drop the chunk entirely.
            return;
        }

        if (self.writableLen() < data.len) {
            // Even after compaction the data does not fit. This only
            // happens if capacity was chosen too small for the caller's
            // chunk size. Signal the error rather than partially accept.
            return error.BufferTooSmall;
        }
        @memcpy(self.buf[self.write_head .. self.write_head + data.len], data);
        self.write_head += data.len;
    }

    /// Return the next complete line, or null if none available. The
    /// returned slice does not include the trailing `\n`.
    pub fn nextLine(self: *LineBuffer) ?Line {
        // A pending truncation: deliver the buffered `max_line_len` head
        // immediately. This fires whether or not we are still skipping
        // the remainder of that overlong line (we may be mid-skip or the
        // skip may have already consumed the trailing newline).
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

        // Normal line: bytes before the newline. Allow truncation if the
        // user shrank max_line_len — never deliver more than it allows.
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

    /// Compact if the read head is past the midpoint of the buffer.
    /// Exposed publicly so tests can assert its behavior; normal code
    /// can rely on `append`/`nextLine` to call it.
    pub fn maybeCompact(self: *LineBuffer) void {
        if (self.read_head > self.buf.len / 2) self.compact();
    }

    /// Unconditionally compact live data to the start of the buffer.
    pub fn compact(self: *LineBuffer) void {
        if (self.read_head == 0) return;
        const live = self.write_head - self.read_head;
        if (live > 0) {
            // Use std.mem.copyForwards for overlap-safe move.
            std.mem.copyForwards(u8, self.buf[0..live], self.buf[self.read_head..self.write_head]);
        }
        self.read_head = 0;
        self.write_head = live;
    }
};

// ============================================================================
// Tests
// ============================================================================

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

    // 32 bytes of 'A' then newline. max_line_len is 16.
    try lb.append("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
    const line = lb.nextLine().?;
    try testing.expectEqual(true, line.truncated);
    try testing.expectEqual(@as(usize, 16), line.bytes.len);
    try testing.expect(std.mem.eql(u8, line.bytes, "AAAAAAAAAAAAAAAA"));
    // After truncation, the next line should be null (the overrun was
    // consumed up to and including the newline).
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

    // Feed 12 bytes, then 20 bytes, then newline. Total is 32 — the
    // 16-byte truncation should kick in during the second append.
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
    // After reading two lines, `read_head` has advanced past half of
    // the 64-byte buffer in combination with appends. Force compact
    // and verify `read_head` resets.
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
    // After consuming a line, compaction may or may not have fired,
    // but `len()` must be 0.
    try testing.expectEqual(@as(usize, 0), lb.len());
}

test "LineBuffer: delivered slices point into buffer (zero-copy)" {
    var lb = try LineBuffer.init(testing.allocator, 64, 16);
    defer lb.deinit();

    try lb.append("stable\n");
    const line = lb.nextLine().?;
    // The slice must be a subslice of lb.buf.
    const buf_start = @intFromPtr(lb.buf.ptr);
    const buf_end = buf_start + lb.buf.len;
    const line_start = @intFromPtr(line.bytes.ptr);
    try testing.expect(line_start >= buf_start and line_start < buf_end);
}
