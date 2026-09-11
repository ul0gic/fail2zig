// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const records = @import("source_record.zig");
const Allocator = std.mem.Allocator;
pub const Start = enum { head, tail };
pub const Framing = enum {
    bytes,
    utf16le,
    utf16be,
    utf32le,
    utf32be,
    fn width(self: Framing) usize {
        return switch (self) {
            .bytes => 1,
            .utf16le, .utf16be => 2,
            .utf32le, .utf32be => 4,
        };
    }
    fn isCharacter(self: Framing, bytes: []const u8, c: u8) bool {
        return switch (self) {
            .bytes => bytes[0] == c,
            .utf16le => std.mem.readInt(u16, bytes[0..2], .little) == c,
            .utf16be => std.mem.readInt(u16, bytes[0..2], .big) == c,
            .utf32le => std.mem.readInt(u32, bytes[0..4], .little) == c,
            .utf32be => std.mem.readInt(u32, bytes[0..4], .big) == c,
        };
    }
};

fn recordEnd(framing: Framing, bytes: []const u8, start: u64) ?usize {
    const width = framing.width();
    var i: usize = @intCast((width - start % width) % width);
    while (i + width <= bytes.len) : (i += width) {
        if (framing.isCharacter(bytes[i..], '\n')) return i + width;
    }
    return null;
}

fn stripTerminator(framing: Framing, bytes: []const u8) []const u8 {
    const width = framing.width();
    var end = bytes.len - width;
    while (end >= width and framing.isCharacter(bytes[end - width ..], '\r')) end -= width;
    return bytes[0..end];
}
pub const Resume = struct {
    version: u8 = 2,
    start: Start = .head,
    codec_configuration_hash: ?[32]u8 = null,
    framing: Framing = .bytes,
    incarnation: [16]u8,
    device: u64,
    inode: u64,
    offset: u64,
    prefix_len: u8,
    prefix_hash: [32]u8,
};

fn openRegularAt(directory: std.fs.Dir, path: []const u8) !std.fs.File {
    const fd = try std.posix.openat(directory.fd, path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }, 0);
    errdefer std.posix.close(fd);
    const stat = try std.posix.fstat(fd);
    if (!std.posix.S.ISREG(stat.mode)) return error.NotRegularFile;
    return .{ .handle = fd };
}

/// One independently acknowledged file incarnation. A caller must retain this
/// object when a path is renamed; open a second source for its replacement.
/// No durable position is updated until the callback returns successfully.
pub const FileSource = struct {
    allocator: Allocator,
    path: []const u8,
    source_id: []const u8,
    file: ?std.fs.File = null,
    start: Start,
    /// Candidate position until baseline_committed; use acknowledgedCheckpoint
    /// for a source-local acknowledged token. The transaction store is authoritative.
    committed: ?Resume = null,
    health: records.Health = .waiting,
    baseline_committed: bool = false,
    /// Per configured stream, not per jail. Tail begins live; a head stream
    /// becomes live only after observing the end of nonempty input.
    in_operation: bool = false,
    pending_eof_check: bool = false,
    framing: Framing = .bytes,
    max_record_bytes: usize = 1024 * 1024,
    frame_callback: ?records.FrameCallback = null,
    frame_context: ?*anyopaque = null,
    codec_configuration_hash: ?[32]u8 = null,

    pub fn setFramer(self: *FileSource, callback: records.FrameCallback, context: ?*anyopaque, configuration_hash: [32]u8, max_bytes: usize) !void {
        if (max_bytes == 0 or max_bytes > 1024 * 1024) return error.InvalidFramingLimit;
        if (self.file != null) return error.SourceAlreadyOpened;
        if (self.committed) |saved_resume| {
            const old = saved_resume.codec_configuration_hash orelse return error.FramingProfileMismatch;
            if (!std.mem.eql(u8, &old, &configuration_hash)) return error.FramingProfileMismatch;
        }
        self.frame_callback = callback;
        self.frame_context = context;
        self.codec_configuration_hash = configuration_hash;
        self.max_record_bytes = max_bytes;
    }

    pub fn init(allocator: Allocator, path: []const u8, source_id: []const u8, start: Start, checkpoint: ?Resume) !FileSource {
        if (path.len == 0 or source_id.len == 0) return error.InvalidSource;
        if (checkpoint) |r| if (r.version != 2 or r.prefix_len > 64) return error.InvalidResume;
        const owned_path = try allocator.dupe(u8, path);
        errdefer allocator.free(owned_path);
        return .{ .allocator = allocator, .path = owned_path, .source_id = try allocator.dupe(u8, source_id), .start = if (checkpoint) |r| r.start else start, .in_operation = start == .tail, .committed = checkpoint, .baseline_committed = checkpoint != null, .framing = if (checkpoint) |r| r.framing else .bytes };
    }

    pub fn acknowledgedCheckpoint(self: *const FileSource) ?Resume {
        return if (self.baseline_committed) self.committed else null;
    }

    pub fn deinit(self: *FileSource) void {
        if (self.file) |f| f.close();
        self.allocator.free(self.path);
        self.allocator.free(self.source_id);
        self.* = undefined;
    }

    fn prefix(f: std.fs.File, n: u8) ![32]u8 {
        var bytes: [64]u8 = undefined;
        const got = try f.preadAll(bytes[0..n], 0);
        if (got != n) return error.ResumeLost;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes[0..n], &digest, .{});
        return digest;
    }

    fn newResume(f: std.fs.File, offset: u64, framing: Framing, start: Start) !Resume {
        const stat = try std.posix.fstat(f.handle);
        var incarnation: [16]u8 = undefined;
        std.crypto.random.bytes(&incarnation);
        const n: u8 = @intCast(@min(@as(u64, @intCast(stat.size)), 64));
        return .{ .start = start, .framing = framing, .incarnation = incarnation, .device = @intCast(stat.dev), .inode = @intCast(stat.ino), .offset = offset, .prefix_len = n, .prefix_hash = try prefix(f, n) };
    }

    fn openIncarnation(self: *FileSource) !?std.fs.File {
        const direct: ?std.fs.File = openRegularAt(std.fs.cwd(), self.path) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        const expected = self.committed orelse return direct;
        if (direct) |f| {
            const stat = std.posix.fstat(f.handle) catch |err| {
                f.close();
                return err;
            };
            if (stat.dev == expected.device and stat.ino == expected.inode) return f;
            f.close();
        }
        // Rotation recovery searches only this configured parent and compares
        // kernel identity first, never equating unrelated files by content.
        var parent = std.fs.cwd().openDir(std.fs.path.dirname(self.path) orelse ".", .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) return error.ResumeLost;
            return err;
        };
        defer parent.close();
        var it = parent.iterate();
        while (try it.next()) |entry| {
            const observed = std.posix.fstatat(parent.fd, entry.name, 0) catch |err| {
                if (err == error.FileNotFound) continue;
                return err;
            };
            if (!std.posix.S.ISREG(observed.mode) or observed.dev != expected.device or observed.ino != expected.inode) continue;
            const f = openRegularAt(parent, entry.name) catch |err| {
                if (err == error.FileNotFound or err == error.NotRegularFile) continue;
                return err;
            };
            const stat = std.posix.fstat(f.handle) catch |err| {
                f.close();
                return err;
            };
            if (std.posix.S.ISREG(stat.mode) and stat.dev == expected.device and stat.ino == expected.inode) return f;
            f.close();
        }
        return error.ResumeLost;
    }

    fn attach(self: *FileSource) !bool {
        if (self.file != null) return true;
        const f = (self.openIncarnation() catch |err| {
            self.health = switch (err) {
                error.FileNotFound => .missing,
                error.AccessDenied => .permission_denied,
                error.ResumeLost => .resume_lost,
                else => .read_failed,
            };
            return err;
        }) orelse {
            self.health = .missing;
            return false;
        };
        errdefer f.close();
        const stat = try std.posix.fstat(f.handle);
        if (!std.posix.S.ISREG(stat.mode)) return error.NotRegularFile;
        if (self.committed) |r| {
            if (r.device != stat.dev or r.inode != stat.ino or stat.size < 0 or @as(u64, @intCast(stat.size)) < r.offset or !std.mem.eql(u8, &(prefix(f, r.prefix_len) catch {
                self.health = .resume_lost;
                return error.ResumeLost;
            }), &r.prefix_hash)) {
                self.health = .resume_lost;
                return error.ResumeLost;
            }
        } else {
            const offset: u64 = if (self.start == .tail) @intCast(stat.size) else 0;
            self.committed = try newResume(f, offset, self.framing, self.start);
            self.committed.?.codec_configuration_hash = self.codec_configuration_hash;
        }
        self.file = f;
        self.health = .healthy;
        return true;
    }

    /// True means the pathname now points at a different file. The retained FD
    /// continues to drain the previous incarnation, including late appends.
    pub fn replaced(self: *FileSource) !bool {
        if (self.file == null) return false;
        const current = openRegularAt(std.fs.cwd(), self.path) catch |err| {
            if (err == error.FileNotFound) return true;
            return err;
        };
        defer current.close();
        const stat = try std.posix.fstat(current.handle);
        const r = self.committed.?;
        return stat.dev != r.device or stat.ino != r.inode;
    }

    /// Deliver at most one newline-terminated record. Partial records remain at
    /// the committed byte offset and are reread, never persisted as consumed.
    /// A detected copytruncate starts a fresh incarnation. Truncate-and-regrow
    /// between observations with an identical prefix cannot be proven detectable.
    pub fn poll(self: *FileSource, callback: records.AckCallback, userdata: ?*anyopaque) !bool {
        if (self.committed) |saved_resume| if (saved_resume.codec_configuration_hash != null and self.frame_callback == null) return error.FramingProfileMismatch;
        if (!try self.attach()) return false;
        try self.finishEofCheck();
        const f = self.file.?;
        var r = self.committed.?;
        const stat = try f.stat();
        if (stat.size < r.offset or !std.mem.eql(u8, &(prefix(f, r.prefix_len) catch [_]u8{0} ** 32), &r.prefix_hash)) {
            r = try newResume(f, 0, self.framing, self.start);
            r.codec_configuration_hash = self.codec_configuration_hash;
            self.committed = r;
            self.baseline_committed = false;
        }
        if (!self.baseline_committed) {
            const cursor = try std.json.stringifyAlloc(self.allocator, r, .{});
            defer self.allocator.free(cursor);
            var id_buf: [128]u8 = undefined;
            const id = try std.fmt.bufPrint(&id_buf, "file:baseline:{s}:{d}", .{ std.fmt.fmtSliceHexLower(&r.incarnation), r.offset });
            callback(.{ .kind = .checkpoint, .source = self.source_id, .source_path = self.path, .occurrence = id, .cursor = cursor, .message = "", .raw_hash = [_]u8{0} ** 32 }, userdata) catch |err| {
                self.health = .commit_failed;
                return err;
            };
            self.baseline_committed = true;
        }
        var line = std.ArrayList(u8).init(self.allocator);
        defer line.deinit();
        var offset = r.offset;
        var chunk: [4096]u8 = undefined;
        var frame_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer frame_arena.deinit();
        var predecoded: ?records.Predecoded = null;
        while (true) {
            const remaining = self.max_record_bytes -| line.items.len;
            const count = f.pread(chunk[0..@min(chunk.len, remaining)], offset) catch |err| {
                self.health = .read_failed;
                return err;
            };
            try line.appendSlice(chunk[0..count]);
            if (line.items.len == 0) {
                self.health = .healthy;
                return false;
            }
            if (self.frame_callback) |frame| {
                const eof = count == 0 or offset + count >= (try f.stat()).size;
                const framed = frame(self.path, line.items, eof, frame_arena.allocator(), self.frame_context) catch |err| {
                    self.health = switch (err) {
                        error.RecordTooLarge => .record_too_long,
                        error.UnsupportedFramingBoundary, error.InvalidFramingResult => .malformed_record,
                        else => .child_failed,
                    };
                    return err;
                };
                if (framed) |result| {
                    if (result.consumed == 0 or result.consumed > line.items.len) return error.InvalidFramingResult;
                    line.shrinkRetainingCapacity(result.consumed);
                    offset = r.offset + result.consumed;
                    predecoded = result.decoded;
                    break;
                }
                if (eof and line.items.len < self.max_record_bytes) {
                    self.in_operation = true;
                    self.health = .healthy;
                    return false;
                }
            } else if (recordEnd(self.framing, line.items, r.offset)) |end| {
                line.shrinkRetainingCapacity(end);
                offset = r.offset + end;
                break;
            }
            if (line.items.len >= self.max_record_bytes) {
                self.health = .record_too_long;
                return error.RecordTooLong;
            }
            if (count == 0) {
                self.in_operation = true;
                self.health = .healthy;
                return false;
            }
            offset += count;
            // Incomplete probes carry no retained state; reclaim their response
            // storage before requesting the next bounded prefix.
            _ = frame_arena.reset(.retain_capacity);
        }

        // Do not pair an old record with a prefix sampled after a concurrent
        // rewrite. This detects observed changes, not unobservable identical-
        // prefix truncate/regrow cycles between reads.
        const after_read = try f.stat();
        var next = r;
        next.offset = offset;
        next.prefix_len = @max(r.prefix_len, @as(u8, @intCast(@min(offset, 64))));
        var captured_prefix: [64]u8 = undefined;
        const captured = try f.preadAll(captured_prefix[0..next.prefix_len], 0);
        var prior_hash: [32]u8 = undefined;
        if (captured != next.prefix_len) {
            self.health = .resume_lost;
            return error.SourceChanged;
        }
        std.crypto.hash.sha2.Sha256.hash(captured_prefix[0..r.prefix_len], &prior_hash, .{});
        if (after_read.size < offset or !std.mem.eql(u8, &prior_hash, &r.prefix_hash)) {
            self.health = .resume_lost;
            return error.SourceChanged;
        }
        if (r.offset < captured) {
            const first: usize = @intCast(r.offset);
            const end: usize = @intCast(@min(offset, captured));
            if (!std.mem.eql(u8, captured_prefix[first..end], line.items[0 .. end - first])) {
                self.health = .resume_lost;
                return error.SourceChanged;
            }
        }
        // Both hashes derive from the same captured prefix; never adopt bytes
        // from a second read after validating the previous fingerprint.
        std.crypto.hash.sha2.Sha256.hash(captured_prefix[0..next.prefix_len], &next.prefix_hash, .{});
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(line.items, &hash, .{});
        var identity_buf: [256]u8 = undefined;
        const identity = try std.fmt.bufPrint(&identity_buf, "file:v1:{s}:{d}:{d}:{s}", .{ std.fmt.fmtSliceHexLower(&r.incarnation), r.offset, offset, std.fmt.fmtSliceHexLower(&hash) });
        const cursor = try std.json.stringifyAlloc(self.allocator, next, .{});
        defer self.allocator.free(cursor);
        if (predecoded) |decoded| if (!std.mem.eql(u8, &decoded.raw_hash, &hash)) return error.InvalidFramingResult;
        const message = if (predecoded != null) line.items else stripTerminator(self.framing, line.items);
        callback(.{ .source = self.source_id, .source_path = self.path, .occurrence = identity, .cursor = cursor, .message = message, .raw_hash = hash, .predecoded = predecoded, .byte_start = r.offset, .byte_end = offset }, userdata) catch |err| {
            self.health = .commit_failed;
            return err;
        };
        self.committed = next;
        // Observe EOF after publication: a writer may append during the
        // transaction, and that next record must retain startup mode until EOF.
        if (!self.in_operation) {
            self.pending_eof_check = true;
            self.finishEofCheck() catch {
                // This record is already committed and delivered. Expose read_failed
                // health and retry the EOF observation before the next record.
                return true;
            };
        }
        self.health = .healthy;
        return true;
    }

    fn finishEofCheck(self: *FileSource) !void {
        if (!self.pending_eof_check) return;
        var byte: [1]u8 = undefined;
        const count = self.file.?.pread(&byte, self.committed.?.offset) catch |err| {
            self.health = .read_failed;
            return err;
        };
        self.pending_eof_check = false;
        if (count == 0) self.in_operation = true;
    }
};

const testing = std.testing;
const Collector = struct {
    ids: std.ArrayList([]u8),
    lines: std.ArrayList([]u8),
    fail: bool = false,
    fn init() Collector {
        return .{ .ids = std.ArrayList([]u8).init(testing.allocator), .lines = std.ArrayList([]u8).init(testing.allocator) };
    }
    fn deinit(self: *Collector) void {
        for (self.ids.items) |s| testing.allocator.free(s);
        self.ids.deinit();
        for (self.lines.items) |s| testing.allocator.free(s);
        self.lines.deinit();
    }
    fn ack(r: records.Record, ud: ?*anyopaque) !void {
        const self: *Collector = @ptrCast(@alignCast(ud.?));
        if (self.fail) return error.CommitFailed;
        if (r.kind == .checkpoint) return;
        try self.ids.append(try testing.allocator.dupe(u8, r.occurrence));
        try self.lines.append(try testing.allocator.dupe(u8, r.message));
    }
};

test "durable file: partial records, failed commit, same-content occurrences and restart" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "input", .data = "same\nsame\npart" });
    const path = try tmp.dir.realpathAlloc(testing.allocator, "input");
    defer testing.allocator.free(path);
    var source = try FileSource.init(testing.allocator, path, "jail/source", .head, null);
    defer source.deinit();
    var c = Collector.init();
    defer c.deinit();
    c.fail = true;
    try testing.expectError(error.CommitFailed, source.poll(Collector.ack, &c));
    try testing.expectEqual(@as(u64, 0), source.committed.?.offset);
    try testing.expect(source.acknowledgedCheckpoint() == null);
    c.fail = false;
    try testing.expect(try source.poll(Collector.ack, &c));
    const checkpoint = source.committed.?;
    try testing.expect(try source.poll(Collector.ack, &c));
    try testing.expect(!std.mem.eql(u8, c.ids.items[0], c.ids.items[1]));
    try testing.expect(!try source.poll(Collector.ack, &c));
    var replay = try FileSource.init(testing.allocator, path, "jail/source", .head, checkpoint);
    defer replay.deinit();
    try testing.expect(try replay.poll(Collector.ack, &c));
    try testing.expectEqualStrings(c.ids.items[1], c.ids.items[2]);
    var f = try tmp.dir.openFile("input", .{ .mode = .write_only });
    defer f.close();
    try f.seekFromEnd(0);
    try f.writeAll("ial\n");
    try testing.expect(try source.poll(Collector.ack, &c));
    try testing.expectEqualStrings("partial", c.lines.items[3]);
}

test "durable file: replacement retains old descriptor, restart recovers rotation and rejects deleted incarnation" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "input", .data = "first\n" });
    const path = try tmp.dir.realpathAlloc(testing.allocator, "input");
    defer testing.allocator.free(path);
    var source = try FileSource.init(testing.allocator, path, "jail/source", .head, null);
    defer source.deinit();
    var c = Collector.init();
    defer c.deinit();
    try testing.expect(try source.poll(Collector.ack, &c));
    const checkpoint = source.committed.?;
    try tmp.dir.rename("input", "old");
    try tmp.dir.writeFile(.{ .sub_path = "input", .data = "replacement\n" });
    var old = try tmp.dir.openFile("old", .{ .mode = .write_only });
    defer old.close();
    try old.seekFromEnd(0);
    try old.writeAll("late\n");
    try testing.expect(try source.replaced());
    try testing.expect(try source.poll(Collector.ack, &c));
    try testing.expectEqualStrings("late", c.lines.items[1]);
    var replay = try FileSource.init(testing.allocator, path, "jail/source", .head, checkpoint);
    defer replay.deinit();
    try testing.expect(try replay.poll(Collector.ack, &c));
    try testing.expectEqualStrings("late", c.lines.items[2]);
    try tmp.dir.deleteFile("old");
    var lost = try FileSource.init(testing.allocator, path, "jail/source", .head, checkpoint);
    defer lost.deinit();
    try testing.expectError(error.ResumeLost, lost.poll(Collector.ack, &c));
    try testing.expectEqual(records.Health.resume_lost, lost.health);
}

test "durable file: tail, delayed creation and copytruncate" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir);
    const path = try std.fs.path.join(testing.allocator, &.{ dir, "input" });
    defer testing.allocator.free(path);
    var source = try FileSource.init(testing.allocator, path, "jail/source", .tail, null);
    defer source.deinit();
    var c = Collector.init();
    defer c.deinit();
    try testing.expect(!try source.poll(Collector.ack, &c));
    try testing.expectEqual(records.Health.missing, source.health);
    try tmp.dir.writeFile(.{ .sub_path = "input", .data = "history\n" });
    try testing.expect(!try source.poll(Collector.ack, &c));
    const incarnation = source.committed.?.incarnation;
    try tmp.dir.writeFile(.{ .sub_path = "input", .data = "new\n" });
    try testing.expect(try source.poll(Collector.ack, &c));
    try testing.expectEqualStrings("new", c.lines.items[0]);
    try testing.expect(!std.mem.eql(u8, &incarnation, &source.committed.?.incarnation));
}

/// Matching follows Python glob's component rules: '*' and '?' do not cross '/',
/// bracket ranges are supported, and leading '.' requires an explicit dot.
/// There is no invented exclude syntax and '**' is not recursive here.
pub fn matchComponent(pattern: []const u8, name: []const u8) bool {
    if (name.len > 0 and name[0] == '.' and (pattern.len == 0 or pattern[0] != '.')) return false;
    return matchRest(pattern, name);
}

fn glyph(bytes: []const u8, index: usize) struct { value: u32, size: usize } {
    const first = bytes[index];
    const length = std.unicode.utf8ByteSequenceLength(first) catch return .{ .value = 0xdc00 + @as(u32, first), .size = 1 };
    if (index + length > bytes.len) return .{ .value = 0xdc00 + @as(u32, first), .size = 1 };
    const value = std.unicode.utf8Decode(bytes[index .. index + length]) catch return .{ .value = 0xdc00 + @as(u32, first), .size = 1 };
    return .{ .value = value, .size = length };
}

fn matchRest(pattern: []const u8, name: []const u8) bool {
    var p: usize = 0;
    var n: usize = 0;
    var star: ?usize = null;
    var retry: usize = 0;
    while (n < name.len) {
        if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            retry = n;
            continue;
        }
        if (p < pattern.len) {
            var class_handled = false;
            if (pattern[p] == '[') {
                if (classMatch(pattern[p..], glyph(name, n).value)) |result| {
                    class_handled = true;
                    if (result.matched) {
                        p += result.consumed;
                        n += glyph(name, n).size;
                        continue;
                    }
                }
            }
            if (!class_handled and (pattern[p] == '?' or glyph(pattern, p).value == glyph(name, n).value)) {
                p += glyph(pattern, p).size;
                n += glyph(name, n).size;
                continue;
            }
        }
        if (star) |s| {
            retry += glyph(name, retry).size;
            n = retry;
            p = s + 1;
            continue;
        }
        return false;
    }
    while (p < pattern.len and pattern[p] == '*') : (p += 1) {}
    return p == pattern.len;
}

fn classMatch(pattern: []const u8, c: u32) ?struct { matched: bool, consumed: usize } {
    var i: usize = 1;
    const negate = i < pattern.len and pattern[i] == '!';
    if (negate) i += 1;
    const start = i;
    if (i < pattern.len and pattern[i] == ']') i += 1;
    while (i < pattern.len and pattern[i] != ']') : (i += 1) {}
    if (i == pattern.len or i == start) return null;
    const finish = i;
    i = start;
    var matched = false;
    while (i < finish) {
        const first = glyph(pattern, i);
        const next = i + first.size;
        if (next + 1 < finish and pattern[next] == '-') {
            const last = glyph(pattern, next + 1);
            if (c >= first.value and c <= last.value) matched = true;
            i = next + 1 + last.size;
        } else {
            if (c == first.value) matched = true;
            i = next;
        }
    }
    return .{ .matched = matched != negate, .consumed = finish + 1 };
}

pub fn expandGlob(allocator: Allocator, pattern: []const u8, limit: usize) ![][]u8 {
    var out = std.ArrayList([]u8).init(allocator);
    errdefer {
        for (out.items) |path| allocator.free(path);
        out.deinit();
    }
    try expandAt(allocator, if (std.fs.path.isAbsolute(pattern)) "/" else ".", std.mem.trimLeft(u8, pattern, "/"), &out, limit);
    std.mem.sort([]u8, out.items, {}, struct {
        fn less(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    return out.toOwnedSlice();
}

fn expandAt(allocator: Allocator, base: []const u8, remaining: []const u8, out: *std.ArrayList([]u8), limit: usize) !void {
    if (remaining.len == 0) return;
    const slash = std.mem.indexOfScalar(u8, remaining, '/');
    const component = if (slash) |s| remaining[0..s] else remaining;
    const rest = if (slash) |s| std.mem.trimLeft(u8, remaining[s + 1 ..], "/") else "";
    if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) {
        const next_base = try std.fs.path.join(allocator, &.{ base, component });
        defer allocator.free(next_base);
        return expandAt(allocator, next_base, rest, out, limit);
    }
    var dir = std.fs.cwd().openDir(base, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound or err == error.NotDir) return;
        return err;
    };
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (!matchComponent(component, entry.name)) continue;
        const path = try std.fs.path.join(allocator, &.{ base, entry.name });
        defer allocator.free(path);
        if (rest.len != 0) {
            try expandAt(allocator, path, rest, out, limit);
        } else {
            const stat = dir.statFile(entry.name) catch |err| {
                if (err == error.FileNotFound) continue;
                return err;
            };
            if (stat.kind != .file) continue;
            if (out.items.len >= limit) return error.SourceLimit;
            try out.append(try allocator.dupe(u8, path));
        }
    }
}

pub const RestoreCallback = *const fn (source_id: []const u8, userdata: ?*anyopaque) anyerror!?Resume;

/// Poll-based discovery adds newly created matching paths and retains every open
/// incarnation for late writes. Exhaustion is explicit, never eviction of unread
/// sources. Operators may remove retired sources only through a drain policy.
pub const FileSet = struct {
    const Spec = struct { pattern: []u8, start: Start };
    allocator: Allocator,
    jail: []u8,
    specs: std.ArrayList(Spec),
    sources: std.ArrayList(FileSource),
    max_sources: usize = 4096,
    framing: Framing = .bytes,
    health: records.Health = .waiting,
    restore: ?RestoreCallback = null,
    restore_userdata: ?*anyopaque = null,
    /// Configure decoding before discovery attaches a file and captures its
    /// initial cursor. The callback must leave ownership with this set.
    initialize_source: ?*const fn (*FileSource, ?*anyopaque) anyerror!void = null,
    initialize_userdata: ?*anyopaque = null,

    pub fn init(allocator: Allocator, jail: []const u8) !FileSet {
        return .{ .allocator = allocator, .jail = try allocator.dupe(u8, jail), .specs = std.ArrayList(Spec).init(allocator), .sources = std.ArrayList(FileSource).init(allocator) };
    }
    pub fn deinit(self: *FileSet) void {
        for (self.sources.items) |*source| source.deinit();
        self.sources.deinit();
        for (self.specs.items) |spec| self.allocator.free(spec.pattern);
        self.specs.deinit();
        self.allocator.free(self.jail);
    }
    pub fn add(self: *FileSet, pattern: []const u8, start: Start) !void {
        if (pattern.len == 0) return error.InvalidSource;
        const owned = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(owned);
        try self.specs.append(.{ .pattern = owned, .start = start });
    }
    /// Rehydrate every persisted source before discovery, including rotated
    /// incarnations whose current pathname no longer matches a configured glob.
    /// The coordinator verifies the source belongs to this configuration generation.
    pub fn addResume(self: *FileSet, path: []const u8, source_id: []const u8, checkpoint: Resume) !void {
        for (self.sources.items) |source| if (std.mem.eql(u8, source.source_id, source_id)) return error.DuplicateSource;
        if (self.sources.items.len >= self.max_sources) return error.SourceLimit;
        var source = try FileSource.init(self.allocator, path, source_id, .head, checkpoint);
        errdefer source.deinit();
        if (self.initialize_source) |initialize| try initialize(&source, self.initialize_userdata);
        try self.sources.append(source);
    }

    pub fn discover(self: *FileSet) !void {
        for (self.specs.items) |spec| {
            const paths = expandGlob(self.allocator, spec.pattern, self.max_sources) catch |err| {
                self.health = if (err == error.AccessDenied) .permission_denied else .read_failed;
                return err;
            };
            defer {
                for (paths) |path| self.allocator.free(path);
                self.allocator.free(paths);
            }
            for (paths) |path| {
                const f = openRegularAt(std.fs.cwd(), path) catch |err| {
                    self.health = if (err == error.AccessDenied) .permission_denied else .read_failed;
                    return err;
                };
                defer f.close();
                const stat = try std.posix.fstat(f.handle);
                const id = try std.fmt.allocPrint(self.allocator, "{s}:{s}:{d}:{d}", .{ self.jail, path, stat.dev, stat.ino });
                defer self.allocator.free(id);
                var found = false;
                for (self.sources.items) |*source| {
                    if (std.mem.eql(u8, source.source_id, id)) {
                        found = true;
                        break;
                    }
                    // Distinct configured aliases are independent inputs while
                    // both paths still name the inode. Only a disappeared or
                    // replaced old pathname identifies retained rotation here.
                    if (source.committed) |known| {
                        if (known.device == stat.dev and known.inode == stat.ino) {
                            const current = std.posix.fstatat(std.fs.cwd().fd, source.path, 0) catch |err| {
                                if (err == error.FileNotFound or err == error.NotDir) {
                                    found = true;
                                    break;
                                }
                                self.health = if (err == error.AccessDenied) .permission_denied else .read_failed;
                                return err;
                            };
                            if (current.dev != known.device or current.ino != known.inode) {
                                found = true;
                                break;
                            }
                        }
                    }
                }
                if (found) continue;
                if (self.sources.items.len >= self.max_sources) {
                    self.health = .read_failed;
                    return error.SourceLimit;
                }
                const checkpoint = if (self.restore) |restore| try restore(id, self.restore_userdata) else null;
                var source = try FileSource.init(self.allocator, path, id, spec.start, checkpoint);
                errdefer source.deinit();
                if (checkpoint == null) source.framing = self.framing;
                // Replacing a configured pathname retains its operational mode;
                // a newly configured pathname starts from its own head/tail policy.
                for (self.sources.items) |previous| {
                    if (std.mem.eql(u8, previous.path, path) and previous.in_operation) source.in_operation = true;
                }
                if (self.initialize_source) |initialize| try initialize(&source, self.initialize_userdata);
                // Attach now to prevent a rename between discovery and poll from
                // pairing this incarnation's identity with a replacement file.
                if (!try source.attach()) {
                    source.deinit();
                    continue;
                }
                const observed = source.committed.?;
                if (observed.device != stat.dev or observed.inode != stat.ino) return error.SourceChanged;
                try self.sources.append(source);
            }
        }
        self.health = if (self.sources.items.len == 0) .missing else .healthy;
    }
    pub fn poll(self: *FileSet, callback: records.AckCallback, userdata: ?*anyopaque) !usize {
        try self.discover();
        var delivered: usize = 0;
        for (self.sources.items) |*source| {
            if (source.poll(callback, userdata) catch |err| {
                self.health = source.health;
                return err;
            }) delivered += 1;
        }
        return delivered;
    }
};

test "durable file set: glob ordering, hidden files and independent rotation streams" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "b.log", .data = "b\n" });
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "a\n" });
    try tmp.dir.writeFile(.{ .sub_path = ".hidden.log", .data = "hidden\n" });
    const dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir);
    const pattern = try std.fs.path.join(testing.allocator, &.{ dir, "*.log" });
    defer testing.allocator.free(pattern);
    var set = try FileSet.init(testing.allocator, "example");
    defer set.deinit();
    try set.add(pattern, .head);
    var c = Collector.init();
    defer c.deinit();
    try testing.expectEqual(@as(usize, 2), try set.poll(Collector.ack, &c));
    try testing.expectEqualStrings("a", c.lines.items[0]);
    try testing.expectEqualStrings("b", c.lines.items[1]);
    try tmp.dir.rename("a.log", "a.old");
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "replacement\n" });
    var old = try tmp.dir.openFile("a.old", .{ .mode = .write_only });
    defer old.close();
    try old.seekFromEnd(0);
    try old.writeAll("late\n");
    try testing.expectEqual(@as(usize, 2), try set.poll(Collector.ack, &c));
    try testing.expectEqualStrings("late", c.lines.items[2]);
    try testing.expectEqualStrings("replacement", c.lines.items[3]);
    try testing.expectEqual(@as(usize, 3), set.sources.items.len);
}

test "glob: bracket classes, negative classes, dot and literal brackets" {
    try testing.expect(matchComponent("a[0-9]?.log", "a2x.log"));
    try testing.expect(matchComponent("[!a]*", "bcd"));
    try testing.expect(!matchComponent("[!a]*", "abc"));
    try testing.expect(!matchComponent("*", ".hidden"));
    try testing.expect(matchComponent(".*", ".hidden"));
    try testing.expect(matchComponent("[[]a", "[a"));
    try testing.expect(matchComponent("a[", "a["));
    try testing.expect(matchComponent("?.log", "é.log"));
    try testing.expect(matchComponent("[é-ê]x", "êx"));
    try testing.expect(!matchComponent("[é-ê]x", "ëx"));
    try testing.expect(matchComponent("*é", "été"));
}

test "durable file: UTF16 and UTF32 boundaries do not split interim newline bytes" {
    const inputs = [_]struct { framing: Framing, bytes: []const u8, first: []const u8, second: []const u8, first_end: u64 }{
        .{ .framing = .utf16le, .bytes = &.{ 0x0a, 0x01, 0x0d, 0, 0x0a, 0, 0x62, 0, 0x0a, 0 }, .first = &.{ 0x0a, 0x01 }, .second = &.{ 0x62, 0 }, .first_end = 6 },
        .{ .framing = .utf16be, .bytes = &.{ 0x01, 0x0a, 0, 0x0d, 0, 0x0a, 0, 0x62, 0, 0x0a }, .first = &.{ 0x01, 0x0a }, .second = &.{ 0, 0x62 }, .first_end = 6 },
        .{ .framing = .utf32le, .bytes = &.{ 0x0a, 0x01, 0, 0, 0x0a, 0, 0, 0, 0x62, 0, 0, 0, 0x0a, 0, 0, 0 }, .first = &.{ 0x0a, 0x01, 0, 0 }, .second = &.{ 0x62, 0, 0, 0 }, .first_end = 8 },
        .{ .framing = .utf32be, .bytes = &.{ 0, 0, 0x01, 0x0a, 0, 0, 0, 0x0a, 0, 0, 0, 0x62, 0, 0, 0, 0x0a }, .first = &.{ 0, 0, 0x01, 0x0a }, .second = &.{ 0, 0, 0, 0x62 }, .first_end = 8 },
    };
    for (inputs) |input| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(.{ .sub_path = "input", .data = input.bytes });
        const path = try tmp.dir.realpathAlloc(testing.allocator, "input");
        defer testing.allocator.free(path);
        var source = try FileSource.init(testing.allocator, path, "encoding", .head, null);
        defer source.deinit();
        source.framing = input.framing;
        var c = Collector.init();
        defer c.deinit();
        try testing.expect(try source.poll(Collector.ack, &c));
        try testing.expectEqualStrings(input.first, c.lines.items[0]);
        try testing.expectEqual(input.first_end, source.committed.?.offset);
        const checkpoint = source.committed.?;
        var restarted = try FileSource.init(testing.allocator, path, "encoding", .head, checkpoint);
        defer restarted.deinit();
        try testing.expect(try restarted.poll(Collector.ack, &c));
        try testing.expectEqualStrings(input.second, c.lines.items[1]);
        try testing.expectEqual(input.framing, restarted.committed.?.framing);
    }
}

test "durable file: data commit failure and overlong record cannot advance consumption" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "input", .data = "first\nsecond\n" });
    const path = try tmp.dir.realpathAlloc(testing.allocator, "input");
    defer testing.allocator.free(path);
    var source = try FileSource.init(testing.allocator, path, "bounded", .head, null);
    defer source.deinit();
    var c = Collector.init();
    defer c.deinit();
    try testing.expect(try source.poll(Collector.ack, &c));
    const checkpoint = source.committed.?;
    c.fail = true;
    try testing.expectError(error.CommitFailed, source.poll(Collector.ack, &c));
    try testing.expectEqual(checkpoint.offset, source.committed.?.offset);
    try testing.expectEqual(records.Health.commit_failed, source.health);
    c.fail = false;
    source.max_record_bytes = 3;
    try testing.expectError(error.RecordTooLong, source.poll(Collector.ack, &c));
    try testing.expectEqual(checkpoint.offset, source.committed.?.offset);
    try testing.expectEqual(records.Health.record_too_long, source.health);
    source.max_record_bytes = 1024;
    try testing.expect(try source.poll(Collector.ack, &c));
    try testing.expectEqualStrings("second", c.lines.items[1]);
}

test "durable file set: renamed file still matching glob is not ingested twice" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "old\n" });
    const dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir);
    const pattern = try std.fs.path.join(testing.allocator, &.{ dir, "*.log*" });
    defer testing.allocator.free(pattern);
    var set = try FileSet.init(testing.allocator, "example");
    defer set.deinit();
    try set.add(pattern, .head);
    var c = Collector.init();
    defer c.deinit();
    try testing.expectEqual(@as(usize, 1), try set.poll(Collector.ack, &c));
    try tmp.dir.rename("a.log", "a.log.1");
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "new\n" });
    try testing.expectEqual(@as(usize, 1), try set.poll(Collector.ack, &c));
    try testing.expectEqual(@as(usize, 2), set.sources.items.len);
    try testing.expectEqualStrings("new", c.lines.items[1]);
}

test "durable file set: configured hardlink aliases retain independent positions" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "original neutral\n" });
    try std.posix.linkat(tmp.dir.fd, "a.log", tmp.dir.fd, "b.log", 0);
    const dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir);
    const pattern = try std.fs.path.join(testing.allocator, &.{ dir, "*.log" });
    defer testing.allocator.free(pattern);
    var set = try FileSet.init(testing.allocator, "aliases");
    defer set.deinit();
    try set.add(pattern, .head);
    try set.add(pattern, .head); // overlapping globs do not register a path twice
    var c = Collector.init();
    defer c.deinit();
    try testing.expectEqual(@as(usize, 2), try set.poll(Collector.ack, &c));
    try testing.expectEqual(@as(usize, 2), set.sources.items.len);
    try testing.expectEqualStrings("original neutral", c.lines.items[0]);
    try testing.expectEqualStrings("original neutral", c.lines.items[1]);
    try testing.expectEqual(@as(usize, 0), try set.poll(Collector.ack, &c));
    var file = try tmp.dir.openFile("a.log", .{ .mode = .write_only });
    defer file.close();
    try file.seekFromEnd(0);
    try file.writeAll("later\n");
    try testing.expectEqual(@as(usize, 2), try set.poll(Collector.ack, &c));
    try testing.expectEqualStrings("later", c.lines.items[2]);
    try testing.expectEqualStrings("later", c.lines.items[3]);
}
