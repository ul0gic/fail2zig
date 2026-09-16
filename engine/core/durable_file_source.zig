// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const linux_dupfd_cloexec = 1030;
const records = @import("source_record.zig");
const native_text = @import("source_text.zig");
const Allocator = std.mem.Allocator;
pub const Start = enum { head, tail };
pub const discovery_entries_per_turn: usize = 256;
pub const discovery_entries_per_episode: usize = 65_536;
pub const discovery_max_depth: usize = 16;
pub const DiscoveryStatus = enum { pending, complete };
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

pub const FileSource = struct {
    const ResumeSearch = struct {
        directory: std.fs.Dir,
        iterator: std.fs.Dir.Iterator,
        visited: usize = 0,
    };
    allocator: Allocator,
    path: []const u8,
    source_id: []const u8,
    file: ?std.fs.File = null,
    start: Start,
    committed: ?Resume = null,
    health: records.Health = .waiting,
    baseline_committed: bool = false,
    in_operation: bool = false,
    pending_eof_check: bool = false,
    framing: Framing = .bytes,
    max_record_bytes: usize = 1024 * 1024,
    frame_callback: ?records.FrameCallback = null,
    frame_context: ?*anyopaque = null,
    codec_configuration_hash: ?[32]u8 = null,
    native_encoding: ?native_text.Encoding = null,
    resume_search: ?ResumeSearch = null,
    read_prefix: *const fn (std.fs.File, u8) anyerror![32]u8 = prefix,

    pub fn framingBinding(encoding: native_text.Encoding, configuration_hash: [32]u8, max_bytes: usize) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-native-framing-v1\x00");
        hash.update(&configuration_hash);
        hash.update(@tagName(encoding));
        var limit: [4]u8 = undefined;
        std.mem.writeInt(u32, &limit, @intCast(max_bytes), .little);
        hash.update(&limit);
        var binding: [32]u8 = undefined;
        hash.final(&binding);
        return binding;
    }
    pub fn setNativeFraming(self: *FileSource, encoding: native_text.Encoding, configuration_hash: [32]u8, max_bytes: usize) !void {
        if (max_bytes < encoding.width() or max_bytes > native_text.max_record_bytes) return error.InvalidFramingLimit;
        if (self.file != null) return error.SourceAlreadyOpened;
        if (self.frame_callback != null) return error.FramerAlreadyBound;
        const binding = framingBinding(encoding, configuration_hash, max_bytes);
        const framing: Framing = switch (encoding) {
            .utf8, .ascii, .latin1 => .bytes,
            .utf16le => .utf16le,
            .utf16be => .utf16be,
            .utf32le => .utf32le,
            .utf32be => .utf32be,
        };
        if (self.committed) |saved| {
            const previous = saved.codec_configuration_hash orelse return error.FramingProfileMismatch;
            if (!std.mem.eql(u8, &previous, &binding) or saved.framing != framing) return error.FramingProfileMismatch;
            if (saved.offset % encoding.width() != 0) return error.MisalignedOffset;
        }
        self.native_encoding = encoding;
        self.framing = framing;
        self.codec_configuration_hash = binding;
        self.max_record_bytes = max_bytes;
    }

    pub fn setFramer(self: *FileSource, callback: records.FrameCallback, context: ?*anyopaque, configuration_hash: [32]u8, max_bytes: usize) !void {
        if (max_bytes == 0 or max_bytes > 1024 * 1024) return error.InvalidFramingLimit;
        if (self.file != null) return error.SourceAlreadyOpened;
        if (self.native_encoding != null) return error.FramerAlreadyBound;
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
        if (path.len == 0 or path.len > 16 * 1024 or source_id.len == 0 or source_id.len > 16 * 1024 or
            std.mem.indexOfScalar(u8, path, 0) != null or std.mem.indexOfScalar(u8, source_id, 0) != null) return error.InvalidSource;
        if (checkpoint) |r| if (r.version != 2 or r.prefix_len > 64) return error.InvalidResume;
        const owned_path = try allocator.dupe(u8, path);
        errdefer allocator.free(owned_path);
        return .{ .allocator = allocator, .path = owned_path, .source_id = try allocator.dupe(u8, source_id), .start = if (checkpoint) |r| r.start else start, .in_operation = start == .tail, .committed = checkpoint, .baseline_committed = checkpoint != null, .framing = if (checkpoint) |r| r.framing else .bytes };
    }

    pub fn acknowledgedCheckpoint(self: *const FileSource) ?Resume {
        return if (self.baseline_committed) self.committed else null;
    }

    pub fn deinit(self: *FileSource) void {
        self.clearResumeSearch();
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
            if (stat.dev == expected.device and stat.ino == expected.inode) {
                self.clearResumeSearch();
                return f;
            }
            f.close();
        }
        if (self.resume_search == null) {
            var parent = std.fs.cwd().openDir(std.fs.path.dirname(self.path) orelse ".", .{ .iterate = true }) catch |err| {
                if (err == error.FileNotFound) return error.ResumeLost;
                return err;
            };
            self.resume_search = .{ .directory = parent, .iterator = parent.iterate() };
        }
        var yielded = false;
        defer if (!yielded) self.clearResumeSearch();
        const search = &self.resume_search.?;
        for (0..discovery_entries_per_turn) |_| {
            const entry = (try search.iterator.next()) orelse {
                self.clearResumeSearch();
                return error.ResumeLost;
            };
            if (search.visited >= discovery_entries_per_episode) return error.DiscoveryEntryLimit;
            search.visited += 1;
            const observed = std.posix.fstatat(search.directory.fd, entry.name, 0) catch |err| {
                if (err == error.FileNotFound) continue;
                return err;
            };
            if (!std.posix.S.ISREG(observed.mode) or observed.dev != expected.device or observed.ino != expected.inode) continue;
            const f = openRegularAt(search.directory, entry.name) catch |err| {
                if (err == error.FileNotFound or err == error.NotRegularFile) continue;
                return err;
            };
            const stat = std.posix.fstat(f.handle) catch |err| {
                f.close();
                return err;
            };
            if (std.posix.S.ISREG(stat.mode) and stat.dev == expected.device and stat.ino == expected.inode) {
                self.clearResumeSearch();
                return f;
            }
            f.close();
        }
        yielded = true;
        return error.SourceRepairPending;
    }

    fn clearResumeSearch(self: *FileSource) void {
        if (self.resume_search) |*search| search.directory.close();
        self.resume_search = null;
    }

    fn attachTurn(self: *FileSource) !bool {
        if (self.file != null) return true;
        const f = (self.openIncarnation() catch |err| {
            self.health = switch (err) {
                error.FileNotFound => .missing,
                error.AccessDenied => .permission_denied,
                error.ResumeLost => .resume_lost,
                error.SourceRepairPending => .waiting,
                else => .read_failed,
            };
            return err;
        }) orelse {
            self.health = .missing;
            return false;
        };
        try self.acceptDescriptor(f);
        return true;
    }

    fn acceptDescriptor(self: *FileSource, f: std.fs.File) !void {
        errdefer f.close();
        const stat = try std.posix.fstat(f.handle);
        if (!std.posix.S.ISREG(stat.mode)) return error.NotRegularFile;
        if (self.committed) |r| {
            const fingerprint = self.read_prefix(f, r.prefix_len) catch |err| {
                self.health = if (err == error.ResumeLost) .resume_lost else .read_failed;
                return err;
            };
            if (r.device != stat.dev or r.inode != stat.ino or stat.size < 0 or @as(u64, @intCast(stat.size)) < r.offset or !std.mem.eql(u8, &fingerprint, &r.prefix_hash)) {
                self.health = .resume_lost;
                return error.ResumeLost;
            }
        } else {
            const offset: u64 = if (self.start == .tail) @intCast(stat.size) else 0;
            if (self.native_encoding) |encoding| if (offset % encoding.width() != 0) {
                self.health = .malformed_record;
                return error.MisalignedOffset;
            };
            self.committed = try newResume(f, offset, self.framing, self.start);
            self.committed.?.codec_configuration_hash = self.codec_configuration_hash;
        }
        self.file = f;
        self.health = .healthy;
    }

    pub fn attachRetained(self: *FileSource, retained: std.fs.File) !void {
        if (self.file != null) return;
        if (self.committed == null) return error.MissingFileCheckpoint;
        const fd = try std.posix.fcntl(retained.handle, linux_dupfd_cloexec, 3);
        try self.acceptDescriptor(.{ .handle = @intCast(fd) });
    }

    pub fn verifyContinuity(self: *FileSource) !bool {
        while (true) {
            return self.verifyContinuityTurn() catch |err| {
                if (err == error.SourceRepairPending) continue;
                return err;
            };
        }
    }

    pub fn verifyContinuityTurn(self: *FileSource) !bool {
        if (self.committed) |r| if (r.codec_configuration_hash != null and self.frame_callback == null and self.native_encoding == null)
            return error.FramingProfileMismatch;
        if (!try self.attachTurn()) return false;
        const file = self.file.?;
        const r = self.committed.?;
        const stat = std.posix.fstat(file.handle) catch |err| {
            self.health = .read_failed;
            return err;
        };
        const fingerprint = self.read_prefix(file, r.prefix_len) catch |err| {
            self.health = if (err == error.ResumeLost) .resume_lost else .read_failed;
            return err;
        };
        if (!std.posix.S.ISREG(stat.mode) or stat.dev != r.device or stat.ino != r.inode or
            stat.size < 0 or @as(u64, @intCast(stat.size)) < r.offset or
            !std.mem.eql(u8, &fingerprint, &r.prefix_hash))
        {
            self.health = .resume_lost;
            return error.ResumeLost;
        }
        self.health = .healthy;
        return true;
    }

    pub fn verifyExistingContinuity(self: *FileSource) !void {
        if (self.acknowledgedCheckpoint() == null) return error.MissingFileCheckpoint;
        if (!try self.verifyContinuityTurn()) return error.ResumeLost;
    }

    pub const PendingIdentity = struct {
        source: []const u8,
        occurrence: []const u8,
        cursor: []const u8,
        raw_hash: [32]u8,
    };

    pub fn verifyPending(self: *FileSource, expected: PendingIdentity) !void {
        try self.verifyExistingContinuity();
        const saved = self.committed;
        const baseline = self.baseline_committed;
        const operational = self.in_operation;
        const eof_check = self.pending_eof_check;
        defer {
            self.committed = saved;
            self.baseline_committed = baseline;
            self.in_operation = operational;
            self.pending_eof_check = eof_check;
        }
        const Probe = struct {
            fn verify(record: records.Record, context: ?*anyopaque) !void {
                const identity: *const PendingIdentity = @ptrCast(@alignCast(context.?));
                if (record.kind != .data or !std.mem.eql(u8, record.source, identity.source) or
                    !std.mem.eql(u8, record.occurrence, identity.occurrence) or
                    !std.mem.eql(u8, record.cursor, identity.cursor) or
                    !std.mem.eql(u8, &record.raw_hash, &identity.raw_hash)) return error.PendingRecordMismatch;
                return error.PendingRecordVerified;
            }
        };
        var identity = expected;
        _ = self.pollTurn(Probe.verify, &identity, true) catch |err| {
            if (err != error.PendingRecordVerified) return err;
            self.health = .healthy;
            return;
        };
        return error.PendingRecordUnavailable;
    }

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

    pub fn poll(self: *FileSource, callback: records.AckCallback, userdata: ?*anyopaque) !bool {
        while (true) return self.pollTurn(callback, userdata, false) catch |err| {
            if (err == error.SourceRepairPending) continue;
            return err;
        };
    }
    pub fn pollTurn(self: *FileSource, callback: records.AckCallback, userdata: ?*anyopaque, preserve_checkpoint: bool) !bool {
        if (self.committed) |saved_resume| if (saved_resume.codec_configuration_hash != null and self.frame_callback == null and self.native_encoding == null) return error.FramingProfileMismatch;
        if (!try self.attachTurn()) return false;
        try self.finishEofCheck();
        const f = self.file.?;
        var r = self.committed.?;
        const stat = try f.stat();
        const shrunk = stat.size < r.offset or stat.size < r.prefix_len;
        const fingerprint = if (shrunk) r.prefix_hash else self.read_prefix(f, r.prefix_len) catch |err| {
            self.health = if (err == error.ResumeLost) .resume_lost else .read_failed;
            return err;
        };
        if (shrunk or !std.mem.eql(u8, &fingerprint, &r.prefix_hash)) {
            if (preserve_checkpoint) {
                self.health = .resume_lost;
                return error.ResumeLost;
            }
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
        var native_payload_len: ?usize = null;
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
            } else if (self.native_encoding) |encoding| {
                const framed = native_text.frame(encoding, line.items, r.offset) catch |err| {
                    self.health = .malformed_record;
                    return err;
                };
                if (framed) |result| {
                    native_payload_len = result.payload.len;
                    line.shrinkRetainingCapacity(result.consumed);
                    offset = r.offset + result.consumed;
                    break;
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
            _ = frame_arena.reset(.retain_capacity);
        }

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
        std.crypto.hash.sha2.Sha256.hash(captured_prefix[0..next.prefix_len], &next.prefix_hash, .{});
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(line.items, &hash, .{});
        var identity_buf: [256]u8 = undefined;
        const identity = try std.fmt.bufPrint(&identity_buf, "file:v1:{s}:{d}:{d}:{s}", .{ std.fmt.fmtSliceHexLower(&r.incarnation), r.offset, offset, std.fmt.fmtSliceHexLower(&hash) });
        const cursor = try std.json.stringifyAlloc(self.allocator, next, .{});
        defer self.allocator.free(cursor);
        if (predecoded) |decoded| if (!std.mem.eql(u8, &decoded.raw_hash, &hash)) return error.InvalidFramingResult;
        const message = if (native_payload_len) |length| line.items[0..length] else if (predecoded != null) line.items else stripTerminator(self.framing, line.items);
        callback(.{ .source = self.source_id, .source_path = self.path, .occurrence = identity, .cursor = cursor, .message = message, .raw_hash = hash, .predecoded = predecoded, .byte_start = r.offset, .byte_end = offset }, userdata) catch |err| {
            self.health = .commit_failed;
            return err;
        };
        self.committed = next;
        if (!self.in_operation) {
            self.pending_eof_check = true;
            self.finishEofCheck() catch {
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

test "durable file: recovery detects truncation on retained descriptors without resetting the cursor" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "input", .data = "ordinary first event\nordinary unread event\n" });
    const path = try tmp.dir.realpathAlloc(testing.allocator, "input");
    defer testing.allocator.free(path);
    var source = try FileSource.init(testing.allocator, path, "fixture", .head, null);
    defer source.deinit();
    var collector = Collector.init();
    defer collector.deinit();
    try testing.expect(try source.poll(Collector.ack, &collector));
    const saved = source.acknowledgedCheckpoint().?;
    try testing.expect(try source.verifyContinuity());
    try tmp.dir.writeFile(.{ .sub_path = "input", .data = "new\n" });
    try testing.expectError(error.ResumeLost, source.verifyContinuity());
    try testing.expectEqual(records.Health.resume_lost, source.health);
    try testing.expectEqualDeep(saved, source.acknowledgedCheckpoint().?);
    try testing.expectEqual(@as(usize, 1), collector.lines.items.len);
}

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
    var discovery = try Discovery.init(allocator, pattern, limit);
    defer discovery.deinit();
    while (try discovery.pollTurn(discovery_entries_per_turn) != .complete) {}
    return discovery.takePaths();
}

pub const Discovery = struct {
    const Frame = struct {
        directory: std.fs.Dir,
        iterator: std.fs.Dir.Iterator,
        base: []u8,
        component: usize,
        direct_done: bool = false,
    };
    allocator: Allocator,
    pattern: []u8,
    components: [discovery_max_depth][]const u8 = undefined,
    component_count: usize = 0,
    frames: [discovery_max_depth]Frame = undefined,
    depth: usize = 0,
    paths: std.ArrayList([]u8),
    max_paths: usize,
    visited: usize = 0,
    max_entries: usize = discovery_entries_per_episode,
    complete: bool = false,
    failure: ?anyerror = null,

    pub fn init(allocator: Allocator, pattern: []const u8, max_paths: usize) !Discovery {
        if (pattern.len == 0 or pattern.len > 16 * 1024 or std.mem.indexOfScalar(u8, pattern, 0) != null) return error.InvalidSource;
        if (max_paths == 0 or max_paths > 4096) return error.SourceLimit;
        const owned = try allocator.dupe(u8, pattern);
        var self = Discovery{ .allocator = allocator, .pattern = owned, .paths = std.ArrayList([]u8).init(allocator), .max_paths = max_paths };
        errdefer self.deinit();
        var parts = std.mem.tokenizeScalar(u8, owned, '/');
        while (parts.next()) |part| {
            if (self.component_count == discovery_max_depth) return error.DiscoveryDepthLimit;
            self.components[self.component_count] = part;
            self.component_count += 1;
        }
        if (self.component_count == 0) {
            self.complete = true;
        } else _ = try self.push(if (std.fs.path.isAbsolute(pattern)) "/" else ".", 0);
        return self;
    }

    fn push(self: *Discovery, base: []const u8, component: usize) !bool {
        if (self.depth == discovery_max_depth) return error.DiscoveryDepthLimit;
        const owned = try self.allocator.dupe(u8, base);
        errdefer self.allocator.free(owned);
        var directory = std.fs.cwd().openDir(base, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound or err == error.NotDir) {
                self.allocator.free(owned);
                return false;
            }
            return err;
        };
        self.frames[self.depth] = .{ .directory = directory, .iterator = directory.iterate(), .base = owned, .component = component };
        self.depth += 1;
        return true;
    }

    fn pop(self: *Discovery) void {
        self.depth -= 1;
        const frame = &self.frames[self.depth];
        frame.directory.close();
        self.allocator.free(frame.base);
    }

    pub fn deinit(self: *Discovery) void {
        while (self.depth > 0) self.pop();
        for (self.paths.items) |path| self.allocator.free(path);
        self.paths.deinit();
        self.allocator.free(self.pattern);
    }

    pub fn pollTurn(self: *Discovery, budget: usize) !DiscoveryStatus {
        if (budget == 0 or budget > discovery_entries_per_turn or self.max_entries > discovery_entries_per_episode) return error.InvalidDiscoveryBudget;
        if (self.failure) |failure| return failure;
        if (self.complete) return .complete;
        return self.pollAdmitted(budget) catch |err| {
            self.failure = err;
            while (self.depth > 0) self.pop();
            return err;
        };
    }

    fn pollAdmitted(self: *Discovery, budget: usize) !DiscoveryStatus {
        var work: usize = 0;
        while (self.depth > 0 and work < budget) {
            work += 1;
            const frame = &self.frames[self.depth - 1];
            const component = self.components[frame.component];
            const direct = std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..");
            const name = if (direct) blk: {
                if (frame.direct_done) {
                    self.pop();
                    continue;
                }
                frame.direct_done = true;
                break :blk component;
            } else blk: {
                const entry = (try frame.iterator.next()) orelse {
                    self.pop();
                    continue;
                };
                if (self.visited >= self.max_entries) return error.DiscoveryEntryLimit;
                self.visited += 1;
                if (!matchComponent(component, entry.name)) continue;
                break :blk entry.name;
            };
            const path = try std.fs.path.join(self.allocator, &.{ frame.base, name });
            defer self.allocator.free(path);
            if (frame.component + 1 < self.component_count) {
                _ = try self.push(path, frame.component + 1);
            } else {
                const stat = frame.directory.statFile(name) catch |err| {
                    if (err == error.FileNotFound or err == error.NotDir) continue;
                    return err;
                };
                if (stat.kind != .file) continue;
                if (self.paths.items.len == self.max_paths) return error.SourceLimit;
                const owned_path = try self.allocator.dupe(u8, path);
                errdefer self.allocator.free(owned_path);
                try self.paths.append(owned_path);
            }
        }
        if (self.depth != 0) return .pending;
        std.mem.sort([]u8, self.paths.items, {}, struct {
            fn less(_: void, a: []u8, b: []u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);
        self.complete = true;
        return .complete;
    }

    pub fn takePaths(self: *Discovery) ![][]u8 {
        if (self.failure) |failure| return failure;
        if (!self.complete) return error.DiscoveryIncomplete;
        return self.paths.toOwnedSlice();
    }
};

pub const RestoreCallback = *const fn (source_id: []const u8, userdata: ?*anyopaque) anyerror!?Resume;

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
    initialize_source: ?*const fn (*FileSource, ?*anyopaque) anyerror!void = null,
    initialize_userdata: ?*anyopaque = null,
    discovery: ?Discovery = null,
    discovery_spec: usize = 0,
    discovery_path: usize = 0,
    discovery_visited: usize = 0,

    pub fn init(allocator: Allocator, jail: []const u8) !FileSet {
        return .{ .allocator = allocator, .jail = try allocator.dupe(u8, jail), .specs = std.ArrayList(Spec).init(allocator), .sources = std.ArrayList(FileSource).init(allocator) };
    }
    pub fn deinit(self: *FileSet) void {
        self.cancelDiscovery();
        for (self.sources.items) |*source| source.deinit();
        self.sources.deinit();
        for (self.specs.items) |spec| self.allocator.free(spec.pattern);
        self.specs.deinit();
        self.allocator.free(self.jail);
    }
    pub fn add(self: *FileSet, pattern: []const u8, start: Start) !void {
        if (self.discovery != null or self.discovery_spec != 0) return error.DiscoveryInProgress;
        if (pattern.len == 0 or pattern.len > 16 * 1024) return error.InvalidSource;
        if (self.specs.items.len >= self.max_sources) return error.SourceLimit;
        const owned = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(owned);
        try self.specs.append(.{ .pattern = owned, .start = start });
    }
    pub fn addResume(self: *FileSet, path: []const u8, source_id: []const u8, checkpoint: Resume) !void {
        for (self.sources.items) |source| if (std.mem.eql(u8, source.source_id, source_id)) return error.DuplicateSource;
        if (self.sources.items.len >= self.max_sources) return error.SourceLimit;
        var source = try FileSource.init(self.allocator, path, source_id, .head, checkpoint);
        errdefer source.deinit();
        if (self.initialize_source) |initialize| try initialize(&source, self.initialize_userdata);
        try self.sources.append(source);
    }

    pub fn addProposal(self: *FileSet, path: []const u8, source_id: []const u8, proposal: Resume) !void {
        try self.addResume(path, source_id, proposal);
        self.sources.items[self.sources.items.len - 1].baseline_committed = false;
    }

    pub fn discover(self: *FileSet) !void {
        while (try self.discoverTurn() != .complete) {}
    }

    pub fn cancelDiscovery(self: *FileSet) void {
        if (self.discovery) |*discovery| discovery.deinit();
        self.discovery = null;
        self.discovery_spec = 0;
        self.discovery_path = 0;
        self.discovery_visited = 0;
    }

    pub fn discoverTurn(self: *FileSet) !DiscoveryStatus {
        errdefer |err| {
            self.health = if (err == error.AccessDenied) .permission_denied else .read_failed;
            self.cancelDiscovery();
        }
        if (self.discovery_spec == self.specs.items.len) {
            self.cancelDiscovery();
            self.health = if (self.sources.items.len == 0) .missing else .healthy;
            return .complete;
        }
        const spec = self.specs.items[self.discovery_spec];
        if (self.discovery == null) {
            self.discovery = try Discovery.init(self.allocator, spec.pattern, self.max_sources);
            self.discovery.?.max_entries = discovery_entries_per_episode - self.discovery_visited;
            self.discovery_path = 0;
        }
        const discovery = &self.discovery.?;
        if (!discovery.complete) {
            _ = try discovery.pollTurn(discovery_entries_per_turn);
            return .pending;
        }
        if (self.discovery_path < discovery.paths.items.len) {
            try self.admitDiscovered(discovery.paths.items[self.discovery_path], spec.start);
            self.discovery_path += 1;
            return .pending;
        }
        self.discovery_visited += discovery.visited;
        discovery.deinit();
        self.discovery = null;
        self.discovery_spec += 1;
        return .pending;
    }

    fn admitDiscovered(self: *FileSet, path: []const u8, start: Start) !void {
        const f = openRegularAt(std.fs.cwd(), path) catch |err| {
            self.health = if (err == error.AccessDenied) .permission_denied else .read_failed;
            return err;
        };
        var owns_descriptor = true;
        defer if (owns_descriptor) f.close();
        const stat = try std.posix.fstat(f.handle);
        const id = try std.fmt.allocPrint(self.allocator, "{s}:{s}:{d}:{d}", .{ self.jail, path, stat.dev, stat.ino });
        defer self.allocator.free(id);
        var found = false;
        for (self.sources.items) |*source| {
            if (std.mem.eql(u8, source.source_id, id)) {
                found = true;
                break;
            }
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
        if (found) return;
        if (self.sources.items.len >= self.max_sources) {
            self.health = .read_failed;
            return error.SourceLimit;
        }
        try self.sources.ensureUnusedCapacity(1);
        const checkpoint = if (self.restore) |restore| try restore(id, self.restore_userdata) else null;
        var source = try FileSource.init(self.allocator, path, id, start, checkpoint);
        errdefer source.deinit();
        if (checkpoint == null) source.framing = self.framing;
        for (self.sources.items) |previous| {
            if (std.mem.eql(u8, previous.path, path) and previous.in_operation) source.in_operation = true;
        }
        if (self.initialize_source) |initialize| try initialize(&source, self.initialize_userdata);
        owns_descriptor = false;
        try source.acceptDescriptor(f);
        const observed = source.committed.?;
        if (observed.device != stat.dev or observed.inode != stat.ino) return error.SourceChanged;
        self.sources.appendAssumeCapacity(source);
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
    try set.add(pattern, .head);
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
