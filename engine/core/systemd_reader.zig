// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const builtin = @import("builtin");
const record_mod = @import("source_record.zig");
const Allocator = std.mem.Allocator;
const Journal = opaque {};
const Open = *const fn (*?*Journal, c_int) callconv(.c) c_int;
const OpenNamespace = *const fn (*?*Journal, [*:0]const u8, c_int) callconv(.c) c_int;
const OpenDirectory = *const fn (*?*Journal, [*:0]const u8, c_int) callconv(.c) c_int;
const OpenFiles = *const fn (*?*Journal, [*:null]const ?[*:0]const u8, c_int) callconv(.c) c_int;
const Close = *const fn (*Journal) callconv(.c) void;
const Move = *const fn (*Journal) callconv(.c) c_int;
const SeekCursor = *const fn (*Journal, [*:0]const u8) callconv(.c) c_int;
const GetCursor = *const fn (*Journal, *?[*:0]u8) callconv(.c) c_int;
const RestartData = *const fn (*Journal) callconv(.c) void;
const EnumerateData = *const fn (*Journal, *?*const anyopaque, *usize) callconv(.c) c_int;
const GetData = *const fn (*Journal, [*:0]const u8, *?*const anyopaque, *usize) callconv(.c) c_int;
const Id128 = extern struct { bytes: [16]u8 };
const GetMonotonic = *const fn (*Journal, *u64, *Id128) callconv(.c) c_int;
const SeekTime = *const fn (*Journal, u64) callconv(.c) c_int;
const GetTime = *const fn (*Journal, *u64) callconv(.c) c_int;
const Match = *const fn (*Journal, ?*const anyopaque, usize) callconv(.c) c_int;
const Threshold = *const fn (*Journal, usize) callconv(.c) c_int;
const Free = *const fn (?*anyopaque) callconv(.c) void;

pub const Selection = struct {
    flags: u32 = 4,
    namespace: ?[]const u8 = null,
    directory: ?[]const u8 = null,
    files: ?[]const []const u8 = null,
    matches: []const []const u8 = &.{},
    pub fn validate(self: Selection) !void {
        if (self.flags > std.math.maxInt(c_int)) return error.InvalidFlags;
        if (self.directory != null and self.files != null) return error.ConflictingJournalSelection;
        if (self.namespace != null and (self.directory != null or self.files != null)) return error.ConflictingJournalSelection;
        var total: usize = 0;
        for ([_]?[]const u8{ self.namespace, self.directory }) |maybe| if (maybe) |value| {
            if (value.len > 4096 or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidJournalSelection;
            total += value.len;
        };
        if (self.files) |paths| {
            if (paths.len > 4096) return error.JournalSelectionLimit;
            for (paths) |path| {
                if (path.len > 4096 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidJournalSelection;
                total += path.len;
            }
        }
        if (self.matches.len > 4096) return error.JournalSelectionLimit;
        for (self.matches) |m| {
            if (m.len > 65536) return error.JournalSelectionLimit;
            total += m.len;
        }
        if (total > 1024 * 1024) return error.JournalSelectionLimit;
        var need_match = true;
        for (self.matches) |m| {
            if (std.mem.eql(u8, m, "+")) {
                if (need_match) return error.InvalidMatch;
                need_match = true;
            } else {
                const eq = std.mem.indexOfScalar(u8, m, '=') orelse return error.InvalidMatch;
                if (eq == 0 or std.mem.indexOfScalar(u8, m, 0) != null) return error.InvalidMatch;
                for (m[0..eq]) |c| if (!(std.ascii.isUpper(c) or std.ascii.isDigit(c) or c == '_')) return error.InvalidMatch;
                need_match = false;
            }
        }
        if (self.matches.len > 0 and need_match) return error.InvalidMatch;
    }
};

const Api = struct {
    lib: std.DynLib,
    open: Open,
    open_namespace: ?OpenNamespace,
    open_directory: OpenDirectory,
    open_files: OpenFiles,
    close: Close,
    next: Move,
    previous: Move,
    seek_head: Move,
    seek_realtime_usec: SeekTime,
    seek_tail: Move,
    process: Move,
    seek_cursor: SeekCursor,
    test_cursor: SeekCursor,
    get_cursor: GetCursor,
    get_data: GetData,
    restart_data: RestartData,
    enumerate_data: EnumerateData,
    get_realtime_usec: GetTime,
    get_monotonic_usec: GetMonotonic,
    add_match: Match,
    add_disjunction: Move,
    set_data_threshold: Threshold,
    free: Free,

    fn load() !Api {
        if (builtin.os.tag != .linux or !builtin.link_libc or builtin.abi.isMusl()) return error.UnsupportedFullProfile;
        var lib = std.DynLib.open("libsystemd.so.0") catch return error.SystemdUnavailable;
        errdefer lib.close();
        var api: Api = undefined;
        api.lib = lib;
        inline for (std.meta.fields(Api)) |field| {
            if (comptime std.mem.eql(u8, field.name, "lib")) continue;
            if (comptime std.mem.eql(u8, field.name, "open_namespace")) {
                api.open_namespace = api.lib.lookup(OpenNamespace, "sd_journal_open_namespace");
            } else if (comptime std.mem.eql(u8, field.name, "free")) {
                api.free = api.lib.lookup(Free, "free") orelse return error.SystemdSymbolMissing;
            } else {
                @field(api, field.name) = api.lib.lookup(field.type, "sd_journal_" ++ field.name) orelse return error.SystemdSymbolMissing;
            }
        }
        return api;
    }
};

pub const Reader = struct {
    allocator: Allocator,
    api: Api,
    journal: *Journal,
    source_id: []u8,
    committed_cursor: ?[:0]u8 = null,
    health: record_mod.Health = .waiting,
    initialized: bool = false,
    pending_cursor: ?[:0]u8 = null,
    pending_checkpoint: bool = false,
    start: enum { head, tail, realtime } = .head,
    start_realtime_us: u64 = 0,
    max_record_bytes: usize = 1024 * 1024,

    pub fn init(allocator: Allocator, source_id: []const u8, selection: Selection, checkpoint: ?[]const u8) !Reader {
        try selection.validate();
        if (source_id.len == 0 or source_id.len > 16384 or std.mem.indexOfScalar(u8, source_id, 0) != null) return error.InvalidSource;
        if (checkpoint) |c| if (c.len == 0 or c.len > 65536 or std.mem.indexOfScalar(u8, c, 0) != null) return error.InvalidCheckpoint;
        var api = try Api.load();
        errdefer api.lib.close();
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var handle: ?*Journal = null;
        const flags: c_int = @intCast(selection.flags);
        const result = if (selection.namespace) |namespace| blk: {
            const open_namespace = api.open_namespace orelse return error.NamespaceUnsupported;
            break :blk open_namespace(&handle, try arena.dupeZ(u8, namespace), flags);
        } else if (selection.directory) |directory|
            api.open_directory(&handle, try arena.dupeZ(u8, directory), flags)
        else if (selection.files) |paths| blk: {
            const files = try arena.allocSentinel(?[*:0]const u8, paths.len, null);
            for (paths, 0..) |path, i| files[i] = (try arena.dupeZ(u8, path)).ptr;
            break :blk api.open_files(&handle, files.ptr, flags);
        } else api.open(&handle, flags);
        if (result < 0) return mapError(result);
        const journal = handle orelse return error.OpenFailed;
        errdefer api.close(journal);
        for (selection.matches) |m| {
            const rc = if (std.mem.eql(u8, m, "+")) api.add_disjunction(journal) else api.add_match(journal, m.ptr, m.len);
            if (rc < 0) return mapError(rc);
        }
        const threshold_result = api.set_data_threshold(journal, 0);
        if (threshold_result < 0) return mapError(threshold_result);
        const owned_id = try allocator.dupe(u8, source_id);
        errdefer allocator.free(owned_id);
        return .{ .allocator = allocator, .api = api, .journal = journal, .source_id = owned_id, .committed_cursor = if (checkpoint) |c| try allocator.dupeZ(u8, c) else null };
    }

    pub fn deinit(self: *Reader) void {
        self.api.close(self.journal);
        self.api.lib.close();
        self.allocator.free(self.source_id);
        if (self.committed_cursor) |c| self.allocator.free(c);
        if (self.pending_cursor) |c| self.allocator.free(c);
        self.* = undefined;
    }

    fn field(self: *Reader, arena: Allocator, key: [:0]const u8) !?[]const u8 {
        var data: ?*const anyopaque = null;
        var length: usize = 0;
        const rc = self.api.get_data(self.journal, key.ptr, &data, &length);
        if (rc == -2) return null;
        if (rc < 0) return mapError(rc);
        if (length > self.max_record_bytes) return error.RecordTooLong;
        const bytes: [*]const u8 = @ptrCast(data orelse return error.MalformedRecord);
        if (length <= key.len or bytes[key.len] != '=') return error.MalformedRecord;
        return try arena.dupe(u8, bytes[key.len + 1 .. length]);
    }

    fn rawEntry(self: *Reader, arena: Allocator) !struct { body: []const u8, hash: [32]u8, fields: []const record_mod.JournalField } {
        self.api.restart_data(self.journal);
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        var body = std.ArrayList(u8).init(arena);
        var fields = std.ArrayList(record_mod.JournalField).init(arena);
        var total: usize = 0;
        var messages: usize = 0;
        while (true) {
            var data: ?*const anyopaque = null;
            var length: usize = 0;
            const rc = self.api.enumerate_data(self.journal, &data, &length);
            if (rc < 0) return mapError(rc);
            if (rc == 0) break;
            if (length > self.max_record_bytes -| total) return error.RecordTooLong;
            total += length;
            const bytes: [*]const u8 = @ptrCast(data orelse return error.MalformedRecord);
            var length_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &length_bytes, @intCast(length), .little);
            hasher.update(&length_bytes);
            hasher.update(bytes[0..length]);
            const equals = std.mem.indexOfScalar(u8, bytes[0..length], '=') orelse return error.MalformedRecord;
            const name = bytes[0..equals];
            inline for (.{ "_HOSTNAME", "SYSLOG_IDENTIFIER", "_COMM", "SYSLOG_PID", "_PID", "MESSAGE", "_SOURCE_MONOTONIC_TIMESTAMP" }) |wanted| {
                if (std.mem.eql(u8, name, wanted)) {
                    if (fields.items.len >= 4096) return error.RecordTooLong;
                    try fields.append(.{ .name = wanted, .value = try arena.dupe(u8, bytes[equals + 1 .. length]) });
                }
            }
            if (std.mem.startsWith(u8, bytes[0..length], "MESSAGE=")) {
                if (messages > 0) try body.append(' ');
                try body.appendSlice(bytes[8..length]);
                messages += 1;
            }
        }
        return .{ .body = body.items, .hash = hasher.finalResult(), .fields = fields.items };
    }

    /// Capture the filtered startup boundary without acknowledging any entry.
    /// Returned cursor is owned by the caller. Existing exact resume remains intact.
    pub fn startupTail(self: *Reader) !?[:0]u8 {
        if (self.initialized or self.pending_cursor != null) return error.SourceAlreadyInitialized;
        const seek = self.api.seek_tail(self.journal);
        if (seek < 0) {
            self.health = .read_failed;
            return mapError(seek);
        }
        const previous = self.api.previous(self.journal);
        if (previous < 0) {
            self.health = .read_failed;
            return mapError(previous);
        }
        return if (previous == 0) null else try self.cursor();
    }

    pub fn setStartRealtime(self: *Reader, timestamp_us: u64) !void {
        if (self.initialized or self.pending_cursor != null) return error.SourceAlreadyInitialized;
        if (self.committed_cursor != null) return error.CursorAlreadySelected;
        self.start = .realtime;
        self.start_realtime_us = timestamp_us;
    }

    fn cursor(self: *Reader) ![:0]u8 {
        var value: ?[*:0]u8 = null;
        const rc = self.api.get_cursor(self.journal, &value);
        if (rc < 0) return mapError(rc);
        const c = value orelse return error.MalformedRecord;
        defer self.api.free(@ptrCast(c));
        return self.allocator.dupeZ(u8, std.mem.span(c));
    }

    fn acknowledge(self: *Reader, callback: record_mod.AckCallback, userdata: ?*anyopaque, checkpoint_only: bool, callback_started: *bool) !void {
        const next_cursor = try self.cursor();
        errdefer self.allocator.free(next_cursor);
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var message: []const u8 = "";
        var timestamp: u64 = 0;
        var journal_fields: ?[]const record_mod.JournalField = null;
        var journal_monotonic: ?u64 = null;
        var hash = [_]u8{0} ** 32;
        if (!checkpoint_only) {
            const rc = self.api.get_realtime_usec(self.journal, &timestamp);
            if (rc < 0) return mapError(rc);
            if (try self.field(arena, "_SOURCE_REALTIME_TIMESTAMP")) |raw| timestamp = std.fmt.parseInt(u64, raw, 10) catch return error.MalformedRecord;
            const raw_entry = try self.rawEntry(arena);
            journal_fields = raw_entry.fields;
            var entry_monotonic: u64 = 0;
            var entry_boot: Id128 = undefined;
            if (self.api.get_monotonic_usec(self.journal, &entry_monotonic, &entry_boot) >= 0) journal_monotonic = entry_monotonic;
            const body = raw_entry.body;
            hash = raw_entry.hash;
            const hostname = try self.field(arena, "_HOSTNAME");
            const identifier = try self.field(arena, "SYSLOG_IDENTIFIER") orelse try self.field(arena, "_COMM");
            const pid = try self.field(arena, "SYSLOG_PID") orelse try self.field(arena, "_PID");
            var monotonic: ?u64 = null;
            if (identifier) |id| if (std.mem.eql(u8, id, "kernel") and (pid == null or pid.?.len == 0)) {
                if (try self.field(arena, "_SOURCE_MONOTONIC_TIMESTAMP")) |raw| monotonic = std.fmt.parseInt(u64, raw, 10) catch null;
                if (monotonic == null) {
                    var usec: u64 = 0;
                    var boot: Id128 = undefined;
                    if (self.api.get_monotonic_usec(self.journal, &usec, &boot) >= 0) monotonic = usec;
                }
            };
            message = try formatMessageWithMonotonic(arena, hostname, identifier, pid, body, monotonic);
        }
        callback_started.* = true;
        callback(.{ .kind = if (checkpoint_only) .checkpoint else .data, .source = self.source_id, .occurrence = next_cursor, .cursor = next_cursor, .message = message, .raw_hash = hash, .timestamp_us = if (checkpoint_only) null else timestamp, .journal_fields = journal_fields, .journal_monotonic_us = journal_monotonic }, userdata) catch |err| {
            self.health = .commit_failed;
            return err;
        };
        if (self.committed_cursor) |old| self.allocator.free(old);
        self.committed_cursor = next_cursor;
        self.health = .healthy;
    }

    fn deliverCurrent(self: *Reader, callback: record_mod.AckCallback, userdata: ?*anyopaque, checkpoint_only: bool) !void {
        if (self.pending_cursor == null) self.pending_cursor = self.cursor() catch |err| {
            self.health = if (err == error.MalformedRecord) .malformed_record else .read_failed;
            return err;
        };
        self.pending_checkpoint = checkpoint_only;
        var callback_started = false;
        self.acknowledge(callback, userdata, checkpoint_only, &callback_started) catch |err| {
            if (!callback_started) self.health = switch (err) {
                error.RecordTooLong => .record_too_long,
                error.MalformedRecord => .malformed_record,
                else => .read_failed,
            };
            return err;
        };
        self.allocator.free(self.pending_cursor.?);
        self.pending_cursor = null;
    }

    /// Reseeking the exact committed cursor makes failed transactions retryable.
    /// Vacuum/replacement is detected with sd_journal_test_cursor, never silently
    /// accepted as a successful seek to the next available record.
    pub fn poll(self: *Reader, callback: record_mod.AckCallback, userdata: ?*anyopaque) !bool {
        const process_result = self.api.process(self.journal);
        if (process_result < 0) {
            self.health = .read_failed;
            return mapError(process_result);
        }
        if (self.pending_cursor) |c| {
            if (self.api.seek_cursor(self.journal, c.ptr) < 0 or self.api.next(self.journal) <= 0 or self.api.test_cursor(self.journal, c.ptr) != 1) {
                self.health = .resume_lost;
                return error.ResumeLost;
            }
            const is_data = !self.pending_checkpoint;
            try self.deliverCurrent(callback, userdata, self.pending_checkpoint);
            return is_data;
        }
        if (self.committed_cursor) |c| {
            if (self.api.seek_cursor(self.journal, c.ptr) < 0 or self.api.next(self.journal) <= 0 or self.api.test_cursor(self.journal, c.ptr) != 1) {
                self.health = .resume_lost;
                return error.ResumeLost;
            }
        } else if (!self.initialized) {
            const rc = switch (self.start) {
                .head => self.api.seek_head(self.journal),
                .tail => self.api.seek_tail(self.journal),
                .realtime => self.api.seek_realtime_usec(self.journal, self.start_realtime_us),
            };
            if (rc < 0) {
                self.health = .read_failed;
                return mapError(rc);
            }
            if (self.start == .tail) {
                const previous = self.api.previous(self.journal);
                if (previous < 0) {
                    self.health = .read_failed;
                    return mapError(previous);
                }
                if (previous > 0) try self.deliverCurrent(callback, userdata, true);
            } else if (self.start == .realtime) {
                // Match the reference's backstep after realtime seek, including
                // the beyond-end case. It does not acknowledge that prior entry.
                const previous = self.api.previous(self.journal);
                if (previous < 0) {
                    self.health = .read_failed;
                    return mapError(previous);
                }
            }
            self.initialized = true;
        }
        const rc = self.api.next(self.journal);
        if (rc < 0) {
            self.health = .read_failed;
            return mapError(rc);
        }
        if (rc == 0) {
            self.health = .healthy;
            return false;
        }
        try self.deliverCurrent(callback, userdata, false);
        return true;
    }
};

fn mapError(code: c_int) anyerror {
    return switch (-code) {
        1, 13 => error.AccessDenied,
        2 => error.FileNotFound,
        12 => error.OutOfMemory,
        22 => error.InvalidJournalSelection,
        93, 95 => error.UnsupportedJournalFeature,
        else => error.JournalReadFailed,
    };
}

pub fn formatMessage(allocator: Allocator, hostname: ?[]const u8, identifier: ?[]const u8, pid: ?[]const u8, body: []const u8) ![]u8 {
    return formatMessageWithMonotonic(allocator, hostname, identifier, pid, body, null);
}

fn formatMessageWithMonotonic(allocator: Allocator, hostname: ?[]const u8, identifier: ?[]const u8, pid: ?[]const u8, body: []const u8, monotonic: ?u64) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    if (hostname) |host| if (host.len > 0) {
        try out.appendSlice(host);
        try out.append(' ');
    };
    if (identifier) |id| if (id.len > 0) {
        try out.appendSlice(id);
        if (pid) |p| if (p.len > 0) {
            try out.append('[');
            const number = std.fmt.parseInt(i64, p, 0) catch null;
            if (number) |n| try out.writer().print("{d}", .{n}) else try out.appendSlice(p);
            try out.append(']');
        };
        try out.appendSlice(": ");
        if (monotonic) |usec| try out.writer().print("[{d:12.6}] ", .{@as(f64, @floatFromInt(usec)) / 1_000_000.0});
    };
    for (body) |c| {
        if (c == '\n') try out.appendSlice("\\n") else try out.append(c);
    }
    return out.toOwnedSlice();
}

test "systemd reader: match validation and reference prefix formatting" {
    try (Selection{ .flags = 2, .matches = &.{ "_SYSTEMD_UNIT=example.service", "PRIORITY=3", "+", "SYSLOG_IDENTIFIER=other" } }).validate();
    try std.testing.expectError(error.InvalidMatch, (Selection{ .matches = &.{ "A=b", "+" } }).validate());
    try std.testing.expectError(error.InvalidJournalSelection, (Selection{ .namespace = "a\x00b" }).validate());
    try std.testing.expectError(error.InvalidJournalSelection, (Selection{ .directory = "a\x00b" }).validate());
    try std.testing.expectError(error.InvalidJournalSelection, (Selection{ .files = &.{"a\x00b"} }).validate());
    const line = try formatMessage(std.testing.allocator, "host", "example", "0x2a", "neutral\nsecond");
    defer std.testing.allocator.free(line);
    try std.testing.expectEqualStrings("host example[42]: neutral\\nsecond", line);
}

const TestCollector = struct {
    allocator: Allocator,
    fail: bool = false,
    lines: std.ArrayList([]u8),
    cursors: std.ArrayList([]u8),
    fn init(allocator: Allocator) TestCollector {
        return .{ .allocator = allocator, .lines = std.ArrayList([]u8).init(allocator), .cursors = std.ArrayList([]u8).init(allocator) };
    }
    fn deinit(self: *TestCollector) void {
        for (self.lines.items) |line| self.allocator.free(line);
        for (self.cursors.items) |c| self.allocator.free(c);
        self.lines.deinit();
        self.cursors.deinit();
    }
    fn ack(record: record_mod.Record, userdata: ?*anyopaque) !void {
        const self: *TestCollector = @ptrCast(@alignCast(userdata.?));
        if (self.fail) return error.CommitFailed;
        if (record.kind == .checkpoint) return;
        try std.testing.expectEqual(@as(?u64, 1730000000123456), record.timestamp_us);
        try self.lines.append(try self.allocator.dupe(u8, record.message));
        try self.cursors.append(try self.allocator.dupe(u8, record.cursor));
    }
};

test "systemd reader: private real journal selectors, commit retry and restart cursor" {
    const allocator = std.testing.allocator;
    const path = std.process.getEnvVarOwned(allocator, "F2Z_TEST_JOURNAL_PATH") catch return error.SkipZigTest;
    defer allocator.free(path);
    const selection = Selection{ .flags = 0, .files = &.{path}, .matches = &.{ "SYSLOG_IDENTIFIER=example", "PRIORITY=3", "+", "SYSLOG_IDENTIFIER=other" } };
    var reader = try Reader.init(allocator, "private/example", selection, null);
    defer reader.deinit();
    var collector = TestCollector.init(allocator);
    defer collector.deinit();
    collector.fail = true;
    try std.testing.expectError(error.CommitFailed, reader.poll(TestCollector.ack, &collector));
    try std.testing.expect(reader.committed_cursor == null);
    collector.fail = false;
    try std.testing.expect(try reader.poll(TestCollector.ack, &collector));
    try std.testing.expectEqualStrings("fixture example[42]: neutral-one", collector.lines.items[0]);
    const checkpoint = try allocator.dupe(u8, reader.committed_cursor.?);
    defer allocator.free(checkpoint);
    try std.testing.expect(try reader.poll(TestCollector.ack, &collector));
    try std.testing.expectEqualStrings("fixture other: neutral-three", collector.lines.items[1]);
    try std.testing.expect(!std.mem.eql(u8, collector.cursors.items[0], collector.cursors.items[1]));
    try std.testing.expect(!try reader.poll(TestCollector.ack, &collector));
    var restarted = try Reader.init(allocator, "private/example", selection, checkpoint);
    defer restarted.deinit();
    try std.testing.expect(try restarted.poll(TestCollector.ack, &collector));
    try std.testing.expectEqualStrings(collector.cursors.items[1], collector.cursors.items[2]);
    // A valid cursor for a non-existent sequence must not fall forward to a
    // nearest available entry and silently declare successful restoration.
    const missing = "s=00000000000000000000000000000000;i=deadbeef;b=11111111111111111111111111111111;m=f4240;t=6256d03780240;x=0";
    var lost = try Reader.init(allocator, "private/example", selection, missing);
    defer lost.deinit();
    try std.testing.expectError(error.ResumeLost, lost.poll(TestCollector.ack, &collector));
    try std.testing.expectEqual(record_mod.Health.resume_lost, lost.health);
}

test "systemd reader: extraction failure health preserves the exact pending record" {
    const allocator = std.testing.allocator;
    const path = std.process.getEnvVarOwned(allocator, "F2Z_TEST_JOURNAL_PATH") catch return error.SkipZigTest;
    defer allocator.free(path);
    var reader = try Reader.init(allocator, "private/health", .{ .files = &.{path}, .flags = 0 }, null);
    defer reader.deinit();
    var collector = TestCollector.init(allocator);
    defer collector.deinit();
    // An ordinary local record budget failure must remain visible on each retry.
    reader.max_record_bytes = 1;
    try std.testing.expectError(error.RecordTooLong, reader.poll(TestCollector.ack, &collector));
    try std.testing.expectEqual(record_mod.Health.record_too_long, reader.health);
    const pending = try allocator.dupe(u8, reader.pending_cursor.?);
    defer allocator.free(pending);
    reader.health = .healthy;
    try std.testing.expectError(error.RecordTooLong, reader.poll(TestCollector.ack, &collector));
    try std.testing.expectEqual(record_mod.Health.record_too_long, reader.health);
    try std.testing.expectEqualStrings(pending, reader.pending_cursor.?);
    try std.testing.expect(reader.committed_cursor == null);
    reader.max_record_bytes = 1024 * 1024;
    const original_time = reader.api.get_realtime_usec;
    reader.api.get_realtime_usec = struct {
        fn unavailable(_: *Journal, _: *u64) callconv(.c) c_int {
            return -5;
        }
    }.unavailable;
    try std.testing.expectError(error.JournalReadFailed, reader.poll(TestCollector.ack, &collector));
    try std.testing.expectEqual(record_mod.Health.read_failed, reader.health);
    reader.api.get_realtime_usec = original_time;
    const original_data = reader.api.get_data;
    reader.api.get_data = struct {
        fn malformed(_: *Journal, _: [*:0]const u8, data: *?*const anyopaque, length: *usize) callconv(.c) c_int {
            const value = "_SOURCE_REALTIME_TIMESTAMP=ordinary-invalid";
            data.* = value.ptr;
            length.* = value.len;
            return 0;
        }
    }.malformed;
    try std.testing.expectError(error.MalformedRecord, reader.poll(TestCollector.ack, &collector));
    try std.testing.expectEqual(record_mod.Health.malformed_record, reader.health);
    reader.api.get_data = original_data;
    // A callback using the same error name is a commit failure, not extraction.
    try std.testing.expectError(error.RecordTooLong, reader.poll(struct {
        fn reject(_: record_mod.Record, _: ?*anyopaque) !void {
            return error.RecordTooLong;
        }
    }.reject, null));
    try std.testing.expectEqual(record_mod.Health.commit_failed, reader.health);
    try std.testing.expectEqualStrings(pending, reader.pending_cursor.?);
    try std.testing.expect(try reader.poll(TestCollector.ack, &collector));
    try std.testing.expectEqual(record_mod.Health.healthy, reader.health);
    try std.testing.expectEqualStrings(pending, reader.committed_cursor.?);
    try std.testing.expect(reader.pending_cursor == null);
    try std.testing.expectEqual(@as(usize, 1), collector.lines.items.len);
}
