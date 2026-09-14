// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Bounded journalctl invocation and complete JSON record decoding. No shell or
//! libsystemd loading. All returned fields borrow caller-owned bounded scratch.
const std = @import("std");
const records = @import("source_record.zig");
pub const max_line_bytes = 64 * 1024;
pub const max_cursor_bytes = 512;
pub const parse_bytes = 512 * 1024;
pub const max_fields = 256;
pub const Target = union(enum) { system, directory: []const u8, files: []const []const u8 };
pub const Options = struct {
    executable: []const u8 = "/usr/bin/journalctl",
    target: Target = .system,
    namespace: ?[]const u8 = null,
    matches: []const []const u8 = &.{},
    timeout_ms: u32 = 5000,
    batch_records: u16 = 16,
};
pub const Query = union(enum) { tail, cursor: []const u8, since_us: i64 };
pub const Diagnostic = struct {
    exit_code: ?u8 = null,
    signal: ?u32 = null,
    stderr: [4096]u8 = undefined,
    stderr_len: usize = 0,
    pub fn message(self: *const Diagnostic) []const u8 {
        return self.stderr[0..self.stderr_len];
    }
};
pub const Executor = struct {
    context: ?*anyopaque = null,
    run: *const fn (std.mem.Allocator, []const []const u8, []u8, *Diagnostic, u32, ?*anyopaque) anyerror![]const u8 = execute,
};
fn bounded(value: []const u8, maximum: usize) !void {
    if (value.len == 0 or value.len > maximum or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidJournalArgument;
}
fn path(value: []const u8) !void {
    try bounded(value, 4096);
    if (!std.fs.path.isAbsolute(value)) return error.InvalidJournalPath;
}
pub fn validate(options: Options) !void {
    try path(options.executable);
    if (options.batch_records == 0 or options.batch_records > 128 or options.timeout_ms == 0 or options.timeout_ms > 60_000) return error.InvalidJournalLimits;
    switch (options.target) {
        .system => {},
        .directory => |value| try path(value),
        .files => |paths| {
            if (paths.len == 0 or paths.len > 64) return error.InvalidJournalFiles;
            for (paths) |value| try path(value);
        },
    }
    if (options.namespace) |value| {
        if (options.target != .system) return error.ConflictingJournalSelection;
        try bounded(value, 255);
        for (value) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.')) return error.InvalidJournalNamespace;
    }
    if (options.matches.len > 64) return error.JournalSelectionLimit;
    var need_match = true;
    for (options.matches) |value| {
        try bounded(value, 4096);
        if (std.mem.eql(u8, value, "+")) {
            if (need_match) return error.InvalidJournalMatch;
            need_match = true;
        } else {
            const equal = std.mem.indexOfScalar(u8, value, '=') orelse return error.InvalidJournalMatch;
            if (!fieldName(value[0..equal])) return error.InvalidJournalMatch;
            need_match = false;
        }
    }
    if (options.matches.len > 0 and need_match) return error.InvalidJournalMatch;
}
fn fieldName(value: []const u8) bool {
    if (value.len == 0 or value.len > 64 or std.ascii.isDigit(value[0])) return false;
    for (value) |c| if (!(std.ascii.isUpper(c) or std.ascii.isDigit(c) or c == '_')) return false;
    return true;
}
/// Arena-owned argv. Positive-prefixed line counts preserve oldest-first bounded
/// since queries on both old and newer journalctl versions; tail uses plain 1.
pub fn argv(a: std.mem.Allocator, options: Options, query: Query, count: usize) ![]const []const u8 {
    try validate(options);
    if (count == 0 or count > @as(usize, options.batch_records) + 1) return error.InvalidPollBudget;
    var args = std.ArrayList([]const u8).init(a);
    try args.appendSlice(&.{ options.executable, "--output=json", "--all", "--no-pager", "--quiet" });
    switch (options.target) {
        .system => try args.append("--system"),
        .directory => |value| try args.append(try std.fmt.allocPrint(a, "--directory={s}", .{value})),
        .files => |values| for (values) |value| try args.append(try std.fmt.allocPrint(a, "--file={s}", .{value})),
    }
    if (options.namespace) |value| try args.append(try std.fmt.allocPrint(a, "--namespace={s}", .{value}));
    switch (query) {
        .tail => try args.append("--lines=1"),
        .cursor => |value| {
            try bounded(value, max_cursor_bytes);
            try args.append(try std.fmt.allocPrint(a, "--cursor={s}", .{value}));
            try args.append(try std.fmt.allocPrint(a, "--lines=+{d}", .{count}));
        },
        .since_us => |value| {
            if (value < 0) return error.InvalidJournalStart;
            try args.append(try std.fmt.allocPrint(a, "--since=@{d}.{d:0>6}", .{ @as(u64, @intCast(@divFloor(value, 1_000_000))), @as(u64, @intCast(@mod(value, 1_000_000))) }));
            try args.append(try std.fmt.allocPrint(a, "--lines=+{d}", .{count}));
        },
    }
    try args.append("--");
    try args.appendSlice(options.matches);
    return args.toOwnedSlice();
}

pub fn execute(a: std.mem.Allocator, args: []const []const u8, output: []u8, diagnostic: *Diagnostic, timeout_ms: u32, _: ?*anyopaque) ![]const u8 {
    diagnostic.* = .{};
    var child = std.process.Child.init(args, a);
    child.stdin_behavior = .Close;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    var reaped = false;
    defer {
        if (!reaped) {
            std.posix.kill(child.id, std.posix.SIG.KILL) catch {};
            _ = std.posix.waitpid(child.id, 0);
        }
        if (child.stdout) |file| file.close();
        if (child.stderr) |file| file.close();
        if (child.err_pipe) |fd| std.posix.close(fd);
    }
    const pipes = [_]std.fs.File{ child.stdout.?, child.stderr.? };
    for (pipes) |file| {
        const flags = try std.posix.fcntl(file.handle, std.posix.F.GETFL, 0);
        _ = try std.posix.fcntl(file.handle, std.posix.F.SETFL, flags | @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
    }
    var timer = try std.time.Timer.start();
    var eof = [_]bool{ false, false };
    var used: usize = 0;
    var status: u32 = 0;
    while (true) {
        for (pipes, 0..) |file, i| {
            if (eof[i]) continue;
            var chunk: [4096]u8 = undefined;
            const n = std.posix.read(file.handle, &chunk) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            if (n == 0) {
                eof[i] = true;
                continue;
            }
            if (i == 0) {
                if (n > output.len - used) return error.JournalOutputLimit;
                @memcpy(output[used..][0..n], chunk[0..n]);
                used += n;
            } else {
                const take = @min(n, diagnostic.stderr.len - diagnostic.stderr_len);
                @memcpy(diagnostic.stderr[diagnostic.stderr_len..][0..take], chunk[0..take]);
                diagnostic.stderr_len += take;
                if (take < n) return error.JournalDiagnosticLimit;
            }
        }
        if (!reaped) {
            const result = std.posix.waitpid(child.id, std.posix.W.NOHANG);
            if (result.pid != 0) {
                status = result.status;
                reaped = true;
            }
        }
        if (reaped and eof[0] and eof[1]) break;
        if (timer.read() / std.time.ns_per_ms >= timeout_ms) return error.JournalTimeout;
        var pollers = [_]std.posix.pollfd{
            .{ .fd = if (eof[0]) -1 else pipes[0].handle, .events = std.posix.POLL.IN, .revents = 0 },
            .{ .fd = if (eof[1]) -1 else pipes[1].handle, .events = std.posix.POLL.IN, .revents = 0 },
        };
        _ = try std.posix.poll(&pollers, 10);
    }
    try child.waitForSpawn(); // reaped: cannot block; also closes the exec error pipe.
    if (std.posix.W.IFEXITED(status)) diagnostic.exit_code = std.posix.W.EXITSTATUS(status) else {
        if (std.posix.W.IFSIGNALED(status)) diagnostic.signal = std.posix.W.TERMSIG(status);
        return error.JournalChildFailed;
    }
    if (diagnostic.exit_code.? != 0) return error.JournalChildFailed;
    // Warnings may report inaccessible/corrupt files and an incomplete view even
    // with exit 0. Never declare that view an empty healthy source.
    if (diagnostic.stderr_len != 0) return error.JournalDiagnostic;
    return output[0..used];
}

pub const Entry = struct {
    cursor: []const u8,
    message: []const u8,
    realtime_us: ?u64,
    monotonic_us: ?u64,
    fields: []records.JournalField,
    raw_hash: [32]u8,
};

/// The caller supplies the complete first line of an inclusive cursor query.
/// No time seek, fresh baseline, cursor update or acknowledgment is performed.
/// Returned origin fields borrow scratch and still require the configured origin
/// qualifier; matching a cursor alone is not evidence of trusted log provenance.
pub fn verifyAnchor(scratch: []u8, line: []const u8, expected_cursor: []const u8, message_limit: usize) !Entry {
    try bounded(expected_cursor, max_cursor_bytes);
    if (line.len == 0) return error.ResumeLost;
    const entry = try decode(scratch, line, message_limit);
    if (!std.mem.eql(u8, entry.cursor, expected_cursor)) return error.ResumeLost;
    return entry;
}

/// Full canonical journal field hash includes origin fields and timestamps.
/// Source/configuration and encoded checkpoint identity remain session checks.
pub fn verifyPending(entry: Entry, expected_cursor: []const u8, expected_hash: [32]u8) !void {
    try bounded(expected_cursor, max_cursor_bytes);
    if (!std.mem.eql(u8, entry.cursor, expected_cursor) or !std.mem.eql(u8, &entry.raw_hash, &expected_hash)) return error.PendingRecordMismatch;
}

fn unsigned(value: ?std.json.Value) !?u64 {
    const v = value orelse return null;
    if (v != .string or v.string.len == 0 or v.string.len > 20) return error.MalformedJournalRecord;
    for (v.string) |c| if (!std.ascii.isDigit(c)) return error.MalformedJournalRecord;
    return std.fmt.parseInt(u64, v.string, 10) catch error.MalformedJournalRecord;
}
fn bytes(a: std.mem.Allocator, value: std.json.Value) ![]const u8 {
    if (value == .string) return value.string;
    if (value != .array) return error.UnsupportedJournalField;
    const out = try a.alloc(u8, value.array.items.len);
    for (value.array.items, out) |item, *c| {
        if (item != .integer or item.integer < 0 or item.integer > 255) return error.UnsupportedJournalField;
        c.* = @intCast(item.integer);
    }
    return out;
}
fn less(_: void, a: records.JournalField, b: records.JournalField) bool {
    const order = std.mem.order(u8, a.name, b.name);
    return order == .lt or (order == .eq and std.mem.lessThan(u8, a.value, b.value));
}
pub fn decode(scratch: []u8, line: []const u8, message_limit: usize) !Entry {
    if (line.len == 0 or line.len > max_line_bytes) return error.JournalRecordLimit;
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const a = fba.allocator();
    const value = std.json.parseFromSliceLeaky(std.json.Value, a, line, .{ .allocate = .alloc_always, .max_value_len = max_line_bytes }) catch |err| switch (err) {
        error.OutOfMemory => return error.JournalParseLimit,
        else => return error.MalformedJournalRecord,
    };
    if (value != .object or value.object.count() > max_fields) return error.MalformedJournalRecord;
    const c = value.object.get("__CURSOR") orelse return error.MissingJournalCursor;
    if (c != .string) return error.MalformedJournalRecord;
    try bounded(c.string, max_cursor_bytes);
    const m = value.object.get("MESSAGE") orelse return error.MissingJournalMessage;
    const message = try bytes(a, m);
    if (message.len > message_limit) return error.JournalMessageLimit;
    const all = try a.alloc(records.JournalField, max_fields);
    var count: usize = 0;
    var iterator = value.object.iterator();
    while (iterator.next()) |field| {
        if (!fieldName(field.key_ptr.*)) return error.MalformedJournalRecord;
        const v = field.value_ptr.*;
        // Repeated string values are retained individually. Integer arrays are
        // journalctl's binary representation; ambiguous duplicate MESSAGE fails.
        if (v == .array and v.array.items.len > 0 and v.array.items[0] == .string) {
            for (v.array.items) |item| {
                if (item != .string or count == max_fields) return error.UnsupportedJournalField;
                all[count] = .{ .name = field.key_ptr.*, .value = item.string };
                count += 1;
            }
        } else {
            if (count == max_fields) return error.JournalParseLimit;
            all[count] = .{ .name = field.key_ptr.*, .value = try bytes(a, v) };
            count += 1;
        }
    }
    const fields = all[0..count];
    std.mem.sort(records.JournalField, fields, {}, less);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("fail2zig-native-journal-record-v1\x00");
    for (fields) |field| for ([_][]const u8{ field.name, field.value }) |part| {
        var size: [8]u8 = undefined;
        std.mem.writeInt(u64, &size, part.len, .little);
        hash.update(&size);
        hash.update(part);
    };
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .cursor = c.string, .message = message, .realtime_us = try unsigned(value.object.get("__REALTIME_TIMESTAMP")), .monotonic_us = try unsigned(value.object.get("__MONOTONIC_TIMESTAMP")), .fields = fields, .raw_hash = digest };
}
