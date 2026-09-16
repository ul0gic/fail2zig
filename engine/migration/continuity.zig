// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const plan_mod = @import("plan.zig");
const db = @import("fail2ban_db.zig");
const file_source = @import("../core/durable_file_source.zig");

pub const first_line_max_bytes: usize = 64 * 1024;
pub const prefix_max_bytes: u8 = 64;

pub const Error = db.Error || error{ PlanInvalid, OutOfMemory };

pub const LogRow = struct {
    jail: []const u8,
    path: []const u8,
    firstlinemd5: ?[]const u8,
    lastfilepos: ?i64,
};

pub const Decision = enum { resume_at_offset, replay_window, start_at_tail, blocked };
pub const Outcome = enum { lossless, non_lossless, blocked };

pub const Observed = struct {
    dev: ?u64,
    ino: ?u64,
    size: ?u64,
    first_line_md5_matches: ?bool,
    offset_valid: bool,
};

pub const FileBoundary = struct {
    group: []const u8,
    path: []const u8,
    observed: Observed,
    decision: Decision,
    reason: []const u8,
    checkpoint: ?file_source.Resume,
};

pub const JournalBoundary = struct {
    group: []const u8,
    decision: Decision,
    reason: []const u8,
};

pub const Replay = struct {
    window_s: u32,
    cutover_us: i64,
    from_us: i64,
};

pub const Boundary = struct {
    arena: std.heap.ArenaAllocator,
    requested: plan_mod.Continuity,
    outcome: Outcome,
    replay: ?Replay,
    files: []const FileBoundary,
    journals: []const JournalBoundary,

    pub fn deinit(self: *Boundary) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const Options = struct {
    doc: *const plan_mod.Document,
    logs: []const LogRow,
    cutover_us: i64,
};

pub fn readLogs(allocator: std.mem.Allocator, snapshot_path: []const u8) Error![]LogRow {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var reader = try db.Reader.open(a, snapshot_path);
    defer reader.close();
    var it = try reader.logs();
    defer it.deinit();
    var rows = std.ArrayListUnmanaged(LogRow){};
    while (try it.next()) |row| {
        try rows.append(a, .{
            .jail = row.jail,
            .path = switch (row.path) {
                .present => |v| v,
                .absent => continue,
            },
            .firstlinemd5 = switch (row.firstlinemd5) {
                .present => |v| v,
                .absent => null,
            },
            .lastfilepos = switch (row.lastfilepos) {
                .present => |v| v,
                .absent => null,
            },
        });
    }
    const out = try allocator.alloc(LogRow, rows.items.len);
    errdefer allocator.free(out);
    for (rows.items, 0..) |row, i| {
        out[i] = .{
            .jail = try allocator.dupe(u8, row.jail),
            .path = try allocator.dupe(u8, row.path),
            .firstlinemd5 = if (row.firstlinemd5) |m| try allocator.dupe(u8, m) else null,
            .lastfilepos = row.lastfilepos,
        };
    }
    return out;
}

pub fn freeLogs(allocator: std.mem.Allocator, rows: []LogRow) void {
    for (rows) |row| {
        allocator.free(row.jail);
        allocator.free(row.path);
        if (row.firstlinemd5) |m| allocator.free(m);
    }
    allocator.free(rows);
}

pub fn evaluate(allocator: std.mem.Allocator, options: Options) Error!Boundary {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_state.deinit();
    const a = arena_state.allocator();
    const doc = options.doc;
    const requested = std.meta.stringToEnum(plan_mod.Continuity, doc.continuity) orelse return error.PlanInvalid;
    const window: ?u32 = doc.replay_window_s;
    const replay: ?Replay = if (requested == .reset_replay and window != null and window.? > 0)
        .{ .window_s = window.?, .cutover_us = options.cutover_us, .from_us = options.cutover_us -| (@as(i64, window.?) * std.time.us_per_s) }
    else
        null;

    var files = std.ArrayListUnmanaged(FileBoundary){};
    var journals = std.ArrayListUnmanaged(JournalBoundary){};
    const groups = manifestGroups(doc) orelse return error.PlanInvalid;
    for (doc.selection) |name| {
        const group = findGroup(groups, name) orelse return error.PlanInvalid;
        const backend = stringField(group, "backend") orelse return error.PlanInvalid;
        if (std.mem.startsWith(u8, backend, "systemd")) {
            try journals.append(a, journalBoundary(name, requested, replay));
            continue;
        }
        const logpaths = (group.object.get("logpaths") orelse return error.PlanInvalid);
        if (logpaths != .array) return error.PlanInvalid;
        for (logpaths.array.items) |lp| {
            if (lp != .string) return error.PlanInvalid;
            try files.append(a, try fileBoundary(name, lp.string, options.logs, requested, replay));
        }
    }
    std.mem.sort(FileBoundary, files.items, {}, fileLessThan);
    std.mem.sort(JournalBoundary, journals.items, {}, journalLessThan);

    var outcome: Outcome = .lossless;
    for (files.items) |f| outcome = worse(outcome, f.decision);
    for (journals.items) |j| outcome = worse(outcome, j.decision);

    return .{
        .arena = arena_state,
        .requested = requested,
        .outcome = outcome,
        .replay = replay,
        .files = try files.toOwnedSlice(a),
        .journals = try journals.toOwnedSlice(a),
    };
}

fn worse(current: Outcome, decision: Decision) Outcome {
    return switch (decision) {
        .blocked => .blocked,
        .replay_window, .start_at_tail => if (current == .blocked) .blocked else .non_lossless,
        .resume_at_offset => current,
    };
}

fn journalBoundary(name: []const u8, requested: plan_mod.Continuity, replay: ?Replay) JournalBoundary {
    return switch (requested) {
        .lossless => .{ .group = name, .decision = .blocked, .reason = "journal-cursor-unavailable" },
        .reset_replay => if (replay != null)
            .{ .group = name, .decision = .replay_window, .reason = "journal-tail-with-bounded-since-replay" }
        else
            .{ .group = name, .decision = .start_at_tail, .reason = "journal-tail-without-replay" },
    };
}

fn fileBoundary(group: []const u8, path: []const u8, logs: []const LogRow, requested: plan_mod.Continuity, replay: ?Replay) Error!FileBoundary {
    var result = FileBoundary{
        .group = group,
        .path = path,
        .observed = .{ .dev = null, .ino = null, .size = null, .first_line_md5_matches = null, .offset_valid = false },
        .decision = .blocked,
        .reason = "",
        .checkpoint = null,
    };
    const row = findRow(logs, group, path);
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        return fallback(result, requested, replay, if (err == error.FileNotFound) "file-missing" else "file-unreadable");
    };
    defer file.close();
    const stat = std.posix.fstat(file.handle) catch return fallback(result, requested, replay, "file-unreadable");
    if (!std.posix.S.ISREG(stat.mode) or stat.size < 0) return fallback(result, requested, replay, "not-a-regular-file");
    const size: u64 = @intCast(stat.size);
    result.observed.dev = @intCast(stat.dev);
    result.observed.ino = @intCast(stat.ino);
    result.observed.size = size;

    const source_row = row orelse return fallback(result, requested, replay, "no-logs-row");
    const recorded = source_row.firstlinemd5 orelse return fallback(result, requested, replay, "first-line-md5-unrecorded");
    if (!digestRecognised(recorded)) return fallback(result, requested, replay, "first-line-digest-unrecognised");
    const current = (firstLineDigest(file, recorded.len) catch return fallback(result, requested, replay, "file-unreadable")) orelse {
        return fallback(result, requested, replay, "first-line-incomplete");
    };
    const matches = std.ascii.eqlIgnoreCase(current[0..recorded.len], recorded);
    result.observed.first_line_md5_matches = matches;
    if (!matches) return fallback(result, requested, replay, "first-line-md5-mismatch");

    const raw_offset = source_row.lastfilepos orelse 0;
    if (raw_offset < 0) return fallback(result, requested, replay, "offset-negative");
    const offset: u64 = @intCast(raw_offset);
    if (offset > size) return fallback(result, requested, replay, "offset-beyond-size");
    result.observed.offset_valid = true;

    result.checkpoint = buildResume(file, size, offset) catch return fallback(result, requested, replay, "file-unreadable");
    result.decision = .resume_at_offset;
    result.reason = if (offset == size) "resume-at-end" else "resume-with-unread-tail";
    return result;
}

fn fallback(base: FileBoundary, requested: plan_mod.Continuity, replay: ?Replay, reason: []const u8) FileBoundary {
    var result = base;
    result.reason = reason;
    result.decision = switch (requested) {
        .lossless => .blocked,
        .reset_replay => if (replay != null) .replay_window else .start_at_tail,
    };
    return result;
}

fn firstLineDigest(file: std.fs.File, recorded_len: usize) !?[40]u8 {
    var buffer: [first_line_max_bytes]u8 = undefined;
    const got = try file.preadAll(&buffer, 0);
    const end = std.mem.indexOfScalar(u8, buffer[0..got], '\n') orelse return null;
    const line = buffer[0 .. end + 1];
    var out: [40]u8 = undefined;
    switch (recorded_len) {
        32 => {
            var digest: [16]u8 = undefined;
            std.crypto.hash.Md5.hash(line, &digest, .{});
            _ = std.fmt.bufPrint(&out, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch unreachable;
        },
        40 => {
            var digest: [20]u8 = undefined;
            std.crypto.hash.Sha1.hash(line, &digest, .{});
            _ = std.fmt.bufPrint(&out, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch unreachable;
        },
        else => return error.UnrecognisedDigest,
    }
    return out;
}

fn digestRecognised(recorded: []const u8) bool {
    if (recorded.len != 32 and recorded.len != 40) return false;
    for (recorded) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

fn buildResume(file: std.fs.File, size: u64, offset: u64) !file_source.Resume {
    const stat = try std.posix.fstat(file.handle);
    const n: u8 = @intCast(@min(size, prefix_max_bytes));
    var bytes: [prefix_max_bytes]u8 = undefined;
    const got = try file.preadAll(bytes[0..n], 0);
    if (got != n) return error.Incomplete;
    var prefix_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes[0..n], &prefix_hash, .{});
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("fail2zig-migration-resume-v1");
    var word: [8]u8 = undefined;
    std.mem.writeInt(u64, &word, @intCast(stat.dev), .little);
    hasher.update(&word);
    std.mem.writeInt(u64, &word, @intCast(stat.ino), .little);
    hasher.update(&word);
    std.mem.writeInt(u64, &word, offset, .little);
    hasher.update(&word);
    hasher.update(&prefix_hash);
    const identity = hasher.finalResult();
    var incarnation: [16]u8 = undefined;
    @memcpy(&incarnation, identity[0..16]);
    return .{
        .start = .head,
        .framing = .bytes,
        .incarnation = incarnation,
        .device = @intCast(stat.dev),
        .inode = @intCast(stat.ino),
        .offset = offset,
        .prefix_len = n,
        .prefix_hash = prefix_hash,
    };
}

fn findRow(logs: []const LogRow, jail: []const u8, path: []const u8) ?LogRow {
    for (logs) |row| if (std.mem.eql(u8, row.jail, jail) and std.mem.eql(u8, row.path, path)) return row;
    return null;
}

fn manifestGroups(doc: *const plan_mod.Document) ?[]const std.json.Value {
    if (doc.manifest != .object) return null;
    const groups = doc.manifest.object.get("groups") orelse return null;
    if (groups != .array) return null;
    return groups.array.items;
}

fn findGroup(groups: []const std.json.Value, name: []const u8) ?std.json.Value {
    for (groups) |g| {
        if (g != .object) continue;
        const n = stringField(g, "name") orelse continue;
        if (std.mem.eql(u8, n, name)) return g;
    }
    return null;
}

fn stringField(value: std.json.Value, key: []const u8) ?[]const u8 {
    if (value != .object) return null;
    const v = value.object.get(key) orelse return null;
    return if (v == .string) v.string else null;
}

fn fileLessThan(_: void, x: FileBoundary, y: FileBoundary) bool {
    const g = std.mem.order(u8, x.group, y.group);
    if (g != .eq) return g == .lt;
    return std.mem.order(u8, x.path, y.path) == .lt;
}
fn journalLessThan(_: void, x: JournalBoundary, y: JournalBoundary) bool {
    return std.mem.order(u8, x.group, y.group) == .lt;
}

fn jsonString(writer: anytype, s: []const u8) !void {
    try std.json.stringify(s, .{}, writer);
}

fn jsonOptU64(writer: anytype, v: ?u64) !void {
    if (v) |x| try writer.print("{d}", .{x}) else try writer.writeAll("null");
}

fn jsonOptBool(writer: anytype, v: ?bool) !void {
    if (v) |x| try writer.print("{}", .{x}) else try writer.writeAll("null");
}

pub fn writeBoundaryJson(boundary: *const Boundary, writer: anytype) !void {
    try writer.writeAll("{\"schema_version\":1,\"requested\":");
    try jsonString(writer, @tagName(boundary.requested));
    try writer.writeAll(",\"outcome\":");
    try jsonString(writer, @tagName(boundary.outcome));
    try writer.writeAll(",\"replay\":");
    if (boundary.replay) |r| {
        try writer.print("{{\"window_s\":{d},\"cutover_us\":{d},\"from_us\":{d}}}", .{ r.window_s, r.cutover_us, r.from_us });
    } else try writer.writeAll("null");
    try writer.writeAll(",\"not_transferable\":[\"pending_records\",\"in_window_failure_counters\",\"multiline_correlation_state\"],\"files\":[");
    for (boundary.files, 0..) |f, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("{\"group\":");
        try jsonString(writer, f.group);
        try writer.writeAll(",\"path\":");
        try jsonString(writer, f.path);
        try writer.writeAll(",\"observed\":{\"dev\":");
        try jsonOptU64(writer, f.observed.dev);
        try writer.writeAll(",\"ino\":");
        try jsonOptU64(writer, f.observed.ino);
        try writer.writeAll(",\"size\":");
        try jsonOptU64(writer, f.observed.size);
        try writer.writeAll(",\"first_line_md5_matches\":");
        try jsonOptBool(writer, f.observed.first_line_md5_matches);
        try writer.print(",\"offset_valid\":{}}},\"decision\":", .{f.observed.offset_valid});
        try jsonString(writer, @tagName(f.decision));
        try writer.writeAll(",\"reason\":");
        try jsonString(writer, f.reason);
        try writer.writeAll(",\"checkpoint\":");
        if (f.checkpoint) |r| {
            try writer.print("{{\"device\":{d},\"inode\":{d},\"offset\":{d},\"prefix_len\":{d},\"prefix_hash\":\"{s}\",\"incarnation\":\"{s}\"}}", .{ r.device, r.inode, r.offset, r.prefix_len, std.fmt.fmtSliceHexLower(&r.prefix_hash), std.fmt.fmtSliceHexLower(&r.incarnation) });
        } else try writer.writeAll("null");
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"journals\":[");
    for (boundary.journals, 0..) |j, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("{\"group\":");
        try jsonString(writer, j.group);
        try writer.writeAll(",\"decision\":");
        try jsonString(writer, @tagName(j.decision));
        try writer.writeAll(",\"reason\":");
        try jsonString(writer, j.reason);
        try writer.writeByte('}');
    }
    try writer.writeAll("]}\n");
}
