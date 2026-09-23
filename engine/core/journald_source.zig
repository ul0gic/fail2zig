// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const linux = std.os.linux;

const event_loop_mod = @import("event_loop.zig");
const log_watcher_mod = @import("log_watcher.zig");
const config_mod = @import("../config/native.zig");
const shared = @import("shared");

const EventLoop = event_loop_mod.EventLoop;
const TimerHandle = event_loop_mod.TimerHandle;
const LineCallback = log_watcher_mod.LineCallback;
const JailHealth = log_watcher_mod.JailHealth;
const JailId = shared.JailId;

pub const Error = error{
    NotLinux,
    OutOfMemory,
    EventLoopError,
    TooManyJails,
    PathTooLong,
    UnsupportedJournaldFilter,
};

pub const poll_interval_ms: u64 = 1000;

pub const max_jails: usize = 64;

pub const max_entries_per_tick: usize = 4096;

pub const max_output_bytes: usize = 16 * 1024 * 1024;

pub const max_cursor_len: usize = 512;

pub const max_line_len: usize = 4096;

pub const max_json_line_len: usize = 64 * 1024;

pub const default_child_timeout_ms: u64 = 60_000;

pub const default_baseline_timeout_ms: u64 = 5_000;

const max_reads_per_callback: usize = 4;

pub const ResolvedSource = enum { file, journald, internal, fail };

pub fn resolveSource(
    source: config_mod.LogSource,
    logpath_exists: bool,
    journalctl_present: bool,
    filter_journald_supported: bool,
) ResolvedSource {
    return switch (source) {
        .file => .file,
        .internal => .internal,
        .journald => if (journalctl_present) .journald else .fail,
        .auto => blk: {
            if (logpath_exists) break :blk .file;
            if (filter_journald_supported and journalctl_present) break :blk .journald;
            break :blk .file;
        },
    };
}

pub const sshd_selectors = [_][]const u8{
    "SYSLOG_IDENTIFIER=sshd",
    "SYSLOG_IDENTIFIER=sshd-session",
    "_COMM=sshd",
    "_COMM=sshd-session",
};

pub fn selectorsForFilter(filter: []const u8) ?[]const []const u8 {
    if (std.mem.eql(u8, filter, "sshd")) return &sshd_selectors;
    return null;
}

fn appendSelectorArgv(
    argv: *std.ArrayList([]const u8),
    selectors: []const []const u8,
) Allocator.Error!void {
    var prev_field: ?[]const u8 = null;
    for (selectors) |sel| {
        const field = fieldOf(sel);
        if (prev_field) |pf| {
            if (!std.mem.eql(u8, pf, field)) {
                try argv.append("+");
            }
        }
        try argv.append(sel);
        prev_field = field;
    }
}

fn fieldOf(selector: []const u8) []const u8 {
    const eq = std.mem.indexOfScalar(u8, selector, '=') orelse return selector;
    return selector[0..eq];
}

pub fn buildBaselineArgv(
    arena: Allocator,
    journalctl_path: []const u8,
    selectors: []const []const u8,
) Allocator.Error![]const []const u8 {
    var argv = std.ArrayList([]const u8).init(arena);
    try argv.append(journalctl_path);
    try appendSelectorArgv(&argv, selectors);
    try argv.append("-n");
    try argv.append("1");
    try argv.append("-o");
    try argv.append("json");
    try argv.append("--no-pager");
    try argv.append("-q");
    return argv.toOwnedSlice();
}

pub fn buildPollArgv(
    arena: Allocator,
    journalctl_path: []const u8,
    selectors: []const []const u8,
    cursor_flag: []const u8,
) Allocator.Error![]const []const u8 {
    var argv = std.ArrayList([]const u8).init(arena);
    try argv.append(journalctl_path);
    try appendSelectorArgv(&argv, selectors);
    try argv.append("-o");
    try argv.append("json");
    try argv.append("--no-pager");
    try argv.append("-q");
    try argv.append(cursor_flag);
    return argv.toOwnedSlice();
}

pub const DecodedEntry = struct {
    message: []const u8,
    cursor: ?[]const u8,
};

pub const DecodeError = error{
    NotAnObject,
    NoMessage,
    MessageTooLong,
    MalformedMessage,
};

pub fn decodeEntry(
    arena: Allocator,
    json_line: []const u8,
    msg_buf: []u8,
    cursor_buf: []u8,
) DecodeError!DecodedEntry {
    const parsed = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena,
        json_line,
        .{},
    ) catch return error.MalformedMessage;

    if (parsed != .object) return error.NotAnObject;
    const obj = parsed.object;

    const msg_val = obj.get("MESSAGE") orelse return error.NoMessage;
    const message = try normalizeMessage(msg_val, msg_buf);

    const cursor = cursorFromObject(obj, cursor_buf);

    return .{ .message = message, .cursor = cursor };
}

fn cursorFromObject(obj: std.json.ObjectMap, cursor_buf: []u8) ?[]const u8 {
    const cur_val = obj.get("__CURSOR") orelse return null;
    switch (cur_val) {
        .string => |s| {
            if (s.len == 0 or s.len > cursor_buf.len) return null;
            @memcpy(cursor_buf[0..s.len], s);
            return cursor_buf[0..s.len];
        },
        else => return null,
    }
}

pub fn extractCursor(arena: Allocator, json_line: []const u8, cursor_buf: []u8) ?[]const u8 {
    const parsed = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena,
        json_line,
        .{},
    ) catch return null;
    if (parsed != .object) return null;
    return cursorFromObject(parsed.object, cursor_buf);
}

fn normalizeMessage(val: std.json.Value, out: []u8) DecodeError![]const u8 {
    switch (val) {
        .string => |s| {
            if (s.len > out.len) return error.MessageTooLong;
            @memcpy(out[0..s.len], s);
            return out[0..s.len];
        },
        .array => |arr| {
            if (arr.items.len > out.len) return error.MessageTooLong;
            var i: usize = 0;
            for (arr.items) |elem| {
                const n: i64 = switch (elem) {
                    .integer => |v| v,
                    else => return error.MalformedMessage,
                };
                if (n < 0 or n > 255) return error.MalformedMessage;
                out[i] = @intCast(n);
                i += 1;
            }
            return out[0..i];
        },
        else => return error.NoMessage,
    }
}

pub const cursor_magic: [4]u8 = .{ 'F', '2', 'Z', 'J' };
pub const cursor_version: u16 = 1;
const cursor_file_basename = "journald-cursors.bin";
const max_sidecar_bytes: usize = 1024 * 1024;

pub const CursorEntry = struct {
    name: []const u8,
    cursor: []const u8,
};

pub const SidecarError = error{
    OutOfMemory,
    WriteFailed,
    ReadFailed,
    OpenFailed,
    FsyncFailed,
    RenameFailed,
    ChmodFailed,
    PathTooLong,
};

pub fn cursorPath(state_file: []const u8, buf: []u8) SidecarError![]const u8 {
    const dir = std.fs.path.dirname(state_file) orelse ".";
    const need = dir.len + 1 + cursor_file_basename.len;
    if (need > buf.len) return error.PathTooLong;
    @memcpy(buf[0..dir.len], dir);
    buf[dir.len] = '/';
    @memcpy(buf[dir.len + 1 ..][0..cursor_file_basename.len], cursor_file_basename);
    return buf[0..need];
}

pub const CursorSaveError = SidecarError || std.fs.File.OpenError;

pub fn saveCursors(entries: []const CursorEntry, path: []const u8) CursorSaveError!void {
    const max_path: usize = 4096;
    if (path.len == 0 or path.len + 4 > max_path) return error.PathTooLong;
    var tmp_buf: [max_path]u8 = undefined;
    @memcpy(tmp_buf[0..path.len], path);
    const tmp_suffix = ".tmp";
    @memcpy(tmp_buf[path.len .. path.len + tmp_suffix.len], tmp_suffix);
    const tmp_path = tmp_buf[0 .. path.len + tmp_suffix.len];

    var file = try std.fs.cwd().createFile(tmp_path, .{
        .mode = 0o600,
        .truncate = true,
    });
    var close_handled = false;
    defer if (!close_handled) file.close();

    var crc = std.hash.Crc32.init();
    const writer = file.writer();

    var hdr: [10]u8 = undefined;
    @memcpy(hdr[0..4], &cursor_magic);
    std.mem.writeInt(u16, hdr[4..6], cursor_version, .little);
    std.mem.writeInt(u32, hdr[6..10], @intCast(entries.len), .little);
    writer.writeAll(&hdr) catch return error.WriteFailed;
    crc.update(&hdr);

    var len_buf: [2]u8 = undefined;
    for (entries) |e| {
        if (e.name.len > std.math.maxInt(u16) or e.cursor.len > std.math.maxInt(u16)) {
            return error.WriteFailed;
        }
        std.mem.writeInt(u16, &len_buf, @intCast(e.name.len), .little);
        writer.writeAll(&len_buf) catch return error.WriteFailed;
        crc.update(&len_buf);
        writer.writeAll(e.name) catch return error.WriteFailed;
        crc.update(e.name);

        std.mem.writeInt(u16, &len_buf, @intCast(e.cursor.len), .little);
        writer.writeAll(&len_buf) catch return error.WriteFailed;
        crc.update(&len_buf);
        writer.writeAll(e.cursor) catch return error.WriteFailed;
        crc.update(e.cursor);
    }

    var crc_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc_buf, crc.final(), .little);
    writer.writeAll(&crc_buf) catch return error.WriteFailed;

    posix.fsync(file.handle) catch return error.FsyncFailed;
    posix.fchmod(file.handle, 0o600) catch return error.ChmodFailed;

    file.close();
    close_handled = true;

    std.fs.cwd().rename(tmp_path, path) catch return error.RenameFailed;
}

pub fn loadCursors(allocator: Allocator, path: []const u8) SidecarError![]CursorEntry {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return allocator.alloc(CursorEntry, 0) catch
            return error.OutOfMemory,
        else => return error.OpenFailed,
    };
    defer file.close();

    const bytes = file.readToEndAlloc(allocator, max_sidecar_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ReadFailed,
    };
    defer allocator.free(bytes);

    const empty = struct {
        fn make(a: Allocator) SidecarError![]CursorEntry {
            return a.alloc(CursorEntry, 0) catch error.OutOfMemory;
        }
    }.make;

    if (bytes.len < 10 + 4) {
        std.log.warn("journald: cursor sidecar too short ({d} bytes); re-seeding", .{bytes.len});
        return empty(allocator);
    }
    if (!std.mem.eql(u8, bytes[0..4], &cursor_magic)) {
        std.log.warn("journald: cursor sidecar bad magic; re-seeding", .{});
        return empty(allocator);
    }
    const ver = std.mem.readInt(u16, bytes[4..6], .little);
    if (ver != cursor_version) {
        std.log.warn("journald: cursor sidecar version {d} unsupported; re-seeding", .{ver});
        return empty(allocator);
    }
    const count = std.mem.readInt(u32, bytes[6..10], .little);

    const body = bytes[0 .. bytes.len - 4];
    const stored_crc = std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little);
    if (std.hash.Crc32.hash(body) != stored_crc) {
        std.log.warn("journald: cursor sidecar checksum mismatch; re-seeding", .{});
        return empty(allocator);
    }

    var out = std.ArrayList(CursorEntry).init(allocator);
    errdefer {
        for (out.items) |e| {
            allocator.free(e.name);
            allocator.free(e.cursor);
        }
        out.deinit();
    }

    var off: usize = 10;
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        if (off + 2 > body.len) return failCorrupt(allocator, &out);
        const name_len = std.mem.readInt(u16, body[off..][0..2], .little);
        off += 2;
        if (off + name_len > body.len) return failCorrupt(allocator, &out);
        const name = allocator.dupe(u8, body[off..][0..name_len]) catch return error.OutOfMemory;
        off += name_len;

        if (off + 2 > body.len) {
            allocator.free(name);
            return failCorrupt(allocator, &out);
        }
        const cur_len = std.mem.readInt(u16, body[off..][0..2], .little);
        off += 2;
        if (off + cur_len > body.len) {
            allocator.free(name);
            return failCorrupt(allocator, &out);
        }
        const cur = allocator.dupe(u8, body[off..][0..cur_len]) catch {
            allocator.free(name);
            return error.OutOfMemory;
        };
        off += cur_len;

        out.append(.{ .name = name, .cursor = cur }) catch {
            allocator.free(name);
            allocator.free(cur);
            return error.OutOfMemory;
        };
    }

    return out.toOwnedSlice() catch error.OutOfMemory;
}

fn failCorrupt(allocator: Allocator, out: *std.ArrayList(CursorEntry)) SidecarError![]CursorEntry {
    std.log.warn("journald: cursor sidecar truncated/corrupt; re-seeding", .{});
    for (out.items) |e| {
        allocator.free(e.name);
        allocator.free(e.cursor);
    }
    out.deinit();
    out.* = std.ArrayList(CursorEntry).init(allocator);
    return allocator.alloc(CursorEntry, 0) catch error.OutOfMemory;
}

const InFlight = struct {
    pid: posix.pid_t,
    stdout_fd: posix.fd_t,
    started_ms: i64,
    baseline: bool,
    registered: bool,
    bytes: usize = 0,
    eof: bool = false,
};

pub const JournalJail = struct {
    jail: JailId,
    selectors: []const []const u8,
    callback: LineCallback,
    userdata: ?*anyopaque,
    pending: []u8,
    pending_len: usize = 0,
    discarding: bool = false,
    entries: usize = 0,
    baseline_done: bool = false,
    child: ?InFlight = null,
    cursor: [max_cursor_len]u8 = [_]u8{0} ** max_cursor_len,
    cursor_len: usize = 0,

    last_read_ok_ts: i64 = 0,
    lines_seen: u64 = 0,

    fn cursorSlice(self: *const JournalJail) []const u8 {
        return self.cursor[0..self.cursor_len];
    }

    fn setCursor(self: *JournalJail, cur: []const u8) void {
        if (cur.len == 0 or cur.len > max_cursor_len) return;
        @memcpy(self.cursor[0..cur.len], cur);
        self.cursor_len = cur.len;
    }

    fn resetStream(self: *JournalJail) void {
        self.pending_len = 0;
        self.discarding = false;
        self.entries = 0;
        self.baseline_done = false;
    }

    pub const TestAccess = if (builtin.is_test) struct {
        pub const cursorSlice = JournalJail.cursorSlice;
        pub const setCursor = JournalJail.setCursor;
    } else struct {};
};

pub const Options = struct {
    journalctl_path: []const u8 = config_mod.journalctl_path,
    child_timeout_ms: u64 = default_child_timeout_ms,
    baseline_timeout_ms: u64 = default_baseline_timeout_ms,
};

pub const JournaldSource = struct {
    allocator: Allocator,
    event_loop: *EventLoop,
    jails: std.ArrayList(JournalJail),
    cursor_path: []u8,
    journalctl_path: []const u8,
    child_timeout_ms: u64,
    baseline_timeout_ms: u64,
    poll_handle: ?TimerHandle = null,
    dirty: bool = false,
    flush_fn: ?*const fn (?*anyopaque) bool = null,
    flush_userdata: ?*anyopaque = null,

    pub fn init(
        allocator: Allocator,
        event_loop: *EventLoop,
        state_file: []const u8,
        options: Options,
    ) Error!JournaldSource {
        if (builtin.os.tag != .linux) return error.NotLinux;

        var path_buf: [4096]u8 = undefined;
        const cp = cursorPath(state_file, &path_buf) catch return error.PathTooLong;
        const owned = allocator.dupe(u8, cp) catch return error.OutOfMemory;
        errdefer allocator.free(owned);

        return .{
            .allocator = allocator,
            .event_loop = event_loop,
            .jails = std.ArrayList(JournalJail).init(allocator),
            .cursor_path = owned,
            .journalctl_path = options.journalctl_path,
            .child_timeout_ms = options.child_timeout_ms,
            .baseline_timeout_ms = options.baseline_timeout_ms,
        };
    }

    pub fn deinit(self: *JournaldSource) void {
        if (self.poll_handle) |h| {
            self.event_loop.cancelTimer(h) catch {};
        }
        for (self.jails.items) |*jj| {
            if (jj.child != null) self.finishChild(jj, .kill);
            self.allocator.free(jj.pending);
        }
        self.jails.deinit();
        self.allocator.free(self.cursor_path);
        self.* = undefined;
    }

    pub fn hasJails(self: *const JournaldSource) bool {
        return self.jails.items.len > 0;
    }

    pub fn addJail(
        self: *JournaldSource,
        jail: JailId,
        filter: []const u8,
        callback: LineCallback,
        userdata: ?*anyopaque,
    ) Error!void {
        const selectors = selectorsForFilter(filter) orelse
            return error.UnsupportedJournaldFilter;
        if (self.jails.items.len >= max_jails) return error.TooManyJails;
        const pending = self.allocator.alloc(u8, max_json_line_len) catch
            return error.OutOfMemory;
        errdefer self.allocator.free(pending);
        self.jails.append(.{
            .jail = jail,
            .selectors = selectors,
            .callback = callback,
            .userdata = userdata,
            .pending = pending,
        }) catch return error.OutOfMemory;
    }

    pub fn setFlushHook(
        self: *JournaldSource,
        fn_ptr: *const fn (?*anyopaque) bool,
        userdata: ?*anyopaque,
    ) void {
        self.flush_fn = fn_ptr;
        self.flush_userdata = userdata;
    }

    pub fn seedCursor(self: *JournaldSource, jail_name: []const u8, cursor: []const u8) void {
        for (self.jails.items) |*jj| {
            if (std.mem.eql(u8, jj.jail.slice(), jail_name)) {
                jj.setCursor(cursor);
                return;
            }
        }
    }

    pub fn attach(self: *JournaldSource) Error!void {
        for (self.jails.items) |*jj| {
            if (jj.cursor_len != 0) continue;
            self.baselineSync(jj) catch |err| {
                std.log.warn(
                    "journald: baseline for jail '{s}' failed: {s}; retrying on the poll timer",
                    .{ jj.jail.slice(), @errorName(err) },
                );
            };
        }
        self.maybeFlush();
        const h = self.event_loop.addTimer(poll_interval_ms, pollTick, self, false) catch
            return error.EventLoopError;
        self.poll_handle = h;
    }

    fn baselineSync(self: *JournaldSource, jj: *JournalJail) PollError!void {
        try self.spawnChild(jj, false);
        const deadline = std.time.milliTimestamp() + @as(i64, @intCast(self.baseline_timeout_ms));

        while (jj.child) |inf| {
            const remaining = deadline - std.time.milliTimestamp();
            if (remaining <= 0) break;
            if (inf.eof) {
                std.time.sleep(std.time.ns_per_ms);
                self.finishChild(jj, .eof);
                continue;
            }
            var pfd = [_]posix.pollfd{.{ .fd = inf.stdout_fd, .events = posix.POLL.IN, .revents = 0 }};
            const ready = posix.poll(&pfd, @intCast(@min(remaining, std.math.maxInt(i32)))) catch 0;
            if (ready == 0) continue;
            self.drainStdout(jj);
        }

        if (jj.child != null) {
            std.log.warn(
                "journald: baseline for jail '{s}' exceeded {d}ms; killing and retrying on the poll timer",
                .{ jj.jail.slice(), self.baseline_timeout_ms },
            );
            self.finishChild(jj, .kill);
        }
    }

    pub fn collectCursors(self: *const JournaldSource, buf: []CursorEntry) []CursorEntry {
        var n: usize = 0;
        for (self.jails.items) |*jj| {
            if (n >= buf.len) break;
            if (jj.cursor_len == 0) continue;
            buf[n] = .{ .name = jj.jail.slice(), .cursor = jj.cursorSlice() };
            n += 1;
        }
        return buf[0..n];
    }

    pub fn jailCount(self: *const JournaldSource) usize {
        return self.jails.items.len;
    }

    pub fn healthForJail(self: *const JournaldSource, name: []const u8) ?JailHealth {
        for (self.jails.items) |*jj| {
            if (std.mem.eql(u8, jj.jail.slice(), name)) {
                return .{
                    .healthy = jj.last_read_ok_ts > 0,
                    .lines_seen = jj.lines_seen,
                    .last_read_ok_ts = jj.last_read_ok_ts,
                };
            }
        }
        return null;
    }

    fn pollTick(expirations: u64, userdata: ?*anyopaque) void {
        _ = expirations;
        const self: *JournaldSource = @ptrCast(@alignCast(userdata.?));
        const now = std.time.milliTimestamp();
        for (self.jails.items) |*jj| {
            if (jj.child) |inf| {
                self.superviseInFlight(jj, inf, now);
                continue;
            }
            self.pollJail(jj) catch |err| {
                std.log.warn(
                    "journald: poll for jail '{s}' failed: {s}; retrying next tick",
                    .{ jj.jail.slice(), @errorName(err) },
                );
            };
        }
        self.maybeFlush();
    }

    fn superviseInFlight(self: *JournaldSource, jj: *JournalJail, inf: InFlight, now: i64) void {
        if (inf.eof) {
            self.finishChild(jj, .eof);
            return;
        }
        const elapsed: i64 = now - inf.started_ms;
        if (elapsed >= 0 and @as(u64, @intCast(elapsed)) >= self.child_timeout_ms) {
            std.log.warn(
                "journald: journalctl for jail '{s}' exceeded {d}ms; killing",
                .{ jj.jail.slice(), self.child_timeout_ms },
            );
            self.finishChild(jj, .kill);
        }
    }

    pub fn maybeFlush(self: *JournaldSource) void {
        if (!self.dirty) return;
        if (self.flush_fn) |f| {
            if (f(self.flush_userdata)) self.dirty = false;
        }
    }

    const PollError = error{
        OutOfMemory,
        SpawnFailed,
        EventLoopError,
    };

    fn pollJail(self: *JournaldSource, jj: *JournalJail) PollError!void {
        return self.spawnChild(jj, true);
    }

    fn spawnChild(self: *JournaldSource, jj: *JournalJail, register: bool) PollError!void {
        if (jj.child != null) return;

        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const baseline = jj.cursor_len == 0;

        const argv = blk: {
            if (baseline) {
                break :blk buildBaselineArgv(arena, self.journalctl_path, jj.selectors) catch
                    return error.OutOfMemory;
            }
            var flag = std.ArrayList(u8).init(arena);
            flag.appendSlice("--after-cursor=") catch return error.OutOfMemory;
            flag.appendSlice(jj.cursorSlice()) catch return error.OutOfMemory;
            const owned_flag = flag.toOwnedSlice() catch return error.OutOfMemory;
            break :blk buildPollArgv(arena, self.journalctl_path, jj.selectors, owned_flag) catch
                return error.OutOfMemory;
        };

        var child = std.process.Child.init(argv, arena);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        child.spawn() catch return error.SpawnFailed;

        const stdout_fd = if (child.stdout) |f| f.handle else {
            _ = killAndReap(child.id);
            return error.SpawnFailed;
        };
        errdefer {
            posix.close(stdout_fd);
            _ = killAndReap(child.id);
        }
        child.waitForSpawn() catch return error.SpawnFailed;

        const flags = posix.fcntl(stdout_fd, posix.F.GETFL, 0) catch return error.SpawnFailed;
        _ = posix.fcntl(stdout_fd, posix.F.SETFL, flags | @as(usize, linux.SOCK.NONBLOCK)) catch
            return error.SpawnFailed;

        if (register) {
            const ev_mask: u32 = linux.EPOLL.IN | linux.EPOLL.HUP | linux.EPOLL.ERR;
            self.event_loop.addFd(stdout_fd, ev_mask, onStdoutReady, self) catch
                return error.EventLoopError;
        }

        jj.resetStream();
        jj.child = .{
            .pid = child.id,
            .stdout_fd = stdout_fd,
            .started_ms = std.time.milliTimestamp(),
            .baseline = baseline,
            .registered = register,
        };
    }

    fn onStdoutReady(fd: posix.fd_t, events: u32, userdata: ?*anyopaque) void {
        _ = events;
        const self: *JournaldSource = @ptrCast(@alignCast(userdata.?));
        for (self.jails.items) |*jj| {
            const inf = jj.child orelse continue;
            if (inf.stdout_fd != fd) continue;
            self.drainStdout(jj);
            return;
        }
    }

    fn drainStdout(self: *JournaldSource, jj: *JournalJail) void {
        var reads: usize = 0;
        while (reads < max_reads_per_callback) : (reads += 1) {
            const inf = jj.child orelse return;
            const n = posix.read(inf.stdout_fd, jj.pending[jj.pending_len..]) catch |err| switch (err) {
                error.WouldBlock => return,
                else => {
                    std.log.warn(
                        "journald: read from journalctl failed for jail '{s}': {s}",
                        .{ jj.jail.slice(), @errorName(err) },
                    );
                    self.finishChild(jj, .kill);
                    return;
                },
            };
            if (n == 0) {
                self.finishChild(jj, .eof);
                return;
            }
            jj.child.?.bytes += n;
            if (jj.child.?.bytes > max_output_bytes) {
                std.log.warn(
                    "journald: jail '{s}' hit {d}-byte/tick cap; resuming next tick",
                    .{ jj.jail.slice(), max_output_bytes },
                );
                self.finishChild(jj, .kill);
                return;
            }
            jj.pending_len += n;
            if (!self.consumeLines(jj)) {
                self.finishChild(jj, .kill);
                return;
            }
        }
    }

    fn consumeLines(self: *JournaldSource, jj: *JournalJail) bool {
        var start: usize = 0;
        var keep_going = true;
        while (std.mem.indexOfScalarPos(u8, jj.pending[0..jj.pending_len], start, '\n')) |nl| {
            const line = jj.pending[start..nl];
            start = nl + 1;
            if (jj.discarding) {
                jj.discarding = false;
                continue;
            }
            if (!self.handleLine(jj, line)) {
                keep_going = false;
                break;
            }
        }

        const rest = jj.pending_len - start;
        if (start > 0 and rest > 0) {
            std.mem.copyForwards(u8, jj.pending[0..rest], jj.pending[start..jj.pending_len]);
        }
        jj.pending_len = rest;

        if (jj.pending_len == jj.pending.len) {
            if (!jj.discarding) {
                std.log.warn(
                    "journald: jail '{s}' entry exceeds {d} bytes; dropping it",
                    .{ jj.jail.slice(), max_json_line_len },
                );
                jj.entries += 1;
            }
            jj.discarding = true;
            jj.pending_len = 0;
        }
        return keep_going;
    }

    fn handleLine(self: *JournaldSource, jj: *JournalJail, raw_line: []const u8) bool {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) return true;
        const baseline = if (jj.child) |inf| inf.baseline else false;
        if (baseline) {
            if (!jj.baseline_done) self.seedBaselineLine(jj, line);
            return true;
        }
        return self.processEntry(jj, line);
    }

    fn seedBaselineLine(self: *JournaldSource, jj: *JournalJail, line: []const u8) void {
        var cursor_buf: [max_cursor_len]u8 = undefined;
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        jj.baseline_done = true;
        if (extractCursor(arena_state.allocator(), line, &cursor_buf)) |cur| {
            jj.setCursor(cur);
            self.dirty = true;
            std.log.info(
                "journald: jail '{s}' baselined at journal tail (no history replay)",
                .{jj.jail.slice()},
            );
        } else {
            std.log.warn(
                "journald: jail '{s}' baseline entry had no usable __CURSOR; re-baselining next tick",
                .{jj.jail.slice()},
            );
        }
    }

    fn processEntry(self: *JournaldSource, jj: *JournalJail, line: []const u8) bool {
        if (jj.entries >= max_entries_per_tick) {
            std.log.warn(
                "journald: jail '{s}' hit {d}-entry/tick cap; resuming next tick",
                .{ jj.jail.slice(), max_entries_per_tick },
            );
            return false;
        }
        jj.entries += 1;

        var msg_buf: [max_line_len]u8 = undefined;
        var cursor_buf: [max_cursor_len]u8 = undefined;
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();

        const entry = decodeEntry(
            arena_state.allocator(),
            line,
            &msg_buf,
            &cursor_buf,
        ) catch |err| {
            std.log.warn(
                "journald: skipping malformed entry for jail '{s}': {s}",
                .{ jj.jail.slice(), @errorName(err) },
            );
            return true;
        };

        jj.callback(entry.message, jj.jail, false, jj.userdata);
        jj.lines_seen += 1;

        if (entry.cursor) |cur| {
            jj.setCursor(cur);
            self.dirty = true;
        }
        return true;
    }

    const FinishMode = enum { eof, kill };

    fn finishChild(self: *JournaldSource, jj: *JournalJail, mode: FinishMode) void {
        var inf = jj.child orelse return;

        if (inf.stdout_fd >= 0) {
            if (inf.registered) self.event_loop.removeFd(inf.stdout_fd) catch {};
            posix.close(inf.stdout_fd);
            inf.stdout_fd = -1;
        }

        const status: u32 = switch (mode) {
            .kill => killAndReap(inf.pid),
            .eof => reapNoHang(inf.pid) orelse {
                inf.eof = true;
                jj.child = inf;
                return;
            },
        };

        jj.child = null;
        jj.resetStream();

        if (mode == .kill) return;
        if (linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 0) {
            jj.last_read_ok_ts = std.time.timestamp();
        } else if (linux.W.IFEXITED(status)) {
            std.log.warn(
                "journald: journalctl exited {d} for jail '{s}'",
                .{ linux.W.EXITSTATUS(status), jj.jail.slice() },
            );
        } else {
            std.log.warn(
                "journald: journalctl terminated abnormally for jail '{s}'",
                .{jj.jail.slice()},
            );
        }
        self.maybeFlush();
    }

    fn seedBaseline(self: *JournaldSource, jj: *JournalJail, stdout: []const u8) void {
        jj.resetStream();
        var it = std.mem.splitScalar(u8, stdout, '\n');
        while (it.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0) continue;
            self.seedBaselineLine(jj, line);
            return;
        }
    }

    fn processBatch(self: *JournaldSource, jj: *JournalJail, stdout: []const u8) void {
        jj.resetStream();
        var it = std.mem.splitScalar(u8, stdout, '\n');
        while (it.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0) continue;
            if (!self.processEntry(jj, line)) break;
        }
    }

    pub const TestAccess = if (builtin.is_test) struct {
        pub const consumeLines = JournaldSource.consumeLines;
        pub const finishChild = JournaldSource.finishChild;
        pub const pollJail = JournaldSource.pollJail;
        pub const processBatch = JournaldSource.processBatch;
        pub const seedBaseline = JournaldSource.seedBaseline;
    } else struct {};
};

fn reapNoHang(pid: posix.pid_t) ?u32 {
    var status: u32 = 0;
    while (true) {
        const rc = linux.waitpid(pid, &status, linux.W.NOHANG);
        switch (linux.E.init(rc)) {
            .SUCCESS => return if (rc == 0) null else status,
            .INTR => continue,
            else => return 0,
        }
    }
}

fn killAndReap(pid: posix.pid_t) u32 {
    _ = linux.kill(pid, linux.SIG.KILL);
    var status: u32 = 0;
    while (true) {
        const rc = linux.waitpid(pid, &status, 0);
        switch (linux.E.init(rc)) {
            .SUCCESS => return status,
            .INTR => continue,
            else => return 0,
        }
    }
}
