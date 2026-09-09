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

const max_reads_per_callback: usize = 4;

pub const ResolvedSource = enum { file, journald, fail };

pub fn resolveSource(
    source: config_mod.LogSource,
    logpath_exists: bool,
    journalctl_present: bool,
    filter_journald_supported: bool,
) ResolvedSource {
    return switch (source) {
        .file => .file,
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

pub fn saveCursors(entries: []const CursorEntry, path: []const u8) SidecarError!void {
    const max_path: usize = 4096;
    if (path.len == 0 or path.len + 4 > max_path) return error.PathTooLong;
    var tmp_buf: [max_path]u8 = undefined;
    @memcpy(tmp_buf[0..path.len], path);
    const tmp_suffix = ".tmp";
    @memcpy(tmp_buf[path.len .. path.len + tmp_suffix.len], tmp_suffix);
    const tmp_path = tmp_buf[0 .. path.len + tmp_suffix.len];

    var file = std.fs.cwd().createFile(tmp_path, .{
        .mode = 0o600,
        .truncate = true,
    }) catch return error.OpenFailed;
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
};

pub const Options = struct {
    journalctl_path: []const u8 = config_mod.journalctl_path,
    child_timeout_ms: u64 = default_child_timeout_ms,
};

pub const JournaldSource = struct {
    allocator: Allocator,
    event_loop: *EventLoop,
    jails: std.ArrayList(JournalJail),
    cursor_path: []u8,
    journalctl_path: []const u8,
    child_timeout_ms: u64,
    poll_handle: ?TimerHandle = null,
    dirty: bool = false,
    flush_fn: ?*const fn (?*anyopaque) void = null,
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
        fn_ptr: *const fn (?*anyopaque) void,
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
        const h = self.event_loop.addTimer(poll_interval_ms, pollTick, self, false) catch
            return error.EventLoopError;
        self.poll_handle = h;
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
            f(self.flush_userdata);
        }
        self.dirty = false;
    }

    const PollError = error{
        OutOfMemory,
        SpawnFailed,
        EventLoopError,
    };

    fn pollJail(self: *JournaldSource, jj: *JournalJail) PollError!void {
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

        const flags = posix.fcntl(stdout_fd, posix.F.GETFL, 0) catch return error.SpawnFailed;
        _ = posix.fcntl(stdout_fd, posix.F.SETFL, flags | @as(usize, linux.SOCK.NONBLOCK)) catch
            return error.SpawnFailed;

        const ev_mask: u32 = linux.EPOLL.IN | linux.EPOLL.HUP | linux.EPOLL.ERR;
        self.event_loop.addFd(stdout_fd, ev_mask, onStdoutReady, self) catch
            return error.EventLoopError;

        jj.resetStream();
        jj.child = .{
            .pid = child.id,
            .stdout_fd = stdout_fd,
            .started_ms = std.time.milliTimestamp(),
            .baseline = baseline,
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
            self.event_loop.removeFd(inf.stdout_fd) catch {};
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

const testing = std.testing;

test "journald: resolveSource explicit .file always picks file" {
    try testing.expectEqual(ResolvedSource.file, resolveSource(.file, false, true, true));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.file, false, false, false));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.file, true, false, true));
}

test "journald: resolveSource explicit .journald needs journalctl, else fails closed" {
    try testing.expectEqual(ResolvedSource.journald, resolveSource(.journald, false, true, true));
    try testing.expectEqual(ResolvedSource.fail, resolveSource(.journald, false, false, true));
    try testing.expectEqual(ResolvedSource.journald, resolveSource(.journald, false, true, false));
}

test "journald: resolveSource auto with an EXISTING logpath picks file (SYS-015)" {
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, true, true, true));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, true, false, true));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, true, true, false));
}

test "journald: resolveSource auto with ABSENT log + sshd + journalctl picks journald (SYS-015)" {
    try testing.expectEqual(ResolvedSource.journald, resolveSource(.auto, false, true, true));
}

test "journald: resolveSource auto with ABSENT log + NON-sshd filter stays file (no fail-closed)" {
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, false, true, false));
}

test "journald: resolveSource auto with ABSENT log + sshd but NO journalctl stays file" {
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, false, false, true));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, false, false, false));
}

test "journald: selectorsForFilter returns the set for sshd, null otherwise" {
    const sshd = selectorsForFilter("sshd");
    try testing.expect(sshd != null);
    try testing.expectEqual(@as(usize, sshd_selectors.len), sshd.?.len);
    try testing.expect(selectorsForFilter("nginx-http-auth") == null);
    try testing.expect(selectorsForFilter("apache-auth") == null);
    try testing.expect(selectorsForFilter("") == null);
    try testing.expect(selectorsForFilter("sshd-ddos") == null);
}

test "journald: config_mod.filterSupportsJournald stays in sync with selectorsForFilter" {
    const candidates = [_][]const u8{ "sshd", "nginx-http-auth", "apache-auth", "postfix", "dovecot", "", "sshd-ddos" };
    for (candidates) |f| {
        try testing.expectEqual(selectorsForFilter(f) != null, config_mod.filterSupportsJournald(f));
    }
}

test "journald: addJail fails closed on an unsupported filter and does not register" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();

    const jail = try JailId.fromSlice("nginx-http-auth");
    try testing.expectError(
        error.UnsupportedJournaldFilter,
        src.addJail(jail, "nginx-http-auth", CallRecorder.onLine, null),
    );
    try testing.expectEqual(@as(usize, 0), src.jailCount());
    try testing.expect(!src.hasJails());

    const sshd = try JailId.fromSlice("sshd");
    try src.addJail(sshd, "sshd", CallRecorder.onLine, null);
    try testing.expectEqual(@as(usize, 1), src.jailCount());
}

test "journald: selector argv ORs across fields with a standalone +" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const argv = try buildPollArgv(arena.allocator(), config_mod.journalctl_path, &sshd_selectors, "--after-cursor=s=abc");
    const expect = [_][]const u8{
        config_mod.journalctl_path,
        "SYSLOG_IDENTIFIER=sshd",
        "SYSLOG_IDENTIFIER=sshd-session",
        "+",
        "_COMM=sshd",
        "_COMM=sshd-session",
        "-o",
        "json",
        "--no-pager",
        "-q",
        "--after-cursor=s=abc",
    };
    try testing.expectEqual(expect.len, argv.len);
    for (expect, argv) |e, got| {
        try testing.expectEqualStrings(e, got);
    }
    try testing.expectEqualStrings("+", argv[3]);
}

test "journald: baseline argv uses -n 1, no --after-cursor" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const argv = try buildBaselineArgv(arena.allocator(), config_mod.journalctl_path, &sshd_selectors);
    var saw_n = false;
    var saw_one = false;
    for (argv, 0..) |tok, i| {
        if (std.mem.eql(u8, tok, "-n")) {
            saw_n = true;
            if (i + 1 < argv.len and std.mem.eql(u8, argv[i + 1], "1")) saw_one = true;
        }
        try testing.expect(!std.mem.startsWith(u8, tok, "--after-cursor"));
    }
    try testing.expect(saw_n and saw_one);
}

test "journald: decodeEntry string MESSAGE passes through verbatim" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    const line =
        \\{"MESSAGE":"Invalid user bob from 1.2.3.4 port 22","__CURSOR":"s=abc;i=1"}
    ;
    const e = try decodeEntry(arena.allocator(), line, &msg_buf, &cur_buf);
    try testing.expectEqualStrings("Invalid user bob from 1.2.3.4 port 22", e.message);
    try testing.expect(e.cursor != null);
    try testing.expectEqualStrings("s=abc;i=1", e.cursor.?);
}

test "journald: decodeEntry byte-array MESSAGE decodes to raw bytes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    const line =
        \\{"MESSAGE":[72,105,255],"__CURSOR":"s=x"}
    ;
    const e = try decodeEntry(arena.allocator(), line, &msg_buf, &cur_buf);
    try testing.expectEqual(@as(usize, 3), e.message.len);
    try testing.expectEqual(@as(u8, 72), e.message[0]);
    try testing.expectEqual(@as(u8, 105), e.message[1]);
    try testing.expectEqual(@as(u8, 255), e.message[2]);
}

test "journald: decodeEntry rejects out-of-range byte-array element" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    const line =
        \\{"MESSAGE":[72,300]}
    ;
    try testing.expectError(error.MalformedMessage, decodeEntry(arena.allocator(), line, &msg_buf, &cur_buf));
}

test "journald: decodeEntry skips missing MESSAGE" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    const line =
        \\{"__CURSOR":"s=x","PRIORITY":"6"}
    ;
    try testing.expectError(error.NoMessage, decodeEntry(arena.allocator(), line, &msg_buf, &cur_buf));
}

test "journald: decodeEntry malformed json is not fatal" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    try testing.expectError(error.MalformedMessage, decodeEntry(arena.allocator(), "{not json", &msg_buf, &cur_buf));
}

test "journald: decodeEntry without __CURSOR yields a null cursor (line still decoded)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    const line =
        \\{"MESSAGE":"Invalid user x from 9.9.9.9 port 1"}
    ;
    const e = try decodeEntry(arena.allocator(), line, &msg_buf, &cur_buf);
    try testing.expectEqualStrings("Invalid user x from 9.9.9.9 port 1", e.message);
    try testing.expect(e.cursor == null);
}

const CallRecorder = struct {
    lines: std.ArrayList([]const u8),
    first_line_ms: i64 = 0,
    fn init(a: Allocator) CallRecorder {
        return .{ .lines = std.ArrayList([]const u8).init(a) };
    }
    fn deinit(self: *CallRecorder) void {
        for (self.lines.items) |l| self.lines.allocator.free(l);
        self.lines.deinit();
    }
    fn onLine(line: []const u8, jail: JailId, truncated: bool, ud: ?*anyopaque) void {
        _ = jail;
        _ = truncated;
        const self: *CallRecorder = @ptrCast(@alignCast(ud.?));
        if (self.first_line_ms == 0) self.first_line_ms = std.time.milliTimestamp();
        const dup = self.lines.allocator.dupe(u8, line) catch return;
        self.lines.append(dup) catch self.lines.allocator.free(dup);
    }
};

test "journald: processBatch feeds callback then advances cursor only from entries with __CURSOR" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();

    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();

    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    const batch =
        "{\"MESSAGE\":\"Invalid user a from 1.1.1.1 port 1\",\"__CURSOR\":\"s=first;i=1\"}\n" ++
        "{\"MESSAGE\":\"Invalid user b from 2.2.2.2 port 2\"}\n";
    src.processBatch(jj, batch);

    try testing.expectEqual(@as(usize, 2), rec.lines.items.len);
    try testing.expectEqualStrings("Invalid user a from 1.1.1.1 port 1", rec.lines.items[0]);
    try testing.expectEqualStrings("Invalid user b from 2.2.2.2 port 2", rec.lines.items[1]);
    try testing.expectEqualStrings("s=first;i=1", jj.cursorSlice());
    try testing.expect(src.dirty);
}

test "journald: processBatch keeps the latest cursor across multiple cursored entries" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    const batch =
        "{\"MESSAGE\":\"m1 1.1.1.1\",\"__CURSOR\":\"s=one\"}\n" ++
        "{\"MESSAGE\":\"m2 2.2.2.2\",\"__CURSOR\":\"s=two\"}\n" ++
        "{\"MESSAGE\":\"m3 3.3.3.3\",\"__CURSOR\":\"s=three\"}\n";
    src.processBatch(jj, batch);
    try testing.expectEqualStrings("s=three", jj.cursorSlice());
}

test "journald: cursorPath derives the sidecar next to the state file" {
    var buf: [4096]u8 = undefined;
    const p = try cursorPath("/var/lib/fail2zig/state.bin", &buf);
    try testing.expectEqualStrings("/var/lib/fail2zig/journald-cursors.bin", p);
}

test "journald: cursor sidecar roundtrips" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dbuf);
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&pbuf, "{s}/journald-cursors.bin", .{dir});

    const entries = [_]CursorEntry{
        .{ .name = "sshd", .cursor = "s=abc;i=1;b=2" },
        .{ .name = "nginx", .cursor = "s=def;i=9" },
    };
    try saveCursors(&entries, path);

    const loaded = try loadCursors(testing.allocator, path);
    defer {
        for (loaded) |e| {
            testing.allocator.free(e.name);
            testing.allocator.free(e.cursor);
        }
        testing.allocator.free(loaded);
    }
    try testing.expectEqual(@as(usize, 2), loaded.len);
    try testing.expectEqualStrings("sshd", loaded[0].name);
    try testing.expectEqualStrings("s=abc;i=1;b=2", loaded[0].cursor);
    try testing.expectEqualStrings("nginx", loaded[1].name);
    try testing.expectEqualStrings("s=def;i=9", loaded[1].cursor);
}

test "journald: cursor sidecar corruption re-seeds (empty)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dbuf);
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&pbuf, "{s}/journald-cursors.bin", .{dir});

    const entries = [_]CursorEntry{.{ .name = "sshd", .cursor = "s=abc" }};
    try saveCursors(&entries, path);

    {
        const f = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
        defer f.close();
        try f.seekTo(12);
        try f.writeAll(&[_]u8{0xFF});
    }

    const loaded = try loadCursors(testing.allocator, path);
    defer testing.allocator.free(loaded);
    try testing.expectEqual(@as(usize, 0), loaded.len);
}

test "journald: cursor sidecar missing file returns empty without error" {
    const loaded = try loadCursors(testing.allocator, "/definitely/not/here/journald-cursors.bin");
    defer testing.allocator.free(loaded);
    try testing.expectEqual(@as(usize, 0), loaded.len);
}

test "journald: collectCursors only includes jails with a cursor" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();

    const sshd = try JailId.fromSlice("sshd");
    const nginx = try JailId.fromSlice("nginx");
    try src.addJail(sshd, "sshd", CallRecorder.onLine, null);
    try src.addJail(nginx, "sshd", CallRecorder.onLine, null);

    src.seedCursor("sshd", "s=seeded");

    var buf: [max_jails]CursorEntry = undefined;
    const got = src.collectCursors(&buf);
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("sshd", got[0].name);
    try testing.expectEqualStrings("s=seeded", got[0].cursor);
}

const FlushSpy = struct {
    calls: u32 = 0,
    fn hook(ud: ?*anyopaque) void {
        const self: *FlushSpy = @ptrCast(@alignCast(ud.?));
        self.calls += 1;
    }
};

test "journald: maybeFlush fires the hook once on a dirty source and clears dirty" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();

    var spy = FlushSpy{};
    src.setFlushHook(FlushSpy.hook, &spy);

    src.dirty = true;
    src.maybeFlush();
    try testing.expectEqual(@as(u32, 1), spy.calls);
    try testing.expect(!src.dirty);

    src.maybeFlush();
    try testing.expectEqual(@as(u32, 1), spy.calls);
}

test "journald: maybeFlush does nothing on a clean source" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();

    var spy = FlushSpy{};
    src.setFlushHook(FlushSpy.hook, &spy);

    src.maybeFlush();
    try testing.expectEqual(@as(u32, 0), spy.calls);
    try testing.expect(!src.dirty);
}

test "journald: processBatch marks dirty so maybeFlush will fire" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    var spy = FlushSpy{};
    src.setFlushHook(FlushSpy.hook, &spy);

    try testing.expect(!src.dirty);
    src.processBatch(jj, "{\"MESSAGE\":\"m 1.2.3.4\",\"__CURSOR\":\"s=c1\"}\n");
    try testing.expect(src.dirty);

    src.maybeFlush();
    try testing.expectEqual(@as(u32, 1), spy.calls);
    try testing.expect(!src.dirty);
}

test "journald: extractCursor returns the cursor even when MESSAGE is missing/malformed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var cur_buf: [max_cursor_len]u8 = undefined;

    const no_msg =
        \\{"__CURSOR":"s=base;i=42","PRIORITY":"6"}
    ;
    const c1 = extractCursor(arena.allocator(), no_msg, &cur_buf);
    try testing.expect(c1 != null);
    try testing.expectEqualStrings("s=base;i=42", c1.?);

    const bad_msg =
        \\{"MESSAGE":[999],"__CURSOR":"s=base2"}
    ;
    const c2 = extractCursor(arena.allocator(), bad_msg, &cur_buf);
    try testing.expect(c2 != null);
    try testing.expectEqualStrings("s=base2", c2.?);

    const no_cursor =
        \\{"MESSAGE":"Invalid user x from 1.2.3.4 port 22"}
    ;
    try testing.expect(extractCursor(arena.allocator(), no_cursor, &cur_buf) == null);

    try testing.expect(extractCursor(arena.allocator(), "{not json", &cur_buf) == null);
}

test "journald: seedBaseline sets cursor + dirty but does NOT invoke the callback" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    try testing.expect(jj.cursor_len == 0);
    const baseline =
        "{\"MESSAGE\":\"some recent journal line\",\"__CURSOR\":\"s=tail;i=7\"}\n";
    src.seedBaseline(jj, baseline);

    try testing.expectEqualStrings("s=tail;i=7", jj.cursorSlice());
    try testing.expect(src.dirty);
    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
}

test "journald: first-run baseline of a FAILURE entry does not ban (no callback)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    const baseline =
        "{\"MESSAGE\":\"Invalid user attacker from 203.0.113.9 port 22\",\"__CURSOR\":\"s=preexisting\"}\n";
    src.seedBaseline(jj, baseline);

    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
    try testing.expectEqualStrings("s=preexisting", jj.cursorSlice());
}

test "journald: seedBaseline with empty output leaves the jail un-baselined" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    src.seedBaseline(jj, "");
    try testing.expectEqual(@as(usize, 0), jj.cursor_len);
    try testing.expect(!src.dirty);
    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
}

test "journald: steady-state processBatch STILL invokes the callback (contrast with baseline)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    jj.setCursor("s=already-baselined");
    const batch =
        "{\"MESSAGE\":\"Invalid user x from 5.5.5.5 port 1\",\"__CURSOR\":\"s=new1\"}\n";
    src.processBatch(jj, batch);

    try testing.expectEqual(@as(usize, 1), rec.lines.items.len);
    try testing.expectEqualStrings("Invalid user x from 5.5.5.5 port 1", rec.lines.items[0]);
    try testing.expectEqualStrings("s=new1", jj.cursorSlice());
    try testing.expectEqual(@as(u64, 1), jj.lines_seen);
}

test "journald: healthForJail unhealthy until a clean poll completes (SYS-017)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    const h0 = src.healthForJail("sshd").?;
    try testing.expect(!h0.healthy);
    try testing.expectEqual(@as(u64, 0), h0.lines_seen);

    jj.last_read_ok_ts = 1234;
    jj.lines_seen = 7;
    const h1 = src.healthForJail("sshd").?;
    try testing.expect(h1.healthy);
    try testing.expectEqual(@as(u64, 7), h1.lines_seen);
    try testing.expectEqual(@as(i64, 1234), h1.last_read_ok_ts);
}

test "journald: healthForJail returns null for an unknown jail (SYS-017)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    try testing.expect(src.healthForJail("nope") == null);
}

fn feedChunk(src: *JournaldSource, jj: *JournalJail, bytes: []const u8) bool {
    @memcpy(jj.pending[jj.pending_len..][0..bytes.len], bytes);
    jj.pending_len += bytes.len;
    return src.consumeLines(jj);
}

test "journald: line buffer reassembles entries split across chunks (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    jj.setCursor("s=seed");

    try testing.expect(feedChunk(&src, jj, "{\"MESSAGE\":\"m1 1.1.1.1\",\"__CUR"));
    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
    try testing.expect(feedChunk(&src, jj, "SOR\":\"s=1\"}\n{\"MESS"));
    try testing.expectEqual(@as(usize, 1), rec.lines.items.len);
    try testing.expectEqualStrings("s=1", jj.cursorSlice());
    try testing.expect(feedChunk(&src, jj, "AGE\":\"m2 2.2.2.2\",\"__CURSOR\":\"s=2\"}\n"));
    try testing.expectEqual(@as(usize, 2), rec.lines.items.len);
    try testing.expectEqualStrings("m2 2.2.2.2", rec.lines.items[1]);
    try testing.expectEqualStrings("s=2", jj.cursorSlice());
    try testing.expectEqual(@as(usize, 0), jj.pending_len);
}

test "journald: line buffer drops an over-long entry and resyncs on the next newline (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    jj.setCursor("s=seed");

    @memset(jj.pending, 'x');
    jj.pending_len = jj.pending.len;
    try testing.expect(src.consumeLines(jj));
    try testing.expect(jj.discarding);
    try testing.expectEqual(@as(usize, 0), jj.pending_len);
    try testing.expectEqual(@as(usize, 1), jj.entries);

    try testing.expect(feedChunk(&src, jj, "yyy\n{\"MESSAGE\":\"ok 3.3.3.3\",\"__CURSOR\":\"s=3\"}\n"));
    try testing.expect(!jj.discarding);
    try testing.expectEqual(@as(usize, 1), rec.lines.items.len);
    try testing.expectEqualStrings("ok 3.3.3.3", rec.lines.items[0]);
    try testing.expectEqualStrings("s=3", jj.cursorSlice());
}

test "journald: entry cap stops the stream and reports it (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    jj.setCursor("s=seed");
    jj.entries = max_entries_per_tick;

    try testing.expect(!feedChunk(&src, jj, "{\"MESSAGE\":\"late 4.4.4.4\",\"__CURSOR\":\"s=late\"}\n"));
    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
    try testing.expectEqualStrings("s=seed", jj.cursorSlice());
}

const FakeJournalctl = struct {
    tmp: testing.TmpDir,
    path_buf: [std.fs.max_path_bytes]u8 = undefined,
    path_len: usize = 0,

    fn create(body: []const u8) !FakeJournalctl {
        var self = FakeJournalctl{ .tmp = testing.tmpDir(.{}) };
        errdefer self.tmp.cleanup();
        try self.tmp.dir.writeFile(.{
            .sub_path = "journalctl",
            .data = body,
            .flags = .{ .mode = 0o755 },
        });
        const p = try self.tmp.dir.realpath("journalctl", &self.path_buf);
        self.path_len = p.len;
        return self;
    }

    fn path(self: *const FakeJournalctl) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    fn cleanup(self: *FakeJournalctl) void {
        self.tmp.cleanup();
    }
};

const LoopDriver = struct {
    loop: *EventLoop,
    rec: *CallRecorder,
    jj: *JournalJail,
    start_ms: i64,
    want_lines: usize,
    want_reaped: bool,
    timer_fired_ms: i64 = 0,
    fd_fired_ms: i64 = 0,

    const deadline_ms: i64 = 8000;

    fn onCheck(_: u64, ud: ?*anyopaque) void {
        const d: *LoopDriver = @ptrCast(@alignCast(ud.?));
        const now = std.time.milliTimestamp();
        const lines_ok = d.rec.lines.items.len >= d.want_lines;
        const reaped_ok = !d.want_reaped or d.jj.child == null;
        if ((lines_ok and reaped_ok) or now - d.start_ms > deadline_ms) d.loop.stop();
    }

    fn onProbeTimer(_: u64, ud: ?*anyopaque) void {
        const d: *LoopDriver = @ptrCast(@alignCast(ud.?));
        d.timer_fired_ms = std.time.milliTimestamp();
    }

    fn onProbeFd(fd: posix.fd_t, _: u32, ud: ?*anyopaque) void {
        const d: *LoopDriver = @ptrCast(@alignCast(ud.?));
        d.fd_fired_ms = std.time.milliTimestamp();
        var buf: [8]u8 = undefined;
        _ = posix.read(fd, &buf) catch {};
    }
};

fn waitpidErrno(pid: posix.pid_t) linux.E {
    var status: u32 = 0;
    const rc = linux.waitpid(pid, &status, linux.W.NOHANG);
    return linux.E.init(rc);
}

test "journald: slow journalctl does not stall the loop — timer and fd serviced mid-poll (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.create(
        \\#!/bin/sh
        \\sleep 2
        \\printf '{"MESSAGE":"Invalid user a from 1.1.1.1 port 1","__CURSOR":"s=a1"}\n'
        \\printf '{"MESSAGE":"Invalid user b from 2.2.2.2 port 2","__CURSOR":"s=a2"}\n'
        \\printf '{"MESSAGE":"Invalid user c from 3.3.3.3 port 3","__CURSOR":"s=a3"}\n'
        \\
    );
    defer fake.cleanup();

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
    });
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    jj.setCursor("s=seed");

    var drv = LoopDriver{
        .loop = &loop,
        .rec = &rec,
        .jj = jj,
        .start_ms = std.time.milliTimestamp(),
        .want_lines = 3,
        .want_reaped = false,
    };

    try src.pollJail(jj);
    const pid = jj.child.?.pid;
    try src.attach();
    _ = try loop.addTimer(200, LoopDriver.onProbeTimer, &drv, true);
    _ = try loop.addTimer(25, LoopDriver.onCheck, &drv, false);

    const efd = try posix.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    defer posix.close(efd);
    try loop.addFd(efd, linux.EPOLL.IN, LoopDriver.onProbeFd, &drv);
    const one: u64 = 1;
    _ = try posix.write(efd, std.mem.asBytes(&one));

    try loop.run();
    try loop.removeFd(efd);

    try testing.expectEqual(@as(usize, 3), rec.lines.items.len);
    try testing.expectEqualStrings("Invalid user c from 3.3.3.3 port 3", rec.lines.items[2]);
    try testing.expectEqualStrings("s=a3", jj.cursorSlice());
    try testing.expect(rec.first_line_ms - drv.start_ms >= 1900);
    try testing.expect(drv.timer_fired_ms > 0);
    try testing.expect(drv.timer_fired_ms < rec.first_line_ms);
    try testing.expect(drv.fd_fired_ms > 0);
    try testing.expect(drv.fd_fired_ms < rec.first_line_ms);

    src.deinit();
    src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    try testing.expectEqual(linux.E.CHILD, waitpidErrno(pid));
}

test "journald: hung journalctl is killed at the timeout, reaped, cursor unchanged (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.create(
        \\#!/bin/sh
        \\exec sleep 1000
        \\
    );
    defer fake.cleanup();

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
        .child_timeout_ms = 1500,
    });
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    jj.setCursor("s=seed");

    var drv = LoopDriver{
        .loop = &loop,
        .rec = &rec,
        .jj = jj,
        .start_ms = std.time.milliTimestamp(),
        .want_lines = 0,
        .want_reaped = true,
    };

    try src.pollJail(jj);
    const pid = jj.child.?.pid;
    try src.attach();
    _ = try loop.addTimer(25, LoopDriver.onCheck, &drv, false);
    try loop.run();

    const elapsed = std.time.milliTimestamp() - drv.start_ms;
    try testing.expect(elapsed >= 1500);
    try testing.expect(elapsed < LoopDriver.deadline_ms);
    try testing.expect(jj.child == null);
    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
    try testing.expectEqualStrings("s=seed", jj.cursorSlice());
    try testing.expectEqual(@as(i64, 0), jj.last_read_ok_ts);
    try testing.expectEqual(linux.E.CHILD, waitpidErrno(pid));
}

test "journald: EOF mid-line drops the partial entry and the next poll starts clean (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.create(
        \\#!/bin/sh
        \\printf '{"MESSAGE":"complete 1.1.1.1","__CURSOR":"s=c1"}\n{"MESSAGE":"partial'
        \\
    );
    defer fake.cleanup();

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
    });
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    jj.setCursor("s=seed");

    var drv = LoopDriver{
        .loop = &loop,
        .rec = &rec,
        .jj = jj,
        .start_ms = std.time.milliTimestamp(),
        .want_lines = 2,
        .want_reaped = true,
    };

    try src.pollJail(jj);
    try src.attach();
    _ = try loop.addTimer(25, LoopDriver.onCheck, &drv, false);
    try loop.run();

    try testing.expectEqual(@as(usize, 2), rec.lines.items.len);
    try testing.expectEqualStrings("complete 1.1.1.1", rec.lines.items[0]);
    try testing.expectEqualStrings("complete 1.1.1.1", rec.lines.items[1]);
    try testing.expectEqualStrings("s=c1", jj.cursorSlice());
    try testing.expectEqual(@as(usize, 0), jj.pending_len);
    try testing.expect(!jj.discarding);
    try testing.expect(jj.last_read_ok_ts > 0);
}

test "journald: a tick while a child is in flight does not spawn a second one (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.create(
        \\#!/bin/sh
        \\exec sleep 1000
        \\
    );
    defer fake.cleanup();

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
    });
    defer src.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, null);
    const jj = &src.jails.items[0];
    jj.setCursor("s=seed");

    try src.pollJail(jj);
    const pid = jj.child.?.pid;
    const fd = jj.child.?.stdout_fd;
    try src.pollJail(jj);
    try testing.expectEqual(pid, jj.child.?.pid);
    try testing.expectEqual(fd, jj.child.?.stdout_fd);
    try testing.expectEqual(@as(usize, 2), loop.registrations.count());

    src.deinit();
    src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    try testing.expectEqual(linux.E.CHILD, waitpidErrno(pid));
    try testing.expectEqual(@as(usize, 1), loop.registrations.count());
}
