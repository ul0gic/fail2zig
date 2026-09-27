// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const linux = std.os.linux;

const event_loop_mod = @import("event_loop.zig");
const line_buffer_mod = @import("line_buffer.zig");
const shared = @import("shared");

const EventLoop = event_loop_mod.EventLoop;
const LineBuffer = line_buffer_mod.LineBuffer;
const JailId = shared.JailId;

pub const Error = error{
    InotifyInitFailed,
    InotifyAddWatchFailed,
    OpenFailed,
    StatFailed,
    ReadFailed,
    OutOfMemory,
    AlreadyWatched,
    PathTooLong,
    NotLinux,
    EventLoopError,
};

pub const JailHealth = struct {
    healthy: bool,
    lines_seen: u64,
    last_read_ok_ts: i64,
};

pub const LineCallback = *const fn (
    line: []const u8,
    jail: JailId,
    truncated: bool,
    userdata: ?*anyopaque,
) void;

const max_path_len: usize = 4096;
const inotify_read_buf_len: usize = 4096;
const fingerprint_len: usize = 64;
const detach_debounce_s: i64 = 2;

const FileWatch = struct {
    path_buf: [max_path_len]u8,
    path_len: usize,
    basename_start: usize,
    jail: JailId,
    callback: LineCallback,
    userdata: ?*anyopaque,

    file_fd: posix.fd_t,
    offset: u64,
    inode: u64,
    prev_size: u64,
    fingerprint: [fingerprint_len]u8,
    fingerprint_len: u8,

    file_wd: i32,
    parent_wd: i32,

    last_read_ok_ts: i64,
    lines_seen: u64,

    was_ever_attached: bool,
    detached_at_ts: i64,

    line_buffer: LineBuffer,
    allocator: Allocator,

    fn path(self: *const FileWatch) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    fn basename(self: *const FileWatch) []const u8 {
        return self.path_buf[self.basename_start..self.path_len];
    }

    fn deinit(self: *FileWatch) void {
        if (self.file_fd >= 0) posix.close(self.file_fd);
        self.line_buffer.deinit();
    }
};

pub const LogWatcher = struct {
    allocator: Allocator,
    event_loop: *EventLoop,
    inotify_fd: posix.fd_t,

    wd_to_file: std.AutoHashMap(i32, *FileWatch),
    files: std.ArrayList(*FileWatch),

    pending_ignored: std.AutoHashMap(i32, u32),

    pub fn init(allocator: Allocator, event_loop: *EventLoop) Error!LogWatcher {
        if (builtin.os.tag != .linux) return error.NotLinux;

        const flags: u32 = linux.IN.NONBLOCK | linux.IN.CLOEXEC;
        const ifd = posix.inotify_init1(flags) catch
            return error.InotifyInitFailed;
        errdefer posix.close(ifd);

        var wd_to_file = std.AutoHashMap(i32, *FileWatch).init(allocator);
        errdefer wd_to_file.deinit();
        var files = std.ArrayList(*FileWatch).init(allocator);
        errdefer files.deinit();
        var pending_ignored = std.AutoHashMap(i32, u32).init(allocator);
        errdefer pending_ignored.deinit();

        var watcher: LogWatcher = .{
            .allocator = allocator,
            .event_loop = event_loop,
            .inotify_fd = ifd,
            .wd_to_file = wd_to_file,
            .files = files,
            .pending_ignored = pending_ignored,
        };

        _ = &watcher;
        return watcher;
    }

    pub fn attach(self: *LogWatcher) Error!void {
        self.event_loop.addFd(
            self.inotify_fd,
            linux.EPOLL.IN,
            inotifyReady,
            self,
        ) catch return error.EventLoopError;
    }

    pub fn healthForJail(self: *const LogWatcher, name: []const u8) ?JailHealth {
        var matched = false;
        var any_attached = false;
        var any_ever_attached = false;
        var total_lines: u64 = 0;
        var max_read_ts: i64 = 0;
        var latest_detach_ts: i64 = 0;
        for (self.files.items) |fw| {
            if (!std.mem.eql(u8, fw.jail.slice(), name)) continue;
            matched = true;
            if (fw.file_fd >= 0) any_attached = true;
            if (fw.was_ever_attached) any_ever_attached = true;
            if (fw.detached_at_ts > latest_detach_ts) latest_detach_ts = fw.detached_at_ts;
            total_lines += fw.lines_seen;
            if (fw.last_read_ok_ts > max_read_ts) max_read_ts = fw.last_read_ok_ts;
        }
        if (!matched) return null;

        if (any_attached) {
            return .{ .healthy = true, .lines_seen = total_lines, .last_read_ok_ts = max_read_ts };
        }
        if (!any_ever_attached) return null;

        if (latest_detach_ts != 0) {
            const now = std.time.timestamp();
            if (now - latest_detach_ts >= detach_debounce_s) {
                return .{ .healthy = false, .lines_seen = total_lines, .last_read_ok_ts = max_read_ts };
            }
        }
        return null;
    }

    pub fn deinit(self: *LogWatcher) void {
        self.event_loop.removeFd(self.inotify_fd) catch {};
        for (self.files.items) |fw| {
            fw.deinit();
            self.allocator.destroy(fw);
        }
        self.files.deinit();
        self.wd_to_file.deinit();
        self.pending_ignored.deinit();
        posix.close(self.inotify_fd);
        self.* = undefined;
    }

    pub fn watchFile(
        self: *LogWatcher,
        path: []const u8,
        jail: JailId,
        callback: LineCallback,
        userdata: ?*anyopaque,
    ) Error!void {
        if (path.len == 0 or path.len > max_path_len - 1) return error.PathTooLong;

        const fw = try self.allocator.create(FileWatch);
        errdefer self.allocator.destroy(fw);

        fw.* = .{
            .path_buf = undefined,
            .path_len = path.len,
            .basename_start = 0,
            .jail = jail,
            .callback = callback,
            .userdata = userdata,
            .file_fd = -1,
            .offset = 0,
            .inode = 0,
            .prev_size = 0,
            .fingerprint = [_]u8{0} ** fingerprint_len,
            .fingerprint_len = 0,
            .file_wd = -1,
            .parent_wd = -1,
            .last_read_ok_ts = 0,
            .lines_seen = 0,
            .was_ever_attached = false,
            .detached_at_ts = 0,
            .line_buffer = undefined,
            .allocator = self.allocator,
        };

        @memcpy(fw.path_buf[0..path.len], path);
        fw.basename_start = basenameStart(path);

        fw.line_buffer = LineBuffer.initDefault(self.allocator) catch
            return error.OutOfMemory;
        errdefer fw.line_buffer.deinit();

        try openAndStat(fw);
        errdefer if (fw.file_fd >= 0) posix.close(fw.file_fd);

        if (fw.file_fd >= 0) {
            blk: {
                posix.lseek_END(fw.file_fd, 0) catch |err| {
                    std.log.warn(
                        "log_watcher: lseek_END failed on {s}: {s}; detaching file watch",
                        .{ fw.path(), @errorName(err) },
                    );
                    self.detachFileWatch(fw);
                    break :blk;
                };
                fw.offset = posix.lseek_CUR_get(fw.file_fd) catch |err| {
                    std.log.warn(
                        "log_watcher: lseek_CUR failed on {s}: {s}; detaching file watch",
                        .{ fw.path(), @errorName(err) },
                    );
                    self.detachFileWatch(fw);
                    break :blk;
                };
                fw.prev_size = fw.offset;
                if (fw.offset >= fingerprint_len) {
                    posix.lseek_SET(fw.file_fd, 0) catch |err| {
                        std.log.warn(
                            "log_watcher: lseek_SET(0) failed on {s}: {s}; detaching file watch",
                            .{ fw.path(), @errorName(err) },
                        );
                        self.detachFileWatch(fw);
                        break :blk;
                    };
                    const got = posix.read(fw.file_fd, fw.fingerprint[0..]) catch |err| {
                        std.log.warn(
                            "log_watcher: read(head) failed on {s}: {s}; detaching file watch",
                            .{ fw.path(), @errorName(err) },
                        );
                        self.detachFileWatch(fw);
                        break :blk;
                    };
                    fw.fingerprint_len = @intCast(got);
                    posix.lseek_SET(fw.file_fd, fw.offset) catch |err| {
                        std.log.warn(
                            "log_watcher: lseek_SET(offset) failed on {s}: {s}; detaching file watch",
                            .{ fw.path(), @errorName(err) },
                        );
                        self.detachFileWatch(fw);
                        break :blk;
                    };
                }
            }
        }

        const parent_path = parentPath(path);
        if (parent_path.len == 0) return error.PathTooLong;

        var parent_z: [max_path_len]u8 = undefined;
        @memcpy(parent_z[0..parent_path.len], parent_path);
        parent_z[parent_path.len] = 0;
        const parent_mask: u32 = linux.IN.CREATE | linux.IN.MOVED_TO;
        const parent_wd = posix.inotify_add_watchZ(
            self.inotify_fd,
            @ptrCast(&parent_z[0]),
            parent_mask,
        ) catch return error.InotifyAddWatchFailed;
        fw.parent_wd = parent_wd;
        errdefer _ = linux.inotify_rm_watch(self.inotify_fd, parent_wd);

        if (fw.file_fd >= 0) {
            var file_z: [max_path_len]u8 = undefined;
            @memcpy(file_z[0..path.len], path);
            file_z[path.len] = 0;
            const file_mask: u32 = linux.IN.MODIFY | linux.IN.MOVE_SELF | linux.IN.DELETE_SELF;
            const file_wd = posix.inotify_add_watchZ(
                self.inotify_fd,
                @ptrCast(&file_z[0]),
                file_mask,
            ) catch return error.InotifyAddWatchFailed;
            fw.file_wd = file_wd;
            fw.was_ever_attached = true;
        }
        errdefer if (fw.file_wd >= 0) {
            _ = linux.inotify_rm_watch(self.inotify_fd, fw.file_wd);
        };

        try self.files.append(fw);
        errdefer _ = self.files.pop();
        if (fw.file_wd >= 0) try self.wd_to_file.put(fw.file_wd, fw);
    }

    fn inotifyReady(fd: posix.fd_t, events: u32, ud: ?*anyopaque) void {
        _ = events;
        const self: *LogWatcher = @ptrCast(@alignCast(ud.?));
        self.drainInotify(fd) catch |err| {
            std.log.warn("log_watcher: inotify drain failed: {s}", .{@errorName(err)});
        };
    }

    fn drainInotify(self: *LogWatcher, fd: posix.fd_t) !void {
        var buf: [inotify_read_buf_len]u8 align(@alignOf(linux.inotify_event)) = undefined;
        while (true) {
            const n = posix.read(fd, &buf) catch |err| switch (err) {
                error.WouldBlock => return,
                else => return err,
            };
            if (n == 0) return;

            var i: usize = 0;
            while (i + @sizeOf(linux.inotify_event) <= n) {
                const ev_ptr: *const linux.inotify_event = @ptrCast(@alignCast(&buf[i]));
                const total = @sizeOf(linux.inotify_event) + ev_ptr.len;
                if (i + total > n) break;

                const name_slice: []const u8 = if (ev_ptr.len > 0) blk: {
                    const start = i + @sizeOf(linux.inotify_event);
                    const end = start + ev_ptr.len;
                    var e = end;
                    while (e > start and buf[e - 1] == 0) : (e -= 1) {}
                    break :blk buf[start..e];
                } else &[_]u8{};

                try self.handleEvent(ev_ptr.*, name_slice);
                i += total;
            }
        }
    }

    fn handleEvent(
        self: *LogWatcher,
        ev: linux.inotify_event,
        name: []const u8,
    ) !void {
        if ((ev.mask & linux.IN.IGNORED) != 0 and self.consumePendingIgnored(ev.wd)) {
            return;
        }

        if (self.wd_to_file.get(ev.wd)) |fw| {
            if ((ev.mask & linux.IN.MODIFY) != 0) {
                self.readNewData(fw) catch |err| {
                    std.log.warn(
                        "log_watcher: read failed on {s}: {s}; detaching file watch",
                        .{ fw.path(), @errorName(err) },
                    );
                    self.detachFileWatch(fw);
                    return;
                };
            }
            if ((ev.mask & (linux.IN.MOVE_SELF | linux.IN.DELETE_SELF | linux.IN.IGNORED)) != 0) {
                self.detachFileWatch(fw);
            }
            return;
        }

        if ((ev.mask & (linux.IN.CREATE | linux.IN.MOVED_TO)) == 0) return;
        for (self.files.items) |fw| {
            if (fw.parent_wd != ev.wd) continue;
            const fw_basename = fw.basename();
            if (name.len == fw_basename.len and std.mem.eql(u8, name, fw_basename)) {
                self.reopenAfterRotation(fw) catch |err| {
                    std.log.warn(
                        "log_watcher: reopen after rotation failed on {s}: {s}",
                        .{ fw.path(), @errorName(err) },
                    );
                };
            }
        }
    }

    fn readNewData(self: *LogWatcher, fw: *FileWatch) !void {
        _ = self;
        if (fw.file_fd < 0) return;

        const st = posix.fstat(fw.file_fd) catch return error.StatFailed;
        const size_u64: u64 = @intCast(st.size);

        var must_reset = size_u64 < fw.offset or size_u64 < fw.prev_size;
        if (!must_reset and fw.fingerprint_len > 0 and size_u64 >= fw.fingerprint_len) {
            const fp_len: usize = fw.fingerprint_len;
            var head: [fingerprint_len]u8 = undefined;
            posix.lseek_SET(fw.file_fd, 0) catch return error.ReadFailed;
            const got = posix.read(fw.file_fd, head[0..fp_len]) catch
                return error.ReadFailed;
            if (got == fp_len and
                !std.mem.eql(u8, head[0..got], fw.fingerprint[0..fp_len]))
            {
                must_reset = true;
            }
        }
        if (must_reset) {
            fw.offset = 0;
            fw.line_buffer.reset();
            fw.fingerprint_len = 0;
        }
        fw.prev_size = size_u64;

        posix.lseek_SET(fw.file_fd, fw.offset) catch return error.ReadFailed;

        var buf: [16 * 1024]u8 = undefined;
        read_loop: while (true) {
            const n = posix.read(fw.file_fd, &buf) catch |err| switch (err) {
                error.WouldBlock => break :read_loop,
                else => return error.ReadFailed,
            };
            if (n == 0) break :read_loop;
            fw.offset += n;
            fw.prev_size = @max(fw.prev_size, fw.offset);

            fw.line_buffer.append(buf[0..n]) catch |err| switch (err) {
                error.BufferTooSmall => {
                    std.log.warn("log_watcher: line buffer rejected {d} bytes from {s}", .{ n, fw.path() });
                    fw.line_buffer.reset();
                },
                else => return error.ReadFailed,
            };

            while (fw.line_buffer.nextLine()) |line| {
                fw.callback(line.bytes, fw.jail, line.truncated, fw.userdata);
                fw.lines_seen += 1;
            }
        }

        fw.last_read_ok_ts = std.time.timestamp();

        if (fw.offset > 0) {
            const sample_len = @min(@as(usize, fingerprint_len), fw.offset);
            posix.lseek_SET(fw.file_fd, 0) catch |err| {
                std.log.warn(
                    "log_watcher: fingerprint lseek_SET(0) failed on {s}: {s}",
                    .{ fw.path(), @errorName(err) },
                );
                return;
            };
            const got = posix.read(fw.file_fd, fw.fingerprint[0..sample_len]) catch |err| {
                std.log.warn(
                    "log_watcher: fingerprint read failed on {s}: {s}",
                    .{ fw.path(), @errorName(err) },
                );
                return;
            };
            fw.fingerprint_len = @intCast(got);
            posix.lseek_SET(fw.file_fd, fw.offset) catch |err| {
                std.log.warn(
                    "log_watcher: fingerprint lseek_SET(offset) failed on {s}: {s}",
                    .{ fw.path(), @errorName(err) },
                );
                return;
            };
        }
    }

    fn detachFileWatch(self: *LogWatcher, fw: *FileWatch) void {
        if (fw.was_ever_attached and fw.file_wd >= 0 and fw.detached_at_ts == 0) {
            fw.detached_at_ts = std.time.timestamp();
        }
        if (fw.file_wd >= 0) {
            _ = self.wd_to_file.remove(fw.file_wd);
            self.markPendingIgnored(fw.file_wd);
            _ = linux.inotify_rm_watch(self.inotify_fd, fw.file_wd);
            fw.file_wd = -1;
        }
        if (fw.file_fd >= 0) {
            posix.close(fw.file_fd);
            fw.file_fd = -1;
        }
        fw.offset = 0;
        fw.prev_size = 0;
        fw.fingerprint_len = 0;
    }

    fn markPendingIgnored(self: *LogWatcher, wd: i32) void {
        const gop = self.pending_ignored.getOrPut(wd) catch {
            std.log.warn("log_watcher: pending-IGNORED bookkeeping alloc failed for wd={d}", .{wd});
            return;
        };
        if (gop.found_existing) {
            gop.value_ptr.* += 1;
        } else {
            gop.value_ptr.* = 1;
        }
    }

    fn consumePendingIgnored(self: *LogWatcher, wd: i32) bool {
        const entry = self.pending_ignored.getPtr(wd) orelse return false;
        if (entry.* <= 1) {
            _ = self.pending_ignored.remove(wd);
        } else {
            entry.* -= 1;
        }
        return true;
    }

    fn reopenAfterRotation(self: *LogWatcher, fw: *FileWatch) !void {
        fw.line_buffer.reset();
        self.detachFileWatch(fw);

        try openAndStat(fw);
        fw.offset = 0;
        fw.prev_size = 0;
        if (fw.file_fd < 0) return;

        var file_z: [max_path_len]u8 = undefined;
        @memcpy(file_z[0..fw.path_len], fw.path_buf[0..fw.path_len]);
        file_z[fw.path_len] = 0;
        const file_mask: u32 = linux.IN.MODIFY | linux.IN.MOVE_SELF | linux.IN.DELETE_SELF;
        const file_wd = posix.inotify_add_watchZ(
            self.inotify_fd,
            @ptrCast(&file_z[0]),
            file_mask,
        ) catch return error.InotifyAddWatchFailed;
        fw.file_wd = file_wd;
        try self.wd_to_file.put(file_wd, fw);
        fw.was_ever_attached = true;
        fw.detached_at_ts = 0;

        try self.readNewData(fw);
    }
};

fn basenameStart(path: []const u8) usize {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| return idx + 1;
    return 0;
}

fn parentPath(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| {
        if (idx == 0) return path[0..1];
        return path[0..idx];
    }
    return ".";
}

fn openAndStat(fw: *FileWatch) !void {
    var path_z: [max_path_len]u8 = undefined;
    @memcpy(path_z[0..fw.path_len], fw.path_buf[0..fw.path_len]);
    path_z[fw.path_len] = 0;

    const flags: posix.O = .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NONBLOCK = true,
    };

    const fd = posix.openatZ(
        posix.AT.FDCWD,
        @ptrCast(&path_z[0]),
        flags,
        0,
    ) catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied => {
            fw.file_fd = -1;
            return;
        },
        else => return error.OpenFailed,
    };

    const st = posix.fstat(fd) catch {
        posix.close(fd);
        return error.StatFailed;
    };

    fw.file_fd = fd;
    fw.inode = st.ino;
}
