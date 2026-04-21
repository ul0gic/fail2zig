//! Inotify-based log watcher.
//!
//! `LogWatcher` owns a single inotify FD shared across all watched files.
//! Per watched file it opens the file (for reading), tracks the current
//! read offset and inode, and keeps two watch descriptors:
//!   - one on the file itself (`IN_MODIFY | IN_MOVE_SELF`) — catches
//!     appends and rename-based rotation.
//!   - one on the parent directory (`IN_CREATE | IN_MOVED_TO`) — catches
//!     the new file showing up after a rename / new-file rotation.
//!
//! Rotation strategies supported:
//!   1. rename (`logrotate` default): old renamed, new created at the
//!      original path. Detected via `IN_MOVE_SELF` + parent `IN_CREATE`
//!      of matching basename. We re-open and reset offset to zero.
//!   2. copytruncate: file copied then truncated. Detected when a read
//!      attempt finds `offset > file size`. We reset offset to zero and
//!      continue reading from the start.
//!   3. delete-and-create: similar to rename but via `IN_DELETE_SELF`
//!      plus parent `IN_CREATE`. Handled by the same re-open path.
//!
//! The watcher drives itself via the event loop: its inotify FD is
//! registered with `EventLoop.addFd`, and `handleInotifyReady` consumes
//! all buffered events in one call.

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

/// Line delivery callback. `line` is a zero-copy slice valid only for the
/// duration of the call. `jail` is the JailId provided when the path was
/// registered. `truncated` is `true` when the line exceeded the per-file
/// line buffer's max-line-length and was delivered truncated.
pub const LineCallback = *const fn (
    line: []const u8,
    jail: JailId,
    truncated: bool,
    userdata: ?*anyopaque,
) void;

const max_path_len: usize = 4096;
/// Max inotify read size — big enough to hold many events in one drain.
const inotify_read_buf_len: usize = 4096;
/// Number of leading bytes sampled for the rotation-detection
/// fingerprint. 64 bytes is plenty for syslog-style headers (date,
/// hostname, program) and fits in a single cache line.
const fingerprint_len: usize = 64;

/// Per-watched-file state. Heap-allocated so the inotify-wd-keyed map
/// can point at it from both the file-watch entry and the parent-dir
/// entry (the dir watch identifies its associated file by basename).
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
    /// Last observed file size. Used to detect copytruncate rotations
    /// that happen atomically between two `readNewData` calls — if the
    /// file shrinks, we reset the offset to 0 regardless of whether the
    /// new size is above or below our stored offset.
    prev_size: u64,
    /// Fingerprint of the file's first `fingerprint_len` bytes, sampled
    /// each time we read. On any mismatch we treat the file as rotated
    /// (truncated-and-rewritten or swapped) and reset to offset 0.
    /// This catches the copytruncate race where a single inotify batch
    /// collapses the truncate + refill into one event.
    fingerprint: [fingerprint_len]u8,
    fingerprint_len: u8,

    file_wd: i32,
    parent_wd: i32,

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

    /// Keyed by file watch descriptor OR parent-dir watch descriptor.
    /// Both point to the same `FileWatch` record.
    wd_to_file: std.AutoHashMap(i32, *FileWatch),
    /// Owns the `FileWatch` pointers; iterate for cleanup.
    files: std.ArrayList(*FileWatch),

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

        var watcher: LogWatcher = .{
            .allocator = allocator,
            .event_loop = event_loop,
            .inotify_fd = ifd,
            .wd_to_file = wd_to_file,
            .files = files,
        };

        // Register the inotify FD with the event loop so read events are
        // delivered. We stash `self` pointer via userdata. The caller
        // retains `watcher` — this pointer becomes valid once the struct
        // is placed in its final storage (see `attach` below).
        _ = &watcher;
        return watcher;
    }

    /// Register the watcher's inotify FD with its event loop. Must be
    /// called exactly once after the caller has placed `LogWatcher` in
    /// its permanent storage — the event loop callback receives a
    /// stable `*LogWatcher` via userdata.
    pub fn attach(self: *LogWatcher) Error!void {
        self.event_loop.addFd(
            self.inotify_fd,
            linux.EPOLL.IN,
            inotifyReady,
            self,
        ) catch return error.EventLoopError;
    }

    pub fn deinit(self: *LogWatcher) void {
        // Best-effort remove from event loop; deinit is terminal anyway.
        self.event_loop.removeFd(self.inotify_fd) catch {};
        // Free each FileWatch (closes file fd + line buffer).
        for (self.files.items) |fw| {
            fw.deinit();
            self.allocator.destroy(fw);
        }
        self.files.deinit();
        self.wd_to_file.deinit();
        posix.close(self.inotify_fd);
        self.* = undefined;
    }

    /// Start watching `path` for appended lines. Invokes `callback` for
    /// each complete line (truncated if it exceeds the per-file line
    /// cap). Memory for per-file state comes from `self.allocator`.
    pub fn watchFile(
        self: *LogWatcher,
        path: []const u8,
        jail: JailId,
        callback: LineCallback,
        userdata: ?*anyopaque,
    ) Error!void {
        if (path.len == 0 or path.len > max_path_len - 1) return error.PathTooLong;

        // Allocate the FileWatch up front — easier to unwind than
        // managing half-initialized state in place.
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
            .line_buffer = undefined,
            .allocator = self.allocator,
        };

        @memcpy(fw.path_buf[0..path.len], path);
        fw.basename_start = basenameStart(path);

        fw.line_buffer = LineBuffer.initDefault(self.allocator) catch
            return error.OutOfMemory;
        errdefer fw.line_buffer.deinit();

        // Open the target file. If it doesn't exist yet we still want to
        // register the parent dir watch so we can pick it up on create.
        try openAndStat(fw);
        errdefer if (fw.file_fd >= 0) posix.close(fw.file_fd);

        // Seek to end: we only care about NEW lines, not the historical
        // file contents. Tailing-from-end is the standard fail2ban
        // behavior. On rotation we reset to 0.
        if (fw.file_fd >= 0) {
            posix.lseek_END(fw.file_fd, 0) catch {};
            fw.offset = posix.lseek_CUR_get(fw.file_fd) catch 0;
            fw.prev_size = fw.offset;
            // Seed the fingerprint from whatever head bytes exist
            // already (if any). Useful when attaching to a long-running
            // file that has existing content.
            if (fw.offset >= fingerprint_len) {
                posix.lseek_SET(fw.file_fd, 0) catch {};
                const got = posix.read(fw.file_fd, fw.fingerprint[0..]) catch 0;
                fw.fingerprint_len = @intCast(got);
                posix.lseek_SET(fw.file_fd, fw.offset) catch {};
            }
        }

        // Add inotify watches. Parent dir must exist — error out if not.
        const parent_path = parentPath(path);
        if (parent_path.len == 0) return error.PathTooLong;

        // Null-terminate for inotify_add_watch. We copy into a small
        // stack buffer; parent_path is guaranteed to be <= max_path_len.
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

        // File watch (may fail if file doesn't exist — that's OK, the
        // parent watch will catch the creation).
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
        }
        errdefer if (fw.file_wd >= 0) {
            _ = linux.inotify_rm_watch(self.inotify_fd, fw.file_wd);
        };

        // Record the FileWatch under both watch descriptors.
        try self.files.append(fw);
        errdefer _ = self.files.pop();
        if (fw.file_wd >= 0) try self.wd_to_file.put(fw.file_wd, fw);
        try self.wd_to_file.put(fw.parent_wd, fw);
    }

    // ------------------------------------------------------------------
    // Internal: inotify event handling
    // ------------------------------------------------------------------

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

                // Name, if any, follows the struct.
                const name_slice: []const u8 = if (ev_ptr.len > 0) blk: {
                    const start = i + @sizeOf(linux.inotify_event);
                    const end = start + ev_ptr.len;
                    // Trim trailing null padding bytes.
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
        const fw = self.wd_to_file.get(ev.wd) orelse return;

        // Event on the file itself.
        if (ev.wd == fw.file_wd) {
            if ((ev.mask & linux.IN.MODIFY) != 0) try self.readNewData(fw);
            if ((ev.mask & (linux.IN.MOVE_SELF | linux.IN.DELETE_SELF | linux.IN.IGNORED)) != 0) {
                // Watched file disappeared — close it but keep the
                // parent watch alive so we'll pick up the replacement.
                self.detachFileWatch(fw);
            }
            return;
        }

        // Event on the parent directory.
        if (ev.wd == fw.parent_wd) {
            const fw_basename = fw.basename();
            if (name.len == fw_basename.len and std.mem.eql(u8, name, fw_basename)) {
                if ((ev.mask & (linux.IN.CREATE | linux.IN.MOVED_TO)) != 0) {
                    try self.reopenAfterRotation(fw);
                }
            }
            return;
        }
    }

    /// Called on IN_MODIFY: read from `offset` to EOF, stream through
    /// the line buffer, invoke callback for each complete line.
    ///
    /// Rotation detection on top of inotify:
    ///   - `size < offset`: file is shorter than our recorded read
    ///     position → classic copytruncate.
    ///   - `size < prev_size`: file shrank since last observation, even
    ///     if it has grown back past our offset.
    ///   - fingerprint mismatch: the first `fingerprint_len` bytes no
    ///     longer match what we saw previously. Catches the race where
    ///     truncate + rewrite happens atomically between two inotify
    ///     batches (resulting in a single IN_MODIFY where size is
    ///     plausibly larger than our offset).
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

        // Seek to our logical offset — we drive it explicitly rather
        // than relying on the kernel cursor, so parallel opens or
        // re-opens do not desync us.
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
            }
        }

        // Refresh fingerprint for next call. Sample however many bytes
        // are available, up to `fingerprint_len`. A populated
        // fingerprint (even a short one) is what enables truncate+refill
        // detection in the IN_MODIFY race.
        if (fw.offset > 0) {
            const sample_len = @min(@as(usize, fingerprint_len), fw.offset);
            posix.lseek_SET(fw.file_fd, 0) catch return;
            const got = posix.read(fw.file_fd, fw.fingerprint[0..sample_len]) catch return;
            fw.fingerprint_len = @intCast(got);
            // Restore offset for the next read.
            posix.lseek_SET(fw.file_fd, fw.offset) catch return;
        }
    }

    fn detachFileWatch(self: *LogWatcher, fw: *FileWatch) void {
        if (fw.file_wd >= 0) {
            _ = self.wd_to_file.remove(fw.file_wd);
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

    fn reopenAfterRotation(self: *LogWatcher, fw: *FileWatch) !void {
        // Drain any queued partial line — the rotated file is gone.
        fw.line_buffer.reset();
        self.detachFileWatch(fw);

        try openAndStat(fw);
        // Read from the start of the new file.
        fw.offset = 0;
        fw.prev_size = 0;
        if (fw.file_fd < 0) return;

        // Re-add file-level inotify watch.
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

        // Read whatever is already present.
        try self.readNewData(fw);
    }
};

// ============================================================================
// Helpers
// ============================================================================

/// Index (into `path`) of the basename start. The slice
/// `path[basenameStart(path)..]` is the basename.
fn basenameStart(path: []const u8) usize {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| return idx + 1;
    return 0;
}

/// Parent directory portion of `path`. Defaults to `.` when `path` has
/// no slash.
fn parentPath(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| {
        if (idx == 0) return path[0..1]; // "/foo" → "/"
        return path[0..idx];
    }
    return ".";
}

/// Open `fw.path()` read-only with O_CLOEXEC and populate `file_fd` +
/// `inode`. If the file is missing, leaves `file_fd = -1` (not an
/// error — the parent watch will pick it up on create).
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

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "log_watcher: basenameStart" {
    try testing.expectEqual(@as(usize, 0), basenameStart("file.log"));
    try testing.expectEqual(@as(usize, 5), basenameStart("/var/log/file.log"[0..5] ++ "file.log"));
    try testing.expectEqual(@as(usize, 10), basenameStart("/tmp/logs/sshd.log"[0..10] ++ "sshd.log"));
    // Exact slice-based path:
    const p = "/var/log/sshd.log";
    try testing.expectEqual(@as(usize, 9), basenameStart(p));
}

test "log_watcher: parentPath" {
    try testing.expectEqualStrings("/var/log", parentPath("/var/log/sshd.log"));
    try testing.expectEqualStrings(".", parentPath("nofile"));
    try testing.expectEqualStrings("/", parentPath("/foo"));
}

// End-to-end test using real inotify. Requires a writable temp dir —
// skip gracefully if not available.

const LineSink = struct {
    mutex: std.Thread.Mutex = .{},
    lines: std.ArrayList([]const u8),
    truncations: u32 = 0,

    fn init(allocator: Allocator) LineSink {
        return .{ .lines = std.ArrayList([]const u8).init(allocator) };
    }
    fn deinit(self: *LineSink, allocator: Allocator) void {
        for (self.lines.items) |l| allocator.free(l);
        self.lines.deinit();
    }
    fn onLine(line: []const u8, jail: JailId, truncated: bool, ud: ?*anyopaque) void {
        _ = jail;
        const self: *LineSink = @ptrCast(@alignCast(ud.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (truncated) self.truncations += 1;
        const dup = self.lines.allocator.dupe(u8, line) catch return;
        self.lines.append(dup) catch {
            self.lines.allocator.free(dup);
        };
    }
    fn count(self: *LineSink) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.lines.items.len;
    }
};

test "log_watcher: detects appended lines" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Build an absolute path for the file we will watch.
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;
    const log_name = "test.log";
    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const log_path = try std.fmt.bufPrint(&full_path_buf, "{s}/{s}", .{ dir_path, log_name });

    // Create the file empty.
    {
        const f = try tmp.dir.createFile(log_name, .{ .truncate = true });
        f.close();
    }

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    var watcher = try LogWatcher.init(testing.allocator, &loop);
    try watcher.attach();
    defer watcher.deinit();

    var sink = LineSink.init(testing.allocator);
    defer sink.deinit(testing.allocator);

    const jail = try JailId.fromSlice("sshd");
    try watcher.watchFile(log_path, jail, LineSink.onLine, &sink);

    // Thread that appends lines, then stops the loop.
    const Ctx = struct { path: []const u8, tmp_dir: std.fs.Dir, loop: *EventLoop, sink: *LineSink };
    var ctx = Ctx{ .path = log_path, .tmp_dir = tmp.dir, .loop = &loop, .sink = &sink };

    const th = try std.Thread.spawn(.{}, struct {
        fn kick(c: *Ctx) void {
            std.time.sleep(30 * std.time.ns_per_ms);
            const f = c.tmp_dir.openFile("test.log", .{ .mode = .write_only }) catch return;
            defer f.close();
            _ = f.seekFromEnd(0) catch {};
            _ = f.writeAll("first line\nsecond line\n") catch {};

            // Wait for the callback to catch up. Bounded by 1s.
            var tries: u32 = 0;
            while (tries < 100 and c.sink.count() < 2) : (tries += 1) {
                std.time.sleep(10 * std.time.ns_per_ms);
            }
            c.loop.stop();
        }
    }.kick, .{&ctx});

    try loop.run();
    th.join();

    try testing.expectEqual(@as(usize, 2), sink.count());
    try testing.expectEqualStrings("first line", sink.lines.items[0]);
    try testing.expectEqualStrings("second line", sink.lines.items[1]);
}

test "log_watcher: detects copytruncate rotation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;
    const log_name = "ct.log";
    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const log_path = try std.fmt.bufPrint(&full_path_buf, "{s}/{s}", .{ dir_path, log_name });

    {
        const f = try tmp.dir.createFile(log_name, .{ .truncate = true });
        f.close();
    }

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var watcher = try LogWatcher.init(testing.allocator, &loop);
    try watcher.attach();
    defer watcher.deinit();
    var sink = LineSink.init(testing.allocator);
    defer sink.deinit(testing.allocator);

    const jail = try JailId.fromSlice("nginx");
    try watcher.watchFile(log_path, jail, LineSink.onLine, &sink);

    const Ctx = struct { tmp_dir: std.fs.Dir, loop: *EventLoop, sink: *LineSink };
    var ctx = Ctx{ .tmp_dir = tmp.dir, .loop = &loop, .sink = &sink };

    const th = try std.Thread.spawn(.{}, struct {
        fn kick(c: *Ctx) void {
            std.time.sleep(30 * std.time.ns_per_ms);
            {
                const f = c.tmp_dir.openFile("ct.log", .{ .mode = .write_only }) catch return;
                defer f.close();
                _ = f.seekFromEnd(0) catch {};
                _ = f.writeAll("alpha\nbeta\n") catch {};
            }
            // Wait for 2 lines.
            var tries: u32 = 0;
            while (tries < 100 and c.sink.count() < 2) : (tries += 1) {
                std.time.sleep(10 * std.time.ns_per_ms);
            }
            // Copytruncate: truncate the file in place, then write
            // new content. The watcher must pick this up.
            {
                const f = c.tmp_dir.openFile("ct.log", .{ .mode = .write_only }) catch return;
                defer f.close();
                f.setEndPos(0) catch {};
                _ = f.seekTo(0) catch {};
                _ = f.writeAll("gamma\ndelta\n") catch {};
            }
            // Wait for 4 lines total.
            tries = 0;
            while (tries < 200 and c.sink.count() < 4) : (tries += 1) {
                std.time.sleep(10 * std.time.ns_per_ms);
            }
            c.loop.stop();
        }
    }.kick, .{&ctx});

    try loop.run();
    th.join();

    try testing.expect(sink.count() >= 4);
    // Verify all four lines are present in order.
    try testing.expectEqualStrings("alpha", sink.lines.items[0]);
    try testing.expectEqualStrings("beta", sink.lines.items[1]);
    try testing.expectEqualStrings("gamma", sink.lines.items[2]);
    try testing.expectEqualStrings("delta", sink.lines.items[3]);
}

test "log_watcher: detects rename rotation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;
    const log_name = "rn.log";
    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const log_path = try std.fmt.bufPrint(&full_path_buf, "{s}/{s}", .{ dir_path, log_name });

    {
        const f = try tmp.dir.createFile(log_name, .{ .truncate = true });
        f.close();
    }

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var watcher = try LogWatcher.init(testing.allocator, &loop);
    try watcher.attach();
    defer watcher.deinit();
    var sink = LineSink.init(testing.allocator);
    defer sink.deinit(testing.allocator);

    const jail = try JailId.fromSlice("sshd");
    try watcher.watchFile(log_path, jail, LineSink.onLine, &sink);

    const Ctx = struct { tmp_dir: std.fs.Dir, loop: *EventLoop, sink: *LineSink };
    var ctx = Ctx{ .tmp_dir = tmp.dir, .loop = &loop, .sink = &sink };

    const th = try std.Thread.spawn(.{}, struct {
        fn kick(c: *Ctx) void {
            std.time.sleep(30 * std.time.ns_per_ms);
            {
                const f = c.tmp_dir.openFile("rn.log", .{ .mode = .write_only }) catch return;
                defer f.close();
                _ = f.writeAll("before\n") catch {};
            }
            var tries: u32 = 0;
            while (tries < 100 and c.sink.count() < 1) : (tries += 1) {
                std.time.sleep(10 * std.time.ns_per_ms);
            }
            // Rename rotation: move old out of the way, create new.
            c.tmp_dir.rename("rn.log", "rn.log.1") catch return;
            {
                const f = c.tmp_dir.createFile("rn.log", .{ .truncate = true }) catch return;
                defer f.close();
                _ = f.writeAll("after\n") catch {};
            }
            tries = 0;
            while (tries < 200 and c.sink.count() < 2) : (tries += 1) {
                std.time.sleep(10 * std.time.ns_per_ms);
            }
            c.loop.stop();
        }
    }.kick, .{&ctx});

    try loop.run();
    th.join();

    try testing.expect(sink.count() >= 2);
    try testing.expectEqualStrings("before", sink.lines.items[0]);
    try testing.expectEqualStrings("after", sink.lines.items[1]);
}
