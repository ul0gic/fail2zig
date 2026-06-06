// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
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

/// Per-jail read-HEALTH verdict (SYS-017), returned by each log source's
/// `healthForJail`. A pure derivation over the source's live per-jail
/// fields — no allocation, no I/O. The status handler's `commands.JailHealth`
/// mirrors this shape; the main.zig adapter copies between them so
/// `net/commands.zig` keeps no compile-time dependency on the source modules.
///
/// This is HEALTH only (is the source reading?). The SOURCE label is the
/// daemon's resolved-source descriptor (`commands.JailSourceSource`), known
/// for every configured jail — so a file jail with an absent path still
/// shows its path, not "unknown". HEALTH being unknown (null here) is the
/// orthogonal, expected signal for such a jail.
///
/// `healthy == false` is a *genuine negative probe*. journald reports it
/// when no clean `journalctl` poll has ever completed; the file source
/// reports it (ENH-004) when a watch that was once attached has been
/// detached past the debounce window (deleted / unmounted / perms revoked).
/// Both are real source breaks an enforcing jail must surface as DEGRADED.
/// A source that has never attached/read returns `null` (unknown), never a
/// hard `false`, so a late-appearing boot log never flashes a false
/// negative.
pub const JailHealth = struct {
    healthy: bool,
    lines_seen: u64,
    last_read_ok_ts: i64,
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
/// Debounce (seconds) before a was-attached-then-detached file watch
/// reports unhealthy (ENH-004). Normal rename rotation is a detach
/// immediately followed by a reopen; a couple of seconds of slack (≥ one
/// ~1 s expiry-sweep tick) absorbs that flicker while still surfacing a
/// genuine source break within a couple of seconds. Not operator-tunable.
const detach_debounce_s: i64 = 2;

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

    /// Read-health (SYS-017). Written in `readNewData` on the loop thread,
    /// read on the cold status/metrics path — same thread, so no atomics
    /// (mirrors the non-atomic `offset` discipline above).
    ///
    /// Wall-clock secs of the last `readNewData` that completed its read
    /// loop without `error.ReadFailed`. `0` means "no clean read yet".
    last_read_ok_ts: i64,
    /// Lines delivered to the callback, lifetime.
    lines_seen: u64,

    /// Structural read-health (ENH-004). `true` once a file-level inotify
    /// watch has ever successfully attached for this path (in `watchFile`
    /// or `reopenAfterRotation`). This is what distinguishes a log that has
    /// never appeared (boot / late log → never attached → unknown health)
    /// from one that was attached then broke (deleted / unmounted / perms
    /// revoked → was-attached-then-detached → genuinely unhealthy). Set
    /// once, never cleared — a watch that has ever read is forever
    /// "was once a real source".
    was_ever_attached: bool,
    /// Wall-clock secs of the most recent was-attached → detached
    /// transition (set in `detachFileWatch` only when `was_ever_attached`).
    /// `0` means "not currently in a detached-after-attach state". The
    /// verdict only reports unhealthy once `now - detached_at_ts >=
    /// detach_debounce_s`, so normal rename-rotation flicker (detach →
    /// reopen within ~one tick) never flips DEGRADED. Cleared on reopen.
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

    /// Keyed by file watch descriptor OR parent-dir watch descriptor.
    /// Both point to the same `FileWatch` record.
    wd_to_file: std.AutoHashMap(i32, *FileWatch),
    /// Owns the `FileWatch` pointers; iterate for cleanup.
    files: std.ArrayList(*FileWatch),

    /// BUG-007: count of trailing `IN_IGNORED` events we still expect for a
    /// wd-NUMBER that *we* proactively `inotify_rm_watch`'d. The kernel
    /// queues exactly one `IN_IGNORED` per removed watch and immediately
    /// frees the wd number for reuse, so a stale `IN_IGNORED` can arrive
    /// AFTER `reopenAfterRotation` has reused that same number for a new,
    /// healthy watch. We must NOT let that trailing event detach the new
    /// watch. Keyed by wd number; the value is a count (the same number can
    /// be removed → reused → removed again before either `IN_IGNORED`
    /// drains). A kernel-AUTO `IN_IGNORED` (file deleted while we held the
    /// watch) has no pending entry → it is a genuine detach. Entries are
    /// removed when the count returns to 0.
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

    /// Per-jail read-HEALTH for the status surface (ENH-004, supersedes the
    /// SYS-017 v1 verdict). Pure structural derivation over the live
    /// `FileWatch` fields — no I/O. A jail may map to several logpaths
    /// (several `FileWatch` records); we aggregate. Returns `null` when
    /// `name` matches no watch (the caller then tries the journald source,
    /// or reports unknown HEALTH — the SOURCE label is the daemon's resolved
    /// descriptor, not this).
    ///
    /// Like the parent-wd dispatch in `handleEvent`, this iterates
    /// `self.files` and so relies on the FileWatch-immortality invariant
    /// documented there (no runtime removal; revisit if dynamic jail reload
    /// is ever added).
    ///
    /// File verdict (no staleness timer — a quiet healthy jail keeps its
    /// inotify watch attached and stays healthy with zero traffic):
    ///
    ///   * healthy (`true`) iff ANY matching watch is currently attached
    ///     (`file_fd >= 0`) — the source is reading, traffic or not.
    ///   * else if NO matching watch was ever attached → `null` (unknown):
    ///     a never-appeared / boot / late log must not flash unhealthy.
    ///   * else (every matching watch is detached, ≥1 was once attached):
    ///     unhealthy (`false`) iff the most recent detach is past the
    ///     `detach_debounce_s` window — a was-attached-then-detached source
    ///     (deleted / unmounted / perms revoked). Within the window → `null`
    ///     (rename-rotation flicker; not yet a confirmed break).
    ///
    /// A `false` from this function is a genuine negative probe and DOES
    /// drive DEGRADED for an enforcing jail (ENH-004 lifts the SYS-017 v1
    /// "file never drives DEGRADED" restriction). `lines_seen`/
    /// `last_read_ok_ts` are still reported for the per-jail display but no
    /// longer source the verdict (the old sticky-healthy defect).
    pub fn healthForJail(self: *const LogWatcher, name: []const u8) ?JailHealth {
        var matched = false;
        var any_attached = false;
        var any_ever_attached = false;
        var total_lines: u64 = 0;
        var max_read_ts: i64 = 0;
        // Most recent (latest) detach across this jail's was-attached watches.
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

        // Any attached watch → the jail is reading → healthy.
        if (any_attached) {
            return .{ .healthy = true, .lines_seen = total_lines, .last_read_ok_ts = max_read_ts };
        }
        // Nothing ever attached → unknown (boot / late log), never false.
        if (!any_ever_attached) return null;

        // Detached after having been attached. Confirm the break only once
        // the debounce has elapsed, so normal rotation flicker stays unknown.
        if (latest_detach_ts != 0) {
            const now = std.time.timestamp();
            if (now - latest_detach_ts >= detach_debounce_s) {
                return .{ .healthy = false, .lines_seen = total_lines, .last_read_ok_ts = max_read_ts };
            }
        }
        return null; // within debounce → unknown, not yet a confirmed break
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
        self.pending_ignored.deinit();
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

        // Open the target file. If it doesn't exist yet we still want to
        // register the parent dir watch so we can pick it up on create.
        try openAndStat(fw);
        errdefer if (fw.file_fd >= 0) posix.close(fw.file_fd);

        // Seek to end: we only care about NEW lines, not the historical
        // file contents. Tailing-from-end is the standard fail2ban
        // behavior. On rotation we reset to 0.
        //
        // SEC-007: lseek errors (ESPIPE on a pipe-backed path, EBADF,
        // EOVERFLOW) previously got silently swallowed, leaving us
        // reading from an unknown cursor. Explicit error handling here:
        // log the failure, detach the watch, and continue setup so the
        // parent-directory watch can still pick up a regular file if it
        // later appears at the same path.
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
                // Seed the fingerprint from whatever head bytes exist
                // already (if any). Useful when attaching to a long-running
                // file that has existing content. Any lseek or read error
                // here is a hard signal that the file isn't a regular
                // file (or the fd is bad); detach and let the parent
                // watch recover if something better shows up.
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
            // ENH-004: a real source attached at least once. Structural
            // health keys off this — a path that never gets here stays
            // "unknown" (boot / late log), never "unhealthy".
            fw.was_ever_attached = true;
        }
        errdefer if (fw.file_wd >= 0) {
            _ = linux.inotify_rm_watch(self.inotify_fd, fw.file_wd);
        };

        // Record the FileWatch. The FILE wd is unique per file, so it keys
        // the 1:1 `wd_to_file` map. The PARENT wd is NOT recorded here: when
        // several jails' logs live in the same directory, inotify dedups the
        // dir watch and hands back the SAME parent wd for all of them, so a
        // 1:1 map would let the last jail registered overwrite the rest
        // (BUG-007). Parent-dir events are instead dispatched by iterating
        // `self.files` for every watch sharing that parent wd (see
        // `handleEvent`).
        try self.files.append(fw);
        errdefer _ = self.files.pop();
        if (fw.file_wd >= 0) try self.wd_to_file.put(fw.file_wd, fw);
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
        // BUG-007: a trailing `IN_IGNORED` for a wd WE proactively removed is
        // a no-op. Check this BEFORE resolving the wd: by the time the stale
        // event drains, `reopenAfterRotation` may have reused the wd NUMBER
        // for a fresh, healthy watch — letting this event reach the detach
        // branch would clobber the reopened watch (stop reading the
        // rotated-in file) and falsely flip the jail to DEGRADED. A
        // kernel-AUTO `IN_IGNORED` (no pending entry) falls through to the
        // genuine-detach handling below.
        if ((ev.mask & linux.IN.IGNORED) != 0 and self.consumePendingIgnored(ev.wd)) {
            return;
        }

        // FILE event: the file wd is unique per file, so the 1:1 map resolves
        // it exactly. (Parent wds are deliberately NOT in this map — see the
        // parent branch below and the note in `watchFile`.)
        if (self.wd_to_file.get(ev.wd)) |fw| {
            if ((ev.mask & linux.IN.MODIFY) != 0) {
                // ENH-004: a hard read/stat failure on a still-open fd (EIO,
                // ESTALE on an unmounted NFS export, EBADF, a revoked-perms
                // remount) means the source is broken even though the fd is
                // still nominally open. Transient cases never reach here:
                // `posix.read` retries EINTR internally and EAGAIN is
                // filtered as `WouldBlock` inside the read loop. So treat a
                // returned error as a genuine break — detach (arming the
                // regression debounce) instead of leaving a dead fd
                // reporting healthy. The parent-dir watch stays alive so a
                // replacement file still triggers `reopenAfterRotation`.
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
                // Watched file disappeared — close it but keep the
                // parent watch alive so we'll pick up the replacement.
                self.detachFileWatch(fw);
            }
            return;
        }

        // PARENT-DIR event: `ev.wd` is a directory watch, which inotify
        // dedups per-inode — so it may be SHARED by several jails whose logs
        // live in the same directory (BUG-007). We cannot rely on a single
        // lookup; iterate every FileWatch on this parent wd and reopen each
        // one whose basename matches the created/moved name. Without this, a
        // shared parent wd resolves to only the last-registered jail and the
        // others never reattach after rotation (missing post-rotation reads +
        // false DEGRADED). O(files) only on a directory event (rare); files
        // is bounded by the jail count.
        if ((ev.mask & (linux.IN.CREATE | linux.IN.MOVED_TO)) == 0) return;
        // INVARIANT: safe to iterate `self.files` here (and to rely on stable
        // `*FileWatch` pointers) ONLY because FileWatches are never removed
        // during the daemon lifetime — they live from startup config load
        // until `deinit`. There is no runtime unwatch / per-jail removal path.
        // If dynamic jail reload / runtime jail add-remove / SIGHUP config
        // reload is ever added, this parent-wd dispatch (and any held
        // `*FileWatch`) must be revisited.
        for (self.files.items) |fw| {
            if (fw.parent_wd != ev.wd) continue;
            const fw_basename = fw.basename();
            if (name.len == fw_basename.len and std.mem.eql(u8, name, fw_basename)) {
                // Per-fw resilience: one jail's reopen failure (e.g. transient
                // open error) must not skip the remaining matching jails on
                // this shared parent wd. Log and continue — the parent watch
                // stays live, so a later create on the same path retries.
                self.reopenAfterRotation(fw) catch |err| {
                    std.log.warn(
                        "log_watcher: reopen after rotation failed on {s}: {s}",
                        .{ fw.path(), @errorName(err) },
                    );
                };
            }
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
                fw.lines_seen += 1; // read-health (SYS-017), lifetime
            }
        }

        // The read loop completed without `error.ReadFailed` (every early
        // return above on a read/stat error skips this) — record the clean
        // read for read-health (SYS-017). The best-effort fingerprint
        // refresh below must NOT gate this: a fingerprint lseek hiccup does
        // not mean we failed to read the appended lines.
        fw.last_read_ok_ts = std.time.timestamp();

        // Refresh fingerprint for next call. Sample however many bytes
        // are available, up to `fingerprint_len`. A populated
        // fingerprint (even a short one) is what enables truncate+refill
        // detection in the IN_MODIFY race.
        //
        // SEC-007: an lseek failure in this block points to a corrupt or
        // non-regular-file fd. Log it so ops know why rotation detection
        // degraded; we keep reading (the caller-owned offset is still
        // correct, but truncate+refill races will go undetected until
        // the next successful refresh).
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
            // Restore offset for the next read. If this fails the next
            // readNewData will re-seek at the top, so no correctness
            // impact; still log to surface the underlying issue.
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
        // ENH-004: arm the regression debounce only for a watch that was
        // genuinely attached. A detach during a never-succeeded first
        // attach must not arm it (that path stays "unknown", not
        // "unhealthy"). Stamp once per detach transition — re-detaching an
        // already-detached watch keeps the original (earliest) timestamp so
        // the debounce measures from the real break, not a later sweep.
        if (fw.was_ever_attached and fw.file_wd >= 0 and fw.detached_at_ts == 0) {
            fw.detached_at_ts = std.time.timestamp();
        }
        if (fw.file_wd >= 0) {
            _ = self.wd_to_file.remove(fw.file_wd);
            // BUG-007: a proactive `inotify_rm_watch` makes the kernel queue
            // exactly one trailing `IN_IGNORED` for this wd number and frees
            // the number for reuse. Record that we owe ourselves one
            // suppression so a stale `IN_IGNORED` arriving AFTER the wd is
            // reused (by `reopenAfterRotation`) cannot detach the new watch.
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

    /// BUG-007: record that one trailing `IN_IGNORED` is expected (and must
    /// be ignored) for `wd` because we proactively removed that watch.
    /// Counting (rather than a set) handles the same wd NUMBER being removed,
    /// reused, and removed again before either `IN_IGNORED` drains. Failure
    /// to allocate the bookkeeping entry is non-fatal: the worst case is the
    /// pre-fix behavior (a stale `IN_IGNORED` could clobber a reused watch),
    /// so we log and continue rather than leak the rm_watch.
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

    /// BUG-007: if a trailing `IN_IGNORED` was expected for `wd`, consume one
    /// and return `true` (the caller must treat the event as a no-op). A
    /// kernel-AUTO `IN_IGNORED` (file deleted while we held the watch) has no
    /// pending entry → returns `false` → genuine detach.
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
        // ENH-004: re-attached after a rotation — the source is reading
        // again. Clear the debounce so the verdict goes back to healthy
        // before the window elapses (this is the flicker we debounce for).
        fw.was_ever_attached = true;
        fw.detached_at_ts = 0;

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

test "log_watcher: fifo path lseek failure detaches cleanly (SEC-007)" {
    // SEC-007: operator points logpath at a FIFO (pipe). lseek_END
    // returns ESPIPE. The watcher must log and detach the file watch
    // rather than silently proceed with a stale cursor or crash.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;
    const fifo_name = "fifo.log";
    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const fifo_path = try std.fmt.bufPrint(&full_path_buf, "{s}/{s}", .{ dir_path, fifo_name });

    // Create the FIFO. `mkfifoat` is the POSIX call.
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(path_z[0..fifo_path.len], fifo_path);
    path_z[fifo_path.len] = 0;
    // libc: int mkfifo(const char *pathname, mode_t mode)
    const mkfifo = struct {
        extern "c" fn mkfifo(path: [*:0]const u8, mode: u32) callconv(.C) c_int;
    }.mkfifo;
    if (mkfifo(@ptrCast(&path_z[0]), 0o600) != 0) return error.SkipZigTest;

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    var watcher = try LogWatcher.init(testing.allocator, &loop);
    try watcher.attach();
    defer watcher.deinit();

    var sink = LineSink.init(testing.allocator);
    defer sink.deinit(testing.allocator);

    const jail = try JailId.fromSlice("sshd");
    // watchFile may succeed or fail depending on whether opening a FIFO
    // for reading blocks. What MUST NOT happen: a panic or crash. On
    // success the FileWatch should have been detached (file_fd=-1).
    watcher.watchFile(fifo_path, jail, LineSink.onLine, &sink) catch {
        // Accept errors; the point is no crash.
        return;
    };
    // If watchFile returned successfully, the file watch must be detached
    // (SEC-007): lseek_END on a FIFO returns ESPIPE, so the handler
    // detaches.
    for (watcher.files.items) |fw| {
        try testing.expect(fw.file_fd == -1);
    }
}

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

test "log_watcher: BUG-007 trailing IN_IGNORED after wd reuse does NOT clobber reopened watch" {
    // BUG-007 regression — the DETERMINISTIC guard. Drives the exact
    // pathological state on a REAL inotify instance:
    //
    //   1. watch a real file → capture its file_wd (old_wd).
    //   2. detachFileWatch → real inotify_rm_watch(old_wd) (kernel queues the
    //      trailing IN_IGNORED for old_wd and frees the number) → our fix
    //      records pending[old_wd].
    //   3. reopenAfterRotation → real inotify_add_watch → new healthy watch.
    //   4. put the watcher in the real-box reused-wd state (see below) and
    //      deliver the trailing IN_IGNORED for old_wd via the real
    //      handleEvent path — the clobber trigger.
    //
    // WITHOUT the fix this re-detaches the freshly reopened watch
    // (file_fd=-1, stuck unhealthy → false DEGRADED, and post-rotation reads
    // stop). WITH the fix the trailing IN_IGNORED is suppressed (pending entry
    // consumed) and the watch survives: still attached, healthy, still reading.
    //
    // Two facts forced explicitly because a fresh in-process inotify instance
    // cannot reproduce them on its own (confirmed by probing kernel 6.12):
    //   * WD REUSE — the kernel's inotify IDR does NOT recycle a wd number on
    //     the immediate next add_watch; reuse only happens after the IDR wraps
    //     on a long-running daemon (f2z-target). We re-point the live mapping
    //     so the reopened watch lands on old_wd, the real-box condition.
    //   * ORDERING — in-process the kernel queues MOVE_SELF+IGNORED together,
    //     so the IGNORED drains BEFORE the later parent IN_CREATE drives
    //     reopen (harmless). We deliver it AFTER reopen, the box ordering.
    // `tests/e2e/degraded_file_source.sh` assertion (c) covers the full
    // real-logrotate timing + real IDR reuse end-to-end on f2z-target.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;
    const log_name = "br.log";
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

    // Locate the FileWatch and capture the OLD file wd (the one the kernel
    // will queue a trailing IN_IGNORED for when we detach).
    try testing.expectEqual(@as(usize, 1), watcher.files.items.len);
    const fw = watcher.files.items[0];
    try testing.expect(fw.file_fd >= 0);
    const old_wd = fw.file_wd;
    try testing.expect(old_wd >= 0);

    // Step 2: detach (real rm_watch(old_wd) → kernel queues the trailing
    // IN_IGNORED for old_wd; our fix records pending[old_wd]).
    watcher.detachFileWatch(fw);
    try testing.expect(fw.file_fd == -1);

    // Step 3: reopen (real add_watch). We write fresh content first so the
    // reopened watch has something to read.
    {
        const f = try tmp.dir.openFile(log_name, .{ .mode = .write_only });
        defer f.close();
        _ = try f.writeAll("after-reopen\n");
    }
    try watcher.reopenAfterRotation(fw);
    try testing.expect(fw.file_fd >= 0); // reopened
    try testing.expect(fw.file_wd >= 0);
    // The reopen reads existing content synchronously.
    try testing.expect(sink.count() >= 1);
    try testing.expectEqualStrings("after-reopen", sink.lines.items[0]);

    // Simulate the kernel REUSING old_wd for the reopened watch. On a
    // long-running daemon the inotify IDR eventually recycles wd numbers, so
    // the reopened watch can land on the very number a stale IN_IGNORED still
    // references — the exact condition that triggers the clobber on
    // f2z-target. A fresh in-process inotify instance won't recycle the
    // number on its own, so we re-point the live mapping to old_wd to put the
    // watcher in that real-box state deterministically. (Only the bookkeeping
    // is adjusted; the underlying open fd is the real reopened one.)
    if (fw.file_wd != old_wd) {
        _ = watcher.wd_to_file.remove(fw.file_wd);
        fw.file_wd = old_wd;
        try watcher.wd_to_file.put(old_wd, fw);
    }

    // Step 4: deliver the STALE trailing IN_IGNORED for old_wd — the event
    // the kernel queued in step 2, now resolving (via reuse) to the freshly
    // reopened watch. This is the clobber path.
    const stale_ignored: linux.inotify_event = .{
        .wd = old_wd,
        .mask = linux.IN.IGNORED,
        .cookie = 0,
        .len = 0,
    };
    try watcher.handleEvent(stale_ignored, &[_]u8{});

    // The fix must keep the reopened watch alive: NOT clobbered.
    try testing.expect(fw.file_fd >= 0);
    try testing.expect(fw.file_wd == old_wd);
    try testing.expectEqual(@as(i64, 0), fw.detached_at_ts); // not re-armed

    // Health stays healthy (an attached watch is healthy regardless of the
    // stale event), not the stuck `false` the bug produced.
    const h = watcher.healthForJail("sshd").?;
    try testing.expect(h.healthy);

    // ENFORCEMENT: the reopened fd still reads NEW content after the stale
    // IGNORED — the daemon did not silently stop reading the rotated-in file.
    // Drive `readNewData` directly on the still-open fd (the wd mapping was
    // re-pointed above to simulate reuse, so an inotify-delivered IN_MODIFY
    // would carry the kernel's real wd; reading the fd is the faithful check
    // that the file source survived). The full inotify→read path under real
    // rotation is covered by the companion test below and e2e assertion (c).
    {
        const f = try tmp.dir.openFile(log_name, .{ .mode = .write_only });
        defer f.close();
        _ = try f.seekFromEnd(0);
        _ = try f.writeAll("still-reading\n");
    }
    try watcher.readNewData(fw);
    try testing.expect(sink.count() >= 2);
    try testing.expectEqualStrings("still-reading", sink.lines.items[1]);
}

test "log_watcher: BUG-007 real same-name rotation keeps reading (enforcement)" {
    // Companion integration check: a REAL mv-away+recreate rotation under the
    // natural event ordering. Confirms the rotation path reads across the
    // rotation and stays healthy. (The deterministic test above is the guard
    // for the post-reopen IN_IGNORED ordering this one cannot force.)
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;
    const log_name = "br2.log";
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
                const f = c.tmp_dir.openFile("br2.log", .{ .mode = .write_only }) catch return;
                defer f.close();
                _ = f.writeAll("pre\n") catch {};
            }
            var tries: u32 = 0;
            while (tries < 100 and c.sink.count() < 1) : (tries += 1) std.time.sleep(10 * std.time.ns_per_ms);
            c.tmp_dir.rename("br2.log", "br2.log.1") catch return;
            {
                const f = c.tmp_dir.createFile("br2.log", .{ .truncate = true }) catch return;
                defer f.close();
                _ = f.writeAll("post1\n") catch {};
            }
            tries = 0;
            while (tries < 200 and c.sink.count() < 2) : (tries += 1) std.time.sleep(10 * std.time.ns_per_ms);
            // Second post-rotation append: confirms the watch keeps reading.
            {
                const f = c.tmp_dir.openFile("br2.log", .{ .mode = .write_only }) catch return;
                defer f.close();
                _ = f.seekFromEnd(0) catch {};
                _ = f.writeAll("post2\n") catch {};
            }
            tries = 0;
            while (tries < 200 and c.sink.count() < 3) : (tries += 1) std.time.sleep(10 * std.time.ns_per_ms);
            c.loop.stop();
        }
    }.kick, .{&ctx});

    try loop.run();
    th.join();

    try testing.expect(sink.count() >= 3);
    try testing.expectEqualStrings("pre", sink.lines.items[0]);
    try testing.expectEqualStrings("post1", sink.lines.items[1]);
    try testing.expectEqualStrings("post2", sink.lines.items[2]);
    const h = watcher.healthForJail("sshd").?;
    try testing.expect(h.healthy);
}

test "log_watcher: BUG-007 same-dir multi-jail rotation reopens the rotated jail (shared parent wd)" {
    // BUG-007 REAL root cause: multiple file jails whose logs live in the
    // SAME directory share one parent-dir inotify wd (inotify dedups per
    // inode). A 1:1 `wd_to_file` parent mapping let the last-registered jail
    // overwrite the rest, so a parent IN_CREATE resolved to the wrong jail,
    // its basename didn't match, and the ROTATED jail never reattached —
    // missing post-rotation reads + false DEGRADED.
    //
    // Drives a REAL same-dir two-jail setup, rotates ONE log (mv-away +
    // recreate), and asserts:
    //   (a) the rotated jail reopens, reads new content, reports healthy;
    //   (b) the OTHER same-dir jail is unaffected (keeps reading + healthy).
    //
    // FAILS before the fix (the rotated jail's parent event resolves to the
    // other jail; basename mismatch → no reopen). PASSES after the fix
    // (handleEvent iterates ALL FileWatches on the shared parent wd).
    // The single-jail tests above cannot see this — they never collide.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;

    var a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var b_buf: [std.fs.max_path_bytes]u8 = undefined;
    const a_path = try std.fmt.bufPrint(&a_buf, "{s}/a.log", .{dir_path});
    const b_path = try std.fmt.bufPrint(&b_buf, "{s}/b.log", .{dir_path});
    {
        const fa = try tmp.dir.createFile("a.log", .{ .truncate = true });
        fa.close();
        const fb = try tmp.dir.createFile("b.log", .{ .truncate = true });
        fb.close();
    }

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var watcher = try LogWatcher.init(testing.allocator, &loop);
    try watcher.attach();
    defer watcher.deinit();

    // Each jail gets its OWN sink so lines are attributable per jail.
    var sink_a = LineSink.init(testing.allocator);
    defer sink_a.deinit(testing.allocator);
    var sink_b = LineSink.init(testing.allocator);
    defer sink_b.deinit(testing.allocator);

    // Register "jail-a" FIRST, "jail-b" LAST — pre-fix, the shared parent wd
    // would resolve to jail-b (last writer), so jail-a (the one we rotate)
    // would never reopen. This ordering makes the bug bite.
    try watcher.watchFile(a_path, try JailId.fromSlice("jail-a"), LineSink.onLine, &sink_a);
    try watcher.watchFile(b_path, try JailId.fromSlice("jail-b"), LineSink.onLine, &sink_b);

    // Sanity: both watches share ONE parent wd (the real-box precondition).
    try testing.expectEqual(@as(usize, 2), watcher.files.items.len);
    try testing.expect(watcher.files.items[0].parent_wd == watcher.files.items[1].parent_wd);

    const Ctx = struct {
        tmp_dir: std.fs.Dir,
        loop: *EventLoop,
        sink_a: *LineSink,
        sink_b: *LineSink,
    };
    var ctx = Ctx{ .tmp_dir = tmp.dir, .loop = &loop, .sink_a = &sink_a, .sink_b = &sink_b };

    const th = try std.Thread.spawn(.{}, struct {
        fn kick(c: *Ctx) void {
            std.time.sleep(30 * std.time.ns_per_ms);
            // Pre-rotation: write to BOTH logs.
            {
                const fa = c.tmp_dir.openFile("a.log", .{ .mode = .write_only }) catch return;
                defer fa.close();
                _ = fa.writeAll("a-pre\n") catch {};
            }
            {
                const fb = c.tmp_dir.openFile("b.log", .{ .mode = .write_only }) catch return;
                defer fb.close();
                _ = fb.writeAll("b-pre\n") catch {};
            }
            var tries: u32 = 0;
            while (tries < 100 and (c.sink_a.count() < 1 or c.sink_b.count() < 1)) : (tries += 1)
                std.time.sleep(10 * std.time.ns_per_ms);

            // Rotate ONLY a.log (mv away + recreate same name).
            c.tmp_dir.rename("a.log", "a.log.1") catch return;
            {
                const fa = c.tmp_dir.createFile("a.log", .{ .truncate = true }) catch return;
                defer fa.close();
                _ = fa.writeAll("a-post\n") catch {};
            }
            // jail-a must reopen and read a-post (the bug: it never does).
            tries = 0;
            while (tries < 300 and c.sink_a.count() < 2) : (tries += 1)
                std.time.sleep(10 * std.time.ns_per_ms);

            // jail-b (untouched) keeps reading — append a second b line.
            {
                const fb = c.tmp_dir.openFile("b.log", .{ .mode = .write_only }) catch return;
                defer fb.close();
                _ = fb.seekFromEnd(0) catch {};
                _ = fb.writeAll("b-post\n") catch {};
            }
            tries = 0;
            while (tries < 300 and c.sink_b.count() < 2) : (tries += 1)
                std.time.sleep(10 * std.time.ns_per_ms);
            c.loop.stop();
        }
    }.kick, .{&ctx});

    try loop.run();
    th.join();

    // (a) The ROTATED jail reopened, read its post-rotation line, is healthy.
    try testing.expect(sink_a.count() >= 2);
    try testing.expectEqualStrings("a-pre", sink_a.lines.items[0]);
    try testing.expectEqualStrings("a-post", sink_a.lines.items[1]);
    try testing.expect(watcher.healthForJail("jail-a").?.healthy);

    // (b) The OTHER same-dir jail is unaffected — kept reading, still healthy.
    try testing.expect(sink_b.count() >= 2);
    try testing.expectEqualStrings("b-pre", sink_b.lines.items[0]);
    try testing.expectEqualStrings("b-post", sink_b.lines.items[1]);
    try testing.expect(watcher.healthForJail("jail-b").?.healthy);
}

// --- ENH-004 structural file read-health verdict ---
//
// These exercise `healthForJail`'s pure structural derivation directly over
// crafted `FileWatch` fields — no inotify, no spawn, no clock dependence
// except the debounce comparison (driven with explicit past/now timestamps).
// A minimal `LogWatcher` (only `files` populated) suffices; the verdict reads
// nothing else.

/// Build a `FileWatch` with only the verdict-relevant fields set. Allocated
/// from `a`; the caller appends it to a watcher and frees via `freeTestWatch`
/// (we deliberately do NOT init `line_buffer`, so do not call `deinit`).
fn testNoopCallback(_: []const u8, _: JailId, _: bool, _: ?*anyopaque) void {}

fn makeTestWatch(
    a: Allocator,
    jail_name: []const u8,
    file_fd: posix.fd_t,
    was_ever_attached: bool,
    detached_at_ts: i64,
    lines_seen: u64,
    last_read_ok_ts: i64,
) !*FileWatch {
    const fw = try a.create(FileWatch);
    // `healthForJail` reads only jail / file_fd / was_ever_attached /
    // detached_at_ts / lines_seen / last_read_ok_ts. The remaining fields are
    // set to inert valid values (line_buffer is never touched — the caller
    // frees via `freeTestWatcher`, which only `destroy`s, never `deinit`s).
    fw.* = .{
        .path_buf = undefined,
        .path_len = 0,
        .basename_start = 0,
        .jail = try JailId.fromSlice(jail_name),
        .callback = testNoopCallback,
        .userdata = null,
        .file_fd = file_fd,
        .offset = 0,
        .inode = 0,
        .prev_size = 0,
        .fingerprint = [_]u8{0} ** fingerprint_len,
        .fingerprint_len = 0,
        .file_wd = -1,
        .parent_wd = -1,
        .last_read_ok_ts = last_read_ok_ts,
        .lines_seen = lines_seen,
        .was_ever_attached = was_ever_attached,
        .detached_at_ts = detached_at_ts,
        .line_buffer = undefined,
        .allocator = a,
    };
    return fw;
}

/// A bare watcher whose only populated field is `files`. `healthForJail`
/// touches nothing else.
fn makeTestWatcher(a: Allocator) LogWatcher {
    return .{
        .allocator = a,
        .event_loop = undefined,
        .inotify_fd = -1,
        .wd_to_file = std.AutoHashMap(i32, *FileWatch).init(a),
        .files = std.ArrayList(*FileWatch).init(a),
        .pending_ignored = std.AutoHashMap(i32, u32).init(a),
    };
}

fn freeTestWatcher(w: *LogWatcher) void {
    for (w.files.items) |fw| w.allocator.destroy(fw);
    w.files.deinit();
    w.wd_to_file.deinit();
    w.pending_ignored.deinit();
}

test "log_watcher: healthForJail attached → healthy with zero traffic (ENH-004)" {
    const a = testing.allocator;
    var w = makeTestWatcher(a);
    defer freeTestWatcher(&w);
    // file_fd >= 0, never read: a quiet healthy jail must NOT be flagged.
    try w.files.append(try makeTestWatch(a, "sshd", 7, true, 0, 0, 0));
    const h = w.healthForJail("sshd").?;
    try testing.expect(h.healthy);
}

test "log_watcher: healthForJail never-attached → unknown, no boot false-flash (ENH-004)" {
    const a = testing.allocator;
    var w = makeTestWatcher(a);
    defer freeTestWatcher(&w);
    // Late-appearing log: detached, never attached, never read → unknown.
    try w.files.append(try makeTestWatch(a, "sshd", -1, false, 0, 0, 0));
    try testing.expect(w.healthForJail("sshd") == null);
}

test "log_watcher: healthForJail detached within debounce → unknown (rotation flicker) (ENH-004)" {
    const a = testing.allocator;
    var w = makeTestWatcher(a);
    defer freeTestWatcher(&w);
    // Was attached, just detached (now): inside the debounce window → unknown,
    // so a normal rename-rotation detach-then-reopen never flips DEGRADED.
    const now = std.time.timestamp();
    try w.files.append(try makeTestWatch(a, "sshd", -1, true, now, 5, now));
    try testing.expect(w.healthForJail("sshd") == null);
}

test "log_watcher: healthForJail detached past debounce → unhealthy (ENH-004)" {
    const a = testing.allocator;
    var w = makeTestWatcher(a);
    defer freeTestWatcher(&w);
    // Was attached, detached well past the debounce window: a genuine break
    // (deleted / unmounted / perms revoked) → hard false (drives DEGRADED).
    const stale = std.time.timestamp() - detach_debounce_s - 5;
    try w.files.append(try makeTestWatch(a, "sshd", -1, true, stale, 5, stale));
    const h = w.healthForJail("sshd").?;
    try testing.expect(!h.healthy);
    try testing.expectEqual(@as(u64, 5), h.lines_seen);
}

test "log_watcher: healthForJail multi-logpath any-attached wins (ENH-004)" {
    const a = testing.allocator;
    var w = makeTestWatcher(a);
    defer freeTestWatcher(&w);
    const stale = std.time.timestamp() - detach_debounce_s - 5;
    // One path broken (detached past debounce), one still reading. The jail
    // is still healthy: it has a live source.
    try w.files.append(try makeTestWatch(a, "sshd", -1, true, stale, 2, stale));
    try w.files.append(try makeTestWatch(a, "sshd", 9, true, 0, 0, 0));
    const h = w.healthForJail("sshd").?;
    try testing.expect(h.healthy);
}

test "log_watcher: healthForJail reopen clears the break (ENH-004)" {
    const a = testing.allocator;
    var w = makeTestWatcher(a);
    defer freeTestWatcher(&w);
    const stale = std.time.timestamp() - detach_debounce_s - 5;
    const fw = try makeTestWatch(a, "sshd", -1, true, stale, 2, stale);
    try w.files.append(fw);
    try testing.expect(!w.healthForJail("sshd").?.healthy); // broken

    // Simulate reopenAfterRotation's effect: re-attached, debounce cleared.
    fw.file_fd = 9;
    fw.detached_at_ts = 0;
    try testing.expect(w.healthForJail("sshd").?.healthy); // recovered
}

test "log_watcher: healthForJail returns null for an unknown jail (ENH-004)" {
    const a = testing.allocator;
    var w = makeTestWatcher(a);
    defer freeTestWatcher(&w);
    try w.files.append(try makeTestWatch(a, "sshd", 7, true, 0, 0, 0));
    try testing.expect(w.healthForJail("nope") == null);
}
