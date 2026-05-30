// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! journald log source (SYS-015).
//!
//! Reads sshd authentication failures from the systemd journal on modern
//! distros where `/var/log/auth.log` does not exist and auth events go to
//! journald only. This is the sibling of `log_watcher.zig`: where the file
//! tailer drives itself from an inotify FD, the journald source drives
//! itself from a periodic poll timer, spawning `journalctl -o json` on
//! each tick.
//!
//! Design constraints (see .project/SYS-015-journald-design.md):
//!   * NO libsystemd / sd-journal linkage — subprocess `journalctl` only,
//!     so the binary stays static + zero-dep.
//!   * NO native journal-file parsing — `journalctl -o json` is the only
//!     ingestion path.
//!   * NO `journalctl -f` — we poll with `--after-cursor` on a 1 s timer;
//!     each tick is an independent reconcile.
//!   * Selector set is FIXED in v1 (sshd): the journal records that carry
//!     auth failures are emitted by `sshd-session` (per-connection), not
//!     just the `sshd` listener, so we OR four selectors. There is no
//!     user-configurable `journalmatch` in v1 (too easy to make silently
//!     AND-to-zero-rows).
//!
//! Hot path: a decoded journal `MESSAGE` has no syslog envelope, so it
//! feeds the SAME `lineCallback` the file watcher uses
//! (`stripSyslogPrefix` is a no-op on a bare message, then `parseLine`).
//! No new parse path, no new callback contract.
//!
//! ALL journal content is attacker-influenced (an attacker controls the
//! username / source IP that lands in `MESSAGE`). We treat the JSON, the
//! cursor, and the byte-array MESSAGE form as untrusted: no `@panic`, no
//! `unreachable`, malformed input is skipped, never fatal.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;

const event_loop_mod = @import("event_loop.zig");
const log_watcher_mod = @import("log_watcher.zig");
const config_mod = @import("../config/native.zig");
const shared = @import("shared");

const EventLoop = event_loop_mod.EventLoop;
const TimerHandle = event_loop_mod.TimerHandle;
const LineCallback = log_watcher_mod.LineCallback;
const JailId = shared.JailId;

pub const Error = error{
    NotLinux,
    OutOfMemory,
    EventLoopError,
    TooManyJails,
    PathTooLong,
    /// A jail asked for the journald source with a filter the journald
    /// backend does not support in v1 (only `sshd`). We fail closed
    /// rather than silently apply sshd selectors to a non-sshd jail.
    UnsupportedJournaldFilter,
};

// ============================================================================
// Tunables
// ============================================================================

/// Poll cadence. Hard-coded for v1 (Lead decision 4) to match the
/// expiry-sweep / ws-tick cadence; no config knob yet.
pub const poll_interval_ms: u64 = 1000;

/// Maximum jails this source will host. journald jails are rare (sshd,
/// maybe a couple more); a small fixed cap keeps the ArrayList bounded.
pub const max_jails: usize = 64;

/// Hard cap on journal entries processed per jail per poll tick. Bounds
/// the work (and the attacker's ability to flood us via journal volume)
/// done on the loop thread between epoll returns. Past this we stop
/// reading the current batch and resume next tick — the cursor still
/// advances to the last processed entry, so no entries are lost, only
/// deferred. Mirrors the `max_per_tick` discipline in main.zig's expiry
/// sweep.
pub const max_entries_per_tick: usize = 4096;

/// Maximum journalctl stdout we will buffer per invocation. A failed-auth
/// JSON line is ~1 KB; `max_entries_per_tick` of them is a few MB. Cap at
/// 16 MB so a pathological journal cannot make us allocate unbounded.
pub const max_output_bytes: usize = 16 * 1024 * 1024;

/// Cursor strings are opaque (`s=…;i=…;b=…;m=…;t=…;x=…`), ~150 bytes in
/// practice. 512 is generous headroom; longer cursors are rejected (we
/// simply don't advance, re-reading next tick).
pub const max_cursor_len: usize = 512;

/// Per-line scratch buffer for the decoded MESSAGE before it is handed to
/// the line callback. 4 KB matches the engine's max-log-line convention.
pub const max_line_len: usize = 4096;

// ============================================================================
// Source resolution — pure, injectable seams for tests
// ============================================================================

pub const ResolvedSource = enum { file, journald, fail };

/// Resolve a jail's effective log source from its configured `source`,
/// its `logpath`, and a probe for journalctl presence. Pure function:
/// the journalctl probe is injected so this is unit-testable with no
/// filesystem (and no journald) — see tests below.
///
///   * `.file`     → `.file` always (the watcher tolerates a not-yet-
///                   present path; "fail-closed for file" only applies to
///                   an empty/invalid path the watcher cannot handle,
///                   which surfaces at `watchFile` time, not here).
///   * `.journald` → `.journald` iff journalctl present, else `.fail`.
///   * `.auto`     → usable logpath → `.file`; else journalctl present →
///                   `.journald`; else `.fail`.
pub fn resolveSource(
    source: config_mod.LogSource,
    logpath: []const []const u8,
    journalctl_present: bool,
) ResolvedSource {
    return switch (source) {
        .file => .file,
        .journald => if (journalctl_present) .journald else .fail,
        .auto => blk: {
            if (config_mod.hasUsableLogpath(logpath)) break :blk .file;
            if (journalctl_present) break :blk .journald;
            break :blk .fail;
        },
    };
}

// ============================================================================
// Selector sets — FIXED in v1, keyed by filter name
// ============================================================================

/// sshd selector set. Auth FAILURES on modern OpenSSH are emitted by the
/// per-connection `sshd-session` process, NOT the `sshd` listener, so we
/// must match both identifiers. We also match on `_COMM` as a belt-and-
/// suspenders fallback for journal entries that lack SYSLOG_IDENTIFIER.
/// These four are OR'd together at the journalctl command level (see
/// `appendSelectorArgv`).
pub const sshd_selectors = [_][]const u8{
    "SYSLOG_IDENTIFIER=sshd",
    "SYSLOG_IDENTIFIER=sshd-session",
    "_COMM=sshd",
    "_COMM=sshd-session",
};

/// Map a filter name to its journald selector set. v1 supports the `sshd`
/// filter ONLY: only for an exact `"sshd"` match do we return the sshd
/// selector set. Any other filter returns `null` — the journald backend
/// has no selectors for it, so the jail MUST fail closed rather than
/// silently apply sshd selectors to (say) an nginx jail and mis-cover it.
/// Per-filter selector sets for other services are v2 work, gated on the
/// same care that keeps a user-configurable `journalmatch` out of v1.
pub fn selectorsForFilter(filter: []const u8) ?[]const []const u8 {
    if (std.mem.eql(u8, filter, "sshd")) return &sshd_selectors;
    return null;
}

// ============================================================================
// journalctl argv construction
// ============================================================================

/// Append the OR'd selector tokens for `selectors` into `argv`, splitting
/// same-field groups with a standalone `+` disjunction so that selectors
/// across DIFFERENT fields are OR'd (journalctl ANDs different fields by
/// default; the `+` turns the cross-field relation into OR).
///
/// For the sshd set the emitted tokens are:
///   SYSLOG_IDENTIFIER=sshd  SYSLOG_IDENTIFIER=sshd-session  +  _COMM=sshd  _COMM=sshd-session
///
/// The grouping is by field prefix (`FIELD=`): consecutive selectors that
/// share a field stay adjacent (auto-OR), and a `+` is inserted between
/// groups of differing fields. `selectors` MUST be ordered so same-field
/// entries are contiguous (the `sshd_selectors` table is).
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

/// The `FIELD` portion of a `FIELD=VALUE` selector (everything before the
/// first `=`). Returns the whole string if there is no `=` (defensive —
/// our selector table always has one).
fn fieldOf(selector: []const u8) []const u8 {
    const eq = std.mem.indexOfScalar(u8, selector, '=') orelse return selector;
    return selector[0..eq];
}

/// Build the argv for the first-run baseline probe (Lead decision 3):
///   journalctl <selectors> -n 1 -o json --no-pager -q
/// Reads the LAST matching entry; we take its `__CURSOR` and start AFTER
/// it, so no history is replayed. Caller owns the returned slice (and the
/// ArrayList backing it lives in the supplied arena).
pub fn buildBaselineArgv(
    arena: Allocator,
    selectors: []const []const u8,
) Allocator.Error![]const []const u8 {
    var argv = std.ArrayList([]const u8).init(arena);
    try argv.append(config_mod.journalctl_path);
    try appendSelectorArgv(&argv, selectors);
    try argv.append("-n");
    try argv.append("1");
    try argv.append("-o");
    try argv.append("json");
    try argv.append("--no-pager");
    try argv.append("-q");
    return argv.toOwnedSlice();
}

/// Build the argv for a steady-state poll:
///   journalctl <selectors> -o json --no-pager -q --after-cursor=<cursor>
/// `cursor_flag` must be the full `--after-cursor=<cursor>` token; it is
/// caller-owned and must outlive the argv. Caller owns the returned slice.
pub fn buildPollArgv(
    arena: Allocator,
    selectors: []const []const u8,
    cursor_flag: []const u8,
) Allocator.Error![]const []const u8 {
    var argv = std.ArrayList([]const u8).init(arena);
    try argv.append(config_mod.journalctl_path);
    try appendSelectorArgv(&argv, selectors);
    try argv.append("-o");
    try argv.append("json");
    try argv.append("--no-pager");
    try argv.append("-q");
    try argv.append(cursor_flag);
    return argv.toOwnedSlice();
}

// ============================================================================
// JSON entry decoding
// ============================================================================

/// A single decoded journal entry: the MESSAGE body (already
/// UTF-8/bytes-normalized) plus its cursor, if present. `message` and
/// `cursor` are slices into the caller-provided scratch buffers, valid
/// only for the duration of the processing of this entry.
pub const DecodedEntry = struct {
    message: []const u8,
    /// null when the entry's JSON had no `__CURSOR` field. The line is
    /// still processed, but the pending cursor is NOT advanced from it
    /// (advance-only-from-entries-that-have-a-cursor invariant).
    cursor: ?[]const u8,
};

pub const DecodeError = error{
    NotAnObject,
    NoMessage,
    MessageTooLong,
    MalformedMessage,
};

/// Decode one journalctl `-o json` object (a single stdout line) into a
/// `DecodedEntry`. `msg_buf` receives the normalized MESSAGE bytes;
/// `cursor_buf` receives the `__CURSOR` string. Both are caller-owned
/// fixed buffers. Uses an arena for the transient JSON DOM so there is no
/// leak and no per-entry heap churn beyond the arena.
///
/// MESSAGE forms handled (per the journal export format):
///   * JSON string  — copied verbatim (already UTF-8).
///   * JSON array of integers — non-UTF-8 message exported byte-by-byte;
///     each element must be 0..255, written as a raw byte. A non-integer
///     or out-of-range element makes the message malformed → skipped.
///   * missing / wrong type → `error.NoMessage` (caller skips the entry).
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

    // ---- MESSAGE ----
    const msg_val = obj.get("MESSAGE") orelse return error.NoMessage;
    const message = try normalizeMessage(msg_val, msg_buf);

    // ---- __CURSOR (optional) ----
    var cursor: ?[]const u8 = null;
    if (obj.get("__CURSOR")) |cur_val| {
        switch (cur_val) {
            .string => |s| {
                if (s.len > 0 and s.len <= cursor_buf.len) {
                    @memcpy(cursor_buf[0..s.len], s);
                    cursor = cursor_buf[0..s.len];
                }
                // An over-long or empty cursor is treated as "no cursor"
                // for this entry — we process the line but do not advance.
            },
            else => {}, // wrong type → treat as absent
        }
    }

    return .{ .message = message, .cursor = cursor };
}

/// Normalize a MESSAGE JSON value into raw bytes in `out`. Returns a slice
/// into `out`. Handles the string form and the byte-array form.
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

// ============================================================================
// Cursor sidecar persistence
// ============================================================================
//
// Cursors live in their OWN file next to the engine state file rather than
// in the binary state format (no wire-format bump). Layout, little-endian:
//
//   Header (10 bytes):
//     magic        [4]u8  = 'F','2','Z','J'
//     version      u16    = 1
//     jail_count   u32
//   Records (jail_count of them), then a trailing CRC32 over header+records:
//     name_len     u16
//     name         [name_len]u8
//     cursor_len   u16
//     cursor       [cursor_len]u8
//   Trailer:
//     checksum     u32    = CRC32 over everything before it
//
// Save is atomic (temp + fsync + fchmod 0600 + rename), mirroring
// engine/core/persist.zig. Any integrity failure on load → empty result →
// the source re-seeds each jail at "now" on the next tick (no replay).

pub const cursor_magic: [4]u8 = .{ 'F', '2', 'Z', 'J' };
pub const cursor_version: u16 = 1;
const cursor_file_basename = "journald-cursors.bin";
const max_sidecar_bytes: usize = 1024 * 1024; // generous; cursors are tiny

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

/// Derive the cursor sidecar path from the engine `state_file` path:
/// `dirname(state_file)/journald-cursors.bin`. Written into `buf`. The
/// sidecar inherits the StateDirectory (0750) the state file lives in.
pub fn cursorPath(state_file: []const u8, buf: []u8) SidecarError![]const u8 {
    const dir = std.fs.path.dirname(state_file) orelse ".";
    const need = dir.len + 1 + cursor_file_basename.len;
    if (need > buf.len) return error.PathTooLong;
    @memcpy(buf[0..dir.len], dir);
    buf[dir.len] = '/';
    @memcpy(buf[dir.len + 1 ..][0..cursor_file_basename.len], cursor_file_basename);
    return buf[0..need];
}

/// Atomically write the cursor sidecar. Caller passes the live set of
/// (jail, cursor) pairs; only jails with a non-empty cursor should be
/// included. Empty input writes a valid zero-record file.
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

    // Header.
    var hdr: [10]u8 = undefined;
    @memcpy(hdr[0..4], &cursor_magic);
    std.mem.writeInt(u16, hdr[4..6], cursor_version, .little);
    std.mem.writeInt(u32, hdr[6..10], @intCast(entries.len), .little);
    writer.writeAll(&hdr) catch return error.WriteFailed;
    crc.update(&hdr);

    // Records.
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

    // Trailing checksum.
    var crc_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc_buf, crc.final(), .little);
    writer.writeAll(&crc_buf) catch return error.WriteFailed;

    posix.fsync(file.handle) catch return error.FsyncFailed;
    posix.fchmod(file.handle, 0o600) catch return error.ChmodFailed;

    file.close();
    close_handled = true;

    std.fs.cwd().rename(tmp_path, path) catch return error.RenameFailed;
}

/// Load the cursor sidecar. Caller owns the returned slice AND each
/// entry's `name`/`cursor` byte slices (all allocated from `allocator`).
/// Missing file → empty slice (no warning). Any integrity failure →
/// warning + empty slice (the source re-seeds at "now").
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

    // Checksum covers everything except the trailing 4 bytes.
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

// ============================================================================
// JournaldSource — the live poller
// ============================================================================

/// One journald-backed jail. Holds the fixed selector set, the callback +
/// userdata (the `*JailContext`), the committed cursor, and a "seeded"
/// flag distinguishing first-run (needs a baseline cursor) from steady
/// state.
pub const JournalJail = struct {
    jail: JailId,
    selectors: []const []const u8,
    callback: LineCallback,
    userdata: ?*anyopaque,
    /// Last committed cursor. `cursor_len == 0` means "no cursor yet" —
    /// the next tick fetches a baseline (-n 1) instead of polling.
    cursor: [max_cursor_len]u8 = [_]u8{0} ** max_cursor_len,
    cursor_len: usize = 0,

    fn cursorSlice(self: *const JournalJail) []const u8 {
        return self.cursor[0..self.cursor_len];
    }

    fn setCursor(self: *JournalJail, cur: []const u8) void {
        if (cur.len == 0 or cur.len > max_cursor_len) return;
        @memcpy(self.cursor[0..cur.len], cur);
        self.cursor_len = cur.len;
    }
};

pub const JournaldSource = struct {
    allocator: Allocator,
    event_loop: *EventLoop,
    jails: std.ArrayList(JournalJail),
    /// Sidecar file path (owned copy).
    cursor_path: []u8,
    poll_handle: ?TimerHandle = null,
    /// True once any jail's cursor changed since the last sidecar flush —
    /// lets `runDaemon`'s flush skip a no-op write.
    dirty: bool = false,
    /// Periodic-flush hook (SYS-015). Invoked after a poll tick that
    /// advanced any cursor, so engine state + the cursor sidecar are
    /// persisted on the loop thread within ≤1 poll interval of the entries
    /// they reflect (bounds crash-replay to one interval without a second
    /// timer). The daemon points this at `journaldFlushHook`, which calls
    /// `flushStateThenCursors` (state FIRST, then cursors). Null in tests
    /// that drive `processBatch`/`maybeFlush` directly.
    flush_fn: ?*const fn (?*anyopaque) void = null,
    flush_userdata: ?*anyopaque = null,

    pub fn init(
        allocator: Allocator,
        event_loop: *EventLoop,
        state_file: []const u8,
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
        };
    }

    pub fn deinit(self: *JournaldSource) void {
        if (self.poll_handle) |h| {
            self.event_loop.cancelTimer(h) catch {};
        }
        self.jails.deinit();
        self.allocator.free(self.cursor_path);
        self.* = undefined;
    }

    /// True when at least one jail has been registered — the daemon only
    /// arms the poll timer if the journald source is actually in use.
    pub fn hasJails(self: *const JournaldSource) bool {
        return self.jails.items.len > 0;
    }

    /// Register a journald-backed jail. `filter` selects the selector set.
    /// The callback + userdata are the SAME `lineCallback` + `*JailContext`
    /// the file watcher uses. Restored cursors are seeded separately via
    /// `seedCursor` before `attach`.
    ///
    /// Fails closed with `error.UnsupportedJournaldFilter` when the journald
    /// backend has no selector set for `filter` (v1: only `sshd`). The jail
    /// is NOT registered in that case — applying sshd selectors to a
    /// non-sshd jail would silently mis-cover it.
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
        self.jails.append(.{
            .jail = jail,
            .selectors = selectors,
            .callback = callback,
            .userdata = userdata,
        }) catch return error.OutOfMemory;
    }

    /// Install the periodic-flush hook (SYS-015 Change 2). Call BEFORE
    /// `attach()`. `fn_ptr(userdata)` is invoked by `maybeFlush` after any
    /// poll tick that advanced a cursor.
    pub fn setFlushHook(
        self: *JournaldSource,
        fn_ptr: *const fn (?*anyopaque) void,
        userdata: ?*anyopaque,
    ) void {
        self.flush_fn = fn_ptr;
        self.flush_userdata = userdata;
    }

    /// Seed a jail's committed cursor from a restored sidecar entry. No-op
    /// if the jail isn't registered. Call between `addJail` and `attach`.
    pub fn seedCursor(self: *JournaldSource, jail_name: []const u8, cursor: []const u8) void {
        for (self.jails.items) |*jj| {
            if (std.mem.eql(u8, jj.jail.slice(), jail_name)) {
                jj.setCursor(cursor);
                return;
            }
        }
    }

    /// Arm the periodic poll timer. Must be called after all `addJail` /
    /// `seedCursor` calls and after the source is in its permanent storage
    /// (the timer callback receives a stable `*JournaldSource`).
    pub fn attach(self: *JournaldSource) Error!void {
        const h = self.event_loop.addTimer(poll_interval_ms, pollTick, self, false) catch
            return error.EventLoopError;
        self.poll_handle = h;
    }

    /// Collect the current (jail, cursor) pairs for jails that have a
    /// cursor, into `buf`. Returns the populated prefix. Used by the
    /// daemon's flush to persist the sidecar AFTER engine state is saved.
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

    // ----- poll tick -----

    fn pollTick(expirations: u64, userdata: ?*anyopaque) void {
        _ = expirations;
        const self: *JournaldSource = @ptrCast(@alignCast(userdata.?));
        for (self.jails.items) |*jj| {
            self.pollJail(jj) catch |err| {
                // Transient failure (spawn error, non-zero exit, decode
                // hiccup) → warn + retry next tick, NEVER crash the daemon.
                std.log.warn(
                    "journald: poll for jail '{s}' failed: {s}; retrying next tick",
                    .{ jj.jail.slice(), @errorName(err) },
                );
            };
        }
        // After processing every jail, flush IF this tick advanced any
        // cursor — bounds crash-replay to ≤1 poll interval. Quiet ticks
        // (no new entries) skip the write entirely.
        self.maybeFlush();
    }

    /// Persist engine state + cursors IFF a poll tick advanced a cursor
    /// since the last flush, then clear the dirty flag. Extracted from
    /// `pollTick` as a testable seam — a recording hook can verify it
    /// fires exactly once on a dirty source and not at all on a clean one,
    /// without spawning journalctl. The hook itself enforces the
    /// load-bearing ordering (engine state FIRST, then cursor sidecar).
    /// Single-threaded loop: the hook never re-enters `pollTick`, so no
    /// recursion.
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
        NonZeroExit,
    };

    /// One reconcile for one jail: spawn journalctl, process the batch,
    /// advance the in-memory cursor. The cursor sidecar is NOT written
    /// here — the daemon flushes it AFTER engine state, so a crash replays
    /// rather than skips (ordering is load-bearing).
    fn pollJail(self: *JournaldSource, jj: *JournalJail) PollError!void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // Build argv: baseline (-n 1) on first run, --after-cursor in
        // steady state.
        const argv = blk: {
            if (jj.cursor_len == 0) {
                break :blk buildBaselineArgv(arena, jj.selectors) catch
                    return error.OutOfMemory;
            }
            var flag = std.ArrayList(u8).init(arena);
            flag.appendSlice("--after-cursor=") catch return error.OutOfMemory;
            flag.appendSlice(jj.cursorSlice()) catch return error.OutOfMemory;
            const owned_flag = flag.toOwnedSlice() catch return error.OutOfMemory;
            break :blk buildPollArgv(arena, jj.selectors, owned_flag) catch
                return error.OutOfMemory;
        };

        const result = std.process.Child.run(.{
            .allocator = arena,
            .argv = argv,
            .max_output_bytes = max_output_bytes,
        }) catch return error.SpawnFailed;

        switch (result.term) {
            .Exited => |code| {
                // journalctl exits non-zero on real errors. An empty
                // result with exit 0 is normal (no new entries). We do not
                // treat a non-zero exit as fatal — warn and bail this tick.
                if (code != 0) {
                    std.log.warn(
                        "journald: journalctl exited {d} for jail '{s}'",
                        .{ code, jj.jail.slice() },
                    );
                    return error.NonZeroExit;
                }
            },
            else => {
                std.log.warn(
                    "journald: journalctl terminated abnormally for jail '{s}'",
                    .{jj.jail.slice()},
                );
                return error.NonZeroExit;
            },
        }

        self.processBatch(jj, result.stdout);
    }

    /// Process a journalctl `-o json` stdout batch for one jail. Each
    /// non-empty line is one JSON object. For each entry we decode the
    /// MESSAGE, feed it to the line callback (which strips any syslog
    /// prefix — a no-op on bare journal messages — and parses it), and
    /// THEN advance the pending cursor from that entry's `__CURSOR`.
    ///
    /// Cursor invariant: advance ONLY after the callback has fully
    /// processed the entry, and ONLY from entries that carried a
    /// `__CURSOR`. An entry without a cursor is still processed but does
    /// not move the cursor forward.
    ///
    /// Bounded by `max_entries_per_tick`: past the cap we stop and resume
    /// next tick. Because the cursor advanced to the last processed entry,
    /// the deferred entries are read again next tick — none are lost.
    fn processBatch(self: *JournaldSource, jj: *JournalJail, stdout: []const u8) void {
        var msg_buf: [max_line_len]u8 = undefined;
        var cursor_buf: [max_cursor_len]u8 = undefined;

        var processed: usize = 0;
        var it = std.mem.splitScalar(u8, stdout, '\n');
        while (it.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0) continue;
            if (processed >= max_entries_per_tick) {
                std.log.warn(
                    "journald: jail '{s}' hit {d}-entry/tick cap; resuming next tick",
                    .{ jj.jail.slice(), max_entries_per_tick },
                );
                break;
            }

            // Per-entry arena for the transient JSON DOM.
            var arena_state = std.heap.ArenaAllocator.init(self.allocator);
            defer arena_state.deinit();

            const entry = decodeEntry(
                arena_state.allocator(),
                line,
                &msg_buf,
                &cursor_buf,
            ) catch |err| {
                // Malformed entry — skip without crashing, do not advance.
                std.log.warn(
                    "journald: skipping malformed entry for jail '{s}': {s}",
                    .{ jj.jail.slice(), @errorName(err) },
                );
                processed += 1;
                continue;
            };

            // Feed the decoded MESSAGE through the SAME callback the file
            // watcher uses. `truncated = false`: we never deliver partial
            // journal messages (a too-long MESSAGE is rejected in decode).
            jj.callback(entry.message, jj.jail, false, jj.userdata);

            // Advance the cursor ONLY after the callback has run, and ONLY
            // from an entry that carried a cursor.
            if (entry.cursor) |cur| {
                jj.setCursor(cur);
                self.dirty = true;
            }
            processed += 1;
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "journald: resolveSource file always picks file" {
    try testing.expectEqual(ResolvedSource.file, resolveSource(.file, &.{}, true));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.file, &.{}, false));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.file, &.{"/var/log/auth.log"}, false));
}

test "journald: resolveSource journald needs journalctl, else fails closed" {
    try testing.expectEqual(ResolvedSource.journald, resolveSource(.journald, &.{}, true));
    try testing.expectEqual(ResolvedSource.fail, resolveSource(.journald, &.{}, false));
}

test "journald: resolveSource auto prefers a usable logpath" {
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, &.{"/var/log/auth.log"}, true));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, &.{"/var/log/auth.log"}, false));
}

test "journald: resolveSource auto falls back to journald, then fails closed" {
    try testing.expectEqual(ResolvedSource.journald, resolveSource(.auto, &.{}, true));
    try testing.expectEqual(ResolvedSource.journald, resolveSource(.auto, &.{""}, true));
    try testing.expectEqual(ResolvedSource.fail, resolveSource(.auto, &.{}, false));
}

test "journald: selectorsForFilter returns the set for sshd, null otherwise" {
    const sshd = selectorsForFilter("sshd");
    try testing.expect(sshd != null);
    try testing.expectEqual(@as(usize, sshd_selectors.len), sshd.?.len);
    // Any non-sshd filter is unsupported in v1 → null (fail closed).
    try testing.expect(selectorsForFilter("nginx-http-auth") == null);
    try testing.expect(selectorsForFilter("apache-auth") == null);
    try testing.expect(selectorsForFilter("") == null);
    // Not a prefix/substring match — must be exact.
    try testing.expect(selectorsForFilter("sshd-ddos") == null);
}

test "journald: addJail fails closed on an unsupported filter and does not register" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin");
    defer src.deinit();

    const jail = try JailId.fromSlice("nginx-http-auth");
    try testing.expectError(
        error.UnsupportedJournaldFilter,
        src.addJail(jail, "nginx-http-auth", CallRecorder.onLine, null),
    );
    // The jail must NOT have been registered.
    try testing.expectEqual(@as(usize, 0), src.jailCount());
    try testing.expect(!src.hasJails());

    // A supported filter still registers fine.
    const sshd = try JailId.fromSlice("sshd");
    try src.addJail(sshd, "sshd", CallRecorder.onLine, null);
    try testing.expectEqual(@as(usize, 1), src.jailCount());
}

test "journald: selector argv ORs across fields with a standalone +" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const argv = try buildPollArgv(arena.allocator(), &sshd_selectors, "--after-cursor=s=abc");
    // Expected token order:
    //   journalctl SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session
    //   + _COMM=sshd _COMM=sshd-session -o json --no-pager -q --after-cursor=...
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
    // The '+' must be its own standalone token.
    try testing.expectEqualStrings("+", argv[3]);
}

test "journald: baseline argv uses -n 1, no --after-cursor" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const argv = try buildBaselineArgv(arena.allocator(), &sshd_selectors);
    // Must contain -n 1 and must NOT contain any --after-cursor token.
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
    // "Hi" + 0xFF (non-UTF8) exported as an integer array.
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

// ----- A fake processBatch harness proving the cursor invariant -----

const CallRecorder = struct {
    lines: std.ArrayList([]const u8),
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
        const dup = self.lines.allocator.dupe(u8, line) catch return;
        self.lines.append(dup) catch self.lines.allocator.free(dup);
    }
};

test "journald: processBatch feeds callback then advances cursor only from entries with __CURSOR" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    // We don't arm a timer here; we drive processBatch directly.
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin");
    defer src.deinit();

    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();

    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    // Two entries: the first with a cursor, the second WITHOUT. Both
    // messages must reach the callback; the committed cursor must be the
    // first entry's (the second carried none, so it cannot advance it).
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
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin");
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

    // Flip a byte in the record region (after the 10-byte header).
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
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin");
    defer src.deinit();

    const sshd = try JailId.fromSlice("sshd");
    const nginx = try JailId.fromSlice("nginx");
    try src.addJail(sshd, "sshd", CallRecorder.onLine, null);
    try src.addJail(nginx, "sshd", CallRecorder.onLine, null);

    // Seed only sshd's cursor.
    src.seedCursor("sshd", "s=seeded");

    var buf: [max_jails]CursorEntry = undefined;
    const got = src.collectCursors(&buf);
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("sshd", got[0].name);
    try testing.expectEqualStrings("s=seeded", got[0].cursor);
}

// ----- Change 2: periodic-flush seam -----

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
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin");
    defer src.deinit();

    var spy = FlushSpy{};
    src.setFlushHook(FlushSpy.hook, &spy);

    // Mark dirty (as a successful batch with an advanced cursor would).
    src.dirty = true;
    src.maybeFlush();
    try testing.expectEqual(@as(u32, 1), spy.calls);
    try testing.expect(!src.dirty);

    // A second call with no new dirtiness must NOT fire the hook again.
    src.maybeFlush();
    try testing.expectEqual(@as(u32, 1), spy.calls);
}

test "journald: maybeFlush does nothing on a clean source" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin");
    defer src.deinit();

    var spy = FlushSpy{};
    src.setFlushHook(FlushSpy.hook, &spy);

    // Never marked dirty — a quiet tick must not write anything.
    src.maybeFlush();
    try testing.expectEqual(@as(u32, 0), spy.calls);
    try testing.expect(!src.dirty);
}

test "journald: processBatch marks dirty so maybeFlush will fire" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin");
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
