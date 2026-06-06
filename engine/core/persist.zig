// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Binary on-disk state for the fail2zig daemon.
//!
//! File layout (little-endian, packed):
//!
//!     Header (14 bytes):
//!       magic       [4]u8  = 'F','2','Z','S'
//!       version     u16    = 3  (legacy v1/v2 still loadable)
//!       entry_count u32
//!       checksum    u32    = CRC32 over the entries region AND, in v3+,
//!                            the trailing per-jail lifetime block
//!
//!     Entry (113 bytes each):
//!       ip_type      u8     (4 or 6)
//!       ip_bytes     [16]u8 (IPv4 stored in first 4 bytes, rest zero)
//!       jail         [64]u8 (null-padded to 64)
//!       attempt_count u32
//!       ban_count     u32
//!       first_attempt i64
//!       last_attempt  i64
//!       ban_expiry    i64   (0 = not banned)
//!
//!     Per-jail lifetime block (v3+ only, immediately after the entries):
//!       jail_count   u32
//!       JailLifetime (72 bytes each), jail_count of them:
//!         jail          [64]u8 (null-padded)
//!         lifetime_bans u64    (monotonic lifetime ban count, BUG-006)
//!
//! Wire format of the entries is identical across v1/v2/v3. v2 (ISSUE-007)
//! signalled per-jail routing on load; v3 (BUG-006) appends the per-jail
//! lifetime block so `Total bans` survives restarts. v1/v2 files are still
//! accepted: they carry no lifetime block, so each jail's lifetime is
//! SEEDED from its restored active-ban count (a floor keeping
//! Total ≥ Active immediately), and the next checkpoint rewrites at v3.
//!
//! Save semantics: write to `<path>.tmp`, fsync, fchmod 0600, rename onto
//! `path`. Either the previous state remains intact OR the new state is
//! durable — no torn write.
//!
//! Load semantics: validate magic + version (1..3); recompute CRC32 over
//! the entries (+ v3 lifetime block). On any integrity failure log a
//! warning and return empty so the daemon starts fresh — the priority is
//! staying up, not preserving a corrupt history.
//!
//! Security: file mode 0600. CRC32 is NOT a cryptographic integrity check
//! — the state file lives in a root-owned directory. The checksum guards
//! against crash-induced truncation, not adversarial tampering.

const std = @import("std");
const posix = std.posix;
const shared = @import("shared");

const state_mod = @import("state.zig");
const tracker_map_mod = @import("tracker_map.zig");

const IpAddress = shared.IpAddress;
const JailId = shared.JailId;
const Timestamp = shared.Timestamp;
const BanState = shared.BanState;
const StateTracker = state_mod.StateTracker;
const IpState = state_mod.IpState;
const TrackerMap = tracker_map_mod.TrackerMap;

// ============================================================================
// On-disk constants
// ============================================================================

pub const magic: [4]u8 = .{ 'F', '2', 'Z', 'S' };
/// Current on-disk version. Saves always write this value.
pub const version: u16 = 3;
/// First version carrying the per-jail lifetime block (BUG-006). Files
/// below this have no block — lifetimes are seeded from active bans.
pub const lifetime_block_version: u16 = 3;
/// Last version we know how to ingest. Anything outside `[1, version]`
/// is treated as unknown and the daemon starts fresh.
pub const min_supported_version: u16 = 1;
pub const header_size: usize = 4 + 2 + 4 + 4; // 14 bytes
pub const entry_size: usize = 1 + 16 + 64 + 4 + 4 + 8 + 8 + 8; // 113 bytes
pub const jail_name_field: usize = 64;
/// One per-jail lifetime record: jail name (64) + lifetime_bans u64 (8).
pub const lifetime_record_size: usize = jail_name_field + 8; // 72 bytes

pub const Error = error{
    OutOfMemory,
    WriteFailed,
    ReadFailed,
    OpenFailed,
    FsyncFailed,
    RenameFailed,
    ChmodFailed,
    PathTooLong,
};

// ============================================================================
// Restored entry — what `load` returns to the daemon before it reseeds
// the live `StateTracker`. Matches the wire layout semantically.
// ============================================================================

pub const StateEntry = struct {
    ip: IpAddress,
    jail: JailId,
    attempt_count: u32,
    ban_count: u32,
    first_attempt: Timestamp,
    last_attempt: Timestamp,
    ban_expiry: ?Timestamp,

    pub fn isBanned(self: StateEntry) bool {
        return self.ban_expiry != null;
    }
};

/// One persisted per-jail lifetime ban count (BUG-006, v3+).
pub const JailLifetime = struct {
    jail: JailId,
    lifetime_bans: u64,
};

/// Full load result: restored IP entries + per-jail lifetime ban counts.
/// `lifetimes` is empty for v1/v2 files (no block) — the caller then seeds
/// each jail's lifetime from its restored active-ban count. Both slices are
/// allocated with the caller's allocator; free both via `deinit`.
pub const Loaded = struct {
    entries: []StateEntry,
    lifetimes: []JailLifetime,

    pub fn deinit(self: Loaded, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        allocator.free(self.lifetimes);
    }
};

// ============================================================================
// Save
// ============================================================================

/// Atomically persist the tracker's state to `path`.
///
/// Writes to `path ++ ".tmp"`, fsyncs, chmods 0600, then renames onto
/// `path`. The rename on Linux is atomic on a single filesystem — either
/// the old file remains or the new file replaces it.
pub fn save(tracker: *const StateTracker, path: []const u8) Error!void {
    const max_path: usize = 4096;
    if (path.len == 0 or path.len + 4 > max_path) return error.PathTooLong;
    var tmp_buf: [max_path]u8 = undefined;
    @memcpy(tmp_buf[0..path.len], path);
    const tmp_suffix = ".tmp";
    @memcpy(tmp_buf[path.len .. path.len + tmp_suffix.len], tmp_suffix);
    const tmp_path = tmp_buf[0 .. path.len + tmp_suffix.len];

    // Create temp file with 0600. Use openat(AT_FDCWD) via std.fs.
    var file = std.fs.cwd().createFile(tmp_path, .{
        .mode = 0o600,
        .truncate = true,
    }) catch return error.OpenFailed;
    var close_handled = false;
    defer if (!close_handled) file.close();

    const writer = file.writer();

    // Count entries first so the header is accurate.
    const entry_count = countPersistable(tracker);

    // Write header placeholder; we'll rewrite it after CRC is known.
    writer.writeAll(&magic) catch return error.WriteFailed;
    writer.writeInt(u16, version, .little) catch return error.WriteFailed;
    writer.writeInt(u32, entry_count, .little) catch return error.WriteFailed;
    writer.writeInt(u32, 0, .little) catch return error.WriteFailed;

    // Stream entries, accumulating CRC32 as we go.
    var crc = std.hash.Crc32.init();
    var entry_buf: [entry_size]u8 = undefined;
    var it = tracker.iterator();
    var written: u32 = 0;
    while (it.next()) |kv| {
        const ip = kv.key_ptr.*;
        const st = kv.value_ptr;
        encodeEntry(&entry_buf, ip, st);
        writer.writeAll(&entry_buf) catch return error.WriteFailed;
        crc.update(&entry_buf);
        written += 1;
    }
    if (written != entry_count) {
        // The iterator must always match our upfront count. If it does
        // not, something mutated the map mid-save — bail.
        return error.WriteFailed;
    }

    // v3 lifetime block (BUG-006). A single tracker represents one jail;
    // key the record by the jail name on its first entry. With no entries
    // there is no jail name to attach a lifetime to → empty block.
    var lifetime_rec: [lifetime_record_size]u8 = undefined;
    if (firstJailName(tracker)) |jail_name| {
        writer.writeInt(u32, 1, .little) catch return error.WriteFailed;
        encodeLifetime(&lifetime_rec, jail_name, tracker.lifetime_bans);
        writer.writeAll(&lifetime_rec) catch return error.WriteFailed;
        crc.update(std.mem.asBytes(&@as(u32, 1)));
        crc.update(&lifetime_rec);
    } else {
        writer.writeInt(u32, 0, .little) catch return error.WriteFailed;
        crc.update(std.mem.asBytes(&@as(u32, 0)));
    }

    // Patch checksum into the header.
    const final_crc = crc.final();
    file.seekTo(header_size - 4) catch return error.WriteFailed;
    writer.writeInt(u32, final_crc, .little) catch return error.WriteFailed;

    // Durability: fsync before the rename so a crash between rename and
    // flush cannot leave us pointing at an unflushed file.
    posix.fsync(file.handle) catch return error.FsyncFailed;

    // Explicitly set permissions (createFile already did, but the mode
    // argument on Linux is advisory in some environments — be explicit).
    posix.fchmod(file.handle, 0o600) catch return error.ChmodFailed;

    file.close();
    close_handled = true;

    std.fs.cwd().rename(tmp_path, path) catch return error.RenameFailed;
}

/// The jail name on this tracker's first entry, or null when empty. A
/// single `StateTracker` holds one jail's IPs, so the first entry's jail
/// names the whole tracker (used to key its lifetime record in `save`).
fn firstJailName(tracker: *const StateTracker) ?[]const u8 {
    var it = tracker.iterator();
    if (it.next()) |kv| return kv.value_ptr.jail.slice();
    return null;
}

/// Encode one per-jail lifetime record: 64-byte null-padded jail name +
/// u64 lifetime ban count (little-endian).
fn encodeLifetime(buf: *[lifetime_record_size]u8, jail_name: []const u8, lifetime_bans: u64) void {
    @memset(buf[0..jail_name_field], 0);
    const n = @min(jail_name.len, jail_name_field);
    @memcpy(buf[0..n], jail_name[0..n]);
    std.mem.writeInt(u64, buf[jail_name_field .. jail_name_field + 8][0..8], lifetime_bans, .little);
}

fn countPersistable(tracker: *const StateTracker) u32 {
    var n: u32 = 0;
    var it = tracker.iterator();
    while (it.next()) |_| : (n += 1) {}
    return n;
}

fn encodeEntry(buf: *[entry_size]u8, ip: IpAddress, st: *const IpState) void {
    // Explicit field-by-field serialization keeps the on-disk format
    // independent of Zig struct layout / padding.
    var off: usize = 0;
    switch (ip) {
        .ipv4 => |v| {
            buf[off] = 4;
            off += 1;
            std.mem.writeInt(u32, buf[off .. off + 4][0..4], v, .big);
            @memset(buf[off + 4 .. off + 16], 0);
            off += 16;
        },
        .ipv6 => |v| {
            buf[off] = 6;
            off += 1;
            std.mem.writeInt(u128, buf[off .. off + 16][0..16], v, .big);
            off += 16;
        },
    }

    // Jail: null-padded, 64 bytes.
    @memset(buf[off .. off + 64], 0);
    const jail_slice = st.jail.slice();
    @memcpy(buf[off .. off + jail_slice.len], jail_slice);
    off += 64;

    std.mem.writeInt(u32, buf[off .. off + 4][0..4], st.attempt_count, .little);
    off += 4;
    std.mem.writeInt(u32, buf[off .. off + 4][0..4], st.ban_count, .little);
    off += 4;
    std.mem.writeInt(i64, buf[off .. off + 8][0..8], st.first_attempt, .little);
    off += 8;
    std.mem.writeInt(i64, buf[off .. off + 8][0..8], st.last_attempt, .little);
    off += 8;
    const expiry: i64 = st.ban_expiry orelse 0;
    std.mem.writeInt(i64, buf[off .. off + 8][0..8], expiry, .little);
    off += 8;

    std.debug.assert(off == entry_size);
}

// ============================================================================
// Load
// ============================================================================

/// Load persisted IP entries. Thin wrapper over `loadFull` that discards
/// the per-jail lifetime block — kept for call sites that only need
/// entries (legacy seed paths, most tests). Caller owns the returned slice.
pub fn load(allocator: std.mem.Allocator, path: []const u8) Error![]StateEntry {
    const loaded = try loadFull(allocator, path);
    allocator.free(loaded.lifetimes);
    return loaded.entries;
}

/// Load persisted state: IP entries + per-jail lifetime ban counts
/// (BUG-006). Missing file returns empty without warning. Corrupt /
/// truncated / checksum-mismatched file logs a warning and returns empty —
/// the daemon continues without history. For v1/v2 files (no lifetime
/// block) `lifetimes` is empty and the caller seeds from active bans.
pub fn loadFull(allocator: std.mem.Allocator, path: []const u8) Error!Loaded {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return emptyLoaded(allocator),
        error.AccessDenied => return error.OpenFailed,
        else => return error.OpenFailed,
    };
    defer file.close();

    // Read whole file — bounded by `max_state_bytes`. Even a million
    // entries at 113 bytes = 108MB, well past any sane budget; reject
    // outright to keep memory predictable.
    const max_state_bytes: usize = 32 * 1024 * 1024;
    const bytes = file.readToEndAlloc(allocator, max_state_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ReadFailed,
    };
    defer allocator.free(bytes);

    if (bytes.len < header_size) {
        std.log.warn("persist: state file too short ({d} bytes); starting fresh", .{bytes.len});
        return emptyLoaded(allocator);
    }
    if (!std.mem.eql(u8, bytes[0..4], &magic)) {
        std.log.warn("persist: state file magic mismatch; starting fresh", .{});
        return emptyLoaded(allocator);
    }
    const ver = std.mem.readInt(u16, bytes[4..6], .little);
    if (ver < min_supported_version or ver > version) {
        std.log.warn("persist: state file version {d} (supported: {d}..{d}); starting fresh", .{ ver, min_supported_version, version });
        return emptyLoaded(allocator);
    }
    if (ver < version) {
        // v1/v2 migration shim. Entries carry the `jail` field so per-jail
        // routing on load is a daemon-side decision; v1/v2 carry no
        // lifetime block (seeded from active bans by the caller). The next
        // checkpoint rewrites the header at the current version.
        std.log.info(
            "persist: migrating state file v{d} -> v{d}; next save will rewrite header",
            .{ ver, version },
        );
    }
    const count = std.mem.readInt(u32, bytes[6..10], .little);
    const stored_crc = std.mem.readInt(u32, bytes[10..14], .little);

    const entries_bytes_len = @as(usize, count) * entry_size;
    const entries_end = header_size + entries_bytes_len;
    if (bytes.len < entries_end) {
        std.log.warn(
            "persist: state file truncated in entries (have {d}, need >= {d}); starting fresh",
            .{ bytes.len, entries_end },
        );
        return emptyLoaded(allocator);
    }

    // v3+ carries a trailing per-jail lifetime block; v1/v2 must end
    // exactly at the entries (SEC-006 strict — trailing junk is rejected).
    var lifetime_count: u32 = 0;
    var crc_region_end = entries_end;
    if (ver >= lifetime_block_version) {
        if (bytes.len < entries_end + 4) {
            std.log.warn("persist: state file missing lifetime block header; starting fresh", .{});
            return emptyLoaded(allocator);
        }
        lifetime_count = std.mem.readInt(u32, bytes[entries_end .. entries_end + 4][0..4], .little);
        crc_region_end = entries_end + 4 + @as(usize, lifetime_count) * lifetime_record_size;
    }

    // SEC-006: fail closed on ANY size mismatch — the save path writes
    // exactly `crc_region_end` bytes and nothing more. Trailing bytes can
    // only come from corruption / tampering; accepting them masks it.
    if (bytes.len != crc_region_end) {
        std.log.warn(
            "persist: state file size mismatch (have {d}, expected {d}); starting fresh",
            .{ bytes.len, crc_region_end },
        );
        return emptyLoaded(allocator);
    }

    // CRC covers the entries AND (v3+) the lifetime block — one integrity
    // check over everything after the header.
    const crc_region = bytes[header_size..crc_region_end];
    const actual_crc = std.hash.Crc32.hash(crc_region);
    if (actual_crc != stored_crc) {
        std.log.warn("persist: state file checksum mismatch (got {x}, want {x}); starting fresh", .{ actual_crc, stored_crc });
        return emptyLoaded(allocator);
    }

    const entries_bytes = bytes[header_size..entries_end];
    var out = allocator.alloc(StateEntry, count) catch return error.OutOfMemory;
    errdefer allocator.free(out);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const off = i * entry_size;
        out[i] = decodeEntry(entries_bytes[off .. off + entry_size][0..entry_size].*) orelse {
            // Corrupt entry (invalid ip_type). Log and return empty —
            // partial load is riskier than starting fresh.
            std.log.warn("persist: invalid entry at index {d}; starting fresh", .{i});
            allocator.free(out);
            return emptyLoaded(allocator);
        };
    }

    // Decode the lifetime block (v3+ only; empty for v1/v2). The block
    // bytes start at `entries_end + 4` (past the u32 count) and only exist
    // when `lifetime_count > 0`, so guard the slice for the v1/v2 path.
    var lifetimes = allocator.alloc(JailLifetime, lifetime_count) catch {
        allocator.free(out);
        return error.OutOfMemory;
    };
    errdefer allocator.free(lifetimes);
    if (lifetime_count > 0) {
        const block = bytes[entries_end + 4 .. crc_region_end];
        var j: usize = 0;
        while (j < lifetime_count) : (j += 1) {
            const off = j * lifetime_record_size;
            lifetimes[j] = decodeLifetime(block[off .. off + lifetime_record_size][0..lifetime_record_size].*) orelse {
                std.log.warn("persist: invalid lifetime record at index {d}; starting fresh", .{j});
                allocator.free(out);
                allocator.free(lifetimes);
                return emptyLoaded(allocator);
            };
        }
    }

    return .{ .entries = out, .lifetimes = lifetimes };
}

/// Allocate an empty `Loaded` (two zero-length slices) for the fresh-start
/// / corruption-recovery paths.
fn emptyLoaded(allocator: std.mem.Allocator) Error!Loaded {
    const e = allocator.alloc(StateEntry, 0) catch return error.OutOfMemory;
    errdefer allocator.free(e);
    const l = allocator.alloc(JailLifetime, 0) catch return error.OutOfMemory;
    return .{ .entries = e, .lifetimes = l };
}

fn decodeLifetime(buf: [lifetime_record_size]u8) ?JailLifetime {
    var jail_len: usize = 0;
    while (jail_len < jail_name_field and buf[jail_len] != 0) : (jail_len += 1) {}
    const jail = JailId.fromSlice(buf[0..jail_len]) catch return null;
    const lifetime_bans = std.mem.readInt(u64, buf[jail_name_field .. jail_name_field + 8][0..8], .little);
    return .{ .jail = jail, .lifetime_bans = lifetime_bans };
}

fn decodeEntry(buf: [entry_size]u8) ?StateEntry {
    var off: usize = 0;
    const ip_type = buf[off];
    off += 1;
    const ip: IpAddress = switch (ip_type) {
        4 => blk: {
            const v = std.mem.readInt(u32, buf[off .. off + 4][0..4], .big);
            break :blk .{ .ipv4 = v };
        },
        6 => blk: {
            const v = std.mem.readInt(u128, buf[off .. off + 16][0..16], .big);
            break :blk .{ .ipv6 = v };
        },
        else => return null,
    };
    off += 16;

    // Jail: read up to the first NUL, cap at 64.
    const jail_bytes = buf[off .. off + 64];
    var jail_len: usize = 0;
    while (jail_len < 64 and jail_bytes[jail_len] != 0) : (jail_len += 1) {}
    const jail = JailId.fromSlice(jail_bytes[0..jail_len]) catch return null;
    off += 64;

    const attempt_count = std.mem.readInt(u32, buf[off .. off + 4][0..4], .little);
    off += 4;
    const ban_count = std.mem.readInt(u32, buf[off .. off + 4][0..4], .little);
    off += 4;
    const first_attempt = std.mem.readInt(i64, buf[off .. off + 8][0..8], .little);
    off += 8;
    const last_attempt = std.mem.readInt(i64, buf[off .. off + 8][0..8], .little);
    off += 8;
    const expiry_raw = std.mem.readInt(i64, buf[off .. off + 8][0..8], .little);
    off += 8;
    std.debug.assert(off == entry_size);

    return StateEntry{
        .ip = ip,
        .jail = jail,
        .attempt_count = attempt_count,
        .ban_count = ban_count,
        .first_attempt = first_attempt,
        .last_attempt = last_attempt,
        .ban_expiry = if (expiry_raw == 0) null else expiry_raw,
    };
}

// ============================================================================
// Seeding a live tracker from loaded entries
// ============================================================================

/// Inject loaded entries into an initialized `StateTracker`. The tracker's
/// map is populated directly (bypasses findtime/threshold logic) so that
/// the restored bans remain active and the ban expiry timer picks them
/// up on the next tick.
pub fn seed(tracker: *StateTracker, entries: []const StateEntry) Error!void {
    for (entries) |e| {
        var st: IpState = .{
            .jail = e.jail,
            .attempt_count = e.attempt_count,
            .ban_count = e.ban_count,
            .first_attempt = e.first_attempt,
            .last_attempt = e.last_attempt,
            .ban_state = if (e.ban_expiry != null) .banned else .monitoring,
            .ban_expiry = e.ban_expiry,
            .ring = [_]Timestamp{0} ** state_mod.max_attempts_per_ip,
            .ring_len = 0,
        };
        _ = &st;
        tracker.map.put(e.ip, st) catch return error.OutOfMemory;
    }
}

// ============================================================================
// Multi-tracker save / seed (ISSUE-007)
// ============================================================================

/// Persist every tracker in `map` to a single file. Entries from all
/// trackers are concatenated into the existing flat layout — the
/// `jail` field on each entry preserves the routing information
/// needed at load time.
pub fn saveAll(map: *const TrackerMap, path: []const u8) Error!void {
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

    const writer = file.writer();

    // Count total entries upfront so the header is accurate.
    var entry_count: u32 = 0;
    {
        var it = map.iterator();
        while (it.next()) |kv| {
            entry_count += countPersistable(kv.value_ptr.*);
        }
    }

    writer.writeAll(&magic) catch return error.WriteFailed;
    writer.writeInt(u16, version, .little) catch return error.WriteFailed;
    writer.writeInt(u32, entry_count, .little) catch return error.WriteFailed;
    writer.writeInt(u32, 0, .little) catch return error.WriteFailed;

    var crc = std.hash.Crc32.init();
    var entry_buf: [entry_size]u8 = undefined;
    var written: u32 = 0;
    {
        var it = map.iterator();
        while (it.next()) |kv| {
            var inner = kv.value_ptr.*.iterator();
            while (inner.next()) |kv2| {
                const ip = kv2.key_ptr.*;
                const st = kv2.value_ptr;
                encodeEntry(&entry_buf, ip, st);
                writer.writeAll(&entry_buf) catch return error.WriteFailed;
                crc.update(&entry_buf);
                written += 1;
            }
        }
    }
    if (written != entry_count) return error.WriteFailed;

    // v3 lifetime block (BUG-006): one record per tracker keyed by its map
    // name, carrying the monotonic lifetime ban count. Persist EVERY jail
    // (even `lifetime_bans == 0`) so the count survives across a window
    // where all bans have expired — lifetime must not silently drop to 0.
    {
        var jail_count: u32 = 0;
        var it = map.iterator();
        while (it.next()) |_| jail_count += 1;
        writer.writeInt(u32, jail_count, .little) catch return error.WriteFailed;
        crc.update(std.mem.asBytes(&jail_count));

        var lifetime_rec: [lifetime_record_size]u8 = undefined;
        var it2 = map.iterator();
        while (it2.next()) |kv| {
            encodeLifetime(&lifetime_rec, kv.key_ptr.*, kv.value_ptr.*.lifetime_bans);
            writer.writeAll(&lifetime_rec) catch return error.WriteFailed;
            crc.update(&lifetime_rec);
        }
    }

    const final_crc = crc.final();
    file.seekTo(header_size - 4) catch return error.WriteFailed;
    writer.writeInt(u32, final_crc, .little) catch return error.WriteFailed;

    posix.fsync(file.handle) catch return error.FsyncFailed;
    posix.fchmod(file.handle, 0o600) catch return error.ChmodFailed;

    file.close();
    close_handled = true;

    std.fs.cwd().rename(tmp_path, path) catch return error.RenameFailed;
}

/// Route loaded `entries` into the matching per-jail tracker. Entries
/// whose `jail` field doesn't match any known tracker land in the
/// synthetic legacy tracker — the caller must have populated it via
/// `TrackerMap.ensureLegacy` before invoking this helper.
///
/// Counters returned by reference: `routed` increments per successful
/// placement, `legacy` increments for orphan entries that fell back to
/// the legacy bucket. Either may be null if the caller doesn't care.
pub fn seedMap(
    map: *TrackerMap,
    entries: []const StateEntry,
    routed: ?*u32,
    legacy: ?*u32,
) Error!void {
    for (entries) |e| {
        const jail_name = e.jail.slice();
        const target = map.get(jail_name) orelse blk: {
            if (legacy) |c| c.* += 1;
            break :blk map.get(tracker_map_mod.legacy_jail_name) orelse
                return error.OutOfMemory;
        };

        const st: IpState = .{
            .jail = e.jail,
            .attempt_count = e.attempt_count,
            .ban_count = e.ban_count,
            .first_attempt = e.first_attempt,
            .last_attempt = e.last_attempt,
            .ban_state = if (e.ban_expiry != null) .banned else .monitoring,
            .ban_expiry = e.ban_expiry,
            .ring = [_]Timestamp{0} ** state_mod.max_attempts_per_ip,
            .ring_len = 0,
        };
        target.map.put(e.ip, st) catch return error.OutOfMemory;
        if (routed) |c| c.* += 1;
    }
}

/// Seed each tracker's monotonic lifetime ban counter from the loaded
/// state (BUG-006). For a v3 file, `lifetimes` carries one record per jail;
/// set each matching tracker's `lifetime_bans`. For a v1/v2 file
/// (`lifetimes` empty), seed each tracker's lifetime from its CURRENT
/// active-ban count — a sane floor so `Total bans ≥ Active bans` holds
/// immediately after an upgrade, without inventing history. Call AFTER
/// `seedMap` so the active-ban floor reflects restored bans.
pub fn seedLifetimes(map: *TrackerMap, lifetimes: []const JailLifetime) void {
    if (lifetimes.len > 0) {
        for (lifetimes) |l| {
            if (map.get(l.jail.slice())) |t| t.seedLifetimeBans(l.lifetime_bans);
        }
        return;
    }
    // v1/v2 back-compat: floor each tracker's lifetime at its active bans.
    var it = map.iterator();
    while (it.next()) |kv| {
        const t = kv.value_ptr.*;
        var active: u64 = 0;
        var inner = t.iterator();
        while (inner.next()) |e| {
            if (e.value_ptr.ban_state == .banned) active += 1;
        }
        t.seedLifetimeBans(active);
    }
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn tIp(comptime s: []const u8) IpAddress {
    return IpAddress.parse(s) catch unreachable;
}
fn tJail(comptime s: []const u8) JailId {
    return JailId.fromSlice(s) catch unreachable;
}

test "persist: header constants" {
    try testing.expectEqual(@as(usize, 14), header_size);
    try testing.expectEqual(@as(usize, 113), entry_size);
}

test "persist: save empty tracker, load returns empty slice" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    var tracker = try StateTracker.init(testing.allocator, .{});
    defer tracker.deinit();

    try save(&tracker, path);
    const entries = try load(testing.allocator, path);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "persist: roundtrip with ipv4 ban + ipv6 monitoring" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 2,
        .findtime = 600,
        .bantime = 300,
    });
    defer tracker.deinit();

    // IPv4: push past threshold so it is banned.
    const jail = tJail("sshd");
    _ = try tracker.recordAttempt(tIp("1.2.3.4"), jail, 1_000);
    _ = try tracker.recordAttempt(tIp("1.2.3.4"), jail, 1_100);
    // IPv6 entry below threshold: monitoring only.
    _ = try tracker.recordAttempt(tIp("2001:db8::1"), jail, 2_000);

    try save(&tracker, path);

    const entries = try load(testing.allocator, path);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 2), entries.len);

    // Find each by IP.
    var v4_idx: ?usize = null;
    var v6_idx: ?usize = null;
    for (entries, 0..) |e, idx| {
        switch (e.ip) {
            .ipv4 => v4_idx = idx,
            .ipv6 => v6_idx = idx,
        }
    }
    try testing.expect(v4_idx != null);
    try testing.expect(v6_idx != null);
    const v4 = entries[v4_idx.?];
    const v6 = entries[v6_idx.?];
    try testing.expect(v4.isBanned());
    try testing.expectEqual(@as(u32, 1), v4.ban_count);
    try testing.expect(!v6.isBanned());
    try testing.expectEqual(@as(u32, 0), v6.ban_count);
    try testing.expectEqualStrings("sshd", v4.jail.slice());
}

test "persist: load missing file returns empty without error" {
    const entries = try load(testing.allocator, "/definitely/not/here/state.bin");
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "persist: corrupted checksum triggers graceful recovery" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 2,
        .findtime = 600,
    });
    defer tracker.deinit();
    const jail = tJail("sshd");
    _ = try tracker.recordAttempt(tIp("9.9.9.9"), jail, 1_000);
    _ = try tracker.recordAttempt(tIp("9.9.9.9"), jail, 1_100);
    try save(&tracker, path);

    // Flip one byte in the entry region (past the header).
    {
        const f = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
        defer f.close();
        try f.seekTo(header_size + 5);
        var one: [1]u8 = .{0xFF};
        _ = try f.writeAll(&one);
    }

    const entries = try load(testing.allocator, path);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "persist: trailing bytes past declared entries rejected (SEC-006)" {
    // SEC-006: silently accepting extra bytes masks corruption / tamper.
    // Write a valid state file, append one junk byte, confirm load
    // returns 0 entries (fail-closed) rather than the original set.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 2,
        .findtime = 600,
    });
    defer tracker.deinit();
    const jail = tJail("sshd");
    _ = try tracker.recordAttempt(tIp("1.2.3.4"), jail, 1_000);
    _ = try tracker.recordAttempt(tIp("1.2.3.4"), jail, 1_100);
    try save(&tracker, path);

    // Append one junk byte — valid file + trailing garbage.
    {
        const f = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
        defer f.close();
        try f.seekFromEnd(0);
        var junk: [1]u8 = .{0xFE};
        _ = try f.writeAll(&junk);
    }

    const entries = try load(testing.allocator, path);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "persist: bad magic returns empty" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    // Write obvious garbage.
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("NOTZ" ++ [_]u8{0} ** 20);
    }

    const entries = try load(testing.allocator, path);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "persist: seed re-populates a tracker from loaded entries" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    // Populate + save.
    {
        var tr = try StateTracker.init(testing.allocator, .{
            .maxretry = 2,
            .findtime = 600,
            .bantime = 300,
        });
        defer tr.deinit();
        const jail = tJail("sshd");
        _ = try tr.recordAttempt(tIp("5.6.7.8"), jail, 1_000);
        _ = try tr.recordAttempt(tIp("5.6.7.8"), jail, 1_100);
        try save(&tr, path);
    }

    const entries = try load(testing.allocator, path);
    defer testing.allocator.free(entries);

    // Fresh tracker, seed from entries.
    var tr2 = try StateTracker.init(testing.allocator, .{});
    defer tr2.deinit();
    try seed(&tr2, entries);
    const restored = tr2.get(tIp("5.6.7.8")).?;
    try testing.expectEqual(BanState.banned, restored.ban_state);
    try testing.expectEqual(@as(u32, 1), restored.ban_count);
    try testing.expectEqualStrings("sshd", restored.jail.slice());
}

// ---------- ISSUE-007: multi-tracker save / seed / migration ----------

test "persist: saveAll roundtrips multiple per-jail trackers via seedMap" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    // Populate two trackers with distinct jail names + entries.
    {
        var tm = TrackerMap.init(testing.allocator);
        defer tm.deinit();

        const sshd = try tm.addTracker("sshd", .{
            .max_entries = 16,
            .maxretry = 2,
            .findtime = 600,
            .bantime = 300,
        });
        const nginx = try tm.addTracker("nginx", .{
            .max_entries = 16,
            .maxretry = 5,
            .findtime = 600,
            .bantime = 300,
        });

        const j_sshd = try JailId.fromSlice("sshd");
        const j_nginx = try JailId.fromSlice("nginx");

        // Ban in sshd.
        _ = try sshd.recordAttempt(tIp("1.2.3.4"), j_sshd, 1_000);
        _ = try sshd.recordAttempt(tIp("1.2.3.4"), j_sshd, 1_100);
        // Monitoring in nginx.
        _ = try nginx.recordAttempt(tIp("5.6.7.8"), j_nginx, 2_000);

        try saveAll(&tm, path);
    }

    // Load back via flat `load`, route via `seedMap` into a fresh map.
    const entries = try load(testing.allocator, path);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 2), entries.len);

    var tm2 = TrackerMap.init(testing.allocator);
    defer tm2.deinit();
    _ = try tm2.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm2.addTracker("nginx", .{ .max_entries = 16 });
    _ = try tm2.ensureLegacy(.{ .max_entries = 16 });

    var routed: u32 = 0;
    var legacy: u32 = 0;
    try seedMap(&tm2, entries, &routed, &legacy);
    try testing.expectEqual(@as(u32, 2), routed);
    try testing.expectEqual(@as(u32, 0), legacy);

    // Routed correctly: sshd has the banned IP, nginx the monitoring one.
    const sshd2 = tm2.get("sshd").?;
    const nginx2 = tm2.get("nginx").?;
    const sshd_entry = sshd2.get(tIp("1.2.3.4")).?;
    try testing.expectEqual(BanState.banned, sshd_entry.ban_state);
    const nginx_entry = nginx2.get(tIp("5.6.7.8")).?;
    try testing.expectEqual(BanState.monitoring, nginx_entry.ban_state);
    // Legacy tracker stayed empty.
    try testing.expectEqual(@as(usize, 0), tm2.get(tracker_map_mod.legacy_jail_name).?.stats().entry_count);
}

test "persist: seedMap routes unknown-jail entries into __legacy__ tracker" {
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();
    _ = try tm.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm.ensureLegacy(.{ .max_entries = 16 });

    // Synthetic entry pretending to come from a jail that's no longer
    // in the config — must funnel to legacy without dropping.
    const entries = [_]StateEntry{
        .{
            .ip = tIp("9.9.9.9"),
            .jail = try JailId.fromSlice("retired-jail"),
            .attempt_count = 2,
            .ban_count = 1,
            .first_attempt = 100,
            .last_attempt = 200,
            .ban_expiry = 999_999,
        },
    };
    var routed: u32 = 0;
    var legacy: u32 = 0;
    try seedMap(&tm, &entries, &routed, &legacy);
    try testing.expectEqual(@as(u32, 1), routed);
    try testing.expectEqual(@as(u32, 1), legacy);

    const leg = tm.get(tracker_map_mod.legacy_jail_name).?;
    const recovered = leg.get(tIp("9.9.9.9")).?;
    try testing.expectEqual(BanState.banned, recovered.ban_state);
    try testing.expectEqual(@as(u32, 1), recovered.ban_count);
}

test "persist: v1 state file is accepted by the migration shim" {
    // ISSUE-007: hand-craft a v1 file (same wire format as v2) and
    // confirm the loader accepts it. Subsequent saveAll writes v2.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    // Build header for one entry, version=1.
    var entry_buf: [entry_size]u8 = undefined;
    {
        const jail = try JailId.fromSlice("sshd");
        const sample: IpState = .{
            .jail = jail,
            .attempt_count = 4,
            .ban_count = 1,
            .first_attempt = 100,
            .last_attempt = 200,
            .ban_state = .banned,
            .ban_expiry = 500_000,
            .ring = [_]Timestamp{0} ** state_mod.max_attempts_per_ip,
            .ring_len = 0,
        };
        encodeEntry(&entry_buf, tIp("203.0.113.7"), &sample);
    }
    const crc_val = std.hash.Crc32.hash(&entry_buf);

    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        try f.writeAll(&magic);
        var v: [2]u8 = undefined;
        std.mem.writeInt(u16, &v, 1, .little);
        try f.writeAll(&v);
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, 1, .little);
        try f.writeAll(&c);
        var crc_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &crc_bytes, crc_val, .little);
        try f.writeAll(&crc_bytes);
        try f.writeAll(&entry_buf);
    }

    // Load -> single entry survives migration intact.
    const entries = try load(testing.allocator, path);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(@as(u32, 1), entries[0].ban_count);
    try testing.expectEqualStrings("sshd", entries[0].jail.slice());
    try testing.expect(entries[0].isBanned());

    // Subsequent saveAll writes the current version header.
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();
    _ = try tm.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm.ensureLegacy(.{ .max_entries = 16 });
    try seedMap(&tm, entries, null, null);
    try saveAll(&tm, path);

    // Header should now say the current `version` constant (v3, BUG-006).
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    var header_buf: [header_size]u8 = undefined;
    _ = try f.readAll(&header_buf);
    const ver = std.mem.readInt(u16, header_buf[4..6], .little);
    try testing.expectEqual(version, ver);
}

test "persist: future-version file is rejected without corrupting daemon start" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        try f.writeAll(&magic);
        var v: [2]u8 = undefined;
        std.mem.writeInt(u16, &v, version + 1, .little);
        try f.writeAll(&v);
        try f.writeAll(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }); // count + crc
    }

    const entries = try load(testing.allocator, path);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "persist: file permissions are 0600 after save" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    var tr = try StateTracker.init(testing.allocator, .{});
    defer tr.deinit();
    try save(&tr, path);

    const st = try std.fs.cwd().statFile(path);
    // Mask off high bits (Linux stat returns more than the perm bits).
    try testing.expectEqual(@as(std.fs.File.Mode, 0o600), st.mode & 0o777);
}

// ---------- BUG-006: persisted lifetime ban counter ----------

test "persist: lifetime ban counts roundtrip across saveAll/loadFull" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    {
        var tm = TrackerMap.init(testing.allocator);
        defer tm.deinit();
        const sshd = try tm.addTracker("sshd", .{ .max_entries = 16, .maxretry = 1, .findtime = 600, .bantime = 300 });
        const nginx = try tm.addTracker("nginx", .{ .max_entries = 16, .maxretry = 1, .findtime = 600, .bantime = 300 });
        // Simulate lifetimes that EXCEED active bans (the whole point —
        // bans issued earlier, some since expired).
        sshd.lifetime_bans = 7;
        nginx.lifetime_bans = 3;
        // One active ban in sshd, none in nginx — proves lifetime persists
        // independent of (and above) the active set.
        _ = try sshd.recordAttempt(tIp("1.2.3.4"), tJail("sshd"), 1_000);
        try saveAll(&tm, path);
    }

    const loaded = try loadFull(testing.allocator, path);
    defer loaded.deinit(testing.allocator);
    // Two jails persisted (even nginx with zero active bans).
    try testing.expectEqual(@as(usize, 2), loaded.lifetimes.len);

    var tm2 = TrackerMap.init(testing.allocator);
    defer tm2.deinit();
    _ = try tm2.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm2.addTracker("nginx", .{ .max_entries = 16 });
    _ = try tm2.ensureLegacy(.{ .max_entries = 16 });
    try seedMap(&tm2, loaded.entries, null, null);
    seedLifetimes(&tm2, loaded.lifetimes);

    try testing.expectEqual(@as(u64, 7), tm2.get("sshd").?.lifetime_bans);
    try testing.expectEqual(@as(u64, 3), tm2.get("nginx").?.lifetime_bans);
    // Lifetime (7) exceeds active (1) — the Total ≥ Active invariant.
    try testing.expect(tm2.get("sshd").?.lifetime_bans > 1);
}

test "persist: v2 back-compat seeds lifetime from active bans (BUG-006)" {
    // A v2 file (no lifetime block) must seed each jail's lifetime at its
    // restored active-ban count — never 0 — so Total ≥ Active immediately.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    // Hand-craft a v2 file with two banned entries in jail "sshd".
    var e1: [entry_size]u8 = undefined;
    var e2: [entry_size]u8 = undefined;
    {
        const banned: IpState = .{
            .jail = tJail("sshd"),
            .attempt_count = 3,
            .ban_count = 1,
            .first_attempt = 100,
            .last_attempt = 200,
            .ban_state = .banned,
            .ban_expiry = 9_999_999,
            .ring = [_]Timestamp{0} ** state_mod.max_attempts_per_ip,
            .ring_len = 0,
        };
        encodeEntry(&e1, tIp("1.2.3.4"), &banned);
        encodeEntry(&e2, tIp("5.6.7.8"), &banned);
    }
    var crc = std.hash.Crc32.init();
    crc.update(&e1);
    crc.update(&e2);
    const crc_val = crc.final();
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        try f.writeAll(&magic);
        var v: [2]u8 = undefined;
        std.mem.writeInt(u16, &v, 2, .little); // v2: no lifetime block
        try f.writeAll(&v);
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, 2, .little); // entry_count = 2
        try f.writeAll(&c);
        var crc_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &crc_bytes, crc_val, .little);
        try f.writeAll(&crc_bytes);
        try f.writeAll(&e1);
        try f.writeAll(&e2);
    }

    const loaded = try loadFull(testing.allocator, path);
    defer loaded.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), loaded.entries.len);
    try testing.expectEqual(@as(usize, 0), loaded.lifetimes.len); // no block

    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();
    _ = try tm.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm.ensureLegacy(.{ .max_entries = 16 });
    try seedMap(&tm, loaded.entries, null, null);
    seedLifetimes(&tm, loaded.lifetimes); // empty block → floor at active

    // Two restored active bans → lifetime floored at 2 (≥ active), not 0.
    try testing.expectEqual(@as(u64, 2), tm.get("sshd").?.lifetime_bans);
}

test "persist: v3 file is accepted (current version supported, BUG-006)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();
    const sshd = try tm.addTracker("sshd", .{ .max_entries = 16, .maxretry = 1, .findtime = 600, .bantime = 300 });
    sshd.lifetime_bans = 5;
    try saveAll(&tm, path);

    // Header must declare the current (v3) version.
    {
        const f = try std.fs.cwd().openFile(path, .{});
        defer f.close();
        var header_buf: [header_size]u8 = undefined;
        _ = try f.readAll(&header_buf);
        try testing.expectEqual(version, std.mem.readInt(u16, header_buf[4..6], .little));
    }

    // And it loads cleanly with the lifetime intact.
    const loaded = try loadFull(testing.allocator, path);
    defer loaded.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), loaded.lifetimes.len);
    try testing.expectEqual(@as(u64, 5), loaded.lifetimes[0].lifetime_bans);
}
