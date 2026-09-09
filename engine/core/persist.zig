// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Header 14B (magic 'F2ZS', u16 version=4, u32 count, u32 crc32) + 114B entries (113B v1-v3 layout + flags) + per-jail lifetime block (v3+); v1-v3 loadable.

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

pub const magic: [4]u8 = .{ 'F', '2', 'Z', 'S' };
pub const version: u16 = 4;
pub const lifetime_block_version: u16 = 3;
pub const flags_version: u16 = 4;
pub const min_supported_version: u16 = 1;
pub const header_size: usize = 4 + 2 + 4 + 4;
pub const entry_size_legacy: usize = 1 + 16 + 64 + 4 + 4 + 8 + 8 + 8;
pub const entry_size: usize = entry_size_legacy + 1;
pub const flag_enforced: u8 = 0x01;
pub const jail_name_field: usize = 64;
pub const lifetime_record_size: usize = jail_name_field + 8;

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

pub const StateEntry = struct {
    ip: IpAddress,
    jail: JailId,
    attempt_count: u32,
    ban_count: u32,
    first_attempt: Timestamp,
    last_attempt: Timestamp,
    ban_expiry: ?Timestamp,
    /// null = pre-v4 file, which never recorded whether the ban reached the firewall; the seeder decides.
    enforced: ?bool = null,

    pub fn isBanned(self: StateEntry) bool {
        return self.ban_expiry != null;
    }
};

/// Decides `enforced` for entries loaded from a pre-v4 file, keyed by jail name.
pub const LegacyEnforcedResolver = struct {
    ctx: ?*anyopaque = null,
    resolve: *const fn (ctx: ?*anyopaque, jail_name: []const u8) bool = assumeEnforced,

    fn assumeEnforced(ctx: ?*anyopaque, jail_name: []const u8) bool {
        _ = ctx;
        _ = jail_name;
        return true;
    }
};

pub const JailLifetime = struct {
    jail: JailId,
    lifetime_bans: u64,
};

pub const Loaded = struct {
    entries: []StateEntry,
    lifetimes: []JailLifetime,

    pub fn deinit(self: Loaded, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        allocator.free(self.lifetimes);
    }
};

pub fn save(tracker: *const StateTracker, path: []const u8) Error!void {
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

    const entry_count = countPersistable(tracker);

    writer.writeAll(&magic) catch return error.WriteFailed;
    writer.writeInt(u16, version, .little) catch return error.WriteFailed;
    writer.writeInt(u32, entry_count, .little) catch return error.WriteFailed;
    writer.writeInt(u32, 0, .little) catch return error.WriteFailed;

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
        return error.WriteFailed;
    }

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

    const final_crc = crc.final();
    file.seekTo(header_size - 4) catch return error.WriteFailed;
    writer.writeInt(u32, final_crc, .little) catch return error.WriteFailed;

    posix.fsync(file.handle) catch return error.FsyncFailed;

    posix.fchmod(file.handle, 0o600) catch return error.ChmodFailed;

    file.close();
    close_handled = true;

    std.fs.cwd().rename(tmp_path, path) catch return error.RenameFailed;
}

fn firstJailName(tracker: *const StateTracker) ?[]const u8 {
    var it = tracker.iterator();
    if (it.next()) |kv| return kv.value_ptr.jail.slice();
    return null;
}

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
    buf[off] = if (st.enforced) flag_enforced else 0;
    off += 1;

    std.debug.assert(off == entry_size);
}

pub fn load(allocator: std.mem.Allocator, path: []const u8) Error![]StateEntry {
    const loaded = try loadFull(allocator, path);
    allocator.free(loaded.lifetimes);
    return loaded.entries;
}

pub fn loadFull(allocator: std.mem.Allocator, path: []const u8) Error!Loaded {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return emptyLoaded(allocator),
        error.AccessDenied => return error.OpenFailed,
        else => return error.OpenFailed,
    };
    defer file.close();

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
        std.log.info(
            "persist: migrating state file v{d} -> v{d}; next save will rewrite header",
            .{ ver, version },
        );
    }
    const count = std.mem.readInt(u32, bytes[6..10], .little);
    const stored_crc = std.mem.readInt(u32, bytes[10..14], .little);

    const esize: usize = if (ver >= flags_version) entry_size else entry_size_legacy;
    const entries_bytes_len = @as(usize, count) * esize;
    const entries_end = header_size + entries_bytes_len;
    if (bytes.len < entries_end) {
        std.log.warn(
            "persist: state file truncated in entries (have {d}, need >= {d}); starting fresh",
            .{ bytes.len, entries_end },
        );
        return emptyLoaded(allocator);
    }

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

    if (bytes.len != crc_region_end) {
        std.log.warn(
            "persist: state file size mismatch (have {d}, expected {d}); starting fresh",
            .{ bytes.len, crc_region_end },
        );
        return emptyLoaded(allocator);
    }

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
        const off = i * esize;
        out[i] = decodeEntry(entries_bytes[off .. off + esize]) orelse {
            std.log.warn("persist: invalid entry at index {d}; starting fresh", .{i});
            allocator.free(out);
            return emptyLoaded(allocator);
        };
    }

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

fn decodeEntry(buf: []const u8) ?StateEntry {
    if (buf.len != entry_size and buf.len != entry_size_legacy) return null;
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
    std.debug.assert(off == entry_size_legacy);
    const enforced: ?bool = if (buf.len == entry_size) (buf[off] & flag_enforced) != 0 else null;

    return StateEntry{
        .ip = ip,
        .jail = jail,
        .attempt_count = attempt_count,
        .ban_count = ban_count,
        .first_attempt = first_attempt,
        .last_attempt = last_attempt,
        .ban_expiry = if (expiry_raw == 0) null else expiry_raw,
        .enforced = enforced,
    };
}

pub fn seed(tracker: *StateTracker, entries: []const StateEntry) Error!void {
    if (entries.len == 0) return;
    tracker.ensureReserved() catch return error.OutOfMemory;
    for (entries) |e| {
        var st: IpState = .{
            .jail = e.jail,
            .attempt_count = e.attempt_count,
            .ban_count = e.ban_count,
            .first_attempt = e.first_attempt,
            .last_attempt = e.last_attempt,
            .ban_state = if (e.ban_expiry != null) .banned else .monitoring,
            .ban_expiry = e.ban_expiry,
            .enforced = e.ban_expiry != null and (e.enforced orelse true),
            .ring = [_]Timestamp{0} ** state_mod.max_attempts_per_ip,
            .ring_len = 0,
        };
        _ = &st;
        tracker.map.put(e.ip, st) catch return error.OutOfMemory;
    }
}

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

pub fn seedMap(
    map: *TrackerMap,
    entries: []const StateEntry,
    routed: ?*u32,
    legacy: ?*u32,
) Error!void {
    return seedMapWith(map, entries, routed, legacy, .{});
}

pub fn seedMapWith(
    map: *TrackerMap,
    entries: []const StateEntry,
    routed: ?*u32,
    legacy: ?*u32,
    legacy_enforced: LegacyEnforcedResolver,
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
            .enforced = e.ban_expiry != null and
                (e.enforced orelse legacy_enforced.resolve(legacy_enforced.ctx, jail_name)),
            .ring = [_]Timestamp{0} ** state_mod.max_attempts_per_ip,
            .ring_len = 0,
        };
        target.ensureReserved() catch return error.OutOfMemory;
        target.map.put(e.ip, st) catch return error.OutOfMemory;
        if (routed) |c| c.* += 1;
    }
}

pub fn seedLifetimes(map: *TrackerMap, lifetimes: []const JailLifetime) void {
    if (lifetimes.len > 0) {
        for (lifetimes) |l| {
            if (map.get(l.jail.slice())) |t| t.seedLifetimeBans(l.lifetime_bans);
        }
        return;
    }
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

const testing = std.testing;

fn tIp(comptime s: []const u8) IpAddress {
    return IpAddress.parse(s) catch unreachable;
}
fn tJail(comptime s: []const u8) JailId {
    return JailId.fromSlice(s) catch unreachable;
}

test "persist: header constants" {
    try testing.expectEqual(@as(usize, 14), header_size);
    try testing.expectEqual(@as(usize, 113), entry_size_legacy);
    try testing.expectEqual(@as(usize, 114), entry_size);
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

    const jail = tJail("sshd");
    _ = try tracker.recordAttempt(tIp("1.2.3.4"), jail, 1_000);
    _ = try tracker.recordAttempt(tIp("1.2.3.4"), jail, 1_100);
    _ = try tracker.recordAttempt(tIp("2001:db8::1"), jail, 2_000);

    try save(&tracker, path);

    const entries = try load(testing.allocator, path);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 2), entries.len);

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

    var tr2 = try StateTracker.init(testing.allocator, .{});
    defer tr2.deinit();
    try seed(&tr2, entries);
    const restored = tr2.get(tIp("5.6.7.8")).?;
    try testing.expectEqual(BanState.banned, restored.ban_state);
    try testing.expectEqual(@as(u32, 1), restored.ban_count);
    try testing.expectEqualStrings("sshd", restored.jail.slice());
}

test "persist: saveAll roundtrips multiple per-jail trackers via seedMap" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

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

        _ = try sshd.recordAttempt(tIp("1.2.3.4"), j_sshd, 1_000);
        _ = try sshd.recordAttempt(tIp("1.2.3.4"), j_sshd, 1_100);
        _ = try nginx.recordAttempt(tIp("5.6.7.8"), j_nginx, 2_000);

        try saveAll(&tm, path);
    }

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

    const sshd2 = tm2.get("sshd").?;
    const nginx2 = tm2.get("nginx").?;
    const sshd_entry = sshd2.get(tIp("1.2.3.4")).?;
    try testing.expectEqual(BanState.banned, sshd_entry.ban_state);
    const nginx_entry = nginx2.get(tIp("5.6.7.8")).?;
    try testing.expectEqual(BanState.monitoring, nginx_entry.ban_state);
    try testing.expectEqual(@as(usize, 0), tm2.get(tracker_map_mod.legacy_jail_name).?.stats().entry_count);
}

test "persist: seedMap routes unknown-jail entries into __legacy__ tracker" {
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();
    _ = try tm.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm.ensureLegacy(.{ .max_entries = 16 });

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
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

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
    const legacy_entry = entry_buf[0..entry_size_legacy];
    const crc_val = std.hash.Crc32.hash(legacy_entry);

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
        try f.writeAll(legacy_entry);
    }

    const entries = try load(testing.allocator, path);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(@as(u32, 1), entries[0].ban_count);
    try testing.expectEqualStrings("sshd", entries[0].jail.slice());
    try testing.expect(entries[0].isBanned());
    try testing.expect(entries[0].enforced == null);

    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();
    _ = try tm.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm.ensureLegacy(.{ .max_entries = 16 });
    try seedMap(&tm, entries, null, null);
    try saveAll(&tm, path);

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
        try f.writeAll(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 });
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
    try testing.expectEqual(@as(std.fs.File.Mode, 0o600), st.mode & 0o777);
}

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
        sshd.lifetime_bans = 7;
        nginx.lifetime_bans = 3;
        _ = try sshd.recordAttempt(tIp("1.2.3.4"), tJail("sshd"), 1_000);
        try saveAll(&tm, path);
    }

    const loaded = try loadFull(testing.allocator, path);
    defer loaded.deinit(testing.allocator);
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
    try testing.expect(tm2.get("sshd").?.lifetime_bans > 1);
}

test "persist: v2 back-compat seeds lifetime from active bans (BUG-006)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

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
    crc.update(e1[0..entry_size_legacy]);
    crc.update(e2[0..entry_size_legacy]);
    const crc_val = crc.final();
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        try f.writeAll(&magic);
        var v: [2]u8 = undefined;
        std.mem.writeInt(u16, &v, 2, .little);
        try f.writeAll(&v);
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, 2, .little);
        try f.writeAll(&c);
        var crc_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &crc_bytes, crc_val, .little);
        try f.writeAll(&crc_bytes);
        try f.writeAll(e1[0..entry_size_legacy]);
        try f.writeAll(e2[0..entry_size_legacy]);
    }

    const loaded = try loadFull(testing.allocator, path);
    defer loaded.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), loaded.entries.len);
    try testing.expectEqual(@as(usize, 0), loaded.lifetimes.len);

    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();
    _ = try tm.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm.ensureLegacy(.{ .max_entries = 16 });
    try seedMap(&tm, loaded.entries, null, null);
    seedLifetimes(&tm, loaded.lifetimes);

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

    {
        const f = try std.fs.cwd().openFile(path, .{});
        defer f.close();
        var header_buf: [header_size]u8 = undefined;
        _ = try f.readAll(&header_buf);
        try testing.expectEqual(version, std.mem.readInt(u16, header_buf[4..6], .little));
    }

    const loaded = try loadFull(testing.allocator, path);
    defer loaded.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), loaded.lifetimes.len);
    try testing.expectEqual(@as(u64, 5), loaded.lifetimes[0].lifetime_bans);
}

fn tmpStatePath(tmp: *testing.TmpDir, buf: *[std.fs.max_path_bytes]u8) ![]const u8 {
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_buf);
    return std.fmt.bufPrint(buf, "{s}/state.bin", .{dir});
}

test "persist: v4 roundtrip preserves enforced vs would-ban per entry (BUG-012)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpStatePath(&tmp, &full);

    {
        var tm = TrackerMap.init(testing.allocator);
        defer tm.deinit();
        const sshd = try tm.addTracker("sshd", .{ .max_entries = 16, .maxretry = 1, .findtime = 600, .bantime = 300 });
        const audit = try tm.addTracker("audit", .{ .max_entries = 16, .maxretry = 1, .findtime = 600, .bantime = 300 });
        _ = try sshd.recordAttempt(tIp("203.0.113.1"), tJail("sshd"), 1_000);
        sshd.markEnforced(tIp("203.0.113.1"));
        _ = try audit.recordAttempt(tIp("203.0.113.2"), tJail("audit"), 1_000);
        try saveAll(&tm, path);
    }

    const loaded = try loadFull(testing.allocator, path);
    defer loaded.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), loaded.entries.len);
    for (loaded.entries) |e| {
        try testing.expect(e.isBanned());
        if (std.mem.eql(u8, e.jail.slice(), "sshd")) {
            try testing.expectEqual(@as(?bool, true), e.enforced);
        } else {
            try testing.expectEqual(@as(?bool, false), e.enforced);
        }
    }

    var tm2 = TrackerMap.init(testing.allocator);
    defer tm2.deinit();
    _ = try tm2.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm2.addTracker("audit", .{ .max_entries = 16 });
    _ = try tm2.ensureLegacy(.{ .max_entries = 16 });
    try seedMap(&tm2, loaded.entries, null, null);
    try testing.expect(tm2.get("sshd").?.get(tIp("203.0.113.1")).?.enforced);
    try testing.expect(!tm2.get("audit").?.get(tIp("203.0.113.2")).?.enforced);
}

const LegacyByJail = struct {
    enforcing_jail: []const u8,
    fn resolve(ctx: ?*anyopaque, jail_name: []const u8) bool {
        const self: *LegacyByJail = @ptrCast(@alignCast(ctx.?));
        return std.mem.eql(u8, jail_name, self.enforcing_jail);
    }
};

test "persist: pre-v4 entries take enforced from the resolver; v4 entries ignore it (BUG-012)" {
    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();
    _ = try tm.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm.addTracker("audit", .{ .max_entries = 16 });
    _ = try tm.ensureLegacy(.{ .max_entries = 16 });

    const entries = [_]StateEntry{
        .{ .ip = tIp("203.0.113.1"), .jail = tJail("sshd"), .attempt_count = 3, .ban_count = 1, .first_attempt = 0, .last_attempt = 0, .ban_expiry = 999_999 },
        .{ .ip = tIp("203.0.113.2"), .jail = tJail("audit"), .attempt_count = 3, .ban_count = 1, .first_attempt = 0, .last_attempt = 0, .ban_expiry = 999_999 },
        .{ .ip = tIp("203.0.113.3"), .jail = tJail("audit"), .attempt_count = 3, .ban_count = 1, .first_attempt = 0, .last_attempt = 0, .ban_expiry = 999_999, .enforced = true },
        .{ .ip = tIp("203.0.113.4"), .jail = tJail("sshd"), .attempt_count = 1, .ban_count = 0, .first_attempt = 0, .last_attempt = 0, .ban_expiry = null },
    };
    var policy = LegacyByJail{ .enforcing_jail = "sshd" };
    try seedMapWith(&tm, &entries, null, null, .{ .ctx = @ptrCast(&policy), .resolve = LegacyByJail.resolve });

    try testing.expect(tm.get("sshd").?.get(tIp("203.0.113.1")).?.enforced);
    try testing.expect(!tm.get("audit").?.get(tIp("203.0.113.2")).?.enforced);
    try testing.expect(tm.get("audit").?.get(tIp("203.0.113.3")).?.enforced);
    try testing.expect(!tm.get("sshd").?.get(tIp("203.0.113.4")).?.enforced);
}

test "persist: v3 file loads with enforced unknown and the default seeder assumes enforced (BUG-012)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpStatePath(&tmp, &full);

    var e1: [entry_size]u8 = undefined;
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
    }
    var crc = std.hash.Crc32.init();
    crc.update(e1[0..entry_size_legacy]);
    const jail_count: u32 = 0;
    crc.update(std.mem.asBytes(&jail_count));
    const crc_val = crc.final();
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        try f.writeAll(&magic);
        var v: [2]u8 = undefined;
        std.mem.writeInt(u16, &v, 3, .little);
        try f.writeAll(&v);
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, 1, .little);
        try f.writeAll(&c);
        var crc_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &crc_bytes, crc_val, .little);
        try f.writeAll(&crc_bytes);
        try f.writeAll(e1[0..entry_size_legacy]);
        try f.writeAll(std.mem.asBytes(&jail_count));
    }

    const loaded = try loadFull(testing.allocator, path);
    defer loaded.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), loaded.entries.len);
    try testing.expect(loaded.entries[0].enforced == null);

    var tm = TrackerMap.init(testing.allocator);
    defer tm.deinit();
    _ = try tm.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm.ensureLegacy(.{ .max_entries = 16 });
    try seedMap(&tm, loaded.entries, null, null);
    try testing.expect(tm.get("sshd").?.get(tIp("1.2.3.4")).?.enforced);

    try saveAll(&tm, path);
    const again = try loadFull(testing.allocator, path);
    defer again.deinit(testing.allocator);
    try testing.expectEqual(@as(?bool, true), again.entries[0].enforced);
}
