// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

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
pub const flag_confirmed: u8 = 0x02;
pub const flag_confirmation_known: u8 = 0x04;
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
    enforced: ?bool = null,
    confirmed: bool = true,

    pub fn isBanned(self: StateEntry) bool {
        return self.ban_expiry != null;
    }
};

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
    buf[off] = (if (st.enforced) flag_enforced else @as(u8, 0)) |
        (if (st.confirmed) flag_confirmed else @as(u8, 0)) | flag_confirmation_known;
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
        .confirmed = if (buf.len == entry_size and buf[off] & flag_confirmation_known != 0) buf[off] & flag_confirmed != 0 else true,
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
            .confirmed = e.confirmed,
            .ring = [_]Timestamp{0} ** state_mod.max_attempts_per_ip,
            .ring_len = 0,
        };
        _ = &st;
        tracker.map.put(e.ip, st) catch return error.OutOfMemory;
    }
}

pub const SaveError = Error || std.fs.File.OpenError;

pub const PreflightOperation = enum {
    validate_path,
    open_directory,
    inspect_target,
    open_target,
    inspect_temporary,
    open_temporary,
    create_probe,
    write_probe,
    sync_probe,
    chmod_probe,
    rename_probe,
    sync_directory,
    remove_probe,
};

pub fn checkWritable(path: []const u8, operation: *PreflightOperation) !void {
    operation.* = .validate_path;
    if (path.len == 0 or path.len + 4 > 4096) return error.PathTooLong;
    if (path[path.len - 1] == '/') return error.InvalidPath;
    const basename = std.fs.path.basename(path);
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or std.mem.eql(u8, basename, "..")) return error.InvalidPath;
    const parent = std.fs.path.dirname(path) orelse ".";
    operation.* = .open_directory;
    var dir = try std.fs.cwd().openDir(parent, .{ .iterate = true });
    defer dir.close();

    var tmp_buf: [4096]u8 = undefined;
    const temporary = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{basename});
    for ([_][]const u8{ basename, temporary }, 0..) |name, i| {
        operation.* = if (i == 0) .inspect_target else .inspect_temporary;
        const stat = dir.statFile(name) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        if (stat.kind != .file) return error.NotRegularFile;
        operation.* = if (i == 0) .open_target else .open_temporary;
        const existing = try dir.openFile(name, .{ .mode = if (i == 0) .read_only else .read_write });
        existing.close();
    }

    var random: [16]u8 = undefined;
    std.crypto.random.bytes(&random);
    const hex = std.fmt.bytesToHex(random, .lower);
    var name_buf: [64]u8 = undefined;
    const probe_name = try std.fmt.bufPrint(&name_buf, ".fail2zig-startup-{s}", .{hex});
    operation.* = .create_probe;
    const reservation = try dir.createFile(probe_name, .{ .exclusive = true, .mode = 0o600 });
    reservation.close();
    defer dir.deleteFile(probe_name) catch {};
    var probe = try dir.atomicFile(probe_name, .{ .mode = 0o600 });
    defer probe.deinit();
    operation.* = .write_probe;
    try probe.file.writeAll("fail2zig persistence startup check\n");
    operation.* = .sync_probe;
    try probe.file.sync();
    operation.* = .chmod_probe;
    try posix.fchmod(probe.file.handle, 0o600);
    operation.* = .rename_probe;
    try probe.finish();
    operation.* = .sync_directory;
    try posix.fsync(dir.fd);
    operation.* = .remove_probe;
    try dir.deleteFile(probe_name);
    operation.* = .sync_directory;
    try posix.fsync(dir.fd);
}

pub fn saveAll(map: *const TrackerMap, path: []const u8) SaveError!void {
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
            .confirmed = e.confirmed,
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
