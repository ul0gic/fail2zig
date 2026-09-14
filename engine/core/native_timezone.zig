// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Bounded TZif v2/v3 interpretation. No host-local timezone, POSIX rule
//! evaluation, leap-second correction or mutable lookup during record processing.
const std = @import("std");
pub const version: u16 = 1;
pub const max_file_bytes = 1024 * 1024;
pub const max_transitions = 32768;
pub const max_types = 256;
pub const max_abbreviations = 4096;
pub const max_tail_bytes = 4096;
pub const Ambiguity = enum(u8) { reject, earlier, later };
pub const Transition = struct { utc_seconds: i64, type_index: u8 };
pub const TimeType = struct { offset_seconds: i32, is_dst: bool, unspecified: bool };
pub const Selection = struct {
    utc_seconds: i64,
    offset_seconds: i32,
    zone_digest: [32]u8,
    generation: [32]u8,
    ambiguity: Ambiguity,
    fold_selected: bool,
};
pub const MicroSelection = struct { utc_us: i64, provenance: Selection };

const Cursor = struct {
    bytes: []const u8,
    position: usize = 0,
    fn take(self: *Cursor, count: usize) ![]const u8 {
        if (count > self.bytes.len - self.position) return error.TruncatedTimezone;
        const result = self.bytes[self.position..][0..count];
        self.position += count;
        return result;
    }
};
const Header = struct {
    ut_count: usize,
    standard_count: usize,
    time_count: usize,
    type_count: usize,
    char_count: usize,
    fn read(cursor: *Cursor) !Header {
        const bytes = try cursor.take(44);
        if (!std.mem.eql(u8, bytes[0..4], "TZif") or !std.mem.allEqual(u8, bytes[5..20], 0)) return error.InvalidTimezoneHeader;
        if (bytes[4] != '2' and bytes[4] != '3') return error.UnsupportedTimezoneVersion;
        var counts: [6]usize = undefined;
        for (&counts, 0..) |*count, i| count.* = std.mem.readInt(u32, bytes[20 + 4 * i ..][0..4], .big);
        if (counts[2] != 0) return error.UnsupportedLeapSeconds;
        if (counts[3] > max_transitions or counts[4] == 0 or counts[4] > max_types or counts[5] == 0 or counts[5] > max_abbreviations) return error.TimezoneLimit;
        if ((counts[0] != 0 and counts[0] != counts[4]) or (counts[1] != 0 and counts[1] != counts[4])) return error.InvalidTimezoneHeader;
        return .{ .ut_count = counts[0], .standard_count = counts[1], .time_count = counts[3], .type_count = counts[4], .char_count = counts[5] };
    }
};
const Block = struct {
    transitions: []Transition,
    types: []TimeType,
    fn deinit(self: Block, allocator: std.mem.Allocator) void {
        allocator.free(self.transitions);
        allocator.free(self.types);
    }
    fn read(allocator: std.mem.Allocator, cursor: *Cursor, header: Header, wide: bool) !Block {
        const width: usize = if (wide) 8 else 4;
        // Validated count limits make arithmetic bounded even on 32-bit targets.
        const raw_times = try cursor.take(header.time_count * width);
        const indices = try cursor.take(header.time_count);
        const raw_types = try cursor.take(header.type_count * 6);
        const abbreviations = try cursor.take(header.char_count);
        const standard = try cursor.take(header.standard_count);
        const universal = try cursor.take(header.ut_count);
        if (abbreviations[abbreviations.len - 1] != 0) return error.InvalidTimezoneType;
        const transitions = try allocator.alloc(Transition, header.time_count);
        errdefer allocator.free(transitions);
        const types = try allocator.alloc(TimeType, header.type_count);
        errdefer allocator.free(types);
        for (transitions, 0..) |*transition, i| {
            const stamp: i64 = if (wide) std.mem.readInt(i64, raw_times[i * 8 ..][0..8], .big) else std.mem.readInt(i32, raw_times[i * 4 ..][0..4], .big);
            if (i > 0 and stamp <= transitions[i - 1].utc_seconds) return error.UnorderedTimezoneTransitions;
            if (indices[i] >= header.type_count) return error.InvalidTimezoneType;
            transition.* = .{ .utc_seconds = stamp, .type_index = indices[i] };
        }
        for (types, 0..) |*kind, i| {
            const raw = raw_types[i * 6 ..][0..6];
            const offset = std.mem.readInt(i32, raw[0..4], .big);
            if (offset == std.math.minInt(i32) or raw[4] > 1 or raw[5] >= abbreviations.len) return error.InvalidTimezoneType;
            const name = std.mem.sliceTo(abbreviations[raw[5]..], 0);
            if (standard.len > 0 and standard[i] > 1) return error.InvalidTimezoneType;
            if (universal.len > 0 and (universal[i] > 1 or (universal[i] == 1 and (standard.len == 0 or standard[i] != 1)))) return error.InvalidTimezoneType;
            kind.* = .{ .offset_seconds = offset, .is_dst = raw[4] == 1, .unspecified = std.mem.eql(u8, name, "-00") };
        }
        return .{ .transitions = transitions, .types = types };
    }
};

pub const Zone = struct {
    allocator: std.mem.Allocator,
    id: []const u8,
    transitions: []const Transition,
    types: []const TimeType,
    data_digest: [32]u8,
    generation: [32]u8,
    ambiguity: Ambiguity,
    tail_present: bool,
    fixed: bool,

    /// The input buffer may be released after return. The owner keeps only its
    /// identifier and validated typed tables; every result includes its digest.
    pub fn parse(allocator: std.mem.Allocator, id: []const u8, bytes: []const u8, policy: Ambiguity) !Zone {
        try validateIdentifier(id);
        if (bytes.len > max_file_bytes) return error.TimezoneLimit;
        var cursor = Cursor{ .bytes = bytes };
        const first = try Header.read(&cursor);
        const first_version = bytes[4];
        {
            const legacy = try Block.read(allocator, &cursor, first, false);
            defer legacy.deinit(allocator);
        }
        const second_position = cursor.position;
        const second = try Header.read(&cursor);
        if (bytes[second_position + 4] != first_version) return error.InvalidTimezoneHeader;
        const block = try Block.read(allocator, &cursor, second, true);
        errdefer block.deinit(allocator);
        if (block.transitions.len == 1 or (block.transitions.len == 0 and (block.types.len != 1 or block.types[0].is_dst))) return error.InsufficientTimezoneCoverage;
        const footer = bytes[cursor.position..];
        if (footer.len < 2 or footer.len > max_tail_bytes + 2 or footer[0] != '\n' or footer[footer.len - 1] != '\n') return error.InvalidTimezoneTail;
        const tail = footer[1 .. footer.len - 1];
        for (tail) |c| if (c < 0x20 or c > 0x7e) return error.InvalidTimezoneTail;
        const owned_id = try allocator.dupe(u8, id);
        errdefer allocator.free(owned_id);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-native-tzif-v1\x00");
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, id.len, .little);
        hash.update(&length);
        hash.update(id);
        hash.update(&digest);
        hash.update(&.{@intFromEnum(policy)});
        var generation: [32]u8 = undefined;
        hash.final(&generation);
        return .{
            .allocator = allocator,
            .id = owned_id,
            .transitions = block.transitions,
            .types = block.types,
            .data_digest = digest,
            .generation = generation,
            .ambiguity = policy,
            .tail_present = tail.len != 0,
            // A no-transition file with a seasonal tail is not a fixed zone.
            .fixed = block.transitions.len == 0 and !block.types[0].unspecified and (tail.len == 0 or fixedTailOffset(tail) == block.types[0].offset_seconds),
        };
    }

    pub fn deinit(self: *Zone) void {
        self.allocator.free(self.id);
        self.allocator.free(self.transitions);
        self.allocator.free(self.types);
        self.* = undefined;
    }

    pub fn resolveLocalSeconds(self: *const Zone, local_seconds: i64) !Selection {
        var earliest: ?i64 = null;
        var latest: ?i64 = null;
        var offset_early: i32 = 0;
        var offset_late: i32 = 0;
        var in_range_candidate = false;
        var specified_offset = false;
        // At most 256 candidate offsets, each with a bounded binary transition
        // lookup. Duplicate offsets cannot create false fold ambiguity.
        for (self.types) |kind| {
            if (kind.unspecified) continue;
            specified_offset = true;
            const candidate = std.math.cast(i64, @as(i128, local_seconds) - kind.offset_seconds) orelse continue;
            in_range_candidate = true;
            const actual = self.typeAt(candidate) orelse continue;
            if (actual.unspecified or actual.offset_seconds != kind.offset_seconds) continue;
            if (earliest == null or candidate < earliest.?) {
                earliest = candidate;
                offset_early = kind.offset_seconds;
            }
            if (latest == null or candidate > latest.?) {
                latest = candidate;
                offset_late = kind.offset_seconds;
            }
        }
        if (earliest) |early| {
            const fold = early != latest.?;
            if (fold and self.ambiguity == .reject) return error.AmbiguousLocalTime;
            const later = fold and self.ambiguity == .later;
            return .{ .utc_seconds = if (later) latest.? else early, .offset_seconds = if (later) offset_late else offset_early, .zone_digest = self.data_digest, .generation = self.generation, .ambiguity = self.ambiguity, .fold_selected = fold };
        }
        if (specified_offset and !in_range_candidate) return error.TimeOutOfRange;
        // Gaps are recognized only between two covered explicit intervals.
        // The first/last transitions are coverage edges, not guessed history.
        if (self.transitions.len >= 3) for (1..self.transitions.len - 1) |i| {
            const before = self.types[self.transitions[i - 1].type_index];
            const after = self.types[self.transitions[i].type_index];
            if (before.unspecified or after.unspecified) continue;
            const start = @as(i128, self.transitions[i].utc_seconds) + before.offset_seconds;
            const end = @as(i128, self.transitions[i].utc_seconds) + after.offset_seconds;
            if (start <= local_seconds and local_seconds < end) return error.LocalTimeGap;
        };
        return error.OutsideTimezoneCoverage;
    }

    pub fn resolveLocalMicros(self: *const Zone, local_us: i64) !MicroSelection {
        const selected = try self.resolveLocalSeconds(@divFloor(local_us, 1_000_000));
        const utc_us = std.math.cast(i64, @as(i128, selected.utc_seconds) * 1_000_000 + @mod(local_us, 1_000_000)) orelse return error.TimeOutOfRange;
        return .{ .utc_us = utc_us, .provenance = selected };
    }

    /// Exact covered offset for an already absolute UTC instant, used to find
    /// the receipt's local calendar year without interpreting host locale.
    pub fn utcOffsetAt(self: *const Zone, utc_seconds: i64) !i32 {
        const kind = self.typeAt(utc_seconds) orelse return error.OutsideTimezoneCoverage;
        if (kind.unspecified) return error.OutsideTimezoneCoverage;
        return kind.offset_seconds;
    }

    fn typeAt(self: *const Zone, utc_seconds: i64) ?TimeType {
        if (self.fixed) return self.types[0];
        if (self.transitions.len < 2 or utc_seconds < self.transitions[0].utc_seconds or utc_seconds >= self.transitions[self.transitions.len - 1].utc_seconds) return null;
        var low: usize = 0;
        var high = self.transitions.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (self.transitions[middle].utc_seconds <= utc_seconds) low = middle + 1 else high = middle;
        }
        return self.types[self.transitions[low - 1].type_index];
    }

    /// Each pathname component is opened relative to a pinned directory with
    /// NOFOLLOW. Symlink aliases, including in-root aliases, are explicitly refused.
    pub fn load(allocator: std.mem.Allocator, trusted_root: []const u8, id: []const u8, policy: Ambiguity) !Zone {
        try validateIdentifier(id);
        if (!std.fs.path.isAbsolute(trusted_root) or trusted_root.len > 4096 or std.mem.indexOfScalar(u8, trusted_root, 0) != null) return error.UnsafeTimezonePath;
        var directory = std.fs.Dir{ .fd = try std.posix.open("/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true }, 0) };
        defer directory.close();
        var roots = std.mem.tokenizeScalar(u8, trusted_root, '/');
        var depth: usize = 0;
        while (roots.next()) |part| {
            if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..") or depth == 32) return error.UnsafeTimezonePath;
            depth += 1;
            const next = try openDirectory(directory, part);
            directory.close();
            directory = next;
        }
        try trustedStat(try std.posix.fstat(directory.fd), true);
        var parts = std.mem.splitScalar(u8, id, '/');
        var part = parts.next().?;
        while (parts.next()) |next_part| {
            var next = try openDirectory(directory, part);
            errdefer next.close();
            try trustedStat(try std.posix.fstat(next.fd), true);
            directory.close();
            directory = next;
            part = next_part;
        }
        const fd = std.posix.openat(directory.fd, part, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .NOFOLLOW = true, .CLOEXEC = true }, 0) catch |err| return pathError(err);
        const file = std.fs.File{ .handle = fd };
        defer file.close();
        const before = try std.posix.fstat(fd);
        try trustedStat(before, false);
        if (before.size < 0 or before.size > max_file_bytes) return error.TimezoneLimit;
        const bytes = try allocator.alloc(u8, @intCast(before.size));
        defer allocator.free(bytes);
        if (try file.readAll(bytes) != bytes.len) return error.TimezoneFileChanged;
        var extra: [1]u8 = undefined;
        if (try file.read(&extra) != 0) return error.TimezoneFileChanged;
        const after = try std.posix.fstat(fd);
        if (before.size != after.size or !std.meta.eql(before.mtim, after.mtim) or !std.meta.eql(before.ctim, after.ctim)) return error.TimezoneFileChanged;
        return parse(allocator, id, bytes, policy);
    }
};

pub fn validateIdentifier(id: []const u8) !void {
    if (id.len == 0 or id.len > 255 or id[0] == '/' or id[id.len - 1] == '/') return error.InvalidZoneIdentifier;
    var parts = std.mem.splitScalar(u8, id, '/');
    var count: usize = 0;
    while (parts.next()) |part| {
        count += 1;
        if (count > 16 or part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidZoneIdentifier;
        for (part) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '+')) return error.InvalidZoneIdentifier;
    }
}

fn openDirectory(parent: std.fs.Dir, part: []const u8) !std.fs.Dir {
    const fd = std.posix.openat(parent.fd, part, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0) catch |err| return pathError(err);
    return .{ .fd = fd };
}
fn pathError(err: anyerror) anyerror {
    return switch (err) {
        error.SymLinkLoop, error.NotDir => error.UnsafeTimezonePath,
        else => err,
    };
}
fn trustedStat(stat: std.posix.Stat, directory: bool) !void {
    if ((if (directory) !std.posix.S.ISDIR(stat.mode) else !std.posix.S.ISREG(stat.mode)) or
        stat.mode & 0o022 != 0 or (stat.uid != 0 and stat.uid != std.os.linux.geteuid())) return error.UntrustedTimezoneFile;
}

/// Parse only the fixed POSIX subset needed to prove no-transition fixed zones.
/// Seasonal/rule tails remain uninterpreted and never extend explicit coverage.
fn fixedTailOffset(tail: []const u8) ?i32 {
    var at: usize = 0;
    if (tail.len > 0 and tail[0] == '<') {
        at = (std.mem.indexOfScalar(u8, tail, '>') orelse return null) + 1;
        if (at < 5) return null;
        for (tail[1 .. at - 1]) |c| if (!(std.ascii.isAlphanumeric(c) or c == '+' or c == '-')) return null;
    } else {
        while (at < tail.len and std.ascii.isAlphabetic(tail[at])) : (at += 1) {}
        if (at < 3) return null;
    }
    var sign: i32 = -1;
    if (at < tail.len and (tail[at] == '+' or tail[at] == '-')) {
        if (tail[at] == '-') sign = 1;
        at += 1;
    }
    var total: i32 = 0;
    var component: usize = 0;
    while (at < tail.len and component < 3) : (component += 1) {
        const start = at;
        var number: i32 = 0;
        while (at < tail.len and std.ascii.isDigit(tail[at])) : (at += 1) {
            if (at - start >= 3) return null;
            number = number * 10 + tail[at] - '0';
        }
        if (start == at or number > (if (component == 0) @as(i32, 24) else 59)) return null;
        total += number * (switch (component) {
            0 => @as(i32, 3600),
            1 => 60,
            else => 1,
        });
        if (at == tail.len) return sign * total;
        if (tail[at] != ':') return null;
        at += 1;
    }
    return null;
}
