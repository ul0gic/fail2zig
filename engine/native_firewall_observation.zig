// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const inspection = @import("firewall/inspection.zig");

pub const max_entries: usize = 256;
pub const default_limit: u16 = 64;
pub const max_limit: u16 = max_entries;
pub const cursor_max_bytes: usize = 128;
pub const cursor_ttl_ms: u64 = 60_000;

pub const Inventory = enum { not_checked, known_entries, unexpected_entries };
pub const Origin = enum { admission, readback, effect, stop, outage };

pub const Stamp = struct {
    monotonic_ms: ?u64,
    wall_us: ?i64,
    origin: Origin,
    inventory: Inventory,
};

pub const AttemptFailure = struct {
    monotonic_ms: ?u64,
    wall_us: ?i64,
    cause: anyerror,
    stage: inspection.OperationStage,
};

pub const PageRequest = struct {
    limit: u16 = default_limit,
    cursor: ?[]const u8 = null,
    now_ms: ?u64 = null,
};

pub const Metadata = struct {
    installation_id: [16]u8,
    backend: inspection.Transport,
    process_nonce: [16]u8,
    sequence: u64 = 0,
    state: enum { unavailable, owned, absent } = .unavailable,
    structure_proof: inspection.StructureProof = .unverified,
    observed_mono_ms: ?u64 = null,
    observed_wall_us: ?i64 = null,
    observed_total: usize = 0,
    retained_count: usize = 0,
    inventory: Inventory = .not_checked,
    origin: Origin = .readback,
    attempt_mono_ms: ?u64 = null,
    attempt_wall_us: ?i64 = null,
    attempt_failure: ?anyerror = null,
    attempt_stage: ?inspection.OperationStage = null,
};

pub const Cache = struct {
    mutex: std.Thread.Mutex = .{},
    metadata: Metadata,
    entries: [max_entries]inspection.Entry = undefined,

    pub fn init(installation: inspection.Installation, nonce: [16]u8) Cache {
        return .{ .metadata = .{
            .installation_id = installation.id,
            .backend = installation.transport,
            .process_nonce = nonce,
        } };
    }

    /// Copies a complete inspector result into the bounded retained sample. This
    /// path allocates nothing and deliberately retains only the first 256 rows.
    pub fn capture(self: *Cache, snapshot: *const inspection.Snapshot, stamp: Stamp) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (!std.mem.eql(u8, &snapshot.installation.id, &self.metadata.installation_id) or
            snapshot.installation.transport != self.metadata.backend)
        {
            self.recordFailureLocked(.{
                .monotonic_ms = stamp.monotonic_ms,
                .wall_us = stamp.wall_us,
                .cause = error.InvalidInstallation,
                .stage = .readback,
            });
            return;
        }
        if (self.metadata.sequence == std.math.maxInt(u64)) {
            self.recordFailureLocked(.{
                .monotonic_ms = stamp.monotonic_ms,
                .wall_us = stamp.wall_us,
                .cause = error.ObservationSequenceOverflow,
                .stage = .readback,
            });
            return;
        }

        const retained = @min(snapshot.entries.len, max_entries);
        @memcpy(self.entries[0..retained], snapshot.entries[0..retained]);
        self.metadata.sequence += 1;
        self.metadata.state = switch (snapshot.state) {
            .owned => .owned,
            .absent => .absent,
        };
        self.metadata.structure_proof = if (snapshot.state == .owned) snapshot.structure_proof else .unverified;
        self.metadata.observed_mono_ms = stamp.monotonic_ms;
        self.metadata.observed_wall_us = stamp.wall_us;
        self.metadata.observed_total = snapshot.entries.len;
        self.metadata.retained_count = retained;
        self.metadata.inventory = stamp.inventory;
        self.metadata.origin = stamp.origin;
        self.metadata.attempt_mono_ms = stamp.monotonic_ms;
        self.metadata.attempt_wall_us = stamp.wall_us;
        self.metadata.attempt_failure = null;
        self.metadata.attempt_stage = null;
    }

    /// Records a failed attempt without discarding the last complete sample.
    pub fn fail(self: *Cache, attempt: AttemptFailure) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.recordFailureLocked(attempt);
    }

    fn recordFailureLocked(self: *Cache, attempt: AttemptFailure) void {
        self.metadata.attempt_mono_ms = attempt.monotonic_ms;
        self.metadata.attempt_wall_us = attempt.wall_us;
        self.metadata.attempt_failure = attempt.cause;
        self.metadata.attempt_stage = attempt.stage;
    }

    /// Copies one bounded page while holding the cache mutex. The caller owns
    /// `out`, which must be allocated before entry; no slice into Cache escapes.
    pub fn readPage(self: *Cache, request: PageRequest, out: *Page) error{ BadCursor, InvalidatedCursor }!void {
        if (request.limit == 0 or request.limit > max_limit) return error.BadCursor;
        const decoded: ?Cursor = if (request.cursor) |cursor| try decodeCursor(cursor) else null;

        self.mutex.lock();
        defer self.mutex.unlock();

        var offset: usize = 0;
        var issued_ms: ?u64 = null;
        if (decoded) |cursor| {
            if (!std.mem.eql(u8, &cursor.nonce, &self.metadata.process_nonce) or
                cursor.sequence != self.metadata.sequence or
                cursor.limit != request.limit or
                self.metadata.state == .unavailable)
            {
                return error.InvalidatedCursor;
            }
            const now = request.now_ms orelse return error.InvalidatedCursor;
            const observed = self.metadata.observed_mono_ms orelse return error.InvalidatedCursor;
            if (observed > now or cursor.issued_ms > now or now - cursor.issued_ms > cursor_ttl_ms or
                cursor.offset > self.metadata.retained_count)
            {
                return error.InvalidatedCursor;
            }
            offset = cursor.offset;
            issued_ms = cursor.issued_ms;
        } else if (self.metadata.state != .unavailable) {
            if (request.now_ms) |now| if (self.metadata.observed_mono_ms) |observed| {
                if (observed <= now) issued_ms = now;
            };
        }

        out.* = .{
            .metadata = self.metadata,
            .count = 0,
            .offset = offset,
            .age_ms = null,
            .issued_ms = issued_ms,
            .limit = request.limit,
        };
        if (request.now_ms) |now| if (self.metadata.observed_mono_ms) |observed| {
            if (observed <= now) out.age_ms = now - observed;
        };
        if (self.metadata.state == .unavailable) return;

        const count = @min(@as(usize, request.limit), self.metadata.retained_count - offset);
        @memcpy(out.entries[0..count], self.entries[offset..][0..count]);
        out.count = count;
    }
};

pub const Page = struct {
    metadata: Metadata,
    entries: [max_entries]inspection.Entry = undefined,
    count: usize = 0,
    offset: usize = 0,
    age_ms: ?u64 = null,
    issued_ms: ?u64 = null,
    limit: u16 = default_limit,

    pub fn nextCursor(self: *const Page, buffer: *[cursor_max_bytes]u8) ?[]const u8 {
        if (self.metadata.state == .unavailable or self.age_ms == null or self.issued_ms == null or
            self.offset + self.count >= self.metadata.retained_count)
        {
            return null;
        }
        const offset = std.math.cast(u16, self.offset + self.count) orelse return null;
        return encodeCursor(buffer, .{
            .nonce = self.metadata.process_nonce,
            .sequence = self.metadata.sequence,
            .offset = offset,
            .limit = self.limit,
            .issued_ms = self.issued_ms.?,
        });
    }
};

const cursor_wire_bytes: usize = 37;
const Cursor = struct {
    nonce: [16]u8,
    sequence: u64,
    offset: u16,
    limit: u16,
    issued_ms: u64,
};

fn encodeCursor(buffer: *[cursor_max_bytes]u8, cursor: Cursor) []const u8 {
    var wire: [cursor_wire_bytes]u8 = undefined;
    wire[0] = 1;
    @memcpy(wire[1..17], &cursor.nonce);
    std.mem.writeInt(u64, wire[17..25], cursor.sequence, .big);
    std.mem.writeInt(u16, wire[25..27], cursor.offset, .big);
    std.mem.writeInt(u16, wire[27..29], cursor.limit, .big);
    std.mem.writeInt(u64, wire[29..37], cursor.issued_ms, .big);
    return std.base64.url_safe_no_pad.Encoder.encode(buffer, &wire);
}

fn decodeCursor(text: []const u8) error{BadCursor}!Cursor {
    if (text.len == 0 or text.len > cursor_max_bytes or
        text.len != std.base64.url_safe_no_pad.Encoder.calcSize(cursor_wire_bytes))
    {
        return error.BadCursor;
    }
    var wire: [cursor_wire_bytes]u8 = undefined;
    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(text) catch return error.BadCursor;
    if (decoded_len != wire.len) return error.BadCursor;
    std.base64.url_safe_no_pad.Decoder.decode(&wire, text) catch return error.BadCursor;
    var canonical: [cursor_max_bytes]u8 = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&canonical, &wire);
    if (!std.mem.eql(u8, encoded, text) or wire[0] != 1) return error.BadCursor;
    return .{
        .nonce = wire[1..17].*,
        .sequence = std.mem.readInt(u64, wire[17..25], .big),
        .offset = std.mem.readInt(u16, wire[25..27], .big),
        .limit = std.mem.readInt(u16, wire[27..29], .big),
        .issued_ms = std.mem.readInt(u64, wire[29..37], .big),
    };
}

pub fn monotonicMs() ?u64 {
    const ts = std.posix.clock_gettime(.MONOTONIC) catch return null;
    if (ts.sec < 0 or ts.nsec < 0 or ts.nsec >= std.time.ns_per_s) return null;
    const seconds = std.math.cast(u64, ts.sec) orelse return null;
    return std.math.add(u64, std.math.mul(u64, seconds, std.time.ms_per_s) catch return null, @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms) catch null;
}

fn testSnapshot(state: @FieldType(inspection.Snapshot, "state"), entries: []inspection.Entry) inspection.Snapshot {
    return .{
        .allocator = std.testing.allocator,
        .installation = .{ .id = [_]u8{0x31} ** 16, .transport = .nftables },
        .state = state,
        .entries = entries,
        .fingerprint = [_]u8{0x42} ** 32,
        .observed_start_ns = 1,
        .observed_end_ns = 2,
    };
}

test "native effect runtime: observation cache pages one immutable complete sample" {
    var source: [max_entries + 1]inspection.Entry = undefined;
    for (&source, 0..) |*entry, index| entry.* = .{
        .address = .{ .ipv4 = @intCast(index + 1) },
        .remaining_ms = @intCast(index),
    };
    var snapshot = testSnapshot(.owned, &source);
    var cache = Cache.init(snapshot.installation, [_]u8{0x52} ** 16);
    cache.capture(&snapshot, .{ .monotonic_ms = 100, .wall_us = 200, .origin = .readback, .inventory = .known_entries });

    var first: Page = undefined;
    try cache.readPage(.{ .limit = 2, .now_ms = 110 }, &first);
    try std.testing.expectEqual(@as(u64, 1), first.metadata.sequence);
    try std.testing.expectEqual(@as(usize, max_entries + 1), first.metadata.observed_total);
    try std.testing.expectEqual(@as(usize, max_entries), first.metadata.retained_count);
    try std.testing.expectEqual(@as(?u64, 10), first.age_ms);
    try std.testing.expectEqual(@as(usize, 2), first.count);
    try std.testing.expectEqualDeep(source[0], first.entries[0]);
    try std.testing.expectEqualDeep(source[1], first.entries[1]);

    var cursor_buffer: [cursor_max_bytes]u8 = undefined;
    const cursor = first.nextCursor(&cursor_buffer).?;
    var second: Page = undefined;
    try cache.readPage(.{ .limit = 2, .cursor = cursor, .now_ms = 120 }, &second);
    try std.testing.expectEqual(@as(usize, 2), second.offset);
    try std.testing.expectEqualDeep(source[2], second.entries[0]);
    try std.testing.expectEqual(@as(?u64, 110), second.issued_ms);
}

test "native effect runtime: observation failure retains stale data and replacement invalidates cursors" {
    var entries = [_]inspection.Entry{.{ .address = .{ .ipv4 = 0xc0000201 } }};
    var snapshot = testSnapshot(.owned, &entries);
    snapshot.structure_proof = .exact_v1;
    var cache = Cache.init(snapshot.installation, [_]u8{0x53} ** 16);
    cache.capture(&snapshot, .{ .monotonic_ms = 1_000, .wall_us = 2_000, .origin = .effect, .inventory = .known_entries });
    var page: Page = undefined;
    try cache.readPage(.{ .limit = 1, .now_ms = 1_010 }, &page);
    cache.fail(.{ .monotonic_ms = 1_020, .wall_us = 2_020, .cause = error.Timeout, .stage = .readback });
    var stale: Page = undefined;
    try cache.readPage(.{ .limit = 1, .now_ms = 1_030 }, &stale);
    try std.testing.expectEqual(@as(u64, 1), stale.metadata.sequence);
    try std.testing.expectEqual(error.Timeout, stale.metadata.attempt_failure.?);
    try std.testing.expectEqual(.exact_v1, stale.metadata.structure_proof);
    try std.testing.expectEqualDeep(entries[0], stale.entries[0]);

    var no_entries: [0]inspection.Entry = .{};
    var absent = testSnapshot(.absent, &no_entries);
    cache.capture(&absent, .{ .monotonic_ms = 1_040, .wall_us = 2_040, .origin = .stop, .inventory = .unexpected_entries });
    try std.testing.expectEqual(@as(u64, 2), cache.metadata.sequence);
    try std.testing.expect(cache.metadata.attempt_failure == null);
    try std.testing.expectEqual(@as(usize, 0), cache.metadata.retained_count);
    try std.testing.expectEqual(.unverified, cache.metadata.structure_proof);
}

test "native effect runtime: observation cursors bind snapshot parameters and lifetime" {
    var entries = [_]inspection.Entry{
        .{ .address = .{ .ipv4 = 1 } },
        .{ .address = .{ .ipv4 = 2 } },
    };
    var snapshot = testSnapshot(.owned, &entries);
    var cache = Cache.init(snapshot.installation, [_]u8{0x54} ** 16);
    cache.capture(&snapshot, .{ .monotonic_ms = 100, .wall_us = null, .origin = .admission, .inventory = .not_checked });
    var first: Page = undefined;
    try cache.readPage(.{ .limit = 1, .now_ms = 101 }, &first);
    var cursor_buffer: [cursor_max_bytes]u8 = undefined;
    const cursor = first.nextCursor(&cursor_buffer).?;

    var out: Page = undefined;
    try std.testing.expectError(error.BadCursor, cache.readPage(.{ .limit = 0, .now_ms = 102 }, &out));
    try std.testing.expectError(error.BadCursor, cache.readPage(.{ .limit = 1, .cursor = "%%%", .now_ms = 102 }, &out));
    try std.testing.expectError(error.InvalidatedCursor, cache.readPage(.{ .limit = 2, .cursor = cursor, .now_ms = 102 }, &out));
    try std.testing.expectError(error.InvalidatedCursor, cache.readPage(.{ .limit = 1, .cursor = cursor, .now_ms = 101 + cursor_ttl_ms + 1 }, &out));
    try std.testing.expectError(error.InvalidatedCursor, cache.readPage(.{ .limit = 1, .cursor = cursor, .now_ms = null }, &out));

    cache.capture(&snapshot, .{ .monotonic_ms = 200, .wall_us = null, .origin = .readback, .inventory = .known_entries });
    try std.testing.expectError(error.InvalidatedCursor, cache.readPage(.{ .limit = 1, .cursor = cursor, .now_ms = 201 }, &out));
    try cache.readPage(.{ .limit = 1, .now_ms = 199 }, &out);
    try std.testing.expect(out.age_ms == null);
    try std.testing.expect(out.nextCursor(&cursor_buffer) == null);
}

test "native effect runtime: observation cache layout stays within frozen bounds" {
    try std.testing.expectEqual(@as(usize, 192), @sizeOf(inspection.Entry));
    try std.testing.expect(@sizeOf(Cache) <= 50 * 1024);
    try std.testing.expect(@sizeOf(Page) <= 50 * 1024);
    try std.testing.expectEqual(@as(usize, 256), max_entries);
}
