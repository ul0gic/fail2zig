// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const inspection = @import("../firewall/inspection.zig");

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
