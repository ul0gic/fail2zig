// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Bounded confirmed-effect input. Store supplies immutable verified events and
//! atomically fences their stream token with the checkpoint CAS. No I/O or policy
//! escalation occurs here; all original per-jail events remain in the Store.
const std = @import("std");
const effects = @import("native_effect.zig");
const detection = @import("native_detection_record.zig");
const state = @import("native_consumer.zig");
pub const version: u16 = 1;
pub const max_page: usize = 64;
pub const checkpoint_bytes: usize = 112;
pub const Error = error{ InvalidHistoryEvent, InvalidHistoryPage, InvalidHistoryCheckpoint, HistoryGenerationMismatch, HistoryGap, StaleHistoryPage, InvalidHistoryTransition, HistoryCapacity, HistoryBusy, HistoryNotReady, HistoryAlreadyReady, HistoryCaughtUp };
const max_number = std.math.maxInt(i64);

pub const Event = struct {
    sequence: u64,
    event_id: [32]u8,
    installation: effects.Installation,
    scope_key: [32]u8,
    scope: effects.Scope,
    jail: detection.Name,
    decision_id: [32]u8,
    confirmed_us: i64,
    /// True only when Store joined this confirmation to a native retry detail.
    native_retry: bool = false,

    pub fn validate(self: *const Event) Error!void {
        if (self.sequence == 0 or self.sequence > max_number or self.jail.len == 0 or self.jail.len > 64) return error.InvalidHistoryEvent;
        self.installation.validate() catch return error.InvalidHistoryEvent;
        const canonical = detection.Name.init(self.jail.slice()) catch return error.InvalidHistoryEvent;
        if (!std.mem.eql(u8, &canonical.bytes, &self.jail.bytes)) return error.InvalidHistoryEvent;
        const scope_identity = self.scope.key(self.installation) catch return error.InvalidHistoryEvent;
        if (!std.mem.eql(u8, &scope_identity, &self.scope_key)) return error.InvalidHistoryEvent;
        const id = effects.hashParts("fail2zig-native-confirmed-owner-v1", &.{ &self.installation.id, &scope_identity, self.jail.slice(), &self.decision_id });
        if (!std.mem.eql(u8, &id, &self.event_id)) return error.InvalidHistoryEvent;
    }
};

pub const PageToken = struct {
    installation: [16]u8,
    stream_revision: u64,
    head_sequence: u64,
    /// First retained sequence, or head+1 when the retained stream is empty.
    retained_from_sequence: u64,
    after_sequence: u64,
    last_sequence: u64,

    pub fn validate(self: PageToken) Error!void {
        if (std.mem.allEqual(u8, &self.installation, 0) or self.stream_revision == 0 or self.stream_revision > max_number or self.head_sequence > max_number or
            self.retained_from_sequence == 0 or self.retained_from_sequence > self.head_sequence + 1 or self.after_sequence > self.head_sequence or
            self.last_sequence < self.after_sequence or self.last_sequence > self.head_sequence or self.last_sequence - self.after_sequence > max_page) return error.InvalidHistoryPage;
        if (self.after_sequence < self.retained_from_sequence - 1) return error.HistoryGap;
    }
};
pub const Page = struct {
    token: PageToken,
    count: usize,
    more: bool,

    pub fn validate(self: Page) Error!void {
        try self.token.validate();
        if (self.count > max_page or self.count != self.token.last_sequence - self.token.after_sequence or
            self.more != (self.token.last_sequence < self.token.head_sequence) or (self.count == 0 and self.more)) return error.InvalidHistoryPage;
    }
};

pub fn generation(installation: effects.Installation, policy_generation: [32]u8) Error![32]u8 {
    installation.validate() catch return error.HistoryGenerationMismatch;
    if (std.mem.allEqual(u8, &policy_generation, 0)) return error.HistoryGenerationMismatch;
    return effects.hashParts("fail2zig-native-confirmed-history-v1", &.{ &installation.id, &.{@intFromEnum(installation.backend)}, installation.selector(), &policy_generation });
}
pub fn key(binding: [32]u8) state.Key {
    return .{ .kind = .history, .jail = "@history", .source = "confirmed-effects", .rule = "checkpoint", .generation = binding };
}

pub const Checkpoint = struct {
    generation: [32]u8,
    installation: [16]u8,
    last_sequence: u64 = 0,
    total_confirmed: u64 = 0,
    /// Original maximum confirmation epoch, never a restore/processing timestamp.
    confirmed_watermark_us: i64 = 0,
    rolling_digest: [32]u8 = [_]u8{0} ** 32,

    pub fn validate(self: Checkpoint) Error!void {
        if (std.mem.allEqual(u8, &self.generation, 0) or std.mem.allEqual(u8, &self.installation, 0) or
            self.last_sequence > max_number or self.total_confirmed != self.last_sequence) return error.InvalidHistoryCheckpoint;
        if (self.last_sequence == 0 and (self.confirmed_watermark_us != 0 or !std.mem.allEqual(u8, &self.rolling_digest, 0))) return error.InvalidHistoryCheckpoint;
        if (self.last_sequence != 0 and std.mem.allEqual(u8, &self.rolling_digest, 0)) return error.InvalidHistoryCheckpoint;
    }
    pub fn encode(self: Checkpoint) Error![checkpoint_bytes]u8 {
        try self.validate();
        var bytes: [checkpoint_bytes]u8 = undefined;
        @memcpy(bytes[0..8], "F2ZHIST1");
        @memcpy(bytes[8..40], &self.generation);
        @memcpy(bytes[40..56], &self.installation);
        std.mem.writeInt(u64, bytes[56..64], self.last_sequence, .little);
        std.mem.writeInt(u64, bytes[64..72], self.total_confirmed, .little);
        std.mem.writeInt(i64, bytes[72..80], self.confirmed_watermark_us, .little);
        @memcpy(bytes[80..112], &self.rolling_digest);
        return bytes;
    }
    pub fn decode(bytes: []const u8) Error!Checkpoint {
        if (bytes.len != checkpoint_bytes or !std.mem.eql(u8, bytes[0..8], "F2ZHIST1")) return error.InvalidHistoryCheckpoint;
        const result = Checkpoint{ .generation = bytes[8..40].*, .installation = bytes[40..56].*, .last_sequence = std.mem.readInt(u64, bytes[56..64], .little), .total_confirmed = std.mem.readInt(u64, bytes[64..72], .little), .confirmed_watermark_us = std.mem.readInt(i64, bytes[72..80], .little), .rolling_digest = bytes[80..112].* };
        try result.validate();
        return result;
    }
};

/// Store must use the actual immutable event rows read inside the same writer
/// transaction, not caller-supplied events. The stream token alone is not a hash
/// of event contents. Global logical-event uniqueness belongs to that stream;
/// this local validator additionally refuses duplicate identities within a page.
pub fn validateTransition(before: Checkpoint, after: Checkpoint, page: Page, events: []const Event) Error!void {
    const expected = try advance(before, page, events);
    if (!std.mem.eql(u8, &try expected.encode(), &try after.encode())) return error.InvalidHistoryTransition;
}
fn advance(before: Checkpoint, page: Page, events: []const Event) Error!Checkpoint {
    try before.validate();
    try page.validate();
    if (events.len != page.count) return error.InvalidHistoryPage;
    if (!std.mem.eql(u8, &before.installation, &page.token.installation)) return error.HistoryGenerationMismatch;
    if (before.last_sequence != page.token.after_sequence) return error.StaleHistoryPage;
    var next = before;
    for (events, 0..) |event, i| {
        try event.validate();
        if (!std.mem.eql(u8, &event.installation.id, &before.installation)) return error.HistoryGenerationMismatch;
        if (event.sequence != before.last_sequence + i + 1) return error.HistoryGap;
        for (events[0..i]) |prior| if (std.mem.eql(u8, &prior.event_id, &event.event_id)) return error.InvalidHistoryEvent;
        var fields: [16]u8 = undefined;
        std.mem.writeInt(u64, fields[0..8], event.sequence, .little);
        std.mem.writeInt(i64, fields[8..16], event.confirmed_us, .little);
        next.rolling_digest = effects.hashParts("fail2zig-native-confirmed-history-chain-v1", &.{ &next.rolling_digest, &fields, &event.event_id });
        next.confirmed_watermark_us = if (next.total_confirmed == 0) event.confirmed_us else @max(next.confirmed_watermark_us, event.confirmed_us);
        next.total_confirmed += 1;
        next.last_sequence = event.sequence;
    }
    return next;
}

pub const Stage = struct {
    owner: *Consumer,
    token: ?PageToken,
    mode: enum { bootstrap, consume, restore },

    /// Borrowed until release. The owner and callback clock must retain stable
    /// addresses through Store.commitConfirmedHistory and subsequent publication.
    pub fn batch(self: Stage, clock: effects.Clock) Error!state.Batch {
        if (self.mode == .restore) return error.InvalidHistoryTransition;
        return .{ .deltas = &self.owner.delta, .prepared_us = clock.prepared_us, .clock_context = clock.context, .clock = clock.read };
    }
    pub fn checkpoint(self: Stage) []const u8 {
        return &self.owner.bytes;
    }
    /// Call only after durable commit, or a final coherent Store restore fence.
    pub fn publish(self: Stage) void {
        self.owner.live = self.owner.staged;
        self.owner.revision = self.owner.staged_revision;
        self.owner.ready = true;
    }
    pub fn release(self: Stage) void {
        self.owner.in_flight = false;
    }
};
pub const Consumer = struct {
    installation: effects.Installation,
    binding: [32]u8,
    live: Checkpoint,
    revision: u64 = 0,
    ready: bool = false,
    in_flight: bool = false,
    staged: Checkpoint = undefined,
    staged_revision: u64 = 0,
    bytes: [checkpoint_bytes]u8 = undefined,
    delta: [1]state.Delta = undefined,
    required: [1]state.Requirement = undefined,

    /// Move to a stable address before obtaining manifests or prepared stages.
    pub fn init(installation: effects.Installation, policy_generation: [32]u8) Error!Consumer {
        const binding = try generation(installation, policy_generation);
        return .{ .installation = installation, .binding = binding, .live = .{ .generation = binding, .installation = installation.id } };
    }
    pub fn manifest(self: *Consumer) state.Manifest {
        self.required[0] = .{ .key = key(self.binding), .format_version = version };
        return .{ .jail = "@history", .source = "confirmed-effects", .source_generation = self.binding, .required = &self.required };
    }
    pub fn prepareInitial(self: *Consumer) Error!Stage {
        if (self.in_flight) return error.HistoryBusy;
        if (self.ready or self.revision != 0) return error.HistoryAlreadyReady;
        return self.stage(self.live, 1, .bootstrap, null);
    }
    pub fn prepareRestore(self: *Consumer, revision: u64, payload: []const u8) Error!Stage {
        if (self.in_flight) return error.HistoryBusy;
        if (self.ready or self.revision != 0) return error.HistoryAlreadyReady;
        if (revision == 0 or revision > max_number) return error.InvalidHistoryCheckpoint;
        const saved = try Checkpoint.decode(payload);
        if (!std.mem.eql(u8, &saved.generation, &self.binding) or !std.mem.eql(u8, &saved.installation, &self.installation.id)) return error.HistoryGenerationMismatch;
        return self.stage(saved, revision, .restore, null);
    }
    pub fn prepare(self: *Consumer, page: Page, events: []const Event, processing_us: i64) Error!Stage {
        if (self.in_flight) return error.HistoryBusy;
        if (!self.ready) return error.HistoryNotReady;
        const next = try advance(self.live, page, events);
        if (page.count == 0) return error.HistoryCaughtUp;
        for (events) |event| {
            if (!std.meta.eql(self.installation, event.installation)) return error.HistoryGenerationMismatch;
            if (event.confirmed_us > processing_us) return error.InvalidHistoryEvent;
        }
        if (self.revision >= max_number) return error.HistoryCapacity;
        return self.stage(next, self.revision + 1, .consume, page.token);
    }
    fn stage(self: *Consumer, next: Checkpoint, revision: u64, mode: @FieldType(Stage, "mode"), token: ?PageToken) Error!Stage {
        self.bytes = try next.encode();
        self.staged = next;
        self.staged_revision = revision;
        self.delta[0] = .{ .key = key(self.binding), .format_version = version, .expected_revision = self.revision, .payload = &self.bytes };
        self.in_flight = true;
        return .{ .owner = self, .token = token, .mode = mode };
    }
};
