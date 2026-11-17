// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Turns confirmed native bans from other jails into candidate detections for a jail that counts repeat offenders.
// Holds: The consuming jail's own events are never counted, and each event commits at most one receipt, keyed by its event id.

const std = @import("std");
const config = @import("../config/config.zig");
const detection = @import("detection_record.zig");
const effects = @import("../effect/effect.zig");
const history = @import("../effect/effect_history.zig");
const retry = @import("retry.zig");
const durable = @import("../store/store.zig");

pub const source_id = "confirmed-effects";
pub const pattern_id = "confirmed-native-ban";

pub const Binding = struct {
    jail: []const u8,
    generation: [32]u8,
    policy: retry.Policy,
    suppress_enforcement: bool = false,
    decay: retry.EscalationDecay = .{},
};

// Does:  Returns false for an event this jail does not count, and true once its receipt is committed, now or earlier.
pub fn consume(store: *durable.Store, binding: Binding, event: history.Event, now: i64, clock: effects.Clock) !bool {
    try event.validate();
    if (event.confirmed_us > now) return error.InvalidHistoryEvent;
    if (!event.native_retry or std.mem.eql(u8, event.jail.slice(), binding.jail)) return false;
    if (!try store.historyEventEligible(event)) return false;
    if (event.scope.canonical.subject.kind != .host) return error.InvalidHistoryEvent;
    const subject: detection.Subject = switch (event.scope.canonical.subject.family) {
        .v4 => .{ .v4 = event.scope.canonical.subject.address[0..4].* },
        .v6 => .{ .v6 = event.scope.canonical.subject.address },
    };
    subject.validate() catch return error.InvalidHistoryEvent;
    const occurrence = std.fmt.bytesToHex(event.event_id, .lower);
    var cursor_buffer: [32]u8 = undefined;
    const cursor = try std.fmt.bufPrint(&cursor_buffer, "{d}", .{event.sequence});
    const revision = try store.revision(binding.jail);
    const identity = durable.ReceiptIdentity{
        .jail = binding.jail,
        .source = source_id,
        .occurrence = &occurrence,
        .cursor = cursor,
        .raw_hash = event.event_id,
        .generation = binding.generation,
    };
    const receipt = store.beginReceipt(identity, .{ .us = now }, revision) catch |failure| switch (failure) {
        error.ReceiptAlreadyCommitted => return true,
        else => return failure,
    };
    _ = try store.commitRecord(.{
        .jail = binding.jail,
        .source = identity.source,
        .occurrence = identity.occurrence,
        .cursor = identity.cursor,
        .raw_hash = identity.raw_hash,
        .receipt = .{ .time = receipt, .generation = binding.generation },
        .native_time_outcome = .{ .eligible = .{ .timestamp = .{ .us = event.confirmed_us }, .receipt = receipt, .original = .{ .us = event.confirmed_us }, .origin = .event } },
        .native_detection = .{
            .kind = .candidate,
            .generation = binding.generation,
            .filter = try detection.Name.init(config.internal_filter),
            .pattern = try detection.Name.init(pattern_id),
            .pattern_index = 0,
            .subject = subject,
        },
        .native_retry = .{ .generation = binding.generation, .policy = binding.policy, .processing_us = now, .suppress_enforcement = binding.suppress_enforcement, .decay = binding.decay },
        .effects_clock = if (binding.policy.enforce and !binding.suppress_enforcement) clock else null,
        .expected_revision = revision,
        .disposition = "time-eligible-event",
        .checkpoint = &occurrence,
    });
    return true;
}
