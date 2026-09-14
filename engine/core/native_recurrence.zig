// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Replay-safe projection of one confirmed native retry event into the one
//! admitted recidive jail. The history page checkpoint is committed separately
//! only after every event in that page has resolved through this identity.
const std = @import("std");
const config = @import("../config/native.zig");
const detection = @import("native_detection_record.zig");
const effects = @import("native_effect.zig");
const history = @import("native_effect_history.zig");
const retry = @import("native_retry.zig");
const durable = @import("record_store.zig");

pub const source_id = "confirmed-effects";
pub const pattern_id = "confirmed-native-ban";

pub const Binding = struct {
    jail: []const u8,
    generation: [32]u8,
    policy: retry.Policy,
};

/// Returns false for non-native or self-origin events after validating the
/// immutable stream event. Exact committed replay also resolves as success.
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
        .native_retry = .{ .generation = binding.generation, .policy = binding.policy, .processing_us = now },
        .effects_clock = clock,
        .expected_revision = revision,
        .disposition = "time-eligible-event",
        .checkpoint = &occurrence,
    });
    return true;
}
