// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const history = @import("core/native_effect_history.zig");
const effects = @import("core/native_effect.zig");
const detection = @import("core/native_detection_record.zig");
fn installation() !effects.Installation {
    return effects.Installation.init([_]u8{17} ** 16, .nftables, "history-fixture");
}
fn event(sequence: u64, id: u8, confirmed: i64) !history.Event {
    const owner = try installation();
    const scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, id } });
    const scope_key = try scope.key(owner);
    const jail = try detection.Name.init("ssh");
    const decision = [_]u8{id} ** 32;
    return .{ .sequence = sequence, .event_id = effects.hashParts("fail2zig-native-confirmed-owner-v1", &.{ &owner.id, &scope_key, jail.slice(), &decision }), .installation = owner, .scope_key = scope_key, .scope = scope, .jail = jail, .decision_id = decision, .confirmed_us = confirmed };
}
fn page(after: u64, last: u64, head: u64) !history.Page {
    return .{ .token = .{ .installation = (try installation()).id, .stream_revision = head + 1, .head_sequence = head, .retained_from_sequence = 1, .after_sequence = after, .last_sequence = last }, .count = @intCast(last - after), .more = last < head };
}
fn ready(owner: *history.Consumer) !void {
    const initial = try owner.prepareInitial();
    initial.publish();
    initial.release();
}
test "native effect history: explicit bootstrap prepare release and publication" {
    var owner = try history.Consumer.init(try installation(), [_]u8{1} ** 32);
    const initial = try owner.prepareInitial();
    try t.expectError(error.HistoryBusy, owner.prepareInitial());
    try t.expect(!owner.ready);
    try t.expectEqual(@as(u64, 0), owner.revision);
    const saved = try history.Checkpoint.decode(initial.checkpoint());
    try t.expectEqual(@as(u64, 0), saved.last_sequence);
    try t.expectEqualStrings("@history", owner.manifest().jail);
    initial.release();
    try t.expect(!owner.ready);
    try ready(&owner);
    try t.expectEqual(@as(u64, 1), owner.revision);
    try t.expectError(error.HistoryAlreadyReady, owner.prepareInitial());
}
test "native effect history: equal and late original times retain exact sequence across restore" {
    var owner = try history.Consumer.init(try installation(), [_]u8{1} ** 32);
    try ready(&owner);
    const events = [_]history.Event{ try event(1, 1, 100), try event(2, 2, 100), try event(3, 3, 90) };
    const input = try page(0, 3, 3);
    const stage = try owner.prepare(input, &events, 200);
    try t.expectEqual(@as(u64, 0), owner.live.total_confirmed);
    const bytes = stage.checkpoint()[0..history.checkpoint_bytes].*;
    const next = try history.Checkpoint.decode(&bytes);
    try t.expectEqual(@as(u64, 3), next.total_confirmed);
    try t.expectEqual(@as(i64, 100), next.confirmed_watermark_us);
    try history.validateTransition(owner.live, next, input, &events);
    stage.publish();
    stage.release();
    try t.expectError(error.StaleHistoryPage, owner.prepare(input, &events, 200));
    var restored = try history.Consumer.init(try installation(), [_]u8{1} ** 32);
    const restore = try restored.prepareRestore(2, &bytes);
    try t.expect(!restored.ready);
    try t.expectError(error.InvalidHistoryTransition, restore.batch(.{ .prepared_us = 500 }));
    restore.publish();
    restore.release();
    try t.expectEqualDeep(owner.live, restored.live);
    try t.expectError(error.HistoryCaughtUp, restored.prepare(try page(3, 3, 3), &.{}, 999));
}
test "native effect history: rollback discards staged counters and digest" {
    var owner = try history.Consumer.init(try installation(), [_]u8{1} ** 32);
    try ready(&owner);
    const stage = try owner.prepare(try page(0, 1, 1), &.{try event(1, 1, 100)}, 100);
    const bytes = stage.checkpoint()[0..history.checkpoint_bytes].*;
    stage.release();
    try t.expectEqual(@as(u64, 0), owner.live.last_sequence);
    const retry = try owner.prepare(try page(0, 1, 1), &.{try event(1, 1, 100)}, 200);
    defer retry.release();
    try t.expectEqualSlices(u8, &bytes, retry.checkpoint());
}
test "native effect history: forged identity canonical name scope and installation refuse" {
    const good = try event(1, 1, 100);
    var bad = good;
    bad.event_id[0] ^= 1;
    try t.expectError(error.InvalidHistoryEvent, bad.validate());
    bad = good;
    bad.scope_key[0] ^= 1;
    try t.expectError(error.InvalidHistoryEvent, bad.validate());
    bad = good;
    bad.scope.canonical.subject.address[15] = 1;
    try t.expectError(error.InvalidHistoryEvent, bad.validate());
    bad = good;
    bad.jail.len = 255;
    try t.expectError(error.InvalidHistoryEvent, bad.validate());
    bad = good;
    bad.jail.bytes[63] = 1;
    try t.expectError(error.InvalidHistoryEvent, bad.validate());
    bad = good;
    bad.installation.selector_bytes[255] = 1;
    try t.expectError(error.InvalidHistoryEvent, bad.validate());
}
test "native effect history: gap duplicate page and duplicate logical event refuse without mutation" {
    var owner = try history.Consumer.init(try installation(), [_]u8{1} ** 32);
    try ready(&owner);
    var duplicate = try event(1, 1, 100);
    duplicate.sequence = 2;
    try t.expectError(error.InvalidHistoryEvent, owner.prepare(try page(0, 2, 2), &.{ try event(1, 1, 100), duplicate }, 200));
    try t.expectError(error.HistoryGap, owner.prepare(try page(0, 1, 1), &.{try event(2, 1, 100)}, 200));
    var gap = try page(0, 1, 1);
    gap.token.retained_from_sequence = 2;
    try t.expectError(error.HistoryGap, owner.prepare(gap, &.{try event(1, 1, 100)}, 200));
    try t.expect(!owner.in_flight);
    try t.expectEqual(@as(u64, 0), owner.live.total_confirmed);
}
test "native effect history: page and checkpoint bounded hostile integer validation" {
    var input = try page(0, 1, 1);
    input.count = std.math.maxInt(usize);
    try t.expectError(error.InvalidHistoryPage, input.validate());
    input = try page(0, 1, 1);
    input.token.head_sequence = std.math.maxInt(u64);
    try t.expectError(error.InvalidHistoryPage, input.validate());
    input = try page(0, 1, 1);
    input.token.after_sequence = 2;
    try t.expectError(error.InvalidHistoryPage, input.validate());
    input = try page(0, 1, 1);
    input.more = true;
    try t.expectError(error.InvalidHistoryPage, input.validate());
    var owner = try history.Consumer.init(try installation(), [_]u8{1} ** 32);
    const initial = try owner.prepareInitial();
    var bytes = initial.checkpoint()[0..history.checkpoint_bytes].*;
    initial.release();
    try t.expectError(error.InvalidHistoryCheckpoint, history.Checkpoint.decode(bytes[0..111]));
    bytes[64] = 1;
    try t.expectError(error.InvalidHistoryCheckpoint, history.Checkpoint.decode(&bytes));
    bytes[64] = 0;
    bytes[80] = 1;
    try t.expectError(error.InvalidHistoryCheckpoint, history.Checkpoint.decode(&bytes));
}
test "native effect history: transition cannot forge unread cursor count watermark or digest" {
    var owner = try history.Consumer.init(try installation(), [_]u8{1} ** 32);
    try ready(&owner);
    const events = [_]history.Event{try event(1, 1, 100)};
    const input = try page(0, 1, 1);
    const stage = try owner.prepare(input, &events, 100);
    defer stage.release();
    const next = try history.Checkpoint.decode(stage.checkpoint());
    var bad = next;
    bad.confirmed_watermark_us = 200;
    try t.expectError(error.InvalidHistoryTransition, history.validateTransition(owner.live, bad, input, &events));
    bad = next;
    bad.rolling_digest[0] ^= 1;
    try t.expectError(error.InvalidHistoryTransition, history.validateTransition(owner.live, bad, input, &events));
    bad = next;
    bad.last_sequence = 2;
    bad.total_confirmed = 2;
    try t.expectError(error.InvalidHistoryTransition, history.validateTransition(owner.live, bad, input, &events));
}
test "native effect history: maximum page original timestamps future refusal and generation binding" {
    var owner = try history.Consumer.init(try installation(), [_]u8{1} ** 32);
    try ready(&owner);
    var events: [64]history.Event = undefined;
    for (&events, 0..) |*item, i| item.* = try event(i + 1, @intCast(i + 1), 100);
    const stage = try owner.prepare(try page(0, 64, 65), &events, 100);
    stage.publish();
    stage.release();
    try t.expectEqual(@as(u64, 64), owner.live.last_sequence);
    try t.expectError(error.InvalidHistoryEvent, owner.prepare(try page(64, 65, 65), &.{try event(65, 65, 101)}, 100));
    var replacement = try history.Consumer.init(try installation(), [_]u8{2} ** 32);
    try t.expectError(error.HistoryGenerationMismatch, replacement.prepareRestore(2, &try owner.live.encode()));
    try t.expectError(error.HistoryGenerationMismatch, history.Consumer.init(try installation(), [_]u8{0} ** 32));
}
