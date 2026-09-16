// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const rules = @import("core/native_rules.zig");
const corr = @import("core/native_correlation.zig");
const adapter = @import("core/native_rule_consumer.zig");
const definition =
    \\{"id":"sessions","source":"application","format":"json","subject":"peer","conditions":[{"field":"phase","text":"failed"}],"exclude":[{"field":"account","text":"monitor"}],"correlation":{"key":"session","phase":"phase","start":"connected","finish":"failed","ttl_seconds":30}}
;
const start =
    \\{"phase":"connected","session":"alpha","peer":"198.51.100.31","account":"ordinary"}
;
const finish =
    \\{"phase":"failed","session":"alpha","account":"ordinary"}
;
fn timing(occurrence: u8, event: i64, receipt: i64, now: i64) corr.Timing {
    return .{ .occurrence = [_]u8{occurrence} ** 32, .event_us = event * 1_000_000, .receipt_us = receipt * 1_000_000, .processing_us = now * 1_000_000 };
}
fn prepare(consumer: *adapter.Consumer, input: []const u8, clock: corr.Timing) !adapter.Prepared {
    return consumer.prepare(.{ .source = "application", .record = input }, clock);
}
fn commit(consumer: *adapter.Consumer, input: []const u8, clock: corr.Timing) !rules.Outcome {
    const stage = try prepare(consumer, input, clock);
    defer stage.release();
    const result = stage.outcome.?;
    stage.publish();
    return result;
}
fn live(consumer: *const adapter.Consumer) usize {
    var count: usize = 0;
    for (consumer.contexts.?.live.entries) |entry| if (entry != null) {
        count += 1;
    };
    return count;
}
test "native correlation: start finish and repeated finish publish only once" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    try t.expectEqual(rules.Kind.awaiting_context, (try commit(&consumer, start, timing(1, 10, 10, 10))).kind);
    try t.expectEqual(@as(usize, 1), live(&consumer));
    const out = try commit(&consumer, finish, timing(2, 11, 11, 11));
    try t.expectEqual(rules.Kind.candidate, out.kind);
    try t.expect(out.subject.?.address.eql(try rules.Ip.parse("198.51.100.31")));
    try t.expectEqual(.context, out.subject_origin.?);
    try t.expectEqual(@as(usize, 0), live(&consumer));
    try t.expectEqual(rules.Reason.context_missing, (try commit(&consumer, finish, timing(2, 11, 11, 12))).reason);
}
test "native correlation: stateless entry cannot bypass required context" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var scratch: rules.Scratch = .{};
    try t.expectError(error.CorrelationRequired, program.evaluate(.{ .source = "application", .record = finish }, &scratch));
}
test "native correlation: aborted prepare leaves counters context and watermark unchanged" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    const initial = try prepare(&consumer, start, timing(1, 10, 10, 10));
    initial.release();
    try t.expectEqual(@as(usize, 0), live(&consumer));
    try t.expect(consumer.contexts.?.live.watermark_us == null);
    _ = try commit(&consumer, start, timing(1, 10, 10, 10));
    const old = consumer.counters;
    const stage = try prepare(&consumer, finish, timing(2, 11, 11, 11));
    try t.expectEqual(@as(usize, 1), live(&consumer));
    try t.expectError(error.ConsumerBusy, prepare(&consumer, finish, timing(2, 11, 11, 11)));
    stage.release();
    try t.expectEqual(old, consumer.counters);
    try t.expectEqual(@as(i64, 10_000_000), consumer.contexts.?.live.watermark_us.?);
    try t.expectEqual(rules.Kind.candidate, (try commit(&consumer, finish, timing(2, 11, 11, 12))).kind);
}
test "native correlation: durable restart after start retains subject and original deadline" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var before = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    const stage = try prepare(&before, start, timing(1, 9, 10, 12));
    const saved = try t.allocator.dupe(u8, stage.checkpoint);
    defer t.allocator.free(saved);
    stage.release();
    try t.expectEqual(@as(usize, 0), live(&before));
    var after = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    const restored = try after.prepareRestore(saved);
    try t.expectEqual(@as(usize, 0), live(&after));
    restored.publish();
    restored.release();
    try t.expectEqual(@as(i64, 40_000_000), after.contexts.?.live.entries[0].?.deadline_us);
    try t.expectEqual(rules.Kind.candidate, (try commit(&after, finish, timing(2, 15, 16, 39))).kind);
}
test "native correlation: committed finish checkpoint restores consumed state without new candidate" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    _ = try commit(&consumer, start, timing(1, 10, 10, 10));
    const stage = try prepare(&consumer, finish, timing(2, 11, 11, 11));
    const saved = try t.allocator.dupe(u8, stage.checkpoint);
    defer t.allocator.free(saved);
    stage.release();
    var restored = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    const loaded = try restored.prepareRestore(saved);
    loaded.publish();
    loaded.release();
    try t.expectEqual(@as(usize, 0), live(&restored));
    try t.expectEqual(@as(u64, 1), restored.counters[@intFromEnum(rules.Kind.candidate)]);
    try t.expectEqual(rules.Reason.context_missing, (try commit(&restored, finish, timing(2, 11, 11, 12))).reason);
}
test "native correlation: duplicate start cannot replace original identity or extend deadline" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    _ = try commit(&consumer, start, timing(1, 10, 10, 10));
    _ = try commit(&consumer, start, timing(1, 10, 10, 39));
    const entry = consumer.contexts.?.live.entries[0].?;
    try t.expectEqual(@as(i64, 40_000_000), entry.deadline_us);
    try t.expectEqual([_]u8{1} ** 32, entry.occurrence);
    try t.expectEqual(rules.Reason.context_expired, (try commit(&consumer, finish, timing(2, 39, 39, 40))).reason);
    try t.expectEqual(@as(usize, 1), live(&consumer));
}
test "native correlation: event interval and processing deadline both bound late finishes" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    _ = try commit(&consumer, start, timing(1, 1, 10, 10));
    try t.expectEqual(rules.Reason.event_order, (try commit(&consumer, finish, timing(2, 0, 11, 11))).reason);
    try t.expectEqual(rules.Reason.event_order, (try commit(&consumer, finish, timing(3, 32, 32, 32))).reason);
    try t.expectEqual(@as(usize, 1), live(&consumer));
    try t.expectEqual(rules.Kind.candidate, (try commit(&consumer, finish, timing(4, 31, 33, 33))).kind);
}
test "native correlation: processing clock reversal refuses without publishing anything" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    _ = try commit(&consumer, start, timing(1, 10, 10, 15));
    const counters = consumer.counters;
    try t.expectError(error.CorrelationClockReversed, prepare(&consumer, finish, timing(2, 11, 11, 14)));
    try t.expect(!consumer.in_flight);
    try t.expectEqual(counters, consumer.counters);
    try t.expectEqual(rules.Kind.candidate, (try commit(&consumer, finish, timing(2, 11, 11, 16))).kind);
}
test "native correlation: conflict rejection no-match and malformed evidence preserve saved subject" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    _ = try commit(&consumer, start, timing(1, 10, 10, 10));
    const bad_start = "{\"phase\":\"connected\",\"session\":\"alpha\",\"account\":\"ordinary\",\"peer\":\"192.0.2.90\"}";
    const bad_finish = "{\"phase\":\"failed\",\"session\":\"alpha\",\"peer\":\"192.0.2.90\",\"account\":\"ordinary\"}";
    try t.expectEqual(rules.Reason.context_conflict, (try commit(&consumer, bad_start, timing(2, 11, 11, 11))).reason);
    try t.expectEqual(rules.Reason.context_conflict, (try commit(&consumer, bad_finish, timing(3, 12, 12, 12))).reason);
    try t.expectEqual(rules.Kind.no_match, (try commit(&consumer, "{\"phase\":\"accepted\",\"session\":\"alpha\"}", timing(4, 13, 13, 13))).kind);
    try t.expectEqual(rules.Kind.rejected, (try commit(&consumer, "{\"phase\":\"failed\",\"session\":\"alpha\"}", timing(5, 14, 14, 14))).kind);
    try t.expectEqual(@as(usize, 1), live(&consumer));
    try t.expectEqual(rules.Kind.candidate, (try commit(&consumer, finish, timing(6, 15, 15, 15))).kind);
}
test "native correlation: valid excluded finish consumes only after commit" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    _ = try commit(&consumer, start, timing(1, 10, 10, 10));
    const excluded = "{\"phase\":\"failed\",\"session\":\"alpha\",\"account\":\"monitor\"}";
    const stage = try prepare(&consumer, excluded, timing(2, 11, 11, 11));
    try t.expectEqual(rules.Kind.excluded, stage.outcome.?.kind);
    stage.release();
    try t.expectEqual(@as(usize, 1), live(&consumer));
    _ = try commit(&consumer, excluded, timing(2, 11, 11, 12));
    try t.expectEqual(@as(usize, 0), live(&consumer));
    try t.expectEqual(@as(u64, 0), consumer.counters[@intFromEnum(rules.Kind.candidate)]);
}
test "native correlation: capacity preserves all eight live keys and reuses expired same key" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    var buffer: [256]u8 = undefined;
    for (0..8) |i| {
        const line = try std.fmt.bufPrint(&buffer, "{{\"phase\":\"connected\",\"session\":\"key-{d}\",\"account\":\"ordinary\",\"peer\":\"198.51.100.31\"}}", .{i});
        _ = try commit(&consumer, line, timing(@intCast(i), 10, 10, 10));
    }
    const old = consumer.counters;
    try t.expectError(error.ContextCapacity, prepare(&consumer, start, timing(9, 11, 11, 11)));
    try t.expectEqual(old, consumer.counters);
    try t.expectEqual(@as(usize, 8), live(&consumer));
    const reused = "{\"phase\":\"connected\",\"session\":\"key-7\",\"account\":\"ordinary\",\"peer\":\"198.51.100.31\"}";
    _ = try commit(&consumer, reused, timing(10, 40, 40, 40));
    try t.expectEqual(@as(i64, 70_000_000), consumer.contexts.?.live.entries[7].?.deadline_us);
}
test "native correlation: late original start never creates a rebased lifetime" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    try t.expectEqual(rules.Reason.context_expired, (try commit(&consumer, start, timing(1, 10, 10, 40))).reason);
    try t.expectEqual(@as(usize, 0), live(&consumer));
}
test "native correlation: checkpoints reject foreign source jail rule and format" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    const stage = try prepare(&consumer, start, timing(1, 10, 10, 10));
    const saved = try t.allocator.dupe(u8, stage.checkpoint);
    defer t.allocator.free(saved);
    stage.publish();
    stage.release();
    var source = try adapter.Consumer.init(program, "application", "inode-b", [_]u8{0} ** 32, false);
    var jail = try adapter.Consumer.init(program, "different", "inode-a", [_]u8{0} ** 32, false);
    try t.expectError(error.RuleGenerationMismatch, source.prepareRestore(saved));
    try t.expectError(error.RuleGenerationMismatch, jail.prepareRestore(saved));
    const changed = try rules.Program.create(t.allocator, definition, .{ .work = 12000 });
    defer changed.destroy();
    var rule = try adapter.Consumer.init(changed, "application", "inode-a", [_]u8{0} ** 32, false);
    try t.expectError(error.RuleGenerationMismatch, rule.prepareRestore(saved));
    try t.expectError(error.InvalidRuleCheckpoint, consumer.prepareRestore(saved[0 .. saved.len - 1]));
    const header = adapter.checkpoint_bytes - corr.checkpoint_bytes;
    saved[header + 4] = 2;
    try t.expectError(error.UnsupportedCorrelationCheckpoint, consumer.prepareRestore(saved));
    try t.expectEqual(@as(usize, 1), live(&consumer));
}
test "native correlation: hostile serialized lengths times subject tags and padding refuse restore" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    const stage = try prepare(&consumer, start, timing(1, 10, 10, 10));
    const saved = try t.allocator.dupe(u8, stage.checkpoint);
    defer t.allocator.free(saved);
    stage.publish();
    stage.release();
    const entry = adapter.checkpoint_bytes - corr.checkpoint_bytes + 48;
    const offsets = [_]usize{ entry, entry + 65, entry + 66, entry + 377, entry + 369, entry + 1 + 63, entry + corr.entry_bytes + 1 };
    for (offsets) |offset| {
        const mutated = try t.allocator.dupe(u8, saved);
        defer t.allocator.free(mutated);
        mutated[offset] = 255;
        try t.expectError(error.InvalidCorrelationCheckpoint, consumer.prepareRestore(mutated));
        try t.expect(!consumer.in_flight);
        try t.expectEqual(@as(usize, 1), live(&consumer));
    }
}
test "native correlation: incomplete and oversized finish never consumes context" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    _ = try commit(&consumer, start, timing(1, 10, 10, 10));
    try t.expectError(error.IncompleteRecord, consumer.prepare(.{ .source = "application", .record = finish, .complete = false }, timing(2, 11, 11, 11)));
    const big = [_]u8{' '} ** 2049;
    try t.expectError(error.RecordTooLarge, prepare(&consumer, &big, timing(2, 11, 11, 11)));
    try t.expectEqual(@as(usize, 1), live(&consumer));
}
test "native correlation: restore abort retains the previous complete live generation" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    _ = try commit(&consumer, start, timing(1, 10, 10, 10));
    const finished = try prepare(&consumer, finish, timing(2, 11, 11, 11));
    const saved = try t.allocator.dupe(u8, finished.checkpoint);
    defer t.allocator.free(saved);
    finished.release();
    const restore = try consumer.prepareRestore(saved);
    restore.release();
    try t.expectEqual(@as(usize, 1), live(&consumer));
    try t.expectEqual(rules.Kind.candidate, (try commit(&consumer, finish, timing(2, 11, 11, 12))).kind);
}
test "native correlation: clock overflow and invalid receipt fail before any stage" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    try t.expectError(error.InvalidCorrelationTime, prepare(&consumer, start, timing(1, 10, 12, 11)));
    try t.expectError(error.CorrelationTimeOverflow, prepare(&consumer, start, .{ .occurrence = [_]u8{1} ** 32, .event_us = std.math.maxInt(i64), .receipt_us = std.math.maxInt(i64), .processing_us = std.math.maxInt(i64) }));
    try t.expect(!consumer.in_flight);
    try t.expectEqual(@as(usize, 0), live(&consumer));
}
test "native correlation: JSON hostname contexts retain canonical name across restore" {
    const config =
        \\{"id":"host-sessions","source":"application","format":"json","subject":"peer","subject_kind":"hostname","conditions":[{"field":"phase","text":"failed"}],"correlation":{"key":"session","phase":"phase","start":"connected","finish":"failed","ttl_seconds":30}}
    ;
    const program = try rules.Program.create(t.allocator, config, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, true);
    const beginning = "{\"phase\":\"connected\",\"session\":\"alpha\",\"account\":\"ordinary\",\"peer\":\"Client.EXAMPLE.\"}";
    const stage = try prepare(&consumer, beginning, timing(1, 10, 10, 10));
    const saved = try t.allocator.dupe(u8, stage.checkpoint);
    defer t.allocator.free(saved);
    stage.release();
    const restore = try consumer.prepareRestore(saved);
    restore.publish();
    restore.release();
    const out = try commit(&consumer, finish, timing(2, 11, 11, 11));
    try t.expectEqual(rules.Kind.candidate, out.kind);
    try t.expectEqualStrings("client.example", out.subject.?.hostname.slice());
}

test "native correlation: interleaved independent keys keep IPv6 attribution through restart" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    _ = try commit(&consumer, start, timing(1, 10, 10, 10));
    const second = "{\"phase\":\"connected\",\"session\":\"beta\",\"account\":\"ordinary\",\"peer\":\"2001:db8::42\"}";
    const stage = try prepare(&consumer, second, timing(2, 11, 11, 11));
    const saved = try t.allocator.dupe(u8, stage.checkpoint);
    defer t.allocator.free(saved);
    stage.release();
    const restore = try consumer.prepareRestore(saved);
    restore.publish();
    restore.release();
    const beta = try commit(&consumer, "{\"phase\":\"failed\",\"session\":\"beta\",\"account\":\"ordinary\"}", timing(3, 12, 12, 12));
    try t.expect(beta.subject.?.address.eql(try rules.Ip.parse("2001:db8::42")));
    const alpha = try commit(&consumer, finish, timing(4, 13, 13, 13));
    try t.expect(alpha.subject.?.address.eql(try rules.Ip.parse("198.51.100.31")));
    try t.expectEqual(@as(usize, 0), live(&consumer));
}

test "native correlation: fresh commit admission checks expiry after wait without losing context" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    _ = try commit(&consumer, start, timing(1, 10, 10, 10));
    const stage = try prepare(&consumer, finish, timing(2, 11, 11, 39));
    try t.expectEqual(@as(?i64, 40_000_000), stage.valid_until_us);
    try stage.validateCommit(39_999_999);
    try t.expectError(error.ConsumerExpired, stage.validateCommit(40_000_000));
    try t.expectError(error.ConsumerClockReversed, stage.validateCommit(38_999_999));
    stage.release();
    try t.expectEqual(@as(usize, 1), live(&consumer));
    try t.expectEqual(rules.Reason.context_expired, (try commit(&consumer, finish, timing(2, 11, 11, 40))).reason);
}

test "native correlation: wrong source and changed parent configuration refuse admission" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    const stage = try prepare(&consumer, start, timing(1, 10, 10, 10));
    const saved = try t.allocator.dupe(u8, stage.checkpoint);
    defer t.allocator.free(saved);
    stage.publish();
    stage.release();
    try t.expectError(error.ConsumerSourceMismatch, consumer.prepare(.{ .source = "other", .record = finish }, timing(2, 11, 11, 11)));
    var changed = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{1} ** 32, false);
    try t.expectError(error.RuleGenerationMismatch, changed.prepareRestore(saved));
    try t.expectEqual(@as(usize, 1), live(&consumer));
}

test "native correlation: counter overflow aborts prepared context consumption" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    _ = try commit(&consumer, start, timing(1, 10, 10, 10));
    consumer.counters[@intFromEnum(rules.Kind.candidate)] = std.math.maxInt(i64);
    try t.expectError(error.ConsumerCounterOverflow, prepare(&consumer, finish, timing(2, 11, 11, 11)));
    try t.expect(!consumer.in_flight);
    try t.expect(!consumer.contexts.?.in_flight);
    try t.expectEqual(@as(usize, 1), live(&consumer));
}

test "native correlation: excluded or unqualified start cannot populate or replace context" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    const excluded = "{\"phase\":\"connected\",\"session\":\"alpha\",\"peer\":\"192.0.2.20\",\"account\":\"monitor\"}";
    try t.expectEqual(rules.Kind.excluded, (try commit(&consumer, excluded, timing(1, 10, 10, 10))).kind);
    try t.expectEqual(@as(usize, 0), live(&consumer));
    try t.expectEqual(rules.Reason.context_missing, (try commit(&consumer, finish, timing(2, 11, 11, 11))).reason);
    const absent = "{\"phase\":\"connected\",\"session\":\"alpha\",\"peer\":\"192.0.2.20\"}";
    const invalid = "{\"phase\":\"connected\",\"session\":\"alpha\",\"peer\":\"192.0.2.20\",\"account\":1}";
    try t.expectEqual(rules.Reason.missing_field, (try commit(&consumer, absent, timing(3, 12, 12, 12))).reason);
    try t.expectEqual(rules.Reason.wrong_type, (try commit(&consumer, invalid, timing(4, 13, 13, 13))).reason);
    try t.expectEqual(@as(usize, 0), live(&consumer));
    _ = try commit(&consumer, start, timing(5, 14, 14, 14));
    try t.expectEqual(rules.Kind.excluded, (try commit(&consumer, excluded, timing(6, 15, 15, 15))).kind);
    try t.expectEqual(@as(usize, 1), live(&consumer));
    const out = try commit(&consumer, finish, timing(7, 16, 16, 16));
    try t.expect(out.subject.?.address.eql(try rules.Ip.parse("198.51.100.31")));
}

test "native correlation: snapshots retain initial watermark and original active context deadlines" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var owner = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    const initial = try owner.prepareSnapshot();
    try t.expect(initial.outcome == null);
    initial.publish();
    initial.release();
    try t.expect(owner.contexts.?.live.watermark_us == null);
    try t.expectEqual(@as(usize, 0), live(&owner));
    _ = try commit(&owner, start, timing(1, 9, 10, 12));
    const counters = owner.counters;
    const snapshot = try owner.prepareSnapshot();
    const saved = try t.allocator.dupe(u8, snapshot.checkpoint);
    defer t.allocator.free(saved);
    snapshot.release();
    var restored = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    const stage = try restored.prepareRestore(saved);
    stage.publish();
    stage.release();
    try t.expectEqual(counters, restored.counters);
    try t.expectEqual(@as(i64, 12_000_000), restored.contexts.?.live.watermark_us.?);
    try t.expectEqual(@as(i64, 40_000_000), restored.contexts.?.live.entries[0].?.deadline_us);
}
