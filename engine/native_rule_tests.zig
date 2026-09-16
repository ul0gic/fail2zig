// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const rules = @import("core/native_rules.zig");
const adapter = @import("core/native_rule_consumer.zig");
const definition =
    \\{"id":"private-login","source":"application","format":"json","subject":"peer","conditions":[{"field":"result","text":"denied"}],"exclude":[{"field":"account","text":"probe"}]}
;
const failure =
    \\{"peer":"198.51.100.81","result":"denied","account":"ordinary"}
;
const timing = @import("core/native_correlation.zig").Timing{ .occurrence = [_]u8{1} ** 32, .event_us = 10, .receipt_us = 11, .processing_us = 12 };
fn evaluate(program: *const rules.Program, record: []const u8) !rules.Outcome {
    var scratch: rules.Scratch = .{};
    return program.evaluate(.{ .source = program.metadata().source, .record = record }, &scratch);
}
fn expect(kind: rules.Kind, reason: rules.Reason, out: rules.Outcome) !void {
    try t.expectEqual(kind, out.kind);
    try t.expectEqual(reason, out.reason);
}
test "native rules: explicit field attribution excludes address-shaped account and injected source" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    const out = try evaluate(program, "{\"peer\":\"2001:db8::81\",\"result\":\"denied\",\"account\":\"192.0.2.99\",\"source\":\"other\"}");
    try expect(.candidate, .matched, out);
    try t.expect(out.subject.?.address.eql(try rules.Ip.parse("2001:db8::81")));
    try t.expectEqualStrings("peer", out.field.?.slice());
    var scratch: rules.Scratch = .{};
    try expect(.no_match, .source_mismatch, try program.evaluate(.{ .source = "other", .record = failure }, &scratch));
}
test "native rules: positive negative exclusion and missing fields retain typed outcomes" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    try expect(.candidate, .matched, try evaluate(program, failure));
    try expect(.no_match, .condition_failed, try evaluate(program, "{\"result\":\"accepted\"}"));
    try expect(.excluded, .exclusion_matched, try evaluate(program, "{\"peer\":\"192.0.2.81\",\"result\":\"denied\",\"account\":\"probe\"}"));
    try expect(.rejected, .missing_field, try evaluate(program, "{\"peer\":\"192.0.2.81\",\"result\":\"denied\"}"));
    try expect(.rejected, .wrong_type, try evaluate(program, "{\"peer\":\"192.0.2.81\",\"result\":1}"));
}
test "native rules: whole typed addresses canonicalize mapped IPv6 and reject invalid subjects" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var buffer: [256]u8 = undefined;
    for ([_][]const u8{ "127.0.0.2", "0.1.2.3", "::", "::1", "::192.0.2.4", "192.0.2.1suffix", "192.0.2.1:22", "[2001:db8::1]" }) |address| {
        const record = try std.fmt.bufPrint(&buffer, "{{\"peer\":\"{s}\",\"result\":\"denied\",\"account\":\"ordinary\"}}", .{address});
        try expect(.rejected, .invalid_subject, try evaluate(program, record));
    }
    const out = try evaluate(program, "{\"peer\":\"::ffff:192.0.2.81\",\"result\":\"denied\",\"account\":\"ordinary\"}");
    try t.expectEqual(@as(u32, 0xc0000251), out.subject.?.address.ipv4);
}
test "native rules: JSON rejects duplicate nested null boolean float and negative fields" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    for ([_][]const u8{ "{\"result\":\"denied\",\"result\":\"accepted\"}", "{\"result\":{}}", "{\"result\":[]}", "{\"result\":null}", "{\"result\":true}", "{\"result\":1.25}", "{\"result\":-1}", "{\"result\":9223372036854775808}" }) |record|
        try expect(.rejected, .invalid_record, try evaluate(program, record));
}
test "native rules: SSH template pins full message and selected peer" {
    const config =
        \\{"id":"ssh-private","source":"ssh-file","format":"template","template":"Denied login for {user:word} from {peer:ip} port {port:uint}","subject":"peer","conditions":[{"field":"port","number":2201}]}
    ;
    const program = try rules.Program.create(t.allocator, config, .{});
    defer program.destroy();
    const out = try evaluate(program, "Denied login for 192.0.2.25 from 2001:db8::25 port 2201");
    try expect(.candidate, .matched, out);
    try t.expect(out.subject.?.address.eql(try rules.Ip.parse("2001:db8::25")));
    try expect(.no_match, .template_mismatch, try evaluate(program, "Accepted login for account from 192.0.2.25 port 2201"));
    try expect(.no_match, .template_mismatch, try evaluate(program, "Denied login for account from 192.0.2.25 port 2201 trailing"));
}
test "native rules: bracketed mail peer and literal punctuation do not backtrack" {
    const config =
        \\{"id":"mail-private","source":"mail","format":"template","template":"smtp peer[{peer:ip}]; status={status:word}","subject":"peer","conditions":[{"field":"status","text":"blocked"}]}
    ;
    const program = try rules.Program.create(t.allocator, config, .{});
    defer program.destroy();
    try expect(.candidate, .matched, try evaluate(program, "smtp peer[2001:db8::50]; status=blocked"));
    try expect(.no_match, .template_mismatch, try evaluate(program, "smtp peer[192.0.2.50] wrong ]; status=blocked"));
    try expect(.no_match, .condition_failed, try evaluate(program, "smtp peer[192.0.2.50]; status=accepted"));
}
const access_config =
    \\{"id":"access-private","source":"access","format":"template","template":"{peer:ip} {request:quoted} code={status:uint}","subject":"peer","conditions":[{"field":"status","number":403},{"field":"request","op":"starts_with","text":"GET /admin/"}]}
;
test "native rules: quoted access fields own escapes and maintain prefix boundary" {
    const program = try rules.Program.create(t.allocator, access_config, .{});
    defer program.destroy();
    try expect(.candidate, .matched, try evaluate(program, "192.0.2.91 \"GET /admin/198.51.100.99 HTTP/1.1\" code=403"));
    try expect(.candidate, .matched, try evaluate(program, "192.0.2.91 \"GET /admin/\\\"quoted\\\"\\\\file\" code=403"));
    try expect(.no_match, .condition_failed, try evaluate(program, "192.0.2.91 \"GET /admin-other/file\" code=403"));
    for ([_][]const u8{ "192.0.2.91 \"GET /admin/\\n\" code=403", "192.0.2.91 \"GET /admin/\"junk\" code=403", "192.0.2.91 \"GET /admin/unterminated" }) |record| {
        const out = try evaluate(program, record);
        try t.expect(out.kind == .rejected or out.kind == .no_match);
    }
}
test "native rules: unsupported grammar capture ambiguity and predicate type conflicts refuse load" {
    for ([_][]const u8{ "{peer:ip}:{status:word}", "{peer:ip}{status:word}", "{peer:ip}.{status:word}", "{peer:ip}suffix {status:word}", "{peer:word} {status:word}", "{peer:quoted} {status:word}", "{peer:ip} {status:uint}", "{peer:ip} {status:regex}" }) |pattern| {
        const config = try std.json.stringifyAlloc(t.allocator, .{ .id = "bad", .source = "input", .format = "template", .template = pattern, .subject = "peer", .conditions = .{.{ .field = "status", .text = "denied" }} }, .{});
        defer t.allocator.free(config);
        try t.expectError(error.InvalidRule, rules.Program.create(t.allocator, config, .{}));
    }
    try t.expectError(error.InvalidRule, rules.Program.create(t.allocator, "{\"id\":\"one\",\"unknown\":1}", .{}));
}
const hostname_config =
    \\{"id":"hostname-private","source":"auth","format":"template","template":"peer={peer:hostname} status={status:word}","subject":"peer","subject_kind":"hostname","conditions":[{"field":"status","text":"denied"}]}
;
test "native rules: explicit hostname capture owns canonical full name without DNS" {
    const program = try rules.Program.create(t.allocator, hostname_config, .{});
    defer program.destroy();
    const out = try evaluate(program, "peer=Client.Example. status=denied");
    try expect(.candidate, .matched, out);
    try t.expectEqualStrings("client.example", out.subject.?.hostname.slice());
    try t.expectError(error.HostnameResolutionRequired, adapter.Consumer.init(program, "auth", "incarnation-1", [_]u8{0} ** 32, false));
    _ = try adapter.Consumer.init(program, "auth", "incarnation-1", [_]u8{0} ** 32, true);
    var buffer: [512]u8 = undefined;
    for ([_][]const u8{ "192.0.2.18", "2001:db8::18", "bad..example", "-bad.example", "bad-.example", "*.example", "client.example:22", "bad_example", "." }) |name| {
        const record = try std.fmt.bufPrint(&buffer, "peer={s} status=denied", .{name});
        try expect(.rejected, .invalid_subject, try evaluate(program, record));
    }
}
test "native rules: JSON hostname requires explicit kind and preserves strict IP default" {
    const config =
        \\{"id":"host-json","source":"auth","format":"json","subject":"peer","subject_kind":"hostname","conditions":[{"field":"status","text":"denied"}]}
    ;
    const program = try rules.Program.create(t.allocator, config, .{});
    defer program.destroy();
    try t.expectEqualStrings("node.example", (try evaluate(program, "{\"peer\":\"NODE.example\",\"status\":\"denied\"}")).subject.?.hostname.slice());
    const ip = try rules.Program.create(t.allocator, definition, .{});
    defer ip.destroy();
    try expect(.rejected, .invalid_subject, try evaluate(ip, "{\"peer\":\"node.example\",\"result\":\"denied\",\"account\":\"ordinary\"}"));
}
test "native rules: hostname label and total length exact boundaries" {
    var label = [_]u8{'a'} ** 64;
    _ = try rules.Hostname.init(label[0..63]);
    try t.expectError(error.InvalidSubject, rules.Hostname.init(&label));
    var name = [_]u8{'a'} ** 254;
    for ([_]usize{ 63, 127, 191 }) |i| name[i] = '.';
    _ = try rules.Hostname.init(name[0..253]);
    try t.expectError(error.InvalidSubject, rules.Hostname.init(&name));
    name[253] = '.';
    try t.expectEqual(@as(usize, 253), (try rules.Hostname.init(&name)).slice().len);
}
test "native rules: rule and record byte limits and field counts are operational errors" {
    const oversized = [_]u8{' '} ** 4097;
    try t.expectError(error.ConfigTooLarge, rules.Program.create(t.allocator, &oversized, .{}));
    try t.expectError(error.InvalidLimits, rules.Program.create(t.allocator, definition, .{ .work = 0 }));
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    try t.expectError(error.RecordTooLarge, evaluate(program, oversized[0..2049]));
    try t.expectError(error.ResourceLimit, evaluate(program, "{\"a\":1,\"b\":1,\"c\":1,\"d\":1,\"e\":1,\"f\":1,\"g\":1,\"h\":1,\"i\":1}"));
}
test "native rules: quoted and decoded string limits count decoded bytes" {
    const program = try rules.Program.create(t.allocator, access_config, .{});
    defer program.destroy();
    var text = [_]u8{'a'} ** 257;
    @memcpy(text[0..11], "GET /admin/");
    var buffer: [512]u8 = undefined;
    for ([_]usize{ 256, 257 }) |length| {
        const record = try std.fmt.bufPrint(&buffer, "192.0.2.6 \"{s}\" code=403", .{text[0..length]});
        if (length == 256) try t.expectEqual(rules.Kind.candidate, (try evaluate(program, record)).kind) else try t.expectError(error.ResourceLimit, evaluate(program, record));
    }
}
test "native rules: work admission failure leaves adapter unchanged and usable" {
    const program = try rules.Program.create(t.allocator, definition, .{ .work = 100 });
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-1", [_]u8{0} ** 32, false);
    try t.expectError(error.ResourceLimit, consumer.prepare(.{ .source = "application", .record = failure }, timing));
    try t.expect(!consumer.in_flight);
    try t.expectEqual([_]u64{0} ** adapter.counter_count, consumer.counters);
}
fn allocateProgram(allocator: std.mem.Allocator) !void {
    const program = try rules.Program.create(allocator, definition, .{});
    defer program.destroy();
}
test "native rules: configuration lifetime allocation failures and semantic generation" {
    try t.checkAllAllocationFailures(t.allocator, allocateProgram, .{});
    const config = try t.allocator.dupe(u8, definition);
    const program = rules.Program.create(t.allocator, config, .{}) catch |err| {
        t.allocator.free(config);
        return err;
    };
    t.allocator.free(config);
    defer program.destroy();
    const spaced = try std.fmt.allocPrint(t.allocator, " \n{s}\n", .{definition});
    defer t.allocator.free(spaced);
    const equivalent = try rules.Program.create(t.allocator, spaced, .{});
    defer equivalent.destroy();
    try t.expectEqual(program.generation, equivalent.generation);
    const bounded = try rules.Program.create(t.allocator, definition, .{ .work = 8000 });
    defer bounded.destroy();
    try t.expect(!std.mem.eql(u8, &program.generation, &bounded.generation));
    try t.expectError(error.InvalidRule, rules.Program.create(t.allocator, "{}", .{}));
    try expect(.candidate, .matched, try evaluate(program, failure));
}
test "native rules: outcome fields survive program and scratch destruction" {
    const program = try rules.Program.create(t.allocator, hostname_config, .{});
    const out = try evaluate(program, "peer=One.Example status=denied");
    program.destroy();
    try t.expectEqualStrings("hostname-private", out.rule.slice());
    try t.expectEqualStrings("one.example", out.subject.?.hostname.slice());
}
test "native rules: adapter rollback publication restore and incarnation mismatch" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var consumer = try adapter.Consumer.init(program, "application", "inode-1", [_]u8{0} ** 32, false);
    const input = rules.Input{ .source = "application", .record = failure };
    const aborted = try consumer.prepare(input, timing);
    aborted.release();
    try t.expectEqual(@as(u64, 0), consumer.counters[@intFromEnum(rules.Kind.candidate)]);
    const stage = try consumer.prepare(input, timing);
    try t.expectError(error.ConsumerBusy, consumer.prepare(input, timing));
    const saved = try t.allocator.dupe(u8, stage.checkpoint);
    defer t.allocator.free(saved);
    stage.publish();
    stage.release();
    try t.expectEqual(@as(u64, 1), consumer.counters[@intFromEnum(rules.Kind.candidate)]);
    var restored = try adapter.Consumer.init(program, "application", "inode-1", [_]u8{0} ** 32, false);
    const restoration = try restored.prepareRestore(saved);
    try t.expectEqual(@as(u64, 0), restored.counters[@intFromEnum(rules.Kind.candidate)]);
    restoration.publish();
    restoration.release();
    try t.expectEqual(consumer.counters, restored.counters);
    var foreign = try adapter.Consumer.init(program, "application", "inode-2", [_]u8{0} ** 32, false);
    try t.expectError(error.RuleGenerationMismatch, foreign.prepareRestore(saved));
    saved[7] = 1;
    try t.expectError(error.UnsupportedRuleCheckpoint, restored.prepareRestore(saved));
    try t.expectEqual(consumer.counters, restored.counters);
}

test "native rules: first-use snapshot advances no observation and remains reversible" {
    const program = try rules.Program.create(t.allocator, definition, .{});
    defer program.destroy();
    var owner = try adapter.Consumer.init(program, "application", "inode-a", [_]u8{0} ** 32, false);
    const first = try owner.prepareSnapshot();
    try t.expect(first.outcome == null);
    try t.expectError(error.ConsumerBusy, owner.prepareSnapshot());
    const saved = try t.allocator.dupe(u8, first.checkpoint);
    defer t.allocator.free(saved);
    first.release();
    try t.expect(std.mem.allEqual(u64, &owner.counters, 0));
    const restored = try owner.prepareRestore(saved);
    restored.publish();
    restored.release();
    try t.expect(std.mem.allEqual(u64, &owner.counters, 0));
    const observation = try owner.prepare(.{ .source = "application", .record = failure }, timing);
    observation.publish();
    observation.release();
    const old = owner.counters;
    const snapshot = try owner.prepareSnapshot();
    snapshot.publish();
    snapshot.release();
    try t.expectEqual(old, owner.counters);
}
