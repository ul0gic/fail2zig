// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const rules = @import("rules.zig");
const Ip = @import("shared").IpAddress;
const t = std.testing;
const auth = @embedFile("fixtures/auth.json");
const template = @embedFile("fixtures/auth-template.json");
const http = @embedFile("fixtures/http.json");
const session = @embedFile("fixtures/session.json");
const failed = "{\"event\":\"auth_failed\",\"client\":\"192.0.2.10\",\"account\":\"guest\"}";
const start = "{\"event\":\"connected\",\"client\":\"192.0.2.10\",\"session\":\"one\"}";
const finish = "{\"event\":\"auth_failed\",\"session\":\"one\"}";

fn expect(kind: rules.Kind, reason: rules.Reason, out: rules.Outcome) !void {
    try t.expectEqual(kind, out.kind);
    try t.expectEqual(reason, out.reason);
    if (kind != .candidate) try t.expect(out.subject == null);
}

test "native rules: private failure, legitimate success and explicit exclusion" {
    const p = try rules.Program.create(t.allocator, auth, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    const out = s.evaluate("auth-log", failed, true, 1);
    try expect(.candidate, .matched, out);
    try t.expect(out.subject.?.eql(try Ip.parse("192.0.2.10")));
    try expect(.no_match, .condition_failed, s.evaluate("auth-log", "{\"event\":\"auth_ok\",\"client\":\"192.0.2.10\",\"account\":\"guest\"}", true, 2));
    try expect(.excluded, .exclusion_matched, s.evaluate("auth-log", "{\"event\":\"auth_failed\",\"client\":\"192.0.2.10\",\"account\":\"healthcheck\"}", true, 3));
}

test "native rules: source identity comes from collector, not a log field" {
    const p = try rules.Program.create(t.allocator, auth, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    try expect(.no_match, .source_mismatch, s.evaluate("other-log", failed, true, 0));
    try expect(.no_match, .source_mismatch, s.evaluate("other-log", "{\"source\":\"auth-log\",\"event\":\"auth_failed\",\"client\":\"192.0.2.10\",\"account\":\"guest\"}", true, 0));
}

test "native rules: missing required exclusion field is visible, not a ban" {
    const p = try rules.Program.create(t.allocator, auth, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    const out = s.evaluate("auth-log", "{\"event\":\"auth_failed\",\"client\":\"192.0.2.10\"}", true, 0);
    try expect(.rejected, .missing_field, out);
    try t.expectEqualStrings("account", out.field.?);
}

test "native rules: subject field is explicit and fully parsed" {
    const p = try rules.Program.create(t.allocator, auth, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    const out = s.evaluate("auth-log", "{\"event\":\"auth_failed\",\"client\":\"192.0.2.10\",\"account\":\"192.0.2.20\"}", true, 0);
    try t.expect(out.subject.?.eql(try Ip.parse("192.0.2.10")));
    try expect(.rejected, .invalid_subject, s.evaluate("auth-log", "{\"event\":\"auth_failed\",\"client\":\"not-an-address\",\"account\":\"guest\"}", true, 0));
    try expect(.rejected, .invalid_subject, s.evaluate("auth-log", "{\"event\":\"auth_failed\",\"client\":\"127.0.0.1\",\"account\":\"guest\"}", true, 0));
}

test "native rules: duplicate fields and unsupported nested values rejected" {
    const p = try rules.Program.create(t.allocator, auth, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    try expect(.rejected, .invalid_record, s.evaluate("auth-log", "{\"event\":\"auth_failed\",\"event\":\"auth_ok\"}", true, 0));
    try expect(.rejected, .invalid_record, s.evaluate("auth-log", "{\"event\":{\"value\":\"auth_failed\"}}", true, 0));
}

test "native rules: IPv6 and mapped IPv4 retain native canonicalization" {
    const p = try rules.Program.create(t.allocator, auth, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    const v6 = s.evaluate("auth-log", "{\"event\":\"auth_failed\",\"client\":\"2001:db8::10\",\"account\":\"guest\"}", true, 0);
    try t.expect(v6.subject.?.eql(try Ip.parse("2001:db8::10")));
    const mapped = s.evaluate("auth-log", "{\"event\":\"auth_failed\",\"client\":\"::ffff:192.0.2.10\",\"account\":\"guest\"}", true, 0);
    try t.expect(mapped.subject.?.eql(try Ip.parse("192.0.2.10")));
}

test "native rules: runtime template supports a deployment-specific text format" {
    const p = try rules.Program.create(t.allocator, template, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    try expect(.candidate, .matched, s.evaluate("auth-log", "login result=failure peer=192.0.2.10 account=guest", true, 0));
    try expect(.no_match, .condition_failed, s.evaluate("auth-log", "login result=success peer=192.0.2.10 account=guest", true, 0));
    try expect(.excluded, .exclusion_matched, s.evaluate("auth-log", "login result=failure peer=192.0.2.10 account=healthcheck", true, 0));
    try expect(.no_match, .template_mismatch, s.evaluate("auth-log", "login result=failure peer=192.0.2.10 account=guest extra", true, 0));
    try expect(.no_match, .template_mismatch, s.evaluate("auth-log", "different prefix login result=failure peer=192.0.2.10 account=guest", true, 0));
}

test "native rules: unsupported template constructs and unknown fields diagnosed at load" {
    for ([_][]const u8{
        "{\"id\":\"a\",\"source\":\"auth-log\",\"format\":\"template\",\"template\":\"{client:ip}{other:word}\",\"subject\":\"client\",\"conditions\":[{\"field\":\"other\",\"text\":\"failure\"}]}",
        "{\"id\":\"a\",\"source\":\"auth-log\",\"format\":\"template\",\"template\":\"{client:word}\",\"subject\":\"client\",\"conditions\":[{\"field\":\"missing\",\"text\":\"failure\"}]}",
        "{\"id\":\"a\",\"source\":\"auth-log\",\"format\":\"template\",\"template\":\"{client:regex}\",\"subject\":\"client\",\"conditions\":[{\"field\":\"client\",\"text\":\"failure\"}]}",
        "{\"id\":\"a\",\"source\":\"auth-log\",\"format\":\"json\",\"subject\":\"client\",\"conditions\":[],\"execute\":\"unsupported\"}",
    }) |config| try t.expectError(error.InvalidRule, rules.Program.create(t.allocator, config, .{}));
}

fn quotedProgram(limits: rules.Limits) !*rules.Program {
    const definition =
        \\{"id":"quoted","source":"text-log","format":"template","template":"peer[{peer:ip}], message={message:quoted}; result={result:word}","subject":"peer","conditions":[{"field":"result","text":"failure"}],"exclude":[{"field":"message","text":"health check"}]}
    ;
    return rules.Program.create(t.allocator, definition, limits);
}

test "native rules: quoted fields preserve spaces and exclude exact decoded text" {
    const p = try quotedProgram(.{});
    defer p.destroy();
    var s = rules.Session{ .program = p };
    const out = s.evaluate("text-log", "peer[2001:db8::42], message=\"ordinary failure\"; result=failure", true, 0);
    try expect(.candidate, .matched, out);
    try t.expect(out.subject.?.eql(try Ip.parse("2001:db8::42")));
    try expect(.excluded, .exclusion_matched, s.evaluate("text-log", "peer[192.0.2.42], message=\"health check\"; result=failure", true, 1));
    try expect(.candidate, .matched, s.evaluate("text-log", "peer[192.0.2.42], message=\"\"; result=failure", true, 2));
}

test "native rules: quote and backslash escapes decode once for predicates" {
    const definition =
        \\{"id":"escapes","source":"text-log","format":"template","template":"peer[{peer:ip}], message={message:quoted}","subject":"peer","conditions":[{"field":"message","text":"said \"no\" at C:\\auth"}]}
    ;
    const p = try rules.Program.create(t.allocator, definition, .{});
    defer p.destroy();
    var s = rules.Session{ .program = p };
    const record =
        \\peer[192.0.2.42], message="said \"no\" at C:\\auth"
    ;
    try expect(.candidate, .matched, s.evaluate("text-log", record, true, 0));
    const escaped_twice =
        \\peer[192.0.2.42], message="said \\\"no\\\" at C:\\\\auth"
    ;
    try expect(.no_match, .condition_failed, s.evaluate("text-log", escaped_twice, true, 1));
}

test "native rules: malformed quotes escapes and control bytes are rejected" {
    const p = try quotedProgram(.{});
    defer p.destroy();
    var s = rules.Session{ .program = p };
    for ([_][]const u8{
        "peer[192.0.2.42], message=unquoted; result=failure",
        "peer[192.0.2.42], message=\"unterminated; result=failure",
        "peer[192.0.2.42], message=\"trailing\\",
        "peer[192.0.2.42], message=\"unsupported\\n\"; result=failure",
        "peer[192.0.2.42], message=\"unsupported\\x41\"; result=failure",
        "peer[192.0.2.42], message=\"tab\there\"; result=failure",
        "peer[192.0.2.42], message=\"line\nbreak\"; result=failure",
        "peer[192.0.2.42], message=\"nul\x00here\"; result=failure",
        "peer[192.0.2.42], message=\"non-ascii\xff\"; result=failure",
    }) |record| try expect(.rejected, .invalid_record, s.evaluate("text-log", record, true, 0));
    try expect(.rejected, .incomplete_record, s.evaluate("text-log", "peer[192.0.2.42], message=\"valid\"; result=failure", false, 0));
    // A bad prior record cannot contaminate the next evaluation's fields/scratch.
    try expect(.candidate, .matched, s.evaluate("text-log", "peer[192.0.2.42], message=\"valid\"; result=failure", true, 1));
}

test "native rules: first delimiter and first closing quote are never reconsidered" {
    const p = try quotedProgram(.{});
    defer p.destroy();
    var s = rules.Session{ .program = p };
    try expect(.no_match, .template_mismatch, s.evaluate("text-log", "peer[192.0.2.42]extra], message=\"valid\"; result=failure", true, 0));
    try expect(.no_match, .template_mismatch, s.evaluate("text-log", "peer[192.0.2.42], message=\"first\" extra\"; result=failure", true, 1));
    try expect(.no_match, .template_mismatch, s.evaluate("text-log", "peer[192.0.2.42], message=\"valid\"; result=failure extra", true, 2));
}

test "native rules: quoted address-looking content cannot replace the typed subject" {
    const p = try quotedProgram(.{});
    defer p.destroy();
    var s = rules.Session{ .program = p };
    const record =
        \\peer[192.0.2.42], message="peer[192.0.2.99], \"result=failure\""; result=failure
    ;
    const out = s.evaluate("text-log", record, true, 0);
    try expect(.candidate, .matched, out);
    try t.expect(out.subject.?.eql(try Ip.parse("192.0.2.42")));
    try expect(.rejected, .invalid_subject, s.evaluate("text-log", "peer[invalid], message=\"peer[192.0.2.99]\"; result=failure", true, 1));
    try expect(.rejected, .invalid_subject, s.evaluate("text-log", "peer[192.0.2.42suffix], message=\"valid\"; result=failure", true, 2));
    try expect(.rejected, .invalid_subject, s.evaluate("text-log", "peer[192.0.2.42/24], message=\"valid\"; result=failure", true, 3));
}

test "native rules: quoted subject and ambiguous capture boundaries reject at load" {
    for ([_][]const u8{
        "{peer:ip}:{result:word}", // Unbracketed IPv6 cannot safely end at a colon.
        "{peer:ip}.{result:word}",
        "{peer:ip}/{result:word}",
        "{peer:ip}{result:quoted}",
        "{peer:ip}end {result:word}",
        "{peer:ip} \"{result:quoted}\"", // Captures own their quotes.
        "{peer:quoted} {result:word}", // Subject remains explicitly IP typed.
    }) |pattern| {
        const config = try std.json.stringifyAlloc(t.allocator, .{
            .id = "invalid",
            .source = "text-log",
            .format = "template",
            .template = pattern,
            .subject = "peer",
            .conditions = .{.{ .field = "result", .text = "failure" }},
        }, .{});
        defer t.allocator.free(config);
        try t.expectError(error.InvalidRule, rules.Program.create(t.allocator, config, .{}));
    }
}

test "native rules: punctuation-delimited unsigned fields retain strict full-field typing" {
    const definition =
        \\{"id":"status","source":"text-log","format":"template","template":"peer=\"{peer:ip}\"; code={code:uint},result={result:word}","subject":"peer","conditions":[{"field":"code","number":401},{"field":"result","text":"failure"}]}
    ;
    const p = try rules.Program.create(t.allocator, definition, .{});
    defer p.destroy();
    var s = rules.Session{ .program = p };
    const out = s.evaluate("text-log", "peer=\"2001:db8::42\"; code=401,result=failure", true, 0);
    try expect(.candidate, .matched, out);
    try t.expect(out.subject.?.eql(try Ip.parse("2001:db8::42")));
    for ([_][]const u8{ "401suffix", "-401", "+401", "18446744073709551616" }) |code| {
        const record = try std.fmt.allocPrint(t.allocator, "peer=\"192.0.2.42\"; code={s},result=failure", .{code});
        defer t.allocator.free(record);
        try expect(.rejected, .invalid_record, s.evaluate("text-log", record, true, 1));
    }
}

test "native rules: quoted decoded length boundary includes escaped bytes" {
    const p = try quotedProgram(.{});
    defer p.destroy();
    var s = rules.Session{ .program = p };
    for ([_]usize{ 255, 256, 257 }) |length| {
        const value = try t.allocator.alloc(u8, length * 2);
        defer t.allocator.free(value);
        for (0..length) |i| {
            value[2 * i] = '\\';
            value[2 * i + 1] = '\\';
        }
        const record = try std.fmt.allocPrint(t.allocator, "peer[192.0.2.42], message=\"{s}\"; result=failure", .{value});
        defer t.allocator.free(record);
        const out = s.evaluate("text-log", record, true, 0);
        if (length <= 256) try expect(.candidate, .matched, out) else try expect(.exhausted, .resource_limit, out);
    }
}

test "native rules: quoted scanning obeys work allowance without publishing candidates" {
    const p = try quotedProgram(.{ .work = 100 });
    defer p.destroy();
    var s = rules.Session{ .program = p };
    const record = "peer[192.0.2.42], message=\"ordinary words\"; result=failure";
    try t.expect(record.len < 100);
    const out = s.evaluate("text-log", record, true, 0);
    try expect(.exhausted, .resource_limit, out);
    try t.expect(out.work_used <= 100);
}

test "native rules: all eight fields fit fixed scratch with independent quoted values" {
    const first = [_]u8{'a'} ** 256;
    const last = [_]u8{'z'} ** 256;
    const pattern = "{peer:ip} {one:quoted} {two:quoted} {three:quoted} {four:quoted} {five:quoted} {six:quoted} {seven:quoted}";
    const config = try std.json.stringifyAlloc(t.allocator, .{
        .id = "all-fields",
        .source = "text-log",
        .format = "template",
        .template = pattern,
        .subject = "peer",
        .conditions = .{ .{ .field = "one", .text = &first }, .{ .field = "seven", .text = &last } },
    }, .{});
    defer t.allocator.free(config);
    const p = try rules.Program.create(t.allocator, config, .{});
    defer p.destroy();
    var s = rules.Session{ .program = p };
    const record = try std.fmt.allocPrint(t.allocator, "192.0.2.42 \"{s}\" \"{s}\" \"{s}\" \"{s}\" \"{s}\" \"{s}\" \"{s}\"", .{ first, first, first, first, first, first, last });
    defer t.allocator.free(record);
    try expect(.candidate, .matched, s.evaluate("text-log", record, true, 1));
    // Reuse cannot leave old decoded strings visible to the next record's predicates.
    try expect(.no_match, .condition_failed, s.evaluate("text-log", "192.0.2.42 \"b\" \"b\" \"b\" \"b\" \"b\" \"b\" \"b\"", true, 2));
}

test "native rules: field-based HTTP conditions distinguish status path and exclusions" {
    const p = try rules.Program.create(t.allocator, http, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    try expect(.candidate, .matched, s.evaluate("http-log", "{\"remote\":\"192.0.2.10\",\"status\":401,\"path\":\"/private/login\"}", true, 0));
    try expect(.no_match, .condition_failed, s.evaluate("http-log", "{\"remote\":\"192.0.2.10\",\"status\":200,\"path\":\"/private/login\"}", true, 0));
    try expect(.no_match, .condition_failed, s.evaluate("http-log", "{\"remote\":\"192.0.2.10\",\"status\":401,\"path\":\"/private-other/login\"}", true, 0));
    try expect(.excluded, .exclusion_matched, s.evaluate("http-log", "{\"remote\":\"192.0.2.10\",\"status\":401,\"path\":\"/private/health\"}", true, 0));
    try expect(.rejected, .wrong_type, s.evaluate("http-log", "{\"remote\":\"192.0.2.10\",\"status\":\"401\",\"path\":\"/private/login\"}", true, 0));
}

test "native rules: truncated and oversized records cannot become candidates" {
    const p = try rules.Program.create(t.allocator, auth, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    try expect(.rejected, .incomplete_record, s.evaluate("auth-log", failed, false, 0));
    const big = [_]u8{' '} ** 2049;
    try expect(.exhausted, .input_limit, s.evaluate("auth-log", &big, true, 0));
}

test "native rules: configuration byte and record field budgets are explicit" {
    const big = [_]u8{' '} ** 4097;
    try t.expectError(error.ConfigTooLarge, rules.Program.create(t.allocator, &big, .{}));
    try t.expectError(error.InvalidLimits, rules.Program.create(t.allocator, auth, .{ .work = 0 }));
    const p = try rules.Program.create(t.allocator, auth, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    try expect(.exhausted, .resource_limit, s.evaluate("auth-log", "{\"a\":1,\"b\":1,\"c\":1,\"d\":1,\"e\":1,\"f\":1,\"g\":1,\"h\":1,\"i\":1}", true, 0));
}

test "native rules: work exhaustion is distinct from healthy no-match" {
    const p = try rules.Program.create(t.allocator, auth, .{ .work = 100 });
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    const out = s.evaluate("auth-log", failed, true, 0);
    try expect(.exhausted, .resource_limit, out);
    try t.expect(out.work_used <= 100);
}

test "native rules: explanations identify decision without exposing account or record" {
    const p = try rules.Program.create(t.allocator, auth, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try s.evaluate("auth-log", failed, true, 0).writeJson(stream.writer());
    const output = stream.getWritten();
    try t.expect(std.mem.indexOf(u8, output, "192.0.2.10") != null);
    try t.expect(std.mem.indexOf(u8, output, "candidate") != null);
    try t.expect(std.mem.indexOf(u8, output, "guest") == null);
    try t.expect(std.mem.indexOf(u8, output, "auth_failed") == null);
}

test "native rules: config strings are owned and evaluation needs no caller heap" {
    const bytes = try t.allocator.dupe(u8, auth);
    const p = rules.Program.create(t.allocator, bytes, .{}) catch |err| {
        t.allocator.free(bytes);
        return err;
    };
    t.allocator.free(bytes);
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    for (0..100) |now| try expect(.candidate, .matched, s.evaluate("auth-log", failed, true, now));
}

fn createDestroy(allocator: std.mem.Allocator) !void {
    const p = try rules.Program.create(allocator, auth, .{});
    defer p.destroy();
}
test "native rules: allocation failure and invalid replacement preserve existing program" {
    try t.checkAllAllocationFailures(t.allocator, createDestroy, .{});
    const p = try rules.Program.create(t.allocator, auth, .{});
    defer p.destroy();
    try t.expectError(error.InvalidRule, rules.Program.create(t.allocator, "{}", .{}));
    var s: rules.Session = .{ .program = p };
    try expect(.candidate, .matched, s.evaluate("auth-log", failed, true, 0));
}

test "native rules: two-record session emits only on finish and consumes context" {
    const p = try rules.Program.create(t.allocator, session, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    try expect(.awaiting_context, .context_stored, s.evaluate("auth-log", start, true, 10));
    const out = s.evaluate("auth-log", finish, true, 11);
    try expect(.candidate, .matched, out);
    try t.expect(out.subject.?.eql(try Ip.parse("192.0.2.10")));
    try expect(.rejected, .context_missing, s.evaluate("auth-log", finish, true, 12));
}

test "native rules: session does not transfer between program instances or sources" {
    const p = try rules.Program.create(t.allocator, session, .{});
    defer p.destroy();
    var a: rules.Session = .{ .program = p };
    var b: rules.Session = .{ .program = p };
    _ = a.evaluate("auth-log", start, true, 1);
    try expect(.rejected, .context_missing, b.evaluate("auth-log", finish, true, 2));
    try expect(.no_match, .source_mismatch, a.evaluate("other-log", finish, true, 2));
    try expect(.candidate, .matched, a.evaluate("auth-log", finish, true, 3));
}

test "native rules: session expiry boundary and duplicate start do not extend lifetime" {
    const p = try rules.Program.create(t.allocator, session, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    _ = s.evaluate("auth-log", start, true, 10);
    try expect(.awaiting_context, .context_stored, s.evaluate("auth-log", start, true, 39));
    try expect(.rejected, .context_expired, s.evaluate("auth-log", finish, true, 40));
}

test "native rules: conflicting subject leaves original context intact" {
    const p = try rules.Program.create(t.allocator, session, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    _ = s.evaluate("auth-log", start, true, 10);
    try expect(.rejected, .context_conflict, s.evaluate("auth-log", "{\"event\":\"connected\",\"client\":\"192.0.2.20\",\"session\":\"one\"}", true, 11));
    try expect(.rejected, .context_conflict, s.evaluate("auth-log", "{\"event\":\"auth_failed\",\"client\":\"192.0.2.20\",\"session\":\"one\"}", true, 12));
    try t.expect(s.evaluate("auth-log", finish, true, 13).subject.?.eql(try Ip.parse("192.0.2.10")));
}

test "native rules: context capacity does not evict live state and expired space is reusable" {
    const p = try rules.Program.create(t.allocator, session, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    var buf: [256]u8 = undefined;
    for (0..8) |i| {
        const record = try std.fmt.bufPrint(&buf, "{{\"event\":\"connected\",\"client\":\"192.0.2.10\",\"session\":\"s{d}\"}}", .{i});
        try expect(.awaiting_context, .context_stored, s.evaluate("auth-log", record, true, 1));
    }
    try expect(.exhausted, .resource_limit, s.evaluate("auth-log", start, true, 2));
    try expect(.awaiting_context, .context_stored, s.evaluate("auth-log", start, true, 31));
    try expect(.candidate, .matched, s.evaluate("auth-log", finish, true, 32));
}

test "native rules: incomplete finish and reversed clock preserve context" {
    const p = try rules.Program.create(t.allocator, session, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    _ = s.evaluate("auth-log", start, true, 10);
    try expect(.rejected, .incomplete_record, s.evaluate("auth-log", finish, false, 11));
    try expect(.rejected, .clock_reversed, s.evaluate("auth-log", finish, true, 9));
    try expect(.candidate, .matched, s.evaluate("auth-log", finish, true, 12));
}

test "native rules: unsigned text fields have strict decimal typing" {
    const config = "{\"id\":\"status-text\",\"source\":\"http-log\",\"format\":\"template\",\"template\":\"peer={client:ip} status={status:uint}\",\"subject\":\"client\",\"conditions\":[{\"field\":\"status\",\"number\":401}]}";
    const p = try rules.Program.create(t.allocator, config, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    try expect(.candidate, .matched, s.evaluate("http-log", "peer=192.0.2.10 status=401", true, 0));
    for ([_][]const u8{ "peer=192.0.2.10 status=+401", "peer=192.0.2.10 status=4_01", "peer=192.0.2.10 status=18446744073709551616" }) |record| {
        try expect(.rejected, .invalid_record, s.evaluate("http-log", record, true, 0));
    }
    try t.expectError(error.InvalidRule, rules.Program.create(t.allocator, "{\"id\":\"status-text\",\"source\":\"http-log\",\"format\":\"template\",\"template\":\"peer={client:ip} status={status:uint}\",\"subject\":\"client\",\"conditions\":[{\"field\":\"status\",\"text\":\"401\"}]}", .{}));
}

test "native rules: correlation explains inherited identity and rejects wrong key type" {
    const p = try rules.Program.create(t.allocator, session, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    try expect(.rejected, .wrong_type, s.evaluate("auth-log", "{\"event\":\"connected\",\"client\":\"192.0.2.10\",\"session\":1}", true, 0));
    _ = s.evaluate("auth-log", start, true, 1);
    const out = s.evaluate("auth-log", finish, true, 2);
    try t.expectEqualStrings("client", out.field.?);
    try t.expect(out.subject_origin.? == .context);
}

test "native rules: oversized finish cannot consume saved correlation state" {
    const p = try rules.Program.create(t.allocator, session, .{ .record_bytes = 128 });
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    _ = s.evaluate("auth-log", start, true, 1);
    const big = [_]u8{' '} ** 129;
    try expect(.exhausted, .input_limit, s.evaluate("auth-log", &big, true, 2));
    try expect(.candidate, .matched, s.evaluate("auth-log", finish, true, 3));
}

test "native rules: oversized decoded strings are a resource outcome" {
    const p = try rules.Program.create(t.allocator, auth, .{});
    defer p.destroy();
    var s: rules.Session = .{ .program = p };
    var buf: [2048]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try stream.writer().writeAll("{\"event\":\"");
    for (0..257) |_| try stream.writer().writeAll("\\u0061");
    try stream.writer().writeAll("\"}");
    try expect(.exhausted, .resource_limit, s.evaluate("auth-log", stream.getWritten(), true, 0));
}
