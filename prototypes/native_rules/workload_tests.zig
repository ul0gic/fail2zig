// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const rules = @import("rules.zig");
const Ip = @import("shared").IpAddress;
const t = std.testing;

test "native workload: plain SSH message keeps the peer distinct from an address-shaped account" {
    const definition =
        \\{"id":"ssh-password","source":"ssh","format":"template","template":"Failed password for {account:word} from {peer:ip} port {port:uint} ssh2","subject":"peer","conditions":[{"field":"port","number":2222}]}
    ;
    const p = try rules.Program.create(t.allocator, definition, .{});
    defer p.destroy();
    var s = rules.Session{ .program = p };
    const result = s.evaluate("ssh", "Failed password for 192.0.2.99 from 2001:db8::42 port 2222 ssh2", true, 1);
    try t.expectEqual(rules.Kind.candidate, result.kind);
    try t.expect(result.subject.?.eql(try Ip.parse("2001:db8::42")));
    const accepted = s.evaluate("ssh", "Accepted password for admin from 192.0.2.42 port 2222 ssh2", true, 2);
    try t.expectEqual(rules.Kind.no_match, accepted.kind);
    try t.expectEqual(rules.Reason.template_mismatch, accepted.reason);
}

test "native workload: bracketed mail peer supports IPv4 and IPv6 with exact status" {
    const definition =
        \\{"id":"mail","source":"mail","format":"template","template":"warning: peer[{peer:ip}]: authentication {result:word}","subject":"peer","conditions":[{"field":"result","text":"failed"}]}
    ;
    const bracketed = try rules.Program.create(t.allocator, definition, .{});
    defer bracketed.destroy();
    var mail = rules.Session{ .program = bracketed };
    for ([_][]const u8{ "192.0.2.42", "2001:db8::42" }) |address| {
        const record = try std.fmt.allocPrint(t.allocator, "warning: peer[{s}]: authentication failed", .{address});
        defer t.allocator.free(record);
        const out = mail.evaluate("mail", record, true, 1);
        try t.expectEqual(rules.Kind.candidate, out.kind);
        try t.expect(out.subject.?.eql(try Ip.parse(address)));
    }
    try t.expectEqual(rules.Kind.no_match, mail.evaluate("mail", "warning: peer[192.0.2.42]: authentication succeeded", true, 2).kind);
    const control =
        \\{"id":"mail","source":"mail","format":"template","template":"warning: peer {peer:ip} authentication {result:word}","subject":"peer","conditions":[{"field":"result","text":"failed"}]}
    ;
    const p = try rules.Program.create(t.allocator, control, .{});
    defer p.destroy();
    var s = rules.Session{ .program = p };
    try t.expectEqual(rules.Kind.candidate, s.evaluate("mail", "warning: peer 192.0.2.42 authentication failed", true, 1).kind);
}

test "native workload: quoted access-log request preserves spaces and isolates the peer" {
    const definition =
        \\{"id":"access","source":"access","format":"template","template":"{peer:ip} - - {request:quoted} {status:uint}","subject":"peer","conditions":[{"field":"status","number":401},{"field":"request","op":"starts_with","text":"GET /private/"}]}
    ;
    const p = try rules.Program.create(t.allocator, definition, .{});
    defer p.destroy();
    var s = rules.Session{ .program = p };
    const result = s.evaluate("access", "192.0.2.42 - - \"GET /private/192.0.2.99 HTTP/1.1\" 401", true, 1);
    try t.expectEqual(rules.Kind.candidate, result.kind);
    try t.expect(result.subject.?.eql(try Ip.parse("192.0.2.42")));
    try t.expectEqual(rules.Kind.no_match, s.evaluate("access", "192.0.2.42 - - \"GET /private/login HTTP/1.1\" 200", true, 2).kind);
    try t.expectEqual(rules.Kind.no_match, s.evaluate("access", "192.0.2.42 - - \"GET /private-other/login HTTP/1.1\" 401", true, 3).kind);
}
