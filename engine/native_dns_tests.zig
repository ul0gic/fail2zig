// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const dns = @import("core/native_dns.zig");
const generation = [_]u8{7} ** 32;
const Packet = struct {
    bytes: [4096]u8 = [_]u8{0} ** 4096,
    len: usize,
    fn init(name: dns.Name, question: dns.Question, id: u16) !Packet {
        var self = Packet{ .len = 0 };
        self.len = (try dns.encodeQuery(name, question, id, &self.bytes)).len;
        self.bytes[2] = 0x81;
        self.bytes[3] = 0x80;
        return self;
    }
    fn record(self: *Packet, kind: u16, ttl: u32, data: []const u8, authority: bool) !void {
        if (self.len + 12 + data.len > self.bytes.len) return error.FixtureLimit;
        const header: usize = if (authority) 8 else 6;
        std.mem.writeInt(u16, self.bytes[header..][0..2], std.mem.readInt(u16, self.bytes[header..][0..2], .big) + 1, .big);
        const out = self.bytes[self.len..];
        out[0] = 0xc0;
        out[1] = 0x0c;
        std.mem.writeInt(u16, out[2..4], kind, .big);
        std.mem.writeInt(u16, out[4..6], 1, .big);
        std.mem.writeInt(u32, out[6..10], ttl, .big);
        std.mem.writeInt(u16, out[10..12], @intCast(data.len), .big);
        @memcpy(out[12 .. 12 + data.len], data);
        self.len += 12 + data.len;
    }
    fn slice(self: *const Packet) []const u8 {
        return self.bytes[0..self.len];
    }
};
fn queryName() !dns.Name {
    return dns.Name.init("client.example");
}
test "native dns: query and original compressed multi-answer response retain all unique addresses" {
    var packet = try Packet.init(try queryName(), .a, 117);
    try packet.record(1, 600, &.{ 192, 0, 2, 9 }, false);
    try packet.record(1, 45, &.{ 198, 51, 100, 9 }, false);
    try packet.record(1, 60, &.{ 192, 0, 2, 9 }, false);
    const answer = try dns.parseReply(packet.slice(), try queryName(), .a, 117);
    try t.expectEqual(.positive, answer.kind);
    try t.expectEqual(@as(u8, 2), answer.count);
    try t.expectEqual(@as(u32, 45), answer.ttl_seconds);
    try t.expectEqual(@as(u32, 0xc0000209), answer.addresses[0].ipv4);
}
test "native dns: 16 and 17 distinct addresses preserve atomic response limit" {
    var packet = try Packet.init(try queryName(), .a, 118);
    for (0..16) |i| try packet.record(1, 60, &.{ 192, 0, 2, @intCast(i + 1) }, false);
    try t.expectEqual(@as(u8, 16), (try dns.parseReply(packet.slice(), try queryName(), .a, 118)).count);
    try packet.record(1, 60, &.{ 192, 0, 2, 17 }, false);
    try t.expectError(error.AnswerLimit, dns.parseReply(packet.slice(), try queryName(), .a, 118));
}
test "native dns: packet identity truncation wrong question and invalid compression remain explicit" {
    var packet = try Packet.init(try queryName(), .a, 119);
    try packet.record(1, 60, &.{ 192, 0, 2, 9 }, false);
    try t.expectError(error.DnsRequestMismatch, dns.parseReply(packet.slice(), try queryName(), .a, 120));
    try t.expectError(error.DnsRequestMismatch, dns.parseReply(packet.slice(), try queryName(), .aaaa, 119));
    try t.expectError(error.InvalidDnsPacket, dns.parseReply(packet.slice()[0 .. packet.len - 1], try queryName(), .a, 119));
    const answer_at = packet.len - 16;
    packet.bytes[answer_at] = 0xc0;
    packet.bytes[answer_at + 1] = @intCast(answer_at);
    try t.expectError(error.InvalidDnsPacket, dns.parseReply(packet.slice(), try queryName(), .a, 119));
    packet.bytes[2] |= 2;
    const partial = try dns.parseReply(packet.slice(), try queryName(), .a, 119);
    try t.expectEqual(.unknown, partial.kind);
    try t.expectEqual(dns.Reason.truncated, partial.reason);
}
test "native dns: validated recursive NXDOMAIN and NODATA bound negative TTL without AA" {
    for ([_]u8{ 0, 3 }) |rcode| {
        var packet = try Packet.init(try queryName(), .a, 121);
        packet.bytes[3] = 0x80 | rcode;
        var soa = [_]u8{0} ** 22; // bounded root MNAME/RNAME and five integer fields
        std.mem.writeInt(u32, soa[18..22], 90, .big);
        try packet.record(6, 70, &soa, true);
        const answer = try dns.parseReply(packet.slice(), try queryName(), .a, 121);
        try t.expectEqual(.negative, answer.kind);
        try t.expectEqual(@as(u32, 30), answer.ttl_seconds);
    }
    const incomplete = try Packet.init(try queryName(), .a, 122);
    try t.expectEqual(.unknown, (try dns.parseReply(incomplete.slice(), try queryName(), .a, 122)).kind);
}
test "native dns: aliases need complete bounded records and never confuse other owner addresses" {
    var packet = try Packet.init(try queryName(), .a, 123);
    const target = [_]u8{ 4, 'h', 'o', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    try packet.record(5, 9, &target, false);
    const alias = try dns.parseReply(packet.slice(), try queryName(), .a, 123);
    try t.expectEqual(.alias, alias.kind);
    try t.expectEqualStrings("host.example", alias.canonical.slice());
    try t.expectEqual(@as(u32, 9), alias.ttl_seconds);
    // A and CNAME at the same owner is ambiguous instead of a partial answer.
    try packet.record(1, 60, &.{ 192, 0, 2, 10 }, false);
    try t.expectError(error.InvalidDnsPacket, dns.parseReply(packet.slice(), try queryName(), .a, 123));
}
test "native dns: cache rollback expiry generation and checkpoint restore preserve original validity" {
    var cache = try dns.Cache.init(t.allocator, generation, 2);
    defer cache.deinit();
    var answer = dns.Answer{ .kind = .positive, .canonical = try queryName(), .ttl_seconds = 10 };
    try answer.add(.{ .ipv4 = 0xc0000209 });
    const result = dns.Result{ .request = .{ .name = try queryName(), .family = .v4, .generation = generation }, .answer = answer, .completed_us = 100, .valid_until_us = 10_000_100, .deadline_ms = 4000 };
    const aborted = try cache.prepare(result, 100);
    aborted.release();
    try t.expect((try cache.lookup(result.request, 100)) == null);
    const stage = try cache.prepare(result, 100);
    const saved = stage.bytes;
    stage.publish();
    stage.release();
    try t.expectEqual(@as(u64, 1), (try cache.lookup(result.request, 100)).?.revision);
    try t.expect((try cache.lookup(result.request, 10_000_100)) == null);
    try t.expectError(error.DnsCacheExpired, cache.prepare(result, 10_000_100));
    var restored = try dns.Cache.init(t.allocator, generation, 2);
    defer restored.deinit();
    const load = try restored.prepareRestore(&saved);
    load.publish();
    load.release();
    try t.expectEqual(result.valid_until_us, (try restored.lookup(result.request, 100)).?.result.valid_until_us);
    var corrupt = saved;
    corrupt[295] = 17;
    try t.expectError(error.InvalidDnsCheckpoint, restored.prepareRestore(&corrupt));
    var request = result.request;
    request.generation[0] ^= 1;
    try t.expectError(error.DnsGenerationMismatch, restored.lookup(request, 100));
}
test "native dns: cache rejects zero TTL unknown answers and capacity without evicting keys" {
    var cache = try dns.Cache.init(t.allocator, generation, 1);
    defer cache.deinit();
    var answer = dns.Answer{ .kind = .positive, .canonical = try queryName(), .ttl_seconds = 10 };
    try answer.add(.{ .ipv4 = 0xc0000209 });
    var result = dns.Result{ .request = .{ .name = try queryName(), .family = .v4, .generation = generation }, .answer = answer, .completed_us = 100, .valid_until_us = 100, .deadline_ms = 4000 };
    try t.expectError(error.DnsCacheExpired, cache.prepare(result, 100));
    result.valid_until_us = 1000;
    const stage = try cache.prepare(result, 100);
    stage.publish();
    stage.release();
    result.request.name = try dns.Name.init("other.example");
    try t.expectError(error.DnsCacheLimit, cache.prepare(result, 100));
    result.answer.kind = .unknown;
    try t.expectError(error.InvalidDnsCheckpoint, cache.prepare(result, 100));
}
fn cacheAllocation(a: std.mem.Allocator) !void {
    var cache = try dns.Cache.init(a, generation, 1024);
    defer cache.deinit();
}
test "native dns: cache allocation failure leaves no owner" {
    try t.checkAllAllocationFailures(t.allocator, cacheAllocation, .{});
}

fn server() !struct { fd: std.posix.socket_t, address: std.net.Address } {
    const fd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC, 0);
    errdefer std.posix.close(fd);
    var address = try std.net.Address.parseIp("127.0.0.1", 0);
    try std.posix.bind(fd, &address.any, address.getOsSockLen());
    var length = address.getOsSockLen();
    try std.posix.getsockname(fd, &address.any, &length);
    return .{ .fd = fd, .address = address };
}
test "native dns: actual nonblocking loopback request verifies peer and original response" {
    const peer = try server();
    defer std.posix.close(peer.fd);
    var client = try dns.Client.init(peer.address, generation);
    defer client.deinit();
    const request = dns.Request{ .name = try queryName(), .family = .v4, .generation = generation };
    try client.begin(request, 0);
    try t.expect((try client.poll(0, 1000)) == null);
    var query: [512]u8 = undefined;
    var address: std.net.Address = undefined;
    var length: std.posix.socklen_t = @sizeOf(std.net.Address);
    const count = try std.posix.recvfrom(peer.fd, &query, 0, &address.any, &length);
    try t.expect(count >= 12);
    var packet = try Packet.init(try queryName(), .a, std.mem.readInt(u16, query[0..2], .big));
    try packet.record(1, 5, &.{ 192, 0, 2, 80 }, false);
    _ = try std.posix.sendto(peer.fd, packet.slice(), 0, &address.any, length);
    const result = (try client.poll(1, 2000)).?;
    try t.expectEqual(.positive, result.answer.kind);
    try t.expectEqual(@as(u32, 0xc0000250), result.answer.addresses[0].ipv4);
    try t.expectEqual(@as(i64, 5_002_000), result.valid_until_us);
    try t.expect(client.socket == null);
}
test "native dns: request timeout and stale generation never produce partial positive state" {
    const peer = try server();
    defer std.posix.close(peer.fd);
    var client = try dns.Client.init(peer.address, generation);
    defer client.deinit();
    var request = dns.Request{ .name = try queryName(), .family = .both, .generation = generation };
    request.generation[0] ^= 1;
    try t.expectError(error.DnsGenerationMismatch, client.begin(request, 0));
    request.generation = generation;
    try client.begin(request, 0);
    try t.expectError(error.DnsBusy, client.begin(request, 0));
    try t.expect((try client.poll(0, 1000)) == null);
    try t.expect((try client.poll(2000, 2_001_000)) == null);
    const result = (try client.poll(4000, 4_001_000)).?;
    try t.expectEqual(.unknown, result.answer.kind);
    try t.expectEqual(dns.Reason.timeout, result.answer.reason);
    try t.expectEqual(@as(u8, 0), result.answer.count);
    try t.expectError(error.DnsClockReversed, client.poll(3999, 4_001_000));
}

test "native dns: UDP truncation resumes bounded TCP framing with fragmented reply" {
    const peer = try server();
    defer std.posix.close(peer.fd);
    const listener = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(listener);
    try std.posix.bind(listener, &peer.address.any, peer.address.getOsSockLen());
    try std.posix.listen(listener, 1);
    var client = try dns.Client.init(peer.address, generation);
    defer client.deinit();
    try client.begin(.{ .name = try queryName(), .family = .v4, .generation = generation, .id = 94 }, 0);
    try t.expect((try client.poll(0, 100)) == null);
    var query: [512]u8 = undefined;
    var sender: std.net.Address = undefined;
    var length: std.posix.socklen_t = @sizeOf(std.net.Address);
    _ = try std.posix.recvfrom(peer.fd, &query, 0, &sender.any, &length);
    const id = std.mem.readInt(u16, query[0..2], .big);
    var packet = try Packet.init(try queryName(), .a, id);
    packet.bytes[2] |= 2;
    _ = try std.posix.sendto(peer.fd, packet.slice(), 0, &sender.any, length);
    try t.expect((try client.poll(1, 200)) == null);
    const stream = try std.posix.accept(listener, null, null, std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC);
    defer std.posix.close(stream);
    try t.expect((try client.poll(2, 300)) == null);
    try t.expect((try client.poll(3, 400)) == null);
    const got = try std.posix.recv(stream, &query, 0);
    try t.expectEqual(@as(usize, std.mem.readInt(u16, query[0..2], .big)) + 2, got);
    packet = try Packet.init(try queryName(), .a, id);
    try packet.record(1, 5, &.{ 192, 0, 2, 81 }, false);
    var framed: [4098]u8 = undefined;
    std.mem.writeInt(u16, framed[0..2], @intCast(packet.len), .big);
    @memcpy(framed[2 .. packet.len + 2], packet.slice());
    _ = try std.posix.send(stream, framed[0..1], std.posix.MSG.NOSIGNAL);
    try t.expect((try client.poll(4, 500)) == null);
    _ = try std.posix.send(stream, framed[1 .. packet.len + 2], std.posix.MSG.NOSIGNAL);
    try t.expect((try client.poll(5, 600)) == null);
    const result = (try client.poll(6, 700)).?;
    try t.expectEqual(.positive, result.answer.kind);
    try t.expectEqual(@as(u64, 94), result.request.id);
    try t.expectEqual(@as(u32, 0xc0000251), result.answer.addresses[0].ipv4);
}
test "native dns: unexpected sender and stale ID cannot complete current request" {
    const peer = try server();
    defer std.posix.close(peer.fd);
    const stranger = try server();
    defer std.posix.close(stranger.fd);
    var client = try dns.Client.init(peer.address, generation);
    defer client.deinit();
    try client.begin(.{ .name = try queryName(), .family = .v4, .generation = generation }, 0);
    _ = try client.poll(0, 100);
    var query: [512]u8 = undefined;
    var sender: std.net.Address = undefined;
    var length: std.posix.socklen_t = @sizeOf(std.net.Address);
    _ = try std.posix.recvfrom(peer.fd, &query, 0, &sender.any, &length);
    const id = std.mem.readInt(u16, query[0..2], .big);
    var packet = try Packet.init(try queryName(), .a, id);
    try packet.record(1, 5, &.{ 192, 0, 2, 81 }, false);
    _ = try std.posix.sendto(stranger.fd, packet.slice(), 0, &sender.any, length);
    try t.expect((try client.poll(1, 200)) == null);
    packet.bytes[0] ^= 1;
    _ = try std.posix.sendto(peer.fd, packet.slice(), 0, &sender.any, length);
    try t.expect((try client.poll(2, 300)) == null);
    packet.bytes[0] ^= 1;
    _ = try std.posix.sendto(peer.fd, packet.slice(), 0, &sender.any, length);
    try t.expectEqual(.positive, (try client.poll(3, 400)).?.answer.kind);
}
test "native dns: two-family answers preserve first expiry and never publish partial excess" {
    for ([_]u8{ 1, 16 }) |v4_count| {
        const peer = try server();
        defer std.posix.close(peer.fd);
        var client = try dns.Client.init(peer.address, generation);
        defer client.deinit();
        try client.begin(.{ .name = try queryName(), .family = .both, .generation = generation }, 0);
        _ = try client.poll(0, 100);
        var query: [512]u8 = undefined;
        var sender: std.net.Address = undefined;
        var length: std.posix.socklen_t = @sizeOf(std.net.Address);
        _ = try std.posix.recvfrom(peer.fd, &query, 0, &sender.any, &length);
        var packet = try Packet.init(try queryName(), .a, std.mem.readInt(u16, query[0..2], .big));
        for (0..v4_count) |i| try packet.record(1, 3, &.{ 192, 0, 2, @intCast(i + 1) }, false);
        _ = try std.posix.sendto(peer.fd, packet.slice(), 0, &sender.any, length);
        try t.expect((try client.poll(1, 200)) == null);
        _ = try client.poll(2, 300);
        length = @sizeOf(std.net.Address);
        _ = try std.posix.recvfrom(peer.fd, &query, 0, &sender.any, &length);
        packet = try Packet.init(try queryName(), .aaaa, std.mem.readInt(u16, query[0..2], .big));
        try packet.record(28, 20, &.{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, false);
        _ = try std.posix.sendto(peer.fd, packet.slice(), 0, &sender.any, length);
        const result = (try client.poll(1000, 1_000_100)).?;
        if (v4_count == 1) {
            try t.expectEqual(.positive, result.answer.kind);
            try t.expectEqual(@as(u8, 2), result.answer.count);
            try t.expectEqual(@as(i64, 3_000_200), result.valid_until_us);
        } else {
            try t.expectEqual(.unknown, result.answer.kind);
            try t.expectEqual(dns.Reason.capacity, result.answer.reason);
            try t.expectEqual(@as(u8, 0), result.answer.count);
        }
    }
}
test "native dns: earlier zero TTL expires during family wait without reusable subject evidence" {
    const peer = try server();
    defer std.posix.close(peer.fd);
    var client = try dns.Client.init(peer.address, generation);
    defer client.deinit();
    try client.begin(.{ .name = try queryName(), .family = .both, .generation = generation }, 0);
    _ = try client.poll(0, 100);
    var query: [512]u8 = undefined;
    var sender: std.net.Address = undefined;
    var length: std.posix.socklen_t = @sizeOf(std.net.Address);
    _ = try std.posix.recvfrom(peer.fd, &query, 0, &sender.any, &length);
    var packet = try Packet.init(try queryName(), .a, std.mem.readInt(u16, query[0..2], .big));
    try packet.record(1, 0, &.{ 192, 0, 2, 1 }, false);
    _ = try std.posix.sendto(peer.fd, packet.slice(), 0, &sender.any, length);
    _ = try client.poll(1, 200);
    _ = try client.poll(2, 300);
    length = @sizeOf(std.net.Address);
    _ = try std.posix.recvfrom(peer.fd, &query, 0, &sender.any, &length);
    packet = try Packet.init(try queryName(), .aaaa, std.mem.readInt(u16, query[0..2], .big));
    try packet.record(28, 20, &.{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, false);
    _ = try std.posix.sendto(peer.fd, packet.slice(), 0, &sender.any, length);
    const result = (try client.poll(3, 400)).?;
    try t.expectEqual(.unknown, result.answer.kind);
    try t.expectEqual(dns.Reason.expired, result.answer.reason);
}
test "native dns: every proper packet prefix refuses and hostile typed cache name cannot panic" {
    var packet = try Packet.init(try queryName(), .a, 55);
    try packet.record(1, 60, &.{ 192, 0, 2, 80 }, false);
    for (0..packet.len) |length| {
        _ = dns.parseReply(packet.slice()[0..length], try queryName(), .a, 55) catch continue;
        return error.AcceptedPartialFixture;
    }
    var cache = try dns.Cache.init(t.allocator, generation, 1);
    defer cache.deinit();
    var request = dns.Request{ .name = try queryName(), .family = .v4, .generation = generation };
    request.name.text.len = 254;
    try t.expectError(error.InvalidSubject, cache.lookup(request, 100));
    try t.expectError(error.InvalidSubject, cache.revision(request));
}

test "native dns: live completion binds logical token and zero TTL allows only immediate preparation" {
    const request = dns.Request{ .name = try queryName(), .family = .v4, .generation = generation, .id = 9 };
    var answer = dns.Answer{ .kind = .positive, .canonical = request.name };
    try answer.add(.{ .ipv4 = 0xc0000250 });
    const result = dns.Result{ .request = request, .answer = answer, .completed_us = 100, .valid_until_us = 100, .deadline_ms = 4000 };
    try result.validateCompletion(request, 1, 100);
    try t.expectError(error.DnsResultExpired, result.validateCompletion(request, 2, 101));
    try t.expectError(error.DnsResultExpired, result.validateCompletion(request, 4000, 100));
    var foreign = request;
    foreign.id += 1;
    try t.expectError(error.DnsRequestMismatch, result.validateCompletion(foreign, 1, 100));
}

test "native dns: nonrecursive negatives and referrals never prove exclusions" {
    for ([_]u16{ 0x8100, 0x8080, 0x8000 }) |flags| {
        var packet = try Packet.init(try queryName(), .a, 61);
        std.mem.writeInt(u16, packet.bytes[2..4], flags, .big);
        var soa = [_]u8{0} ** 22;
        std.mem.writeInt(u32, soa[18..22], 5, .big);
        try packet.record(6, 5, &soa, true);
        try t.expectEqual(.unknown, (try dns.parseReply(packet.slice(), try queryName(), .a, 61)).kind);
    }
    var referral = try Packet.init(try queryName(), .a, 62);
    const server_name = [_]u8{ 2, 'n', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    try referral.record(2, 60, &server_name, true);
    try t.expectEqual(.unknown, (try dns.parseReply(referral.slice(), try queryName(), .a, 62)).kind);
}
test "native dns: supplied TTL cannot extend upstream validity through prepare or restart" {
    var cache = try dns.Cache.init(t.allocator, generation, 1);
    defer cache.deinit();
    const request = dns.Request{ .name = try queryName(), .family = .v4, .generation = generation, .id = 16 };
    var answer = dns.Answer{ .kind = .positive, .canonical = request.name, .ttl_seconds = 1 };
    try answer.add(.{ .ipv4 = 0xc0000250 });
    var result = dns.Result{ .request = request, .answer = answer, .completed_us = 100, .valid_until_us = 300_000_100, .deadline_ms = 4000 };
    try t.expectError(error.InvalidDnsCheckpoint, cache.prepare(result, 100));
    try t.expectError(error.InvalidDnsCheckpoint, result.validateCompletion(request, 1, 100));
    result.valid_until_us = 1_000_100;
    const stage = try cache.prepare(result, 100);
    var checkpoint = stage.bytes;
    stage.release();
    var restored = try dns.Cache.init(t.allocator, generation, 1);
    defer restored.deinit();
    const load = try restored.prepareRestore(&checkpoint);
    load.publish();
    load.release();
    try t.expectEqual(@as(u32, 1), (try restored.lookup(request, 100)).?.result.answer.ttl_seconds);
    std.mem.writeInt(i64, checkpoint[576..584], 2_000_100, .little);
    try t.expectError(error.InvalidDnsCheckpoint, cache.prepareRestore(&checkpoint));
}
