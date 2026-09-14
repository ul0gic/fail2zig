// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Bounded DNS packets and one nonblocking logical request. No libc resolver,
//! shell, implicit nameserver discovery or unbounded packet/cache allocation.
const std = @import("std");
pub const Name = @import("native_rules.zig").Hostname;
const Text = @import("native_rules.zig").Text;
pub const Ip = @import("shared").IpAddress;
pub const version: u16 = 1;
pub const max_answers = 16;
pub const max_aliases = 8;
pub const max_packet = 65535;
pub const max_udp = 4096;
pub const Family = enum { v4, v6, both };
pub const Question = enum(u16) { a = 1, aaaa = 28 };
pub const Reason = enum { none, timeout, truncated, invalid, unavailable, server, incomplete, capacity, cancelled, expired };
pub const Answer = struct {
    kind: enum { positive, negative, alias, unknown },
    reason: Reason = .none,
    addresses: [max_answers]Ip = undefined,
    count: u8 = 0,
    ttl_seconds: u32 = 0,
    canonical: Name,
    aliases: u8 = 0,
    pub fn add(self: *Answer, ip: Ip) !void {
        for (self.addresses[0..self.count]) |existing| if (existing.eql(ip)) return;
        if (self.count == max_answers) return error.AnswerLimit;
        self.addresses[self.count] = ip;
        self.count += 1;
    }
};
/// `id` is the coordinator's logical request token, echoed in live results.
/// Cache identity excludes that token; restored/cache results are dependencies,
/// never unsolicited completions of a currently pending request.
pub const Request = struct { name: Name, family: Family, generation: [32]u8, id: u64 = 0 };
pub const Result = struct {
    request: Request,
    answer: Answer,
    completed_us: i64,
    valid_until_us: i64,
    /// Same total monotonic deadline survives aliases, families and retry.
    deadline_ms: u64,
    /// Called after scheduler/storage waits before consuming a live reply.
    /// Cache snapshots use their own revision/deadline dependency instead.
    pub fn validateCompletion(self: Result, expected: Request, now_ms: u64, now_us: i64) !void {
        try expected.name.validate();
        try self.request.name.validate();
        if (self.request.id != expected.id or self.request.family != expected.family or
            !std.mem.eql(u8, &self.request.generation, &expected.generation) or
            !std.mem.eql(u8, self.request.name.slice(), expected.name.slice())) return error.DnsRequestMismatch;
        if (now_us < self.completed_us) return error.DnsClockReversed;
        if (now_ms >= self.deadline_ms) return error.DnsResultExpired;
        if (self.answer.kind == .positive or self.answer.kind == .negative) {
            try validateResult(self);
            // A zero-TTL subject answer has one immediate preparation only.
            if (now_us > self.valid_until_us or (self.valid_until_us != self.completed_us and now_us == self.valid_until_us)) return error.DnsResultExpired;
        }
    }
};
const Budget = struct {
    left: usize = 64 * 1024,
    fn spend(self: *Budget, count: usize) !void {
        if (count > self.left) return error.DnsWorkLimit;
        self.left -= count;
    }
};
fn u16be(packet: []const u8, at: usize) !u16 {
    if (at > packet.len or packet.len - at < 2) return error.InvalidDnsPacket;
    return std.mem.readInt(u16, packet[at..][0..2], .big);
}
fn u32be(packet: []const u8, at: usize) !u32 {
    if (at > packet.len or packet.len - at < 4) return error.InvalidDnsPacket;
    return std.mem.readInt(u32, packet[at..][0..4], .big);
}
/// Names in SOA/authority may be root. Every pointer chain, label byte and
/// expanded name is bounded; compression never makes a slice escape the packet.
fn readName(packet: []const u8, position: *usize, budget: *Budget) !Text(253) {
    var out: Text(253) = .{};
    var at = position.*;
    var jumped = false;
    var seen: [16]usize = undefined;
    var pointers: usize = 0;
    while (true) {
        try budget.spend(1);
        if (at >= packet.len) return error.InvalidDnsPacket;
        const length = packet[at];
        if (length & 0xc0 == 0xc0) {
            if (at + 1 >= packet.len or pointers == seen.len) return error.InvalidDnsPacket;
            const target = ((@as(usize, length) & 0x3f) << 8) | packet[at + 1];
            if (target < 12 or target >= at) return error.InvalidDnsPacket;
            for (seen[0..pointers]) |prior| if (prior == target) return error.InvalidDnsPacket;
            seen[pointers] = target;
            pointers += 1;
            if (!jumped) position.* = at + 2;
            jumped = true;
            at = target;
            continue;
        }
        if (length & 0xc0 != 0) return error.InvalidDnsPacket;
        at += 1;
        if (length == 0) {
            if (!jumped) position.* = at;
            return out;
        }
        if (length > 63 or length > packet.len - at) return error.InvalidDnsPacket;
        if (out.len != 0) {
            if (out.len == out.bytes.len) return error.InvalidDnsPacket;
            out.bytes[out.len] = '.';
            out.len += 1;
        }
        if (@as(usize, out.len) + length > out.bytes.len) return error.InvalidDnsPacket;
        try budget.spend(length);
        for (packet[at .. at + length]) |byte| {
            // Host/zone names are ASCII labels under the admitted native route.
            if (!std.ascii.isAlphanumeric(byte) and byte != '-') return error.InvalidDnsPacket;
            out.bytes[out.len] = std.ascii.toLower(byte);
            out.len += 1;
        }
        at += length;
    }
}
pub fn encodeQuery(name: Name, question: Question, id: u16, output: []u8) ![]const u8 {
    try name.validate();
    if (output.len < 12 + name.slice().len + 2 + 4) return error.DnsBufferSmall;
    @memset(output[0..12], 0);
    std.mem.writeInt(u16, output[0..2], id, .big);
    output[2] = 1; // recursion desired
    output[5] = 1;
    var position: usize = 12;
    var labels = std.mem.splitScalar(u8, name.slice(), '.');
    while (labels.next()) |label| {
        output[position] = @intCast(label.len);
        position += 1;
        @memcpy(output[position .. position + label.len], label);
        position += label.len;
    }
    output[position] = 0;
    position += 1;
    std.mem.writeInt(u16, output[position..][0..2], @intFromEnum(question), .big);
    position += 2;
    std.mem.writeInt(u16, output[position..][0..2], 1, .big);
    position += 2;
    return output[0..position];
}
const Record = struct { name: Text(253), kind: u16, class: u16, ttl: u32, offset: usize, length: usize, section: enum { answer, authority, additional } };
fn suffix(name: []const u8, zone: []const u8) bool {
    return zone.len == 0 or std.mem.eql(u8, name, zone) or (name.len > zone.len and name[name.len - zone.len - 1] == '.' and std.mem.endsWith(u8, name, zone));
}
pub fn parseReply(packet: []const u8, name: Name, question: Question, id: u16) !Answer {
    try name.validate();
    if (packet.len < 12 or packet.len > max_packet) return error.InvalidDnsPacket;
    if (try u16be(packet, 0) != id) return error.DnsRequestMismatch;
    const flags = try u16be(packet, 2);
    if (flags & 0x8000 == 0 or flags & 0x7800 != 0 or flags & 0x0040 != 0 or try u16be(packet, 4) != 1) return error.InvalidDnsPacket;
    var budget: Budget = .{};
    var position: usize = 12;
    const query_name = try readName(packet, &position, &budget);
    if (!std.mem.eql(u8, query_name.slice(), name.slice()) or try u16be(packet, position) != @intFromEnum(question) or try u16be(packet, position + 2) != 1) return error.DnsRequestMismatch;
    position += 4;
    if (flags & 0x0200 != 0) return .{ .kind = .unknown, .reason = .truncated, .canonical = name };
    const rcode = flags & 0xf;
    if (rcode != 0 and rcode != 3) return .{ .kind = .unknown, .reason = .server, .canonical = name };
    const answers = try u16be(packet, 6);
    const authority = try u16be(packet, 8);
    const additional = try u16be(packet, 10);
    const total = @as(usize, answers) + authority + additional;
    if (total > 128) return error.DnsRecordLimit;
    var records: [128]Record = undefined;
    for (records[0..total], 0..) |*record, index| {
        const owner = try readName(packet, &position, &budget);
        if (position > packet.len or packet.len - position < 10) return error.InvalidDnsPacket;
        record.* = .{ .name = owner, .kind = try u16be(packet, position), .class = try u16be(packet, position + 2), .ttl = try u32be(packet, position + 4), .offset = position + 10, .length = try u16be(packet, position + 8), .section = if (index < answers) .answer else if (index < @as(usize, answers) + authority) .authority else .additional };
        position += 10;
        if (record.length > packet.len - position) return error.InvalidDnsPacket;
        position += record.length;
    }
    if (position != packet.len) return error.InvalidDnsPacket;
    var result = Answer{ .kind = .unknown, .reason = .incomplete, .canonical = name, .ttl_seconds = 300 };
    var visited: [max_aliases + 1]Name = undefined;
    visited[0] = name;
    while (true) {
        var alias: ?Name = null;
        var alias_ttl: u32 = 300;
        for (records[0..total]) |record| {
            try budget.spend(1 + record.name.len + result.canonical.text.len);
            if (record.section != .answer or record.class != 1 or !std.mem.eql(u8, record.name.slice(), result.canonical.slice())) continue;
            if (record.kind == 5) {
                if (alias != null) return error.InvalidDnsPacket;
                var offset = record.offset;
                const target = try readName(packet, &offset, &budget);
                if (offset != record.offset + record.length) return error.InvalidDnsPacket;
                alias = Name.init(target.slice()) catch return error.InvalidDnsPacket;
                alias_ttl = @min(300, record.ttl);
            } else if (record.kind == @intFromEnum(question)) {
                if (question == .a) {
                    if (record.length != 4) return error.InvalidDnsPacket;
                    try result.add(.{ .ipv4 = try u32be(packet, record.offset) });
                } else {
                    if (record.length != 16) return error.InvalidDnsPacket;
                    const address = Ip.fromIpv6Bits(std.mem.readInt(u128, packet[record.offset..][0..16], .big)) catch return error.InvalidDnsPacket;
                    if (address != .ipv6) return error.InvalidDnsPacket;
                    try result.add(address);
                }
                result.ttl_seconds = @min(result.ttl_seconds, record.ttl);
            }
        }
        if (result.count != 0) {
            if (alias != null or rcode != 0) return error.InvalidDnsPacket;
            result.kind = .positive;
            result.reason = .none;
            return result;
        }
        if (alias) |target| {
            if (result.aliases == max_aliases) return error.DnsAliasLimit;
            for (visited[0 .. @as(usize, result.aliases) + 1]) |seen| if (std.mem.eql(u8, seen.slice(), target.slice())) return error.InvalidDnsPacket;
            result.aliases += 1;
            visited[result.aliases] = target;
            result.canonical = target;
            result.ttl_seconds = @min(result.ttl_seconds, alias_ttl);
            continue;
        }
        var negative_ttl: ?u32 = null;
        for (records[0..total]) |record| {
            if (record.section != .authority or record.class != 1 or record.kind != 6 or !suffix(result.canonical.slice(), record.name.slice())) continue;
            var offset = record.offset;
            _ = try readName(packet, &offset, &budget);
            _ = try readName(packet, &offset, &budget);
            if (offset > record.offset + record.length or record.offset + record.length - offset != 20) return error.InvalidDnsPacket;
            const ttl = @min(@min(record.ttl, try u32be(packet, offset + 16)), 30);
            negative_ttl = @min(negative_ttl orelse ttl, ttl);
        }
        if (negative_ttl) |ttl| {
            // A recursive cache exclusion requires the configured resolver to
            // echo RD and advertise RA; a referral is not negative evidence.
            if (flags & 0x0180 != 0x0180) return .{ .kind = .unknown, .reason = .incomplete, .canonical = name };
            result.kind = .negative;
            result.reason = .none;
            result.ttl_seconds = @min(result.ttl_seconds, ttl);
            return result;
        }
        if (result.aliases != 0 and rcode == 0) {
            result.kind = .alias;
            result.reason = .none;
        }
        return result;
    }
}

pub const Client = struct {
    server: std.net.Address,
    generation: [32]u8,
    socket: ?std.posix.socket_t = null,
    phase: enum { idle, udp_send, udp_receive, tcp_connect, tcp_send, tcp_receive, complete } = .idle,
    request: Request = undefined,
    result: ?Result = null,
    query_name: Name = undefined,
    question: Question = .a,
    query_id: u16 = 0,
    started_ms: u64 = 0,
    deadline_ms: u64 = 0,
    attempt_deadline_ms: u64 = 0,
    last_ms: u64 = 0,
    last_us: ?i64 = null,
    aggregate_expiry_us: ?i64 = null,
    retried: bool = false,
    aliases: u8 = 0,
    query_count: u8 = 0,
    aggregate: Answer = undefined,
    tx: [512]u8 = undefined,
    tx_len: usize = 0,
    tx_sent: usize = 0,
    rx: [max_packet + 2]u8 = undefined,
    rx_len: usize = 0,
    tcp_expected: ?usize = null,

    pub fn init(server: std.net.Address, generation: [32]u8) !Client {
        if ((server.any.family != std.posix.AF.INET and server.any.family != std.posix.AF.INET6) or server.getPort() == 0) return error.InvalidNameserver;
        return .{ .server = server, .generation = generation };
    }
    pub fn deinit(self: *Client) void {
        self.closeSocket();
        self.phase = .idle;
    }
    fn closeSocket(self: *Client) void {
        if (self.socket) |fd| std.posix.close(fd);
        self.socket = null;
    }
    pub fn begin(self: *Client, request: Request, now_ms: u64) !void {
        if (self.phase != .idle and self.phase != .complete) return error.DnsBusy;
        try request.name.validate();
        if (!std.mem.eql(u8, &request.generation, &self.generation)) return error.DnsGenerationMismatch;
        self.closeSocket();
        self.result = null;
        self.request = request;
        self.started_ms = now_ms;
        self.last_ms = now_ms;
        self.last_us = null;
        self.aggregate_expiry_us = null;
        self.deadline_ms = std.math.add(u64, now_ms, 4000) catch return error.DnsClockOverflow;
        self.retried = false;
        self.aliases = 0;
        self.query_count = 0;
        self.question = if (request.family == .v6) .aaaa else .a;
        self.aggregate = .{ .kind = .negative, .canonical = request.name, .ttl_seconds = 300 };
        try self.nextQuestion(request.name, now_ms);
    }
    fn nextQuestion(self: *Client, name: Name, now_ms: u64) !void {
        self.closeSocket();
        if (self.query_count >= 20) return error.DnsQueryLimit;
        self.query_count += 1;
        self.query_name = name;
        self.query_id = std.crypto.random.int(u16);
        const query = try encodeQuery(name, self.question, self.query_id, self.tx[2..]);
        self.tx_len = query.len;
        self.tx_sent = 0;
        self.rx_len = 0;
        self.tcp_expected = null;
        self.attempt_deadline_ms = @min(self.deadline_ms, std.math.add(u64, now_ms, 2000) catch return error.DnsClockOverflow);
        self.socket = try std.posix.socket(self.server.any.family, std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC, 0);
        self.phase = .udp_send;
    }
    fn unknown(self: *Client, reason: Reason, now_us: i64) void {
        self.finish(.{ .kind = .unknown, .reason = reason, .canonical = self.request.name }, now_us);
    }
    fn finish(self: *Client, answer: Answer, now_us: i64) void {
        self.closeSocket();
        const own_expiry = std.math.add(i64, now_us, @as(i64, answer.ttl_seconds) * 1_000_000) catch now_us;
        const expiry = if (answer.kind == .positive or answer.kind == .negative) @min(own_expiry, self.aggregate_expiry_us orelse own_expiry) else now_us;
        self.result = .{ .request = self.request, .answer = answer, .completed_us = now_us, .valid_until_us = expiry, .deadline_ms = self.deadline_ms };
        self.phase = .complete;
    }
    /// Exactly one bounded readiness operation per turn. Caller services other
    /// sources/health between calls; no stage or SQL transaction spans this wait.
    pub fn poll(self: *Client, now_ms: u64, now_us: i64) !?Result {
        if (self.phase == .idle) return error.DnsNotStarted;
        if (now_ms < self.last_ms) return error.DnsClockReversed;
        if (self.last_us) |prior| if (now_us < prior) return error.DnsClockReversed;
        self.last_ms = now_ms;
        self.last_us = now_us;
        if (self.phase == .complete) return self.result;
        if (now_ms >= self.deadline_ms) {
            self.unknown(.timeout, now_us);
            return self.result;
        }
        if (now_ms >= self.attempt_deadline_ms) {
            if (self.retried) {
                self.unknown(.timeout, now_us);
                return self.result;
            }
            self.retried = true;
            self.nextQuestion(self.query_name, now_ms) catch {
                self.unknown(.unavailable, now_us);
            };
            return self.result;
        }
        self.step(now_ms, now_us) catch |err| switch (err) {
            error.WouldBlock, error.DnsRequestMismatch => {},
            error.AnswerLimit, error.DnsAliasLimit, error.DnsRecordLimit, error.DnsQueryLimit, error.DnsWorkLimit => self.unknown(.capacity, now_us),
            error.InvalidDnsPacket => self.unknown(.invalid, now_us),
            else => self.unknown(.unavailable, now_us),
        };
        return self.result;
    }
    fn step(self: *Client, now_ms: u64, now_us: i64) !void {
        const fd = self.socket orelse return error.DnsNotStarted;
        switch (self.phase) {
            .udp_send => {
                const sent = try std.posix.sendto(fd, self.tx[2 .. 2 + self.tx_len], 0, &self.server.any, self.server.getOsSockLen());
                if (sent != self.tx_len) return error.InvalidDnsPacket;
                self.phase = .udp_receive;
            },
            .udp_receive => {
                var sender: std.net.Address = undefined;
                var length: std.posix.socklen_t = @sizeOf(std.net.Address);
                const count = try std.posix.recvfrom(fd, self.rx[0..max_udp], std.posix.MSG.TRUNC, &sender.any, &length);
                if (length != self.server.getOsSockLen() or sender.any.family != self.server.any.family or !sender.eql(self.server)) return error.DnsRequestMismatch;
                if (count > max_udp) return error.InvalidDnsPacket;
                const answer = try parseReply(self.rx[0..count], self.query_name, self.question, self.query_id);
                if (answer.kind == .unknown and answer.reason == .truncated) {
                    self.closeSocket();
                    self.socket = try std.posix.socket(self.server.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC, 0);
                    self.phase = .tcp_connect;
                    std.posix.connect(self.socket.?, &self.server.any, self.server.getOsSockLen()) catch |err| if (err != error.WouldBlock and err != error.ConnectionPending) return err;
                    std.mem.writeInt(u16, self.tx[0..2], @intCast(self.tx_len), .big);
                } else try self.accept(answer, now_ms, now_us);
            },
            .tcp_connect => {
                var ready = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
                if (try std.posix.poll(&ready, 0) == 0) return;
                try std.posix.getsockoptError(fd);
                self.phase = .tcp_send;
            },
            .tcp_send => {
                self.tx_sent += try std.posix.send(fd, self.tx[self.tx_sent .. self.tx_len + 2], std.posix.MSG.NOSIGNAL);
                if (self.tx_sent == self.tx_len + 2) self.phase = .tcp_receive;
            },
            .tcp_receive => {
                const wanted = self.tcp_expected orelse 2;
                const count = try std.posix.recv(fd, self.rx[self.rx_len..wanted], 0);
                if (count == 0) return error.InvalidDnsPacket;
                self.rx_len += count;
                if (self.tcp_expected == null and self.rx_len == 2) {
                    const length = try u16be(&self.rx, 0);
                    if (length < 12) return error.InvalidDnsPacket;
                    self.tcp_expected = @as(usize, length) + 2;
                } else if (self.tcp_expected != null and self.rx_len == wanted) {
                    const answer = try parseReply(self.rx[2..wanted], self.query_name, self.question, self.query_id);
                    try self.accept(answer, now_ms, now_us);
                }
            },
            .idle, .complete => return error.DnsNotStarted,
        }
    }
    fn accept(self: *Client, answer: Answer, now_ms: u64, now_us: i64) !void {
        if (@as(usize, self.aliases) + answer.aliases > max_aliases) return error.DnsAliasLimit;
        self.aliases += answer.aliases;
        if (answer.kind == .unknown) {
            self.finish(answer, now_us);
            return;
        }
        self.aggregate.ttl_seconds = @min(self.aggregate.ttl_seconds, answer.ttl_seconds);
        const expires = std.math.add(i64, now_us, @as(i64, answer.ttl_seconds) * 1_000_000) catch return error.DnsClockOverflow;
        self.aggregate_expiry_us = @min(self.aggregate_expiry_us orelse expires, expires);
        if (answer.kind == .alias) {
            try self.nextQuestion(answer.canonical, now_ms);
            return;
        }
        for (answer.addresses[0..answer.count]) |ip| try self.aggregate.add(ip);
        if (self.request.family == .both and self.question == .a) {
            self.question = .aaaa;
            try self.nextQuestion(self.request.name, now_ms);
            return;
        }
        self.aggregate.kind = if (self.aggregate.count == 0) .negative else .positive;
        self.aggregate.reason = .none;
        if (self.aggregate_expiry_us.? < now_us) {
            self.unknown(.expired, now_us);
            return;
        }
        self.finish(self.aggregate, now_us);
    }
};

pub const cache_entry_bytes = 600;
pub const CacheEntry = struct { result: Result, revision: u64 };
pub const Cache = struct {
    allocator: std.mem.Allocator,
    generation: [32]u8,
    // Keep canonical wire bytes in the cache; detached expanded answers exist
    // only for the current consumer. All 1024 slots fit below the 1 MiB bound.
    entries: []?[cache_entry_bytes]u8,
    in_flight: bool = false,
    pub const Stage = struct {
        owner: *Cache,
        index: usize,
        expected_revision: u64,
        entry: CacheEntry,
        bytes: [cache_entry_bytes]u8,
        pub fn checkpoint(self: *const Stage) []const u8 {
            return &self.bytes;
        }
        pub fn publish(self: *const Stage) void {
            self.owner.entries[self.index] = self.bytes;
        }
        pub fn release(self: *const Stage) void {
            self.owner.in_flight = false;
        }
    };
    pub fn init(allocator: std.mem.Allocator, generation: [32]u8, capacity: usize) !Cache {
        if (capacity == 0 or capacity > 1024 or capacity * @sizeOf(?[cache_entry_bytes]u8) > 1024 * 1024) return error.DnsCacheLimit;
        const entries = try allocator.alloc(?[cache_entry_bytes]u8, capacity);
        @memset(entries, null);
        return .{ .allocator = allocator, .generation = generation, .entries = entries };
    }
    pub fn deinit(self: *Cache) void {
        self.allocator.free(self.entries);
    }
    fn indexOf(self: *const Cache, request: Request) ?usize {
        const family: u8 = switch (request.family) {
            .v4 => 4,
            .v6 => 6,
            .both => 10,
        };
        for (self.entries, 0..) |*slot, index| if (slot.*) |*bytes| {
            const length = std.mem.readInt(u16, bytes[40..42], .little);
            if (bytes[6] == family and length == request.name.text.len and std.mem.eql(u8, bytes[42 .. 42 + length], request.name.slice())) return index;
        };
        return null;
    }
    /// Detached snapshot. Missing/expired state never grants an exclusion. The
    /// caller records a dependency even for an absent revision-zero result.
    pub fn lookup(self: *const Cache, request: Request, now_us: i64) !?CacheEntry {
        try request.name.validate();
        if (!std.mem.eql(u8, &request.generation, &self.generation)) return error.DnsGenerationMismatch;
        const index = self.indexOf(request) orelse return null;
        const entry = try decodeEntry(&self.entries[index].?);
        if (now_us < entry.result.completed_us) return error.DnsClockReversed;
        if (now_us >= entry.result.valid_until_us) return null;
        return entry;
    }
    pub fn revision(self: *const Cache, request: Request) !u64 {
        try request.name.validate();
        if (!std.mem.eql(u8, &request.generation, &self.generation)) return error.DnsGenerationMismatch;
        return if (self.indexOf(request)) |index| std.mem.readInt(u64, self.entries[index].?[584..592], .little) else 0;
    }
    /// Updating the same key preserves monotonic revision. New keys never evict
    /// another key: retirement/reclamation needs the coordinator's durable pins.
    pub fn prepare(self: *Cache, result: Result, now_us: i64) !Stage {
        if (self.in_flight) return error.DnsCacheBusy;
        try validateResult(result);
        if (!std.mem.eql(u8, &result.request.generation, &self.generation)) return error.DnsGenerationMismatch;
        if (now_us < result.completed_us) return error.DnsClockReversed;
        if (now_us >= result.valid_until_us) return error.DnsCacheExpired;
        var index = self.indexOf(result.request);
        if (index == null) for (self.entries, 0..) |entry, i| {
            if (entry == null) {
                index = i;
                break;
            }
        };
        const slot = index orelse return error.DnsCacheLimit;
        const expected = if (self.entries[slot]) |bytes| std.mem.readInt(u64, bytes[584..592], .little) else 0;
        if (expected >= std.math.maxInt(i64)) return error.DnsRevisionOverflow;
        var stage = Stage{ .owner = self, .index = slot, .expected_revision = expected, .entry = .{ .result = result, .revision = expected + 1 }, .bytes = undefined };
        try encodeEntry(stage.entry, &stage.bytes);
        self.in_flight = true;
        return stage;
    }
    /// Coherent restore supplies each persisted key once before publication.
    /// Unknown, malformed and foreign data never falls back to an empty cache.
    pub fn prepareRestore(self: *Cache, bytes: []const u8) !Stage {
        if (self.in_flight) return error.DnsCacheBusy;
        const entry = try decodeEntry(bytes);
        if (!std.mem.eql(u8, &entry.result.request.generation, &self.generation)) return error.DnsGenerationMismatch;
        if (self.indexOf(entry.result.request) != null) return error.DuplicateDnsCheckpoint;
        var index: ?usize = null;
        for (self.entries, 0..) |slot, i| if (slot == null) {
            index = i;
            break;
        };
        var stage = Stage{ .owner = self, .index = index orelse return error.DnsCacheLimit, .expected_revision = 0, .entry = entry, .bytes = undefined };
        @memcpy(&stage.bytes, bytes);
        self.in_flight = true;
        return stage;
    }
};
fn validateResult(result: Result) !void {
    try result.request.name.validate();
    if (result.answer.kind != .positive and result.answer.kind != .negative) return error.InvalidDnsCheckpoint;
    if (result.answer.count > max_answers or (result.answer.kind == .positive) != (result.answer.count != 0) or result.answer.reason != .none) return error.InvalidDnsCheckpoint;
    const maximum: i64 = if (result.answer.kind == .positive) 300_000_000 else 30_000_000;
    const ttl_us = @as(i64, result.answer.ttl_seconds) * 1_000_000;
    if (ttl_us > maximum or result.valid_until_us < result.completed_us or @as(i128, result.valid_until_us) > @as(i128, result.completed_us) + ttl_us) return error.InvalidDnsCheckpoint;
    for (result.answer.addresses[0..result.answer.count], 0..) |ip, i| {
        if ((result.request.family == .v4 and ip != .ipv4) or (result.request.family == .v6 and ip != .ipv6)) return error.InvalidDnsCheckpoint;
        if (ip == .ipv6) {
            const canonical = Ip.fromIpv6Bits(ip.ipv6) catch return error.InvalidDnsCheckpoint;
            if (!canonical.eql(ip)) return error.InvalidDnsCheckpoint;
        }
        for (result.answer.addresses[0..i]) |prior| if (prior.eql(ip)) return error.InvalidDnsCheckpoint;
    }
}
fn encodeEntry(entry: CacheEntry, bytes: *[cache_entry_bytes]u8) !void {
    try validateResult(entry.result);
    if (entry.revision == 0 or entry.revision > std.math.maxInt(i64)) return error.InvalidDnsCheckpoint;
    @memset(bytes, 0);
    @memcpy(bytes[0..4], "F2ND");
    std.mem.writeInt(u16, bytes[4..6], version, .little);
    bytes[6] = switch (entry.result.request.family) {
        .v4 => 4,
        .v6 => 6,
        .both => 10,
    };
    bytes[7] = if (entry.result.answer.kind == .positive) 1 else 2;
    @memcpy(bytes[8..40], &entry.result.request.generation);
    std.mem.writeInt(u16, bytes[40..42], entry.result.request.name.text.len, .little);
    @memcpy(bytes[42..295], &entry.result.request.name.text.bytes);
    bytes[295] = entry.result.answer.count;
    for (entry.result.answer.addresses[0..entry.result.answer.count], 0..) |ip, i| {
        const out = bytes[296 + i * 17 ..][0..17];
        switch (ip) {
            .ipv4 => |v| {
                out[0] = 4;
                std.mem.writeInt(u32, out[1..5], v, .big);
            },
            .ipv6 => |v| {
                out[0] = 6;
                std.mem.writeInt(u128, out[1..17], v, .big);
            },
        }
    }
    std.mem.writeInt(i64, bytes[568..576], entry.result.completed_us, .little);
    std.mem.writeInt(i64, bytes[576..584], entry.result.valid_until_us, .little);
    std.mem.writeInt(u64, bytes[584..592], entry.revision, .little);
    std.mem.writeInt(u32, bytes[592..596], entry.result.answer.ttl_seconds, .little);
}
fn decodeEntry(bytes: []const u8) !CacheEntry {
    if (bytes.len != cache_entry_bytes or !std.mem.eql(u8, bytes[0..4], "F2ND")) return error.InvalidDnsCheckpoint;
    if (std.mem.readInt(u16, bytes[4..6], .little) != version) return error.UnsupportedDnsCheckpoint;
    const family: Family = switch (bytes[6]) {
        4 => .v4,
        6 => .v6,
        10 => .both,
        else => return error.InvalidDnsCheckpoint,
    };
    if (bytes[7] != 1 and bytes[7] != 2 or bytes[295] > max_answers or !std.mem.allEqual(u8, bytes[596..], 0)) return error.InvalidDnsCheckpoint;
    const length = std.mem.readInt(u16, bytes[40..42], .little);
    if (length == 0 or length > 253 or !std.mem.allEqual(u8, bytes[42 + @as(usize, length) .. 295], 0)) return error.InvalidDnsCheckpoint;
    const name = Name.init(bytes[42 .. 42 + length]) catch return error.InvalidDnsCheckpoint;
    if (!std.mem.eql(u8, name.slice(), bytes[42 .. 42 + length])) return error.InvalidDnsCheckpoint;
    var answer = Answer{ .kind = if (bytes[7] == 1) .positive else .negative, .canonical = name, .ttl_seconds = std.mem.readInt(u32, bytes[592..596], .little) };
    for (0..max_answers) |i| {
        const input = bytes[296 + i * 17 ..][0..17];
        if (i >= bytes[295]) {
            if (!std.mem.allEqual(u8, input, 0)) return error.InvalidDnsCheckpoint;
            continue;
        }
        const ip: Ip = switch (input[0]) {
            4 => blk: {
                if (!std.mem.allEqual(u8, input[5..], 0)) return error.InvalidDnsCheckpoint;
                break :blk .{ .ipv4 = std.mem.readInt(u32, input[1..5], .big) };
            },
            6 => .{ .ipv6 = std.mem.readInt(u128, input[1..17], .big) },
            else => return error.InvalidDnsCheckpoint,
        };
        answer.addresses[i] = ip;
    }
    answer.count = bytes[295];
    const revision = std.mem.readInt(u64, bytes[584..592], .little);
    if (revision == 0 or revision > std.math.maxInt(i64)) return error.InvalidDnsCheckpoint;
    const result = Result{ .request = .{ .name = name, .family = family, .generation = bytes[8..40].* }, .answer = answer, .completed_us = std.mem.readInt(i64, bytes[568..576], .little), .valid_until_us = std.mem.readInt(i64, bytes[576..584], .little), .deadline_ms = 0 };
    try validateResult(result);
    return .{ .result = result, .revision = revision };
}
