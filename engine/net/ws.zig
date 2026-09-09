// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const event_loop_mod = @import("../core/event_loop.zig");
const EventLoop = event_loop_mod.EventLoop;

pub const default_max_clients: usize = 16;

pub const hard_max_clients: usize = 1024;
pub const max_handshake_bytes: usize = 8 * 1024;
pub const max_inbound_payload: usize = 64 * 1024;

pub const ping_interval_ms: u64 = 30_000;
pub const pong_timeout_ms: u64 = 10_000;

pub const ws_magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,
};

pub const Error = error{
    EventLoopError,
    TooManyClients,
    OutOfMemory,
    NotLinux,
    InvalidMaxClients,
};

const ClientReg = struct {
    server: *WsServer,
    fd: posix.fd_t,
    upgraded: bool = true,
    buf: []u8,
    len: usize = 0,
    last_ping_ms: i64 = 0,
    last_pong_ms: i64 = 0,
};

pub const WsServer = struct {
    allocator: std.mem.Allocator,
    loop: *EventLoop,
    clients: []?*ClientReg,

    pub fn init(
        allocator: std.mem.Allocator,
        loop: *EventLoop,
        max_clients: usize,
    ) Error!WsServer {
        if (builtin.os.tag != .linux) return error.NotLinux;
        if (max_clients == 0 or max_clients > hard_max_clients) {
            return error.InvalidMaxClients;
        }
        const slots = allocator.alloc(?*ClientReg, max_clients) catch
            return error.OutOfMemory;
        @memset(slots, null);
        return .{
            .allocator = allocator,
            .loop = loop,
            .clients = slots,
        };
    }

    pub fn deinit(self: *WsServer) void {
        for (self.clients) |*slot| {
            if (slot.*) |cli| {
                self.loop.removeFd(cli.fd) catch {};
                posix.close(cli.fd);
                self.allocator.free(cli.buf);
                self.allocator.destroy(cli);
                slot.* = null;
            }
        }
        self.allocator.free(self.clients);
        self.* = undefined;
    }

    pub fn admitUpgraded(
        self: *WsServer,
        fd: posix.fd_t,
        pre_read_tail: []const u8,
    ) Error!void {
        var idx: ?usize = null;
        for (self.clients, 0..) |slot, i| {
            if (slot == null) {
                idx = i;
                break;
            }
        }
        if (idx == null) {
            posix.close(fd);
            return error.TooManyClients;
        }

        const buf_size = @max(max_handshake_bytes, max_inbound_payload + 16);
        if (pre_read_tail.len > buf_size) {
            posix.close(fd);
            return error.OutOfMemory;
        }

        const cli = self.allocator.create(ClientReg) catch {
            posix.close(fd);
            return error.OutOfMemory;
        };
        errdefer self.allocator.destroy(cli);
        const buf = self.allocator.alloc(u8, buf_size) catch {
            posix.close(fd);
            return error.OutOfMemory;
        };
        errdefer self.allocator.free(buf);

        cli.* = .{
            .server = self,
            .fd = fd,
            .upgraded = true,
            .buf = buf,
            .last_pong_ms = std.time.milliTimestamp(),
        };
        if (pre_read_tail.len > 0) {
            @memcpy(cli.buf[0..pre_read_tail.len], pre_read_tail);
            cli.len = pre_read_tail.len;
        }

        self.loop.addFd(fd, linux.EPOLL.IN, onClientReadable, @ptrCast(cli)) catch {
            posix.close(fd);
            return error.EventLoopError;
        };
        self.clients[idx.?] = cli;

        if (cli.len > 0) self.readFrames(cli);
    }

    fn onClientReadable(fd: posix.fd_t, events: u32, userdata: ?*anyopaque) void {
        _ = events;
        _ = fd;
        const cli: *ClientReg = @ptrCast(@alignCast(userdata.?));
        cli.server.readFrames(cli);
    }

    fn readFrames(self: *WsServer, cli: *ClientReg) void {
        while (true) {
            const n = posix.read(cli.fd, cli.buf[cli.len..]) catch |err| switch (err) {
                error.WouldBlock => break,
                else => {
                    self.closeClient(cli);
                    return;
                },
            };
            if (n == 0) {
                self.closeClient(cli);
                return;
            }
            cli.len += n;
            if (cli.len == cli.buf.len) break;
        }

        var cursor: usize = 0;
        while (cursor < cli.len) {
            const parse = parseFrame(cli.buf[cursor..cli.len]) catch |err| switch (err) {
                error.Incomplete => break,
                error.BadMask, error.UnsupportedLength => {
                    self.closeClient(cli);
                    return;
                },
            };
            self.dispatchFrame(cli, parse) catch {
                self.closeClient(cli);
                return;
            };
            cursor += parse.consumed;
        }
        // Buffer full with nothing consumed: the next read would be zero-length, so close instead of spinning.
        if (cursor == 0 and cli.len == cli.buf.len) {
            @branchHint(.unlikely);
            std.log.warn(
                "ws: client fd={d} filled buffer with unparseable bytes; closing (policy)",
                .{cli.fd},
            );
            self.closeClient(cli);
            return;
        }
        if (cursor > 0) {
            std.mem.copyForwards(u8, cli.buf[0 .. cli.len - cursor], cli.buf[cursor..cli.len]);
            cli.len -= cursor;
        }
    }

    // Never closeClient() here: the caller keeps iterating cli after return (read-after-free). Return an error instead.
    fn dispatchFrame(self: *WsServer, cli: *ClientReg, frame: ParsedFrame) !void {
        _ = self;
        switch (frame.opcode) {
            .close => {
                const close_frame = [_]u8{ 0x88, 0x00 };
                _ = posix.write(cli.fd, &close_frame) catch {};
                return error.ClientClosing;
            },
            .ping => {
                try writePongFrame(cli.fd, frame.payload);
            },
            .pong => {
                cli.last_pong_ms = std.time.milliTimestamp();
            },
            .text => {},
            .binary => {
                const close_frame = [_]u8{ 0x88, 0x02, 0x03, 0xEB };
                _ = posix.write(cli.fd, &close_frame) catch {};
                return error.UnsupportedOpcode;
            },
            else => return error.UnsupportedOpcode,
        }
    }

    pub fn broadcast(self: *WsServer, text: []const u8) !void {
        for (self.clients) |*slot| {
            if (slot.*) |cli| {
                if (!cli.upgraded) continue;
                writeTextFrame(cli.fd, text) catch {
                    self.closeClient(cli);
                };
            }
        }
    }

    pub fn broadcastAttackDetected(
        self: *WsServer,
        a: std.mem.Allocator,
        ip: []const u8,
        jail: []const u8,
        pattern_name: []const u8,
    ) !void {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        var ts_buf: [32]u8 = undefined;
        const ts = try formatIso8601Utc(&ts_buf, std.time.milliTimestamp());
        try buf.writer(a).print(
            "{{\"type\":\"attack_detected\",\"ts\":\"{s}\",\"payload\":{{\"ip\":\"{s}\",\"jail\":\"{s}\",\"pattern_name\":\"{s}\"}}}}",
            .{ ts, ip, jail, pattern_name },
        );
        try self.broadcast(buf.items);
    }

    pub fn broadcastBanned(
        self: *WsServer,
        a: std.mem.Allocator,
        ip: []const u8,
        jail: []const u8,
        bantime_s: u64,
    ) !void {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        var ts_buf: [32]u8 = undefined;
        const ts = try formatIso8601Utc(&ts_buf, std.time.milliTimestamp());
        try buf.writer(a).print(
            "{{\"type\":\"ip_banned\",\"ts\":\"{s}\",\"payload\":{{\"ip\":\"{s}\",\"jail\":\"{s}\",\"bantime_s\":{d}}}}}",
            .{ ts, ip, jail, bantime_s },
        );
        try self.broadcast(buf.items);
    }

    pub fn broadcastUnbanned(
        self: *WsServer,
        a: std.mem.Allocator,
        ip: []const u8,
        jail: []const u8,
    ) !void {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        var ts_buf: [32]u8 = undefined;
        const ts = try formatIso8601Utc(&ts_buf, std.time.milliTimestamp());
        try buf.writer(a).print(
            "{{\"type\":\"ip_unbanned\",\"ts\":\"{s}\",\"payload\":{{\"ip\":\"{s}\",\"jail\":\"{s}\"}}}}",
            .{ ts, ip, jail },
        );
        try self.broadcast(buf.items);
    }

    pub const MetricsPayload = struct {
        lines_parsed: u64,
        lines_matched: u64,
        bans_total: u64,
        active_bans: u32,
        memory_bytes_used: u64,
        uptime_s: u64,
        protection_state: []const u8 = "active",
        degraded: bool = false,
    };

    pub fn broadcastMetrics(
        self: *WsServer,
        a: std.mem.Allocator,
        m: MetricsPayload,
    ) !void {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        var ts_buf: [32]u8 = undefined;
        const ts = try formatIso8601Utc(&ts_buf, std.time.milliTimestamp());
        try buf.writer(a).print(
            "{{\"type\":\"metrics\",\"ts\":\"{s}\",\"payload\":{{\"lines_parsed\":{d},\"lines_matched\":{d},\"bans_total\":{d},\"active_bans\":{d},\"memory_bytes_used\":{d},\"uptime_s\":{d},\"protection_state\":\"{s}\",\"degraded\":{s}}}}}",
            .{ ts, m.lines_parsed, m.lines_matched, m.bans_total, m.active_bans, m.memory_bytes_used, m.uptime_s, m.protection_state, if (m.degraded) "true" else "false" },
        );
        try self.broadcast(buf.items);
    }

    pub fn tickHeartbeat(self: *WsServer) void {
        const now = std.time.milliTimestamp();
        for (self.clients) |*slot| {
            if (slot.*) |cli| {
                if (!cli.upgraded) continue;
                if (cli.last_pong_ms != 0 and
                    now - cli.last_pong_ms > @as(i64, @intCast(ping_interval_ms + pong_timeout_ms)))
                {
                    self.closeClient(cli);
                    continue;
                }
                if (cli.last_ping_ms == 0 or
                    now - cli.last_ping_ms > @as(i64, @intCast(ping_interval_ms)))
                {
                    writePingFrame(cli.fd, "") catch {
                        self.closeClient(cli);
                        continue;
                    };
                    cli.last_ping_ms = now;
                }
            }
        }
    }

    fn closeClient(self: *WsServer, cli: *ClientReg) void {
        for (self.clients) |*slot| {
            if (slot.*) |existing| {
                if (existing == cli) {
                    slot.* = null;
                    break;
                }
            }
        }
        self.loop.removeFd(cli.fd) catch {};
        posix.close(cli.fd);
        self.allocator.free(cli.buf);
        self.allocator.destroy(cli);
    }
};

pub fn formatIso8601Utc(buf: []u8, ms_since_epoch: i64) ![]const u8 {
    const ms_u: u64 = if (ms_since_epoch < 0) 0 else @intCast(ms_since_epoch);
    const seconds_total: u64 = ms_u / 1000;
    const ms_part: u16 = @intCast(ms_u % 1000);
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = seconds_total };
    const day_seconds = epoch_seconds.getDaySeconds();
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return std.fmt.bufPrint(
        buf,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z",
        .{
            year_day.year,
            @intFromEnum(month_day.month),
            @as(u16, month_day.day_index) + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
            ms_part,
        },
    );
}

pub fn computeAccept(key: []const u8, out: []u8) ![]const u8 {
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(key);
    sha.update(ws_magic);
    var digest: [20]u8 = undefined;
    sha.final(&digest);
    const enc = std.base64.standard.Encoder;
    const needed = enc.calcSize(digest.len);
    if (out.len < needed) return error.BufferTooSmall;
    return enc.encode(out[0..needed], &digest);
}

pub fn findHeader(req: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, req, "\r\n");
    _ = it.next();
    while (it.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const hname = line[0..colon];
        if (!asciiEqlIgnoreCase(hname, name)) continue;
        var value = line[colon + 1 ..];
        while (value.len > 0 and (value[0] == ' ' or value[0] == '\t')) {
            value = value[1..];
        }
        return value;
    }
    return null;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

pub const ParsedFrame = struct {
    opcode: Opcode,
    fin: bool,
    payload: []const u8,
    consumed: usize,
};

pub const ParseError = error{ Incomplete, BadMask, UnsupportedLength };

pub fn parseFrame(buf: []u8) ParseError!ParsedFrame {
    if (buf.len < 2) return error.Incomplete;
    const b0 = buf[0];
    const b1 = buf[1];
    const fin = (b0 & 0x80) != 0;
    const opcode: Opcode = @enumFromInt(@as(u4, @intCast(b0 & 0x0F)));
    const masked = (b1 & 0x80) != 0;
    const len7 = b1 & 0x7F;

    var offset: usize = 2;
    var payload_len: u64 = undefined;
    if (len7 < 126) {
        payload_len = len7;
    } else if (len7 == 126) {
        if (buf.len < offset + 2) return error.Incomplete;
        payload_len = std.mem.readInt(u16, buf[offset..][0..2], .big);
        offset += 2;
    } else {
        if (buf.len < offset + 8) return error.Incomplete;
        const n = std.mem.readInt(u64, buf[offset..][0..8], .big);
        if (n > max_inbound_payload) return error.UnsupportedLength;
        payload_len = n;
        offset += 8;
    }
    if (payload_len > max_inbound_payload) return error.UnsupportedLength;

    // RFC 6455 §5.1: client-to-server frames must be masked.
    if (!masked) return error.BadMask;
    if (buf.len < offset + 4) return error.Incomplete;
    const mask_key = buf[offset..][0..4].*;
    offset += 4;

    const pl_len: usize = @intCast(payload_len);
    if (buf.len < offset + pl_len) return error.Incomplete;
    var i: usize = 0;
    while (i < pl_len) : (i += 1) {
        buf[offset + i] ^= mask_key[i & 3];
    }
    return .{
        .opcode = opcode,
        .fin = fin,
        .payload = buf[offset .. offset + pl_len],
        .consumed = offset + pl_len,
    };
}

pub fn writeTextFrame(fd: posix.fd_t, text: []const u8) !void {
    try writeFrame(fd, .text, text);
}

fn writePingFrame(fd: posix.fd_t, payload: []const u8) !void {
    try writeFrame(fd, .ping, payload);
}

fn writePongFrame(fd: posix.fd_t, payload: []const u8) !void {
    try writeFrame(fd, .pong, payload);
}

fn writeFrame(fd: posix.fd_t, op: Opcode, payload: []const u8) !void {
    var hdr: [10]u8 = undefined;
    var hdr_len: usize = 2;
    hdr[0] = 0x80 | @as(u8, @intFromEnum(op));
    if (payload.len < 126) {
        hdr[1] = @intCast(payload.len);
    } else if (payload.len <= 0xFFFF) {
        hdr[1] = 126;
        std.mem.writeInt(u16, hdr[2..4], @intCast(payload.len), .big);
        hdr_len = 4;
    } else {
        hdr[1] = 127;
        std.mem.writeInt(u64, hdr[2..10], @intCast(payload.len), .big);
        hdr_len = 10;
    }
    try writeAll(fd, hdr[0..hdr_len]);
    if (payload.len > 0) try writeAll(fd, payload);
}

fn writeAll(fd: posix.fd_t, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try posix.write(fd, bytes[written..]);
        if (n == 0) return error.ShortWrite;
        written += n;
    }
}

const testing = std.testing;

test "ws: computeAccept matches RFC 6455 sample vector" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    var out: [64]u8 = undefined;
    const accept = try computeAccept(key, &out);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "ws: findHeader is case-insensitive and tolerant of whitespace" {
    const req = "GET /events HTTP/1.1\r\nHost: x\r\nUpgrade:websocket\r\nSec-WebSocket-Key:  abc  \r\n\r\n";
    try testing.expectEqualStrings("websocket", findHeader(req, "upgrade").?);
    try testing.expectEqualStrings("abc  ", findHeader(req, "sec-websocket-key").?);
    try testing.expect(findHeader(req, "missing") == null);
}

test "ws: parseFrame round-trip via encode + decode" {
    var buf: [64]u8 = undefined;
    buf[0] = 0x81;
    buf[1] = 0x85;
    const mask = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    @memcpy(buf[2..6], &mask);
    const payload = "hello";
    for (payload, 0..) |c, i| {
        buf[6 + i] = c ^ mask[i & 3];
    }
    const f = try parseFrame(buf[0 .. 6 + payload.len]);
    try testing.expect(f.fin);
    try testing.expectEqual(Opcode.text, f.opcode);
    try testing.expectEqualStrings("hello", f.payload);
    try testing.expectEqual(@as(usize, 11), f.consumed);
}

test "ws: parseFrame rejects unmasked client frame" {
    var buf: [8]u8 = .{ 0x81, 0x05, 'h', 'e', 'l', 'l', 'o', 0 };
    try testing.expectError(error.BadMask, parseFrame(buf[0..7]));
}

test "ws: parseFrame reports Incomplete on short buffers" {
    var buf: [1]u8 = .{0x81};
    try testing.expectError(error.Incomplete, parseFrame(&buf));
}

test "ws: parseFrame rejects payload larger than max_inbound_payload" {
    var buf: [10]u8 = undefined;
    buf[0] = 0x81;
    buf[1] = 0xFF;
    std.mem.writeInt(u64, buf[2..10], max_inbound_payload + 1, .big);
    try testing.expectError(error.UnsupportedLength, parseFrame(&buf));
}

test "ws: writeTextFrame uses short length for payload < 126" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    const stype_u32: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    const rc = linux.socketpair(
        @as(i32, linux.AF.UNIX),
        @as(i32, @intCast(stype_u32)),
        0,
        &fds,
    );
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    try writeTextFrame(fds[0], "hi");
    var buf: [16]u8 = undefined;
    const n = try posix.read(fds[1], &buf);
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqual(@as(u8, 0x81), buf[0]);
    try testing.expectEqual(@as(u8, 0x02), buf[1]);
    try testing.expectEqualStrings("hi", buf[2..4]);
}

test "ws: writeTextFrame uses 16-bit length for payload 126..65535" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    const stype_u32: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    const rc = linux.socketpair(
        @as(i32, linux.AF.UNIX),
        @as(i32, @intCast(stype_u32)),
        0,
        &fds,
    );
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    const big = try testing.allocator.alloc(u8, 1000);
    defer testing.allocator.free(big);
    @memset(big, 'x');
    try writeTextFrame(fds[0], big);

    var hdr: [4]u8 = undefined;
    try readExact(fds[1], &hdr);
    try testing.expectEqual(@as(u8, 0x81), hdr[0]);
    try testing.expectEqual(@as(u8, 126), hdr[1]);
    try testing.expectEqual(
        @as(u16, 1000),
        std.mem.readInt(u16, hdr[2..4], .big),
    );
}

fn readExact(fd: posix.fd_t, buf: []u8) !void {
    var i: usize = 0;
    while (i < buf.len) {
        const n = try posix.read(fd, buf[i..]);
        if (n == 0) return error.EndOfStream;
        i += n;
    }
}

test "ws: buffer full with unparseable bytes closes client (SEC-010)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = try WsServer.init(a, &loop, default_max_clients);
    defer server.deinit();

    var fds: [2]i32 = undefined;
    const stype_u32: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const rc = linux.socketpair(
        @as(i32, linux.AF.UNIX),
        @as(i32, @intCast(stype_u32)),
        0,
        &fds,
    );
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
    defer posix.close(fds[1]);

    try server.admitUpgraded(fds[0], &.{});
    const cli = server.clients[0].?;

    std.debug.assert(cli.buf.len >= 16);
    cli.buf[0] = 0x81;
    cli.buf[1] = 0xFF;
    std.mem.writeInt(u64, cli.buf[2..10], @as(u64, max_inbound_payload), .big);
    cli.buf[10] = 0;
    cli.buf[11] = 0;
    cli.buf[12] = 0;
    cli.buf[13] = 0;
    cli.len = cli.buf.len;

    server.readFrames(cli);
    try testing.expect(server.clients[0] == null);
}

test "ws: admitUpgraded takes ownership of fd and broadcasts reach it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = try WsServer.init(a, &loop, default_max_clients);
    defer server.deinit();

    var fds: [2]i32 = undefined;
    const stype_u32: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const rc = linux.socketpair(
        @as(i32, linux.AF.UNIX),
        @as(i32, @intCast(stype_u32)),
        0,
        &fds,
    );
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
    defer posix.close(fds[1]);

    try server.admitUpgraded(fds[0], &.{});

    try server.broadcast("ping");

    var buf: [16]u8 = undefined;
    const n = try posix.read(fds[1], &buf);
    try testing.expectEqual(@as(usize, 6), n);
    try testing.expectEqual(@as(u8, 0x81), buf[0]);
    try testing.expectEqual(@as(u8, 4), buf[1]);
    try testing.expectEqualStrings("ping", buf[2..6]);
}

test "ws: admitUpgraded rejects past max_clients and closes the fd" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = try WsServer.init(a, &loop, default_max_clients);
    defer server.deinit();

    var peer_fds: [default_max_clients]i32 = undefined;
    for (0..default_max_clients) |i| {
        var fds: [2]i32 = undefined;
        const stype_u32: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
        const rc = linux.socketpair(
            @as(i32, linux.AF.UNIX),
            @as(i32, @intCast(stype_u32)),
            0,
            &fds,
        );
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            else => return error.SkipZigTest,
        }
        peer_fds[i] = fds[1];
        try server.admitUpgraded(fds[0], &.{});
    }
    defer for (peer_fds) |pfd| posix.close(pfd);

    var extra: [2]i32 = undefined;
    const stype_u32: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const rc = linux.socketpair(
        @as(i32, linux.AF.UNIX),
        @as(i32, @intCast(stype_u32)),
        0,
        &extra,
    );
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
    defer posix.close(extra[1]);
    try testing.expectError(error.TooManyClients, server.admitUpgraded(extra[0], &.{}));
}

test "ws: broadcast to 3 in-memory clients all receive the same frame" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = try WsServer.init(a, &loop, default_max_clients);

    var peer_fds: [3]i32 = undefined;
    defer for (&peer_fds) |f| posix.close(f);

    inline for (0..3) |i| {
        var fds: [2]i32 = undefined;
        const stype_u32: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
        const rc = linux.socketpair(
            @as(i32, linux.AF.UNIX),
            @as(i32, @intCast(stype_u32)),
            0,
            &fds,
        );
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            else => return error.SkipZigTest,
        }
        peer_fds[i] = fds[1];

        const buf_size = @max(max_handshake_bytes, max_inbound_payload + 16);
        const cli = try a.create(ClientReg);
        const buf = try a.alloc(u8, buf_size);
        cli.* = .{
            .server = &server,
            .fd = fds[0],
            .upgraded = true,
            .buf = buf,
        };
        server.clients[i] = cli;
    }

    try server.broadcast("hello world");

    for (peer_fds) |pfd| {
        var buf: [32]u8 = undefined;
        const n = try posix.read(pfd, &buf);
        try testing.expectEqual(@as(usize, 13), n);
        try testing.expectEqual(@as(u8, 0x81), buf[0]);
        try testing.expectEqual(@as(u8, 11), buf[1]);
        try testing.expectEqualStrings("hello world", buf[2..13]);
    }

    for (server.clients) |*slot| {
        if (slot.*) |cli| {
            posix.close(cli.fd);
            a.free(cli.buf);
            a.destroy(cli);
            slot.* = null;
        }
    }
    a.free(server.clients);
}

test "ws: init rejects max_clients == 0" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var loop = try EventLoop.init(a);
    defer loop.deinit();
    try testing.expectError(error.InvalidMaxClients, WsServer.init(a, &loop, 0));
}

test "ws: init rejects max_clients above hard_max_clients" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var loop = try EventLoop.init(a);
    defer loop.deinit();
    try testing.expectError(
        error.InvalidMaxClients,
        WsServer.init(a, &loop, hard_max_clients + 1),
    );
}

test "ws: init with custom max_clients sizes slot table" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = try WsServer.init(a, &loop, 3);
    defer server.deinit();
    try testing.expectEqual(@as(usize, 3), server.clients.len);

    var big = try WsServer.init(a, &loop, hard_max_clients);
    defer big.deinit();
    try testing.expectEqual(hard_max_clients, big.clients.len);
}

test "ws: dispatchFrame returns error on close/binary/unknown (no self-close UAF)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var loop = try EventLoop.init(a);
    defer loop.deinit();
    var server = try WsServer.init(a, &loop, default_max_clients);
    defer server.deinit();

    var fds: [2]i32 = undefined;
    const stype_u32: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    switch (posix.errno(linux.socketpair(
        @as(i32, linux.AF.UNIX),
        @as(i32, @intCast(stype_u32)),
        0,
        &fds,
    ))) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
    defer posix.close(fds[1]);
    try server.admitUpgraded(fds[0], &.{});

    var cli: *ClientReg = undefined;
    for (server.clients) |slot| {
        if (slot) |c| {
            cli = c;
            break;
        }
    } else return error.Unexpected;

    try testing.expectError(
        error.ClientClosing,
        server.dispatchFrame(cli, .{ .opcode = .close, .fin = true, .payload = &.{}, .consumed = 2 }),
    );
    try testing.expectError(
        error.UnsupportedOpcode,
        server.dispatchFrame(cli, .{ .opcode = .binary, .fin = true, .payload = &.{}, .consumed = 2 }),
    );
    try testing.expectError(
        error.UnsupportedOpcode,
        server.dispatchFrame(cli, .{ .opcode = @enumFromInt(@as(u4, 3)), .fin = true, .payload = &.{}, .consumed = 2 }),
    );

    var still_alive = false;
    for (server.clients) |slot| {
        if (slot) |c| {
            if (c == cli) {
                still_alive = true;
                break;
            }
        }
    }
    try testing.expect(still_alive);
}
