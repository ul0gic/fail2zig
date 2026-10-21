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
