//! Minimal WebSocket (RFC 6455) server for the fail2zig dashboard.
//!
//! Scope:
//!   - Text frames only (server -> clients). Binary frames from clients
//!     are rejected with close code 1003 (Unsupported Data).
//!   - Ping / pong heartbeat: we send ping every 30s, close the client
//!     if no pong within 10s.
//!   - `broadcast(text)` writes the same text frame to every connected
//!     client. Slow clients whose send buffer fills are dropped.
//!
//! The WsServer does NOT own a TCP listener. The `HttpServer` in
//! `http.zig` owns the single user-facing port; when it sees an
//! `Upgrade: websocket` request on `/events` it completes the handshake
//! and calls `WsServer.admitUpgraded(fd, ...)` to hand the connected
//! socket off to this module. The handoff re-registers the FD with the
//! event loop under WsServer's frame-reading callback.
//!
//! Security notes:
//!   - Max 16 clients hard-capped. Excess connections rejected at the
//!     HTTP layer with 503 before the upgrade completes.
//!   - Payloads from clients capped at 64 KB (dashboard only ever
//!     sends pings/pongs, so this is generous).
//!   - Masking enforced on every frame we receive per RFC. Server
//!     frames are never masked.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const event_loop_mod = @import("../core/event_loop.zig");
const EventLoop = event_loop_mod.EventLoop;

// ============================================================================
// Constants
// ============================================================================

pub const max_clients: usize = 16;
pub const max_handshake_bytes: usize = 8 * 1024;
pub const max_inbound_payload: usize = 64 * 1024;

pub const ping_interval_ms: u64 = 30_000;
pub const pong_timeout_ms: u64 = 10_000;

/// RFC 6455 magic GUID. Concatenated to the client key, SHA-1'd, then
/// base64-encoded to produce the `Sec-WebSocket-Accept` header value.
pub const ws_magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ============================================================================
// Opcodes (low nibble of the frame's first byte)
// ============================================================================

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,
};

// ============================================================================
// Errors
// ============================================================================

pub const Error = error{
    EventLoopError,
    TooManyClients,
    OutOfMemory,
    NotLinux,
};

// ============================================================================
// Per-client state
// ============================================================================

const ClientReg = struct {
    server: *WsServer,
    fd: posix.fd_t,
    /// True after the upgrade handshake has been completed (always true
    /// in the HTTP-handoff architecture — the HttpServer only hands off
    /// post-handshake sockets). Kept as a field so the broadcast and
    /// heartbeat loops can be defensive.
    upgraded: bool = true,
    /// Buffer for incoming frame bytes. Sized generously; one frame is
    /// never allowed to exceed `max_inbound_payload`.
    buf: []u8,
    len: usize = 0,
    /// Last time we sent a ping to this client (ms since an epoch).
    last_ping_ms: i64 = 0,
    /// Last pong we received. Used for pong_timeout enforcement.
    last_pong_ms: i64 = 0,
};

// ============================================================================
// WsServer
// ============================================================================

pub const WsServer = struct {
    allocator: std.mem.Allocator,
    loop: *EventLoop,
    clients: [max_clients]?*ClientReg = [_]?*ClientReg{null} ** max_clients,

    /// Construct a WsServer with no listening socket. The HttpServer
    /// is expected to feed upgraded client FDs in via `admitUpgraded`.
    pub fn init(
        allocator: std.mem.Allocator,
        loop: *EventLoop,
    ) Error!WsServer {
        if (builtin.os.tag != .linux) return error.NotLinux;
        return .{
            .allocator = allocator,
            .loop = loop,
        };
    }

    pub fn deinit(self: *WsServer) void {
        for (&self.clients) |*slot| {
            if (slot.*) |cli| {
                self.loop.removeFd(cli.fd) catch {};
                posix.close(cli.fd);
                self.allocator.free(cli.buf);
                self.allocator.destroy(cli);
                slot.* = null;
            }
        }
        self.* = undefined;
    }

    /// Called by the HTTP server after it has observed a WebSocket
    /// Upgrade request, written the `101 Switching Protocols` response
    /// with a valid `Sec-WebSocket-Accept`, and removed the FD from its
    /// own event-loop registration.
    ///
    /// `pre_read_tail` is any bytes the HTTP server read past the end of
    /// the request headers (e.g. the first WebSocket frame arriving in
    /// the same TCP segment as the upgrade). They are copied into the
    /// new client's frame buffer so no data is lost.
    ///
    /// On success the FD's lifetime transfers to the WsServer. On error
    /// the FD is closed by this function — the caller does NOT need
    /// errdefer around the handoff.
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
            // FD ownership transferred to us on entry; close on reject.
            posix.close(fd);
            return error.TooManyClients;
        }

        const buf_size = @max(max_handshake_bytes, max_inbound_payload + 16);
        if (pre_read_tail.len > buf_size) {
            posix.close(fd);
            return error.OutOfMemory; // caller-side bug: HTTP cap is smaller than ours.
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

        // If the HTTP server already delivered frame bytes, drain them now
        // so we don't wait for the next EPOLLIN to process them.
        if (cli.len > 0) self.readFrames(cli);
    }

    fn onClientReadable(fd: posix.fd_t, events: u32, userdata: ?*anyopaque) void {
        _ = events;
        _ = fd;
        const cli: *ClientReg = @ptrCast(@alignCast(userdata.?));
        cli.server.readFrames(cli);
    }

    fn readFrames(self: *WsServer, cli: *ClientReg) void {
        // Append to cli.buf; once a full frame is present, dispatch it.
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
            if (cli.len == cli.buf.len) break; // buffer full — try to parse.
        }

        // Drain as many complete frames as we can.
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
        // SEC-010: buffer-full but no frame consumed. The client either
        // sent garbage or stalled mid-frame with enough bytes to fill
        // the buffer. Either way, we cannot make progress and the next
        // read would be into a zero-length slice — relying on the
        // kernel's zero-length-read semantics is brittle. Close the
        // client with an explicit policy-violation log.
        if (cursor == 0 and cli.len == cli.buf.len) {
            @branchHint(.unlikely);
            std.log.warn(
                "ws: client fd={d} filled buffer with unparseable bytes; closing (policy)",
                .{cli.fd},
            );
            self.closeClient(cli);
            return;
        }
        // Compact leftover bytes to the front of the buffer.
        if (cursor > 0) {
            std.mem.copyForwards(u8, cli.buf[0 .. cli.len - cursor], cli.buf[cursor..cli.len]);
            cli.len -= cursor;
        }
    }

    fn dispatchFrame(self: *WsServer, cli: *ClientReg, frame: ParsedFrame) !void {
        switch (frame.opcode) {
            .close => {
                // Echo close frame, then drop.
                const close_frame = [_]u8{ 0x88, 0x00 }; // FIN|CLOSE, len=0
                _ = posix.write(cli.fd, &close_frame) catch {};
                self.closeClient(cli);
            },
            .ping => {
                // Build a pong frame with the same payload.
                try writePongFrame(cli.fd, frame.payload);
            },
            .pong => {
                cli.last_pong_ms = std.time.milliTimestamp();
            },
            .text => {
                // Dashboard doesn't send messages; we accept + ignore.
            },
            .binary => {
                // Unsupported: close 1003.
                const close_frame = [_]u8{ 0x88, 0x02, 0x03, 0xEB }; // 1003
                _ = posix.write(cli.fd, &close_frame) catch {};
                self.closeClient(cli);
            },
            else => {
                self.closeClient(cli);
            },
        }
    }

    /// Send a text message to every connected (post-upgrade) client.
    /// Slow clients whose write would block are dropped.
    pub fn broadcast(self: *WsServer, text: []const u8) !void {
        for (&self.clients) |*slot| {
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
        timestamp: i64,
    ) !void {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        try buf.writer(a).print(
            "{{\"type\":\"attack_detected\",\"ip\":\"{s}\",\"jail\":\"{s}\",\"timestamp\":{d}}}",
            .{ ip, jail, timestamp },
        );
        try self.broadcast(buf.items);
    }

    pub fn broadcastBanned(
        self: *WsServer,
        a: std.mem.Allocator,
        ip: []const u8,
        jail: []const u8,
        timestamp: i64,
    ) !void {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        try buf.writer(a).print(
            "{{\"type\":\"ip_banned\",\"ip\":\"{s}\",\"jail\":\"{s}\",\"timestamp\":{d}}}",
            .{ ip, jail, timestamp },
        );
        try self.broadcast(buf.items);
    }

    pub fn broadcastUnbanned(
        self: *WsServer,
        a: std.mem.Allocator,
        ip: []const u8,
        jail: []const u8,
        timestamp: i64,
    ) !void {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        try buf.writer(a).print(
            "{{\"type\":\"ip_unbanned\",\"ip\":\"{s}\",\"jail\":\"{s}\",\"timestamp\":{d}}}",
            .{ ip, jail, timestamp },
        );
        try self.broadcast(buf.items);
    }

    pub fn broadcastMetrics(
        self: *WsServer,
        a: std.mem.Allocator,
        parse_rate: u64,
        active_bans: u32,
    ) !void {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        try buf.writer(a).print(
            "{{\"type\":\"metrics\",\"parse_rate\":{d},\"active_bans\":{d}}}",
            .{ parse_rate, active_bans },
        );
        try self.broadcast(buf.items);
    }

    /// Heartbeat tick. Intended to be called once per second by an
    /// event-loop timer. Sends pings to clients whose last_ping is
    /// older than `ping_interval_ms`; drops clients whose
    /// `last_pong` is older than `ping_interval_ms + pong_timeout_ms`.
    pub fn tickHeartbeat(self: *WsServer) void {
        const now = std.time.milliTimestamp();
        for (&self.clients) |*slot| {
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
        for (&self.clients) |*slot| {
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

// ============================================================================
// Handshake helpers
// ============================================================================

/// Compute `Sec-WebSocket-Accept` = base64(SHA1(key ++ ws_magic)).
/// `out` must be at least 32 bytes (SHA-1 is 20 bytes -> base64 28 chars).
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

/// Find a header value (case-insensitive name). Returns the trimmed
/// value slice, or null if the header is not present.
pub fn findHeader(req: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, req, "\r\n");
    _ = it.next(); // skip request line
    while (it.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const hname = line[0..colon];
        if (!asciiEqlIgnoreCase(hname, name)) continue;
        var value = line[colon + 1 ..];
        // Trim leading space.
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

// ============================================================================
// Frame parsing / encoding
// ============================================================================

pub const ParsedFrame = struct {
    opcode: Opcode,
    fin: bool,
    payload: []const u8,
    /// Total bytes this frame consumed from the input. May include
    /// header bytes after unmasking.
    consumed: usize,
};

pub const ParseError = error{ Incomplete, BadMask, UnsupportedLength };

/// Parse a single WebSocket frame from a caller-owned mutable buffer.
/// The buffer is mutated to unmask the payload in place (WebSocket
/// client frames are always masked).
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

    // Client frames MUST be masked. Server frames must NOT be. We only
    // parse frames we receive (client->server), so enforce masked=true.
    if (!masked) return error.BadMask;
    if (buf.len < offset + 4) return error.Incomplete;
    const mask_key = buf[offset..][0..4].*;
    offset += 4;

    const pl_len: usize = @intCast(payload_len);
    if (buf.len < offset + pl_len) return error.Incomplete;
    // Unmask in place.
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

/// Write an unmasked server -> client text frame.
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

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "ws: computeAccept matches RFC 6455 sample vector" {
    // Sample from RFC 6455 section 1.3.
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
    // Build a masked client frame manually: opcode=text, FIN=1, len=5,
    // mask=[0xaa,0xbb,0xcc,0xdd], payload="hello" xor'd.
    var buf: [64]u8 = undefined;
    buf[0] = 0x81; // FIN + text
    buf[1] = 0x85; // masked + len=5
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
    // Server-origin frame (no mask bit). Must be rejected per RFC.
    var buf: [8]u8 = .{ 0x81, 0x05, 'h', 'e', 'l', 'l', 'o', 0 };
    try testing.expectError(error.BadMask, parseFrame(buf[0..7]));
}

test "ws: parseFrame reports Incomplete on short buffers" {
    var buf: [1]u8 = .{0x81};
    try testing.expectError(error.Incomplete, parseFrame(&buf));
}

test "ws: parseFrame rejects payload larger than max_inbound_payload" {
    var buf: [10]u8 = undefined;
    buf[0] = 0x81; // FIN + text
    buf[1] = 0xFF; // masked + 127 (8-byte length follows)
    std.mem.writeInt(u64, buf[2..10], max_inbound_payload + 1, .big);
    try testing.expectError(error.UnsupportedLength, parseFrame(&buf));
}

test "ws: writeTextFrame uses short length for payload < 126" {
    // Use a socketpair — write into one end, verify the bytes arrive.
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
    try testing.expectEqual(@as(u8, 0x81), buf[0]); // FIN + text
    try testing.expectEqual(@as(u8, 0x02), buf[1]); // len=2, not masked
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
    // SEC-010: a client that fills the read buffer with bytes that
    // cannot form a complete frame (declared payload longer than the
    // buffer can hold, no matter how many more bytes arrive) must be
    // closed explicitly. Without the SEC-010 guard, the next read
    // into cli.buf[cli.len..] is a zero-length slice and correctness
    // depends on kernel semantics — brittle.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = try WsServer.init(a, &loop);
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

    // Forge a "first bytes of a valid masked frame whose declared payload
    // is exactly max_inbound_payload (the biggest the parser accepts) but
    // whose total frame size (14-byte header + payload) exceeds
    // cli.buf.len". parseFrame accepts the length (at the cap), then
    // requires `buf.len >= offset + payload_len` which is false, so
    // returns Incomplete. cursor stays 0, cli.len == cli.buf.len → the
    // SEC-010 guard closes the client.
    //
    // Wire shape (14-byte header): b0=0x81 (FIN + text), b1=0xFF
    // (masked + 127-extended), u64 length = max_inbound_payload, u32 mask.
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
    // Slot cleared ⇒ client was closed.
    try testing.expect(server.clients[0] == null);
}

test "ws: admitUpgraded takes ownership of fd and broadcasts reach it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = try WsServer.init(a, &loop);
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

    // Admitting transfers fds[0] ownership to server; empty pre-read tail.
    try server.admitUpgraded(fds[0], &.{});

    try server.broadcast("ping");

    var buf: [16]u8 = undefined;
    const n = try posix.read(fds[1], &buf);
    try testing.expectEqual(@as(usize, 6), n); // 2 header + 4 payload
    try testing.expectEqual(@as(u8, 0x81), buf[0]);
    try testing.expectEqual(@as(u8, 4), buf[1]);
    try testing.expectEqualStrings("ping", buf[2..6]);
}

test "ws: admitUpgraded rejects past max_clients and closes the fd" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = try WsServer.init(a, &loop);
    defer server.deinit();

    // Fill all slots.
    var peer_fds: [max_clients]i32 = undefined;
    for (0..max_clients) |i| {
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

    // One more should be rejected.
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
    // extra[0] was closed by admitUpgraded on rejection.
}

test "ws: broadcast to 3 in-memory clients all receive the same frame" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    // We don't need a listener for this test — construct a WsServer
    // and inject three "upgraded" clients backed by socketpair fds. The
    // test reads from the peer side of each pair to verify the frame.
    var server = try WsServer.init(a, &loop);

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
        // NOTE: we do NOT register these fds with the loop — the loop
        // is idle in this test. We only exercise broadcast().
    }

    try server.broadcast("hello world");

    // Each peer must have received an unmasked text frame with the
    // same payload.
    for (peer_fds) |pfd| {
        var buf: [32]u8 = undefined;
        const n = try posix.read(pfd, &buf);
        try testing.expectEqual(@as(usize, 13), n); // 2 header + 11 payload
        try testing.expectEqual(@as(u8, 0x81), buf[0]);
        try testing.expectEqual(@as(u8, 11), buf[1]);
        try testing.expectEqualStrings("hello world", buf[2..13]);
    }

    // Manual cleanup since we skipped the loop.
    for (&server.clients) |*slot| {
        if (slot.*) |cli| {
            posix.close(cli.fd);
            a.free(cli.buf);
            a.destroy(cli);
            slot.* = null;
        }
    }
}
