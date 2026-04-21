// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Minimal HTTP/1.1 server — `/metrics` (Prometheus), `/api/status`,
//! and `GET /events` WebSocket upgrade.
//!
//! This server is intentionally minimal: read-only, localhost-by-default,
//! routes are hardcoded, no keep-alive (Connection: close on every
//! response). Attacker-exposed surface is small and the server is never
//! expected to handle more than a few operator connections per second.
//!
//! Request parsing cap: 8 KB per request. Any request whose headers
//! exceed that are answered with 413 and closed. Response size cap:
//! 64 KB — more than enough for thousands of jails in Prometheus text
//! exposition format.
//!
//! Integration:
//!   - `MetricsSource` vtable: read Prometheus metrics on demand.
//!   - `StatusSource` vtable: produce a JSON status document on demand.
//!   - `WsServer` pointer (nullable): when a request on `/events` asks
//!     for a WebSocket upgrade, the HTTP server completes the handshake
//!     (101 + Sec-WebSocket-Accept), removes the FD from its own epoll
//!     registration, and hands it off to the WsServer. When `null`, any
//!     Upgrade request receives 400 Bad Request.
//!   The daemon installs all three after constructing its metrics and
//!   IPC handler. Decoupling means this file has no compile-time
//!   dependency on `core/metrics.zig` or `net/commands.zig`.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const event_loop_mod = @import("../core/event_loop.zig");
const EventLoop = event_loop_mod.EventLoop;
const ws_mod = @import("ws.zig");

// ============================================================================
// Configuration constants
// ============================================================================

pub const max_clients: usize = 16;
pub const max_request_bytes: usize = 8 * 1024;
pub const max_response_bytes: usize = 64 * 1024;

/// SEC-008: per-client read deadline. If the client has not sent a
/// complete request (\r\n\r\n) within this many ms of admission, the
/// connection is closed. Defends against slowloris holding a slot
/// indefinitely.
pub const client_read_deadline_ms: i64 = 5_000;

/// SEC-008: accept-side rate cap. At most this many new connections
/// admitted per rolling 1-second bucket. Excess `accept()` results are
/// closed immediately. Defends against local flood that would otherwise
/// saturate all `max_clients` slots.
pub const max_accepts_per_second: u32 = 100;

// ============================================================================
// Public error set
// ============================================================================

pub const Error = error{
    SocketCreateFailed,
    BindFailed,
    ListenFailed,
    SetsockoptFailed,
    EventLoopError,
    AlreadyStarted,
    OutOfMemory,
    NotLinux,
};

// ============================================================================
// Source vtables
// ============================================================================

/// Produce Prometheus text exposition output. Writer is whatever the
/// server gave — typically a `std.ArrayListUnmanaged(u8).Writer`.
pub const MetricsSource = struct {
    ctx: ?*anyopaque = null,
    /// Write Prometheus text exposition into `out`. Caller bounds the
    /// total response size externally via `max_response_bytes` — if
    /// the producer exceeds that the server will truncate and close.
    write: *const fn (
        ctx: ?*anyopaque,
        out: *std.ArrayListUnmanaged(u8),
        a: std.mem.Allocator,
    ) anyerror!void = defaultWriteMetrics,
};

pub const StatusSource = struct {
    ctx: ?*anyopaque = null,
    /// Produce a JSON body (no newlines required). Same contract as
    /// `MetricsSource.write`.
    write: *const fn (
        ctx: ?*anyopaque,
        out: *std.ArrayListUnmanaged(u8),
        a: std.mem.Allocator,
    ) anyerror!void = defaultWriteStatus,
};

fn defaultWriteMetrics(
    ctx: ?*anyopaque,
    out: *std.ArrayListUnmanaged(u8),
    a: std.mem.Allocator,
) anyerror!void {
    _ = ctx;
    try out.appendSlice(a, "# HELP fail2zig_up 1 when the daemon is running\n");
    try out.appendSlice(a, "# TYPE fail2zig_up gauge\n");
    try out.appendSlice(a, "fail2zig_up 1\n");
}

fn defaultWriteStatus(
    ctx: ?*anyopaque,
    out: *std.ArrayListUnmanaged(u8),
    a: std.mem.Allocator,
) anyerror!void {
    _ = ctx;
    try out.appendSlice(a, "{\"status\":\"ok\"}");
}

// ============================================================================
// Per-client state
// ============================================================================

const ClientReg = struct {
    server: *HttpServer,
    fd: posix.fd_t,
    buf: [max_request_bytes]u8 = undefined,
    len: usize = 0,
    /// SEC-008: wall-clock time (ms) when the client was admitted. Used
    /// to enforce `client_read_deadline_ms` on slow / stalled clients.
    admitted_ms: i64 = 0,
};

// ============================================================================
// HttpServer
// ============================================================================

pub const HttpServer = struct {
    allocator: std.mem.Allocator,
    loop: *EventLoop,
    port: u16,
    bind_addr: []const u8,
    listen_fd: posix.fd_t = -1,
    started: bool = false,
    metrics_source: MetricsSource = .{},
    status_source: StatusSource = .{},
    /// Optional sibling WebSocket server. When non-null, `GET /events`
    /// requests that carry a valid `Upgrade: websocket` header get the
    /// 101 handshake completed here and the FD is handed off. When null,
    /// any Upgrade request gets 400.
    ws_server: ?*ws_mod.WsServer = null,
    clients: [max_clients]?*ClientReg = [_]?*ClientReg{null} ** max_clients,
    /// SEC-008: rolling 1-second accept-rate bucket.
    accept_bucket_epoch_s: i64 = 0,
    accept_bucket_count: u32 = 0,

    /// Create a TCP listening socket. `bind_addr` is a dotted IPv4 —
    /// typically `"127.0.0.1"` (the default we recommend). `port == 0`
    /// asks the kernel to pick an ephemeral port; call `getBoundPort()`
    /// after init to learn it. Useful for tests.
    pub fn init(
        allocator: std.mem.Allocator,
        loop: *EventLoop,
        port: u16,
        bind_addr: []const u8,
    ) Error!HttpServer {
        if (builtin.os.tag != .linux) return error.NotLinux;

        const stype: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
        const fd = posix.socket(posix.AF.INET, stype, 0) catch
            return error.SocketCreateFailed;
        errdefer posix.close(fd);

        const yes: i32 = 1;
        posix.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&yes)) catch
            return error.SetsockoptFailed;

        const parsed = parseIpv4(bind_addr) orelse return error.BindFailed;
        var addr: linux.sockaddr.in = .{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, parsed),
            .zero = [_]u8{0} ** 8,
        };
        const addr_len: posix.socklen_t = @sizeOf(linux.sockaddr.in);
        posix.bind(fd, @ptrCast(&addr), addr_len) catch
            return error.BindFailed;

        posix.listen(fd, @intCast(max_clients)) catch return error.ListenFailed;

        return .{
            .allocator = allocator,
            .loop = loop,
            .port = port,
            .bind_addr = bind_addr,
            .listen_fd = fd,
        };
    }

    pub fn deinit(self: *HttpServer) void {
        for (&self.clients) |*slot| {
            if (slot.*) |cli| {
                self.loop.removeFd(cli.fd) catch {};
                posix.close(cli.fd);
                self.allocator.destroy(cli);
                slot.* = null;
            }
        }
        if (self.started) {
            self.loop.removeFd(self.listen_fd) catch {};
            self.started = false;
        }
        if (self.listen_fd != -1) {
            posix.close(self.listen_fd);
            self.listen_fd = -1;
        }
        self.* = undefined;
    }

    /// Return the actual bound port (useful when caller passed 0). Must
    /// be called after `init()` succeeds and before `deinit()`.
    pub fn getBoundPort(self: *const HttpServer) !u16 {
        var addr: linux.sockaddr.in = undefined;
        var len: posix.socklen_t = @sizeOf(linux.sockaddr.in);
        try posix.getsockname(self.listen_fd, @ptrCast(&addr), &len);
        return std.mem.bigToNative(u16, addr.port);
    }

    pub fn setMetricsSource(self: *HttpServer, s: MetricsSource) void {
        self.metrics_source = s;
    }

    pub fn setStatusSource(self: *HttpServer, s: StatusSource) void {
        self.status_source = s;
    }

    /// Install the sibling WebSocket server that receives upgraded
    /// `/events` connections. Pass `null` to disable the upgrade path.
    pub fn setWsServer(self: *HttpServer, server: ?*ws_mod.WsServer) void {
        self.ws_server = server;
    }

    pub fn start(self: *HttpServer) Error!void {
        if (self.started) return error.AlreadyStarted;
        self.loop.addFd(
            self.listen_fd,
            linux.EPOLL.IN,
            onListenReadable,
            @ptrCast(self),
        ) catch return error.EventLoopError;
        self.started = true;
    }

    fn onListenReadable(
        fd: posix.fd_t,
        events: u32,
        userdata: ?*anyopaque,
    ) void {
        _ = events;
        const self: *HttpServer = @ptrCast(@alignCast(userdata.?));
        self.acceptPending(fd);
    }

    fn acceptPending(self: *HttpServer, listen_fd: posix.fd_t) void {
        // First: sweep any clients that blew past the read deadline.
        // Cheap to run on every accept batch; keeps slots available.
        self.sweepDeadlines();

        while (true) {
            const accept_flags: u32 = posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
            const cfd = posix.accept(listen_fd, null, null, accept_flags) catch |err| switch (err) {
                error.WouldBlock => return,
                else => {
                    std.log.warn("http: accept failed: {s}", .{@errorName(err)});
                    return;
                },
            };
            // SEC-008: accept-side rate limit. Rolling 1-second bucket.
            if (!self.consumeAcceptToken()) {
                @branchHint(.unlikely);
                std.log.warn("http: accept rate cap reached; dropping fd={d}", .{cfd});
                posix.close(cfd);
                continue;
            }
            self.admitClient(cfd) catch |err| {
                std.log.warn("http: admit fd={d}: {s}", .{ cfd, @errorName(err) });
                posix.close(cfd);
            };
        }
    }

    /// SEC-008: close any admitted client that has exceeded the read
    /// deadline. Called opportunistically from the accept loop; bounded
    /// by `max_clients` so it's a cheap constant-time scan.
    fn sweepDeadlines(self: *HttpServer) void {
        const now_ms = std.time.milliTimestamp();
        for (&self.clients) |*slot| {
            if (slot.*) |cli| {
                if (now_ms - cli.admitted_ms > client_read_deadline_ms) {
                    @branchHint(.unlikely);
                    std.log.info(
                        "http: client fd={d} exceeded {d}ms read deadline; closing",
                        .{ cli.fd, client_read_deadline_ms },
                    );
                    self.closeClient(cli);
                }
            }
        }
    }

    /// SEC-008: accept-rate bucket. Returns true iff a token is available
    /// in the current 1-second window. Rolls the bucket when the wall
    /// clock advances to a new second.
    fn consumeAcceptToken(self: *HttpServer) bool {
        const now_s: i64 = @divTrunc(std.time.milliTimestamp(), 1000);
        if (now_s != self.accept_bucket_epoch_s) {
            self.accept_bucket_epoch_s = now_s;
            self.accept_bucket_count = 0;
        }
        if (self.accept_bucket_count >= max_accepts_per_second) return false;
        self.accept_bucket_count += 1;
        return true;
    }

    fn admitClient(self: *HttpServer, fd: posix.fd_t) !void {
        var idx: ?usize = null;
        for (self.clients, 0..) |slot, i| {
            if (slot == null) {
                idx = i;
                break;
            }
        }
        if (idx == null) return error.TooManyClients;

        const cli = try self.allocator.create(ClientReg);
        errdefer self.allocator.destroy(cli);
        cli.* = .{ .server = self, .fd = fd, .admitted_ms = std.time.milliTimestamp() };

        try self.loop.addFd(fd, linux.EPOLL.IN, onClientReadable, @ptrCast(cli));
        self.clients[idx.?] = cli;
    }

    fn onClientReadable(
        fd: posix.fd_t,
        events: u32,
        userdata: ?*anyopaque,
    ) void {
        _ = events;
        _ = fd;
        const cli: *ClientReg = @ptrCast(@alignCast(userdata.?));
        cli.server.handleClient(cli);
    }

    fn handleClient(self: *HttpServer, cli: *ClientReg) void {
        // SEC-008: enforce the read deadline on every wake-up. A slow
        // client that dribbles bytes to stay under EAGAIN still gets
        // dropped once the total time since admission exceeds the cap.
        const now_ms = std.time.milliTimestamp();
        if (now_ms - cli.admitted_ms > client_read_deadline_ms) {
            @branchHint(.unlikely);
            std.log.info(
                "http: client fd={d} exceeded {d}ms read deadline; closing",
                .{ cli.fd, client_read_deadline_ms },
            );
            self.closeClient(cli);
            return;
        }

        // Read until we have the end of headers (\r\n\r\n) or the buffer
        // fills. Body is ignored — we only support GET.
        while (cli.len < cli.buf.len) {
            const n = posix.read(cli.fd, cli.buf[cli.len..]) catch |err| switch (err) {
                error.WouldBlock => return,
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

            if (std.mem.indexOf(u8, cli.buf[0..cli.len], "\r\n\r\n")) |hdr_end| {
                // Respond on the full-headers event. `respond` returns
                // `.handoff` if it transferred fd ownership to the WS
                // server — in that case we must NOT close the fd.
                const outcome = self.respond(cli, hdr_end) catch Outcome.close;
                switch (outcome) {
                    .close => self.closeClient(cli),
                    .handoff => self.releaseClient(cli),
                }
                return;
            }
        }
        // Buffer full without end-of-headers: too-big request.
        writeSimpleResponse(cli.fd, 413, "Payload Too Large", "text/plain", "request too large\n") catch {};
        self.closeClient(cli);
    }

    const Outcome = enum { close, handoff };

    fn respond(self: *HttpServer, cli: *ClientReg, hdr_end_idx: usize) !Outcome {
        const req_end = std.mem.indexOf(u8, cli.buf[0..cli.len], "\r\n") orelse {
            try writeSimpleResponse(cli.fd, 400, "Bad Request", "text/plain", "bad request\n");
            return .close;
        };
        const request_line = cli.buf[0..req_end];
        const parsed = parseRequestLine(request_line) orelse {
            try writeSimpleResponse(cli.fd, 400, "Bad Request", "text/plain", "bad request line\n");
            return .close;
        };

        if (!std.mem.eql(u8, parsed.method, "GET")) {
            try writeSimpleResponse(cli.fd, 405, "Method Not Allowed", "text/plain", "only GET\n");
            return .close;
        }

        // Strip query string for routing.
        const path = blk: {
            if (std.mem.indexOfScalar(u8, parsed.path, '?')) |i| break :blk parsed.path[0..i];
            break :blk parsed.path;
        };

        if (std.mem.eql(u8, path, "/metrics")) {
            try self.respondMetrics(cli.fd);
            return .close;
        } else if (std.mem.eql(u8, path, "/api/status")) {
            try self.respondStatus(cli.fd);
            return .close;
        } else if (std.mem.eql(u8, path, "/events")) {
            return self.tryWsUpgrade(cli, hdr_end_idx);
        } else {
            try writeSimpleResponse(cli.fd, 404, "Not Found", "text/plain", "not found\n");
            return .close;
        }
    }

    /// Attempt to complete a WebSocket upgrade on `/events`. On success,
    /// the client's FD is removed from this server's epoll registration
    /// and handed off to `ws_server`. Returns `.handoff` on success,
    /// `.close` otherwise (including when no ws_server is installed or
    /// the upgrade headers are missing).
    fn tryWsUpgrade(self: *HttpServer, cli: *ClientReg, hdr_end_idx: usize) !Outcome {
        const ws = self.ws_server orelse {
            try writeSimpleResponse(cli.fd, 400, "Bad Request", "text/plain", "websocket not enabled\n");
            return .close;
        };

        // Validate upgrade headers.
        const req_bytes = cli.buf[0..cli.len];
        const upgrade_hdr = ws_mod.findHeader(req_bytes, "Upgrade") orelse {
            try writeSimpleResponse(cli.fd, 400, "Bad Request", "text/plain", "upgrade required\n");
            return .close;
        };
        if (!asciiEqlIgnoreCase(upgrade_hdr, "websocket")) {
            try writeSimpleResponse(cli.fd, 400, "Bad Request", "text/plain", "bad upgrade\n");
            return .close;
        }
        const conn_hdr = ws_mod.findHeader(req_bytes, "Connection") orelse {
            try writeSimpleResponse(cli.fd, 400, "Bad Request", "text/plain", "connection: upgrade required\n");
            return .close;
        };
        if (!asciiContainsIgnoreCase(conn_hdr, "upgrade")) {
            try writeSimpleResponse(cli.fd, 400, "Bad Request", "text/plain", "connection header missing upgrade\n");
            return .close;
        }
        const key = ws_mod.findHeader(req_bytes, "Sec-WebSocket-Key") orelse {
            try writeSimpleResponse(cli.fd, 400, "Bad Request", "text/plain", "Sec-WebSocket-Key required\n");
            return .close;
        };

        // Compose handshake response (must happen BEFORE handoff — we
        // still hold the epoll registration and own any write errors).
        var accept_buf: [64]u8 = undefined;
        const accept = ws_mod.computeAccept(key, &accept_buf) catch {
            try writeSimpleResponse(cli.fd, 500, "Internal Server Error", "text/plain", "handshake failed\n");
            return .close;
        };
        var hs_buf: [256]u8 = undefined;
        const hs = std.fmt.bufPrint(
            &hs_buf,
            "HTTP/1.1 101 Switching Protocols\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Accept: {s}\r\n\r\n",
            .{accept},
        ) catch unreachable; // fixed-size format — cannot overflow
        writeAll(cli.fd, hs) catch return .close;

        // Any bytes already in the buffer past the request terminator
        // belong to the client's first WebSocket frame — must be handed
        // off to the WsServer along with the FD.
        const tail_start = hdr_end_idx + 4; // skip "\r\n\r\n"
        const tail = if (tail_start <= cli.len) cli.buf[tail_start..cli.len] else cli.buf[0..0];

        // Transfer ownership: remove from our epoll, hand to ws server.
        self.loop.removeFd(cli.fd) catch {};
        ws.admitUpgraded(cli.fd, tail) catch |err| {
            std.log.warn("http: ws handoff failed (fd={d}): {s}", .{ cli.fd, @errorName(err) });
            // admitUpgraded already closed the fd on failure.
            return .handoff;
        };
        return .handoff;
    }

    fn respondMetrics(self: *HttpServer, fd: posix.fd_t) !void {
        var body: std.ArrayListUnmanaged(u8) = .{};
        defer body.deinit(self.allocator);
        try self.metrics_source.write(self.metrics_source.ctx, &body, self.allocator);
        if (body.items.len > max_response_bytes) {
            try writeSimpleResponse(fd, 500, "Internal Server Error", "text/plain", "metrics body too large\n");
            return;
        }
        try writeResponse(fd, 200, "OK", "text/plain; version=0.0.4", body.items);
    }

    fn respondStatus(self: *HttpServer, fd: posix.fd_t) !void {
        var body: std.ArrayListUnmanaged(u8) = .{};
        defer body.deinit(self.allocator);
        try self.status_source.write(self.status_source.ctx, &body, self.allocator);
        if (body.items.len > max_response_bytes) {
            try writeSimpleResponse(fd, 500, "Internal Server Error", "text/plain", "status body too large\n");
            return;
        }
        try writeResponse(fd, 200, "OK", "application/json", body.items);
    }

    fn closeClient(self: *HttpServer, cli: *ClientReg) void {
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
        self.allocator.destroy(cli);
    }

    /// Drop the HTTP-side client bookkeeping without closing the fd or
    /// touching the event loop. Used after a successful WebSocket handoff
    /// where both have already been transferred to the WsServer.
    fn releaseClient(self: *HttpServer, cli: *ClientReg) void {
        for (&self.clients) |*slot| {
            if (slot.*) |existing| {
                if (existing == cli) {
                    slot.* = null;
                    break;
                }
            }
        }
        self.allocator.destroy(cli);
    }
};

// ============================================================================
// HTTP plumbing
// ============================================================================

const RequestLine = struct {
    method: []const u8,
    path: []const u8,
};

fn parseRequestLine(line: []const u8) ?RequestLine {
    // Format: METHOD SP PATH SP HTTP/VERSION
    const sp1 = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    const rest = line[sp1 + 1 ..];
    const sp2 = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    // Very small sanity check: path must start with '/'.
    if (rest.len == 0 or rest[0] != '/') return null;
    return .{ .method = line[0..sp1], .path = rest[0..sp2] };
}

/// SEC-005: security headers emitted on every response. Constants so
/// they compile to a single static string and cost nothing at runtime.
///
/// Rationale:
///   - `X-Content-Type-Options: nosniff` — stop browsers MIME-sniffing
///     our text/plain metrics into executable content.
///   - `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` — we
///     never embed, never want to be framed.
///   - `Referrer-Policy: no-referrer` — our endpoints never link out.
///   - `Cache-Control: no-store` — metrics / status are live state; any
///     intermediary cache would leak stale data.
///   - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
///     — we serve only text/plain and application/json bodies, never HTML.
const security_headers =
    "X-Content-Type-Options: nosniff\r\n" ++
    "X-Frame-Options: DENY\r\n" ++
    "Referrer-Policy: no-referrer\r\n" ++
    "Cache-Control: no-store\r\n" ++
    "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n";

fn writeResponse(
    fd: posix.fd_t,
    status: u16,
    reason: []const u8,
    content_type: []const u8,
    body: []const u8,
) !void {
    var hdr: [512]u8 = undefined;
    const head = try std.fmt.bufPrint(
        &hdr,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n" ++
            security_headers ++
            "\r\n",
        .{ status, reason, content_type, body.len },
    );
    try writeAll(fd, head);
    try writeAll(fd, body);
}

fn writeSimpleResponse(
    fd: posix.fd_t,
    status: u16,
    reason: []const u8,
    content_type: []const u8,
    body: []const u8,
) !void {
    try writeResponse(fd, status, reason, content_type, body);
}

fn writeAll(fd: posix.fd_t, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try posix.write(fd, bytes[written..]);
        if (n == 0) return error.ShortWrite;
        written += n;
    }
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

fn asciiContainsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (asciiEqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

// Simple dotted-quad IPv4 parser; the net/types variant is overkill here.
fn parseIpv4(s: []const u8) ?u32 {
    var parts = std.mem.splitScalar(u8, s, '.');
    var out: u32 = 0;
    var count: usize = 0;
    while (parts.next()) |p| {
        if (count >= 4) return null;
        const v = std.fmt.parseInt(u8, p, 10) catch return null;
        out = (out << 8) | v;
        count += 1;
    }
    if (count != 4) return null;
    return out;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "http: parseRequestLine accepts GET / HTTP/1.1" {
    const r = parseRequestLine("GET / HTTP/1.1").?;
    try testing.expectEqualStrings("GET", r.method);
    try testing.expectEqualStrings("/", r.path);
}

test "http: parseRequestLine rejects missing path slash" {
    try testing.expect(parseRequestLine("GET foo HTTP/1.1") == null);
    try testing.expect(parseRequestLine("GET") == null);
}

test "http: parseIpv4 accepts and rejects correctly" {
    try testing.expectEqual(@as(?u32, 0x7F000001), parseIpv4("127.0.0.1"));
    try testing.expectEqual(@as(?u32, 0x00000000), parseIpv4("0.0.0.0"));
    try testing.expect(parseIpv4("127.0.0.256") == null);
    try testing.expect(parseIpv4("127.0.0") == null);
    try testing.expect(parseIpv4("abc") == null);
}

fn drive(loop: *EventLoop, ms: u64) !void {
    const Wd = struct {
        fn run(l: *EventLoop, m: u64) void {
            std.time.sleep(m * std.time.ns_per_ms);
            l.stop();
        }
    };
    const th = try std.Thread.spawn(.{}, Wd.run, .{ loop, ms });
    try loop.run();
    th.join();
}

fn connectLocalhost(port: u16) !posix.fd_t {
    const stype: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    const fd = try posix.socket(posix.AF.INET, stype, 0);
    errdefer posix.close(fd);
    var addr: linux.sockaddr.in = .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7F000001),
        .zero = [_]u8{0} ** 8,
    };
    try posix.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
    return fd;
}

fn readAll(fd: posix.fd_t, buf: []u8) !usize {
    var total: usize = 0;
    while (total < buf.len) {
        const n = posix.read(fd, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }
    return total;
}

/// Single client driver that sends `req`, reads response, returns it.
const ClientResult = struct {
    buf: [4096]u8 = undefined,
    len: usize = 0,

    fn bytes(self: *const ClientResult) []const u8 {
        return self.buf[0..self.len];
    }
};

fn httpRoundTrip(port: u16, req: []const u8) !ClientResult {
    const fd = try connectLocalhost(port);
    defer posix.close(fd);
    try writeAll(fd, req);
    var res: ClientResult = .{};
    res.len = try readAll(fd, &res.buf);
    return res;
}

const Counter = struct { calls: u32 = 0 };

fn countingMetrics(
    ctx: ?*anyopaque,
    out: *std.ArrayListUnmanaged(u8),
    a: std.mem.Allocator,
) anyerror!void {
    const self: *Counter = @ptrCast(@alignCast(ctx.?));
    self.calls += 1;
    try out.appendSlice(a, "# HELP custom_metric hi\n# TYPE custom_metric counter\ncustom_metric 42\n");
}

fn jsonStatus(
    ctx: ?*anyopaque,
    out: *std.ArrayListUnmanaged(u8),
    a: std.mem.Allocator,
) anyerror!void {
    _ = ctx;
    try out.appendSlice(a, "{\"hello\":\"world\"}");
}

test "http: accept rate cap enforces 1-second bucket (SEC-008)" {
    // SEC-008: consumeAcceptToken must allow exactly max_accepts_per_second
    // admissions per rolling 1-second window. We exercise it directly on a
    // minimal server — no listener, no event-loop interaction needed.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server: HttpServer = .{
        .allocator = a,
        .loop = &loop,
        .port = 0,
        .bind_addr = "127.0.0.1",
        .listen_fd = -1,
    };

    // First max_accepts_per_second calls succeed within the same bucket.
    for (0..max_accepts_per_second) |_| {
        try testing.expect(server.consumeAcceptToken());
    }
    // The next one fails — bucket exhausted.
    try testing.expect(!server.consumeAcceptToken());

    // Force-roll the bucket by pretending time advanced to the next
    // second. In production this happens naturally; here we poke the
    // internal epoch so the test doesn't need a 1s sleep.
    server.accept_bucket_epoch_s -= 1;
    try testing.expect(server.consumeAcceptToken());
}

test "http: sweep closes clients past the read deadline (SEC-008)" {
    // SEC-008: a client admitted long enough ago must be closed by
    // sweepDeadlines even if it has never been readable. We admit a
    // client via a socketpair, back-date its admitted_ms, then call
    // sweepDeadlines and confirm the slot is freed.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server: HttpServer = .{
        .allocator = a,
        .loop = &loop,
        .port = 0,
        .bind_addr = "127.0.0.1",
        .listen_fd = -1,
    };
    defer {
        // Any leftover clients would leak; closeClient is idempotent
        // at the slot-level so this is safe.
        for (&server.clients) |*slot| {
            if (slot.*) |cli| {
                loop.removeFd(cli.fd) catch {};
                posix.close(cli.fd);
                a.destroy(cli);
                slot.* = null;
            }
        }
    }

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

    try server.admitClient(fds[0]);
    // Back-date the admission clock so the deadline is guaranteed to be exceeded.
    if (server.clients[0]) |cli| {
        cli.admitted_ms = std.time.milliTimestamp() - client_read_deadline_ms - 1000;
    }
    server.sweepDeadlines();
    // The slot must be empty; the fd was closed by closeClient.
    try testing.expect(server.clients[0] == null);
}

test "http: responses include security headers (SEC-005)" {
    // SEC-005: every response must carry the full set of defense-in-depth
    // headers regardless of status code or content type. Exercise both a
    // 200 and a 404 to confirm the headers come from writeResponse, not
    // from the success path.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = HttpServer.init(a, &loop, 0, "127.0.0.1") catch return error.SkipZigTest;
    defer server.deinit();
    try server.start();

    const port = try server.getBoundPort();
    const Ctx = struct { port: u16, metrics: *ClientResult, notfound: *ClientResult };
    var metrics: ClientResult = .{};
    var notfound: ClientResult = .{};
    var ctx = Ctx{ .port = port, .metrics = &metrics, .notfound = &notfound };

    const Driver = struct {
        fn run(c: *Ctx, l: *EventLoop) void {
            std.time.sleep(20 * std.time.ns_per_ms);
            // /metrics → 200
            const fd1 = connectLocalhost(c.port) catch {
                l.stop();
                return;
            };
            defer posix.close(fd1);
            writeAll(fd1, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n") catch {};
            c.metrics.len = readAll(fd1, &c.metrics.buf) catch 0;
            // /nope → 404
            const fd2 = connectLocalhost(c.port) catch {
                l.stop();
                return;
            };
            defer posix.close(fd2);
            writeAll(fd2, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n") catch {};
            c.notfound.len = readAll(fd2, &c.notfound.buf) catch 0;
            l.stop();
        }
    };
    const th = try std.Thread.spawn(.{}, Driver.run, .{ &ctx, &loop });
    const Wd = struct {
        fn run(l: *EventLoop) void {
            std.time.sleep(2 * std.time.ns_per_s);
            l.stop();
        }
    };
    const wd = try std.Thread.spawn(.{}, Wd.run, .{&loop});
    try loop.run();
    th.join();
    wd.join();

    const required = [_][]const u8{
        "X-Content-Type-Options: nosniff",
        "X-Frame-Options: DENY",
        "Referrer-Policy: no-referrer",
        "Cache-Control: no-store",
        "Content-Security-Policy: default-src 'none'",
    };
    for (required) |h| {
        try testing.expect(std.mem.indexOf(u8, metrics.bytes(), h) != null);
        try testing.expect(std.mem.indexOf(u8, notfound.bytes(), h) != null);
    }
}

test "http: GET /metrics returns Prometheus body" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = HttpServer.init(a, &loop, 0, "127.0.0.1") catch return error.SkipZigTest;
    defer server.deinit();

    var ctr = Counter{};
    server.setMetricsSource(.{ .ctx = @ptrCast(&ctr), .write = countingMetrics });
    try server.start();

    const port = try server.getBoundPort();

    // Driver thread: connect, send GET, read response, stop loop.
    const Ctx = struct { port: u16, result: *ClientResult, err: *?anyerror };
    var result: ClientResult = .{};
    var caught: ?anyerror = null;
    var ctx = Ctx{ .port = port, .result = &result, .err = &caught };

    const Driver = struct {
        fn run(c: *Ctx, l: *EventLoop) void {
            std.time.sleep(20 * std.time.ns_per_ms);
            const fd = connectLocalhost(c.port) catch |e| {
                c.err.* = e;
                l.stop();
                return;
            };
            defer posix.close(fd);
            writeAll(fd, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n") catch |e| {
                c.err.* = e;
                l.stop();
                return;
            };
            c.result.len = readAll(fd, &c.result.buf) catch 0;
            l.stop();
        }
    };
    const th = try std.Thread.spawn(.{}, Driver.run, .{ &ctx, &loop });
    // Watchdog safety.
    const Wd = struct {
        fn run(l: *EventLoop) void {
            std.time.sleep(2 * std.time.ns_per_s);
            l.stop();
        }
    };
    const wd = try std.Thread.spawn(.{}, Wd.run, .{&loop});
    try loop.run();
    th.join();
    wd.join();

    if (caught) |e| return e;

    const body = result.bytes();
    try testing.expect(body.len > 0);
    try testing.expect(std.mem.indexOf(u8, body, "200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, body, "text/plain; version=0.0.4") != null);
    try testing.expect(std.mem.indexOf(u8, body, "custom_metric 42") != null);
    try testing.expect(ctr.calls >= 1);
}

test "http: GET /api/status returns JSON" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = HttpServer.init(a, &loop, 0, "127.0.0.1") catch return error.SkipZigTest;
    defer server.deinit();

    server.setStatusSource(.{ .ctx = null, .write = jsonStatus });
    try server.start();

    const port = try server.getBoundPort();
    const Ctx = struct { port: u16, result: *ClientResult };
    var result: ClientResult = .{};
    var ctx = Ctx{ .port = port, .result = &result };

    const Driver = struct {
        fn run(c: *Ctx, l: *EventLoop) void {
            std.time.sleep(20 * std.time.ns_per_ms);
            const fd = connectLocalhost(c.port) catch {
                l.stop();
                return;
            };
            defer posix.close(fd);
            writeAll(fd, "GET /api/status HTTP/1.1\r\nHost: x\r\n\r\n") catch {};
            c.result.len = readAll(fd, &c.result.buf) catch 0;
            l.stop();
        }
    };
    const th = try std.Thread.spawn(.{}, Driver.run, .{ &ctx, &loop });
    const Wd = struct {
        fn run(l: *EventLoop) void {
            std.time.sleep(2 * std.time.ns_per_s);
            l.stop();
        }
    };
    const wd = try std.Thread.spawn(.{}, Wd.run, .{&loop});
    try loop.run();
    th.join();
    wd.join();

    const body = result.bytes();
    try testing.expect(std.mem.indexOf(u8, body, "200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, body, "application/json") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"hello\":\"world\"") != null);
}

test "http: GET unknown path returns 404" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = HttpServer.init(a, &loop, 0, "127.0.0.1") catch return error.SkipZigTest;
    defer server.deinit();
    try server.start();

    const port = try server.getBoundPort();
    const Ctx = struct { port: u16, result: *ClientResult };
    var result: ClientResult = .{};
    var ctx = Ctx{ .port = port, .result = &result };

    const Driver = struct {
        fn run(c: *Ctx, l: *EventLoop) void {
            std.time.sleep(20 * std.time.ns_per_ms);
            const fd = connectLocalhost(c.port) catch {
                l.stop();
                return;
            };
            defer posix.close(fd);
            writeAll(fd, "GET /does-not-exist HTTP/1.1\r\nHost: x\r\n\r\n") catch {};
            c.result.len = readAll(fd, &c.result.buf) catch 0;
            l.stop();
        }
    };
    const th = try std.Thread.spawn(.{}, Driver.run, .{ &ctx, &loop });
    const Wd = struct {
        fn run(l: *EventLoop) void {
            std.time.sleep(2 * std.time.ns_per_s);
            l.stop();
        }
    };
    const wd = try std.Thread.spawn(.{}, Wd.run, .{&loop});
    try loop.run();
    th.join();
    wd.join();

    try testing.expect(std.mem.indexOf(u8, result.bytes(), "404") != null);
}

test "http: POST on known path returns 405" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = HttpServer.init(a, &loop, 0, "127.0.0.1") catch return error.SkipZigTest;
    defer server.deinit();
    try server.start();

    const port = try server.getBoundPort();
    const Ctx = struct { port: u16, result: *ClientResult };
    var result: ClientResult = .{};
    var ctx = Ctx{ .port = port, .result = &result };

    const Driver = struct {
        fn run(c: *Ctx, l: *EventLoop) void {
            std.time.sleep(20 * std.time.ns_per_ms);
            const fd = connectLocalhost(c.port) catch {
                l.stop();
                return;
            };
            defer posix.close(fd);
            writeAll(fd, "POST /metrics HTTP/1.1\r\nHost: x\r\n\r\n") catch {};
            c.result.len = readAll(fd, &c.result.buf) catch 0;
            l.stop();
        }
    };
    const th = try std.Thread.spawn(.{}, Driver.run, .{ &ctx, &loop });
    const Wd = struct {
        fn run(l: *EventLoop) void {
            std.time.sleep(2 * std.time.ns_per_s);
            l.stop();
        }
    };
    const wd = try std.Thread.spawn(.{}, Wd.run, .{&loop});
    try loop.run();
    th.join();
    wd.join();

    try testing.expect(std.mem.indexOf(u8, result.bytes(), "405") != null);
}

test "http: defaultWriteMetrics produces Prometheus preamble" {
    const a = testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try defaultWriteMetrics(null, &out, a);
    try testing.expect(std.mem.indexOf(u8, out.items, "fail2zig_up") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "# TYPE") != null);
}

test "http: defaultWriteStatus produces JSON" {
    const a = testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try defaultWriteStatus(null, &out, a);
    try testing.expect(std.mem.indexOf(u8, out.items, "\"status\":\"ok\"") != null);
}
