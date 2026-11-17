// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Serves the metrics, status and health endpoints over HTTP/1.1.
// Holds: A connection gets one response to one request of at most 8 KiB and is then closed; ban details are never served.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const event_loop_mod = @import("../platform/event_loop.zig");
const EventLoop = event_loop_mod.EventLoop;

pub const max_clients: usize = 16;
pub const max_request_bytes: usize = 8 * 1024;
pub const max_response_bytes: usize = 64 * 1024;

pub const client_read_deadline_ms: i64 = 5_000;

pub const max_accepts_per_second: u32 = 100;

pub const Error = error{
    SocketCreateFailed,
    BindFailed,
    ListenFailed,
    SetsockoptFailed,
    EventLoopError,
    AlreadyStarted,
    OutOfMemory,
    NotLinux,
} || posix.BindError;

pub const MetricsSource = struct {
    ctx: ?*anyopaque = null,
    write: *const fn (
        ctx: ?*anyopaque,
        out: *std.ArrayListUnmanaged(u8),
        a: std.mem.Allocator,
    ) anyerror!void = defaultWriteMetrics,
};

pub const StatusSource = struct {
    ctx: ?*anyopaque = null,
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

const ClientReg = struct {
    server: *HttpServer,
    fd: posix.fd_t,
    buf: [max_request_bytes]u8 = undefined,
    len: usize = 0,
    admitted_ms: i64 = 0,
};

pub const HttpServer = struct {
    allocator: std.mem.Allocator,
    loop: *EventLoop,
    port: u16,
    bind_addr: []const u8,
    listen_fd: posix.fd_t = -1,
    started: bool = false,
    metrics_source: MetricsSource = .{},
    status_source: StatusSource = .{},
    health_source: StatusSource = .{},
    clients: [max_clients]?*ClientReg = [_]?*ClientReg{null} ** max_clients,
    accept_bucket_epoch_s: i64 = 0,
    accept_bucket_count: u32 = 0,

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
        try posix.bind(fd, @ptrCast(&addr), addr_len);

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

    pub fn setMetricsSource(self: *HttpServer, s: MetricsSource) void {
        self.metrics_source = s;
    }

    pub fn setHealthSource(self: *HttpServer, s: StatusSource) void {
        self.health_source = s;
    }
    pub fn setStatusSource(self: *HttpServer, s: StatusSource) void {
        self.status_source = s;
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
        // Why: No timer runs here; stalled clients are swept when the next connection arrives.
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

            // Why: The header section ends at the first empty line (RFC 9112 section 2.1); no request body is ever read.
            if (std.mem.indexOf(u8, cli.buf[0..cli.len], "\r\n\r\n") != null) {
                self.respond(cli) catch {};
                self.closeClient(cli);
                return;
            }
        }
        writeSimpleResponse(cli.fd, 413, "Payload Too Large", "text/plain", "request too large\n") catch {};
        self.closeClient(cli);
    }

    fn respond(self: *HttpServer, cli: *ClientReg) !void {
        const req_end = std.mem.indexOf(u8, cli.buf[0..cli.len], "\r\n") orelse {
            try writeSimpleResponse(cli.fd, 400, "Bad Request", "text/plain", "bad request\n");
            return;
        };
        const request_line = cli.buf[0..req_end];
        const parsed = parseRequestLine(request_line) orelse {
            try writeSimpleResponse(cli.fd, 400, "Bad Request", "text/plain", "bad request line\n");
            return;
        };

        if (!std.mem.eql(u8, parsed.method, "GET")) {
            try writeSimpleResponse(cli.fd, 405, "Method Not Allowed", "text/plain", "only GET\n");
            return;
        }

        const path = blk: {
            if (std.mem.indexOfScalar(u8, parsed.path, '?')) |i| break :blk parsed.path[0..i];
            break :blk parsed.path;
        };

        if (std.mem.eql(u8, path, "/metrics")) {
            try self.respondMetrics(cli.fd);
            return;
        } else if (std.mem.eql(u8, path, "/api/status")) {
            try self.respondStatus(cli.fd);
            return;
        } else if (std.mem.eql(u8, path, "/api/health")) {
            try self.respondHealth(cli.fd);
            return;
        } else if (std.mem.eql(u8, path, "/api/bans")) {
            try writeSimpleResponse(cli.fd, 403, "Forbidden", "text/plain", "ban details require administrator access through the local socket\n");
            return;
        } else {
            try writeSimpleResponse(cli.fd, 404, "Not Found", "text/plain", "not found\n");
            return;
        }
    }

    fn respondMetrics(self: *HttpServer, fd: posix.fd_t) !void {
        var body: std.ArrayListUnmanaged(u8) = .{};
        defer body.deinit(self.allocator);
        self.metrics_source.write(self.metrics_source.ctx, &body, self.allocator) catch |failure| switch (failure) {
            error.ResponseTooLarge, error.SnapshotLimit => {
                try writeSimpleResponse(fd, 500, "Internal Server Error", "text/plain", "metrics body too large\n");
                return;
            },
            else => return failure,
        };
        if (body.items.len > max_response_bytes) {
            try writeSimpleResponse(fd, 500, "Internal Server Error", "text/plain", "metrics body too large\n");
            return;
        }
        // Why: version=0.0.4 names the Prometheus text exposition format (prometheus.io/docs/instrumenting/exposition_formats).
        try writeResponse(fd, 200, "OK", "text/plain; version=0.0.4", body.items);
    }

    fn respondStatus(self: *HttpServer, fd: posix.fd_t) !void {
        var body: std.ArrayListUnmanaged(u8) = .{};
        defer body.deinit(self.allocator);
        self.status_source.write(self.status_source.ctx, &body, self.allocator) catch |failure| switch (failure) {
            error.ResponseTooLarge, error.SnapshotLimit => {
                try writeSimpleResponse(fd, 500, "Internal Server Error", "text/plain", "status body too large\n");
                return;
            },
            else => return failure,
        };
        if (body.items.len > max_response_bytes) {
            try writeSimpleResponse(fd, 500, "Internal Server Error", "text/plain", "status body too large\n");
            return;
        }
        try writeResponse(fd, 200, "OK", "application/json", body.items);
    }

    fn respondHealth(self: *HttpServer, fd: posix.fd_t) !void {
        var body: std.ArrayListUnmanaged(u8) = .{};
        defer body.deinit(self.allocator);
        self.health_source.write(self.health_source.ctx, &body, self.allocator) catch |failure| switch (failure) {
            error.ResponseTooLarge, error.SnapshotLimit => {
                try writeSimpleResponse(fd, 500, "Internal Server Error", "text/plain", "health body too large\n");
                return;
            },
            else => return failure,
        };
        if (body.items.len > max_response_bytes) {
            try writeSimpleResponse(fd, 500, "Internal Server Error", "text/plain", "health body too large\n");
            return;
        }
        // Why: The status code is read off the body: only the exact text "ready":true answers 200, so that spelling is load-bearing.
        if (std.mem.indexOf(u8, body.items, "\"ready\":true") != null) {
            try writeResponse(fd, 200, "OK", "application/json", body.items);
        } else {
            try writeResponse(fd, 503, "Service Unavailable", "application/json", body.items);
        }
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
};

const RequestLine = struct {
    method: []const u8,
    path: []const u8,
};

fn parseRequestLine(line: []const u8) ?RequestLine {
    const sp1 = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    const rest = line[sp1 + 1 ..];
    const sp2 = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    // Why: Only origin-form request targets are served (RFC 9112 section 3.2.1).
    if (rest.len == 0 or rest[0] != '/') return null;
    return .{ .method = line[0..sp1], .path = rest[0..sp2] };
}

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
