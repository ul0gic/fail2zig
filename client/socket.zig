// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Unix-domain-socket client for the fail2zig daemon IPC protocol.
//!
//! Wire format is defined in `shared/protocol.zig`:
//!   [u32 payload_size little-endian][payload_size bytes of body]
//!
//! The client performs a single synchronous round-trip per command:
//!   1. `connect()`   — open AF_UNIX stream socket, set send/recv timeouts,
//!                      connect to the daemon socket path.
//!   2. `sendCommand()` — serialize `shared.protocol.Command`, write, read a
//!                        response, deserialize.
//!   3. `close()`     — shutdown and close the FD.
//!
//! Errors are normalized into a `ClientError` set plus an optional diagnostic
//! message describing exactly what went wrong and how the user might fix it.
//! `SocketClient.err_buf` stores the message for the lifetime of the client.

const std = @import("std");
const posix = std.posix;
const shared = @import("shared");

pub const default_socket_path: []const u8 = "/run/fail2zig/fail2zig.sock";

pub const ClientError = error{
    DaemonUnreachable, // ENOENT / ECONNREFUSED on connect
    PermissionDenied, // EACCES / EPERM on connect or send
    Timeout, // SO_SNDTIMEO / SO_RCVTIMEO elapsed
    ProtocolError, // deserialization failed (corrupt or oversized response)
    SocketError, // any other socket/system error
    PathTooLong, // sockaddr_un.sun_path overflow
    OutOfMemory,
};

/// A connected Unix-domain-socket client. The file descriptor is owned by the
/// struct — always call `close()` (or `deinit()`) exactly once.
pub const SocketClient = struct {
    fd: posix.socket_t,
    timeout_ms: u64,
    allocator: std.mem.Allocator,
    err_buf: [256]u8 = [_]u8{0} ** 256,
    err_len: usize = 0,

    /// Human-readable description of the most recent error (or empty string).
    pub fn errorMessage(self: *const SocketClient) []const u8 {
        return self.err_buf[0..self.err_len];
    }

    fn setErr(self: *SocketClient, comptime fmt: []const u8, args: anytype) void {
        const slice = std.fmt.bufPrint(&self.err_buf, fmt, args) catch {
            const trunc = "error message truncated";
            @memcpy(self.err_buf[0..trunc.len], trunc);
            self.err_len = trunc.len;
            return;
        };
        self.err_len = slice.len;
    }

    /// Cleanly close the socket. Idempotent — safe to call after an error.
    pub fn close(self: *SocketClient) void {
        posix.close(self.fd);
    }

    /// Alias for `close` for API symmetry with Zig conventions.
    pub fn deinit(self: *SocketClient) void {
        self.close();
    }

    /// Serialize `cmd`, send it, read the framed response, and return it.
    /// The returned `Response` owns heap buffers — call `response.deinit(alloc)`.
    pub fn sendCommand(self: *SocketClient, cmd: shared.Command) ClientError!shared.Response {
        // Serialize into a stack buffer (protocol bodies are small; 1 MiB cap is
        // enforced by the deserializer but commands in practice are <100 bytes).
        var tx_buf: [4096]u8 = undefined;
        var stream = std.io.fixedBufferStream(&tx_buf);
        shared.serializeCommand(cmd, stream.writer()) catch {
            self.setErr("failed to serialize command (buffer too small?)", .{});
            return error.ProtocolError;
        };
        const written = stream.getWritten();

        writeAll(self.fd, written) catch |e| return self.mapSendErr(e);

        // Read response via a buffered reader over the raw socket.
        const sock_reader = std.io.Reader(posix.socket_t, SocketReadError, socketRead){ .context = self.fd };
        var buffered = std.io.bufferedReader(sock_reader);
        const resp = shared.deserializeResponse(buffered.reader(), self.allocator) catch |e| {
            return self.mapDeserializeErr(e);
        };
        return resp;
    }

    fn mapSendErr(self: *SocketClient, e: anyerror) ClientError {
        // Blocking sockets with SO_SNDTIMEO set surface timeouts as WouldBlock.
        // AccessDenied is the SendError; PermissionDenied is the ConnectError —
        // list both to keep the mapping robust across OS + std version changes.
        if (e == error.WouldBlock) {
            self.setErr(
                "Daemon did not respond within {d}ms. Check daemon health.",
                .{self.timeout_ms},
            );
            return error.Timeout;
        }
        if (e == error.AccessDenied) {
            self.setErr(
                "Permission denied. fail2zig-client requires group 'fail2zig' membership.",
                .{},
            );
            return error.PermissionDenied;
        }
        if (e == error.BrokenPipe or e == error.ConnectionResetByPeer) {
            self.setErr("Daemon closed the connection before the command completed.", .{});
            return error.SocketError;
        }
        self.setErr("Socket write failed: {s}", .{@errorName(e)});
        return error.SocketError;
    }

    fn mapDeserializeErr(self: *SocketClient, e: anyerror) ClientError {
        if (e == error.WouldBlock) {
            self.setErr(
                "Daemon did not respond within {d}ms. Check daemon health.",
                .{self.timeout_ms},
            );
            return error.Timeout;
        }
        if (e == error.EndOfStream) {
            self.setErr("Daemon closed the connection without sending a response.", .{});
            return error.ProtocolError;
        }
        if (e == error.OutOfMemory) return error.OutOfMemory;
        self.setErr("Malformed response from daemon ({s}).", .{@errorName(e)});
        return error.ProtocolError;
    }
};

/// Connect to a Unix domain socket, setting send/recv timeouts. On error, the
/// returned struct is NOT valid — the FD is already closed and an error is
/// returned with a populated diagnostic.
pub fn connect(
    allocator: std.mem.Allocator,
    path: []const u8,
    timeout_ms: u64,
    diag: *DiagBuf,
) ClientError!SocketClient {
    // sockaddr_un.sun_path is 108 bytes on Linux and must be null-terminated.
    if (path.len == 0) {
        diag.set("socket path is empty", .{});
        return error.PathTooLong;
    }
    var addr: posix.sockaddr.un = undefined;
    if (path.len >= addr.path.len) {
        diag.set(
            "socket path too long ({d} bytes; max {d})",
            .{ path.len, addr.path.len - 1 },
        );
        return error.PathTooLong;
    }
    addr.family = posix.AF.UNIX;
    @memset(&addr.path, 0);
    @memcpy(addr.path[0..path.len], path);

    const fd = posix.socket(
        posix.AF.UNIX,
        posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
        0,
    ) catch |e| {
        diag.set("failed to create socket: {s}", .{@errorName(e)});
        return error.SocketError;
    };
    errdefer posix.close(fd);

    // Apply send/recv timeouts before connect so a non-responsive peer can't
    // stall us indefinitely. SO_SNDTIMEO / SO_RCVTIMEO both apply — connect
    // respects SO_SNDTIMEO on Linux when the socket is blocking.
    const tv = timeoutToTimeval(timeout_ms);
    setTimeout(fd, posix.SO.SNDTIMEO, tv) catch |e| {
        diag.set("failed to set send timeout: {s}", .{@errorName(e)});
        return error.SocketError;
    };
    setTimeout(fd, posix.SO.RCVTIMEO, tv) catch |e| {
        diag.set("failed to set recv timeout: {s}", .{@errorName(e)});
        return error.SocketError;
    };

    const addr_len: posix.socklen_t = @intCast(@sizeOf(posix.sockaddr.un));
    posix.connect(fd, @ptrCast(&addr), addr_len) catch |e| {
        switch (e) {
            error.FileNotFound, error.ConnectionRefused => {
                diag.set(
                    "Cannot connect to fail2zig daemon at {s}. Is the service running?",
                    .{path},
                );
                return error.DaemonUnreachable;
            },
            error.PermissionDenied => {
                diag.set(
                    "Permission denied. fail2zig-client requires group 'fail2zig' membership.",
                    .{},
                );
                return error.PermissionDenied;
            },
            error.WouldBlock, error.ConnectionTimedOut => {
                diag.set(
                    "Daemon did not respond within {d}ms. Check daemon health.",
                    .{timeout_ms},
                );
                return error.Timeout;
            },
            else => {
                diag.set("connect failed: {s}", .{@errorName(e)});
                return error.SocketError;
            },
        }
    };

    var client = SocketClient{
        .fd = fd,
        .timeout_ms = timeout_ms,
        .allocator = allocator,
    };
    // Mirror diag into the client so error messages survive after `connect`.
    @memcpy(client.err_buf[0..diag.len], diag.buf[0..diag.len]);
    client.err_len = diag.len;
    return client;
}

/// A short pre-connect diagnostic buffer owned by the caller.
pub const DiagBuf = struct {
    buf: [256]u8 = [_]u8{0} ** 256,
    len: usize = 0,

    pub fn message(self: *const DiagBuf) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn set(self: *DiagBuf, comptime fmt: []const u8, args: anytype) void {
        const slice = std.fmt.bufPrint(&self.buf, fmt, args) catch {
            const trunc = "error message truncated";
            @memcpy(self.buf[0..trunc.len], trunc);
            self.len = trunc.len;
            return;
        };
        self.len = slice.len;
    }
};

fn timeoutToTimeval(ms: u64) posix.timeval {
    const secs: i64 = @intCast(ms / 1000);
    const usecs: i64 = @intCast((ms % 1000) * 1000);
    return .{ .sec = secs, .usec = usecs };
}

fn setTimeout(fd: posix.socket_t, optname: u32, tv: posix.timeval) !void {
    try posix.setsockopt(fd, posix.SOL.SOCKET, optname, std.mem.asBytes(&tv));
}

// ============================================================================
// Raw socket write / read (no std.net dependency)
// ============================================================================

const SocketReadError = error{
    WouldBlock,
    Timeout,
    ConnectionResetByPeer,
    SystemResources,
    Unexpected,
    AccessDenied,
};

fn socketRead(fd: posix.socket_t, buf: []u8) SocketReadError!usize {
    return posix.recv(fd, buf, 0) catch |e| switch (e) {
        error.WouldBlock => error.WouldBlock,
        error.ConnectionResetByPeer => error.ConnectionResetByPeer,
        error.ConnectionRefused => error.ConnectionResetByPeer,
        error.SystemResources => error.SystemResources,
        error.SocketNotConnected => error.ConnectionResetByPeer,
        else => error.Unexpected,
    };
}

fn writeAll(fd: posix.socket_t, data: []const u8) !void {
    var offset: usize = 0;
    while (offset < data.len) {
        const n = try posix.send(fd, data[offset..], 0);
        if (n == 0) return error.BrokenPipe;
        offset += n;
    }
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "socket: connect to nonexistent path returns DaemonUnreachable" {
    var diag: DiagBuf = .{};
    const result = connect(
        testing.allocator,
        "/tmp/fail2zig-definitely-does-not-exist-xyz.sock",
        500,
        &diag,
    );
    try testing.expectError(error.DaemonUnreachable, result);
    try testing.expect(std.mem.indexOf(u8, diag.message(), "Cannot connect") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message(), "Is the service running") != null);
}

test "socket: connect rejects empty path" {
    var diag: DiagBuf = .{};
    const result = connect(testing.allocator, "", 500, &diag);
    try testing.expectError(error.PathTooLong, result);
}

test "socket: connect rejects oversize path" {
    var diag: DiagBuf = .{};
    const long = [_]u8{'a'} ** 200;
    const result = connect(testing.allocator, &long, 500, &diag);
    try testing.expectError(error.PathTooLong, result);
    try testing.expect(std.mem.indexOf(u8, diag.message(), "too long") != null);
}

test "socket: roundtrip via socketpair — ok response" {
    // socketpair(AF_UNIX, SOCK_STREAM) gives us two connected FDs; we simulate
    // the daemon on one side and the client on the other.
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (std.os.linux.E.init(rc) != .SUCCESS) return error.SkipZigTest;
    defer posix.close(fds[0]);
    // fds[1] is owned by SocketClient below.

    var client = SocketClient{
        .fd = fds[1],
        .timeout_ms = 2000,
        .allocator = testing.allocator,
    };
    defer client.close();

    // Server thread: read the incoming command, respond with an OK payload.
    const ServerCtx = struct {
        fd: posix.socket_t,
        thread_err: ?anyerror = null,

        fn run(ctx: *@This()) void {
            ctx.runInner() catch |e| {
                ctx.thread_err = e;
            };
        }

        fn runInner(ctx: *@This()) !void {
            // Read the command using protocol helpers.
            var buf: [1024]u8 = undefined;
            const header = try readNExact(ctx.fd, buf[0..4]);
            _ = header;
            const size = std.mem.readInt(u32, buf[0..4], .little);
            if (size > buf.len - 4) return error.Overflow;
            _ = try readNExact(ctx.fd, buf[4 .. 4 + size]);

            // Send an OK response with payload "hello".
            const resp = shared.Response{ .ok = .{ .payload = "hello" } };
            var out_buf: [64]u8 = undefined;
            var s = std.io.fixedBufferStream(&out_buf);
            try shared.serializeResponse(resp, s.writer());
            var off: usize = 0;
            const bytes = s.getWritten();
            while (off < bytes.len) {
                const n = try posix.send(ctx.fd, bytes[off..], 0);
                off += n;
            }
        }
    };

    var ctx = ServerCtx{ .fd = fds[0] };
    const thread = try std.Thread.spawn(.{}, ServerCtx.run, .{&ctx});

    const resp = try client.sendCommand(.{ .status = {} });
    defer resp.deinit(testing.allocator);

    thread.join();
    if (ctx.thread_err) |e| return e;

    try testing.expect(resp == .ok);
    try testing.expectEqualStrings("hello", resp.ok.payload);
}

test "socket: roundtrip via socketpair — err response" {
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (std.os.linux.E.init(rc) != .SUCCESS) return error.SkipZigTest;
    defer posix.close(fds[0]);

    var client = SocketClient{
        .fd = fds[1],
        .timeout_ms = 2000,
        .allocator = testing.allocator,
    };
    defer client.close();

    const ServerCtx = struct {
        fd: posix.socket_t,
        thread_err: ?anyerror = null,

        fn run(ctx: *@This()) void {
            ctx.runInner() catch |e| {
                ctx.thread_err = e;
            };
        }

        fn runInner(ctx: *@This()) !void {
            var buf: [1024]u8 = undefined;
            _ = try readNExact(ctx.fd, buf[0..4]);
            const size = std.mem.readInt(u32, buf[0..4], .little);
            if (size > buf.len - 4) return error.Overflow;
            _ = try readNExact(ctx.fd, buf[4 .. 4 + size]);

            const resp = shared.Response{ .err = .{ .code = 7, .message = "boom" } };
            var out_buf: [64]u8 = undefined;
            var s = std.io.fixedBufferStream(&out_buf);
            try shared.serializeResponse(resp, s.writer());
            var off: usize = 0;
            const bytes = s.getWritten();
            while (off < bytes.len) {
                const n = try posix.send(ctx.fd, bytes[off..], 0);
                off += n;
            }
        }
    };

    var ctx = ServerCtx{ .fd = fds[0] };
    const thread = try std.Thread.spawn(.{}, ServerCtx.run, .{&ctx});

    const resp = try client.sendCommand(.{ .reload = {} });
    defer resp.deinit(testing.allocator);

    thread.join();
    if (ctx.thread_err) |e| return e;

    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 7), resp.err.code);
    try testing.expectEqualStrings("boom", resp.err.message);
}

test "socket: peer reads but closes without responding yields ProtocolError" {
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (std.os.linux.E.init(rc) != .SUCCESS) return error.SkipZigTest;

    var client = SocketClient{
        .fd = fds[1],
        .timeout_ms = 2000,
        .allocator = testing.allocator,
    };
    defer client.close();

    // Server reads the command bytes (so the client's send() succeeds) and
    // then closes the socket without writing a response — client should surface
    // a ProtocolError with an end-of-stream diagnostic.
    const ServerCtx = struct {
        fd: posix.socket_t,

        fn run(ctx: *@This()) void {
            var buf: [256]u8 = undefined;
            _ = posix.recv(ctx.fd, &buf, 0) catch {};
            posix.close(ctx.fd);
        }
    };
    var ctx = ServerCtx{ .fd = fds[0] };
    const thread = try std.Thread.spawn(.{}, ServerCtx.run, .{&ctx});

    const result = client.sendCommand(.{ .status = {} });
    thread.join();

    try testing.expectError(error.ProtocolError, result);
    try testing.expect(client.errorMessage().len > 0);
}

// Test helper: read exactly `buf.len` bytes or fail.
fn readNExact(fd: posix.socket_t, buf: []u8) !usize {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try posix.recv(fd, buf[off..], 0);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
    return off;
}
