// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;

const shared = @import("shared");
const protocol = shared.protocol;
const ipc = @import("engine_test").net.ipc;
const auth = @import("engine_test").net.ipc_auth;
const event_loop = @import("engine_test").core.event_loop;

const EventLoop = event_loop.EventLoop;
const IpcServer = ipc.IpcServer;

comptime {
    _ = ipc;
    _ = auth;
}

fn socketpairNonblock(fds: *[2]i32) !void {
    const stype: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const rc = linux.socketpair(@as(i32, linux.AF.UNIX), @as(i32, @intCast(stype)), 0, fds);
    switch (linux.E.init(rc)) {
        .SUCCESS => {},
        else => return error.SocketpairFailed,
    }
}

fn runLoopBriefly(loop: *EventLoop, ms: u64) !void {
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

fn writeAllFd(fd: posix.fd_t, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        written += posix.write(fd, bytes[written..]) catch |err| switch (err) {
            error.WouldBlock => {
                std.time.sleep(5 * std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };
    }
}

fn readResponse(a: std.mem.Allocator, fd: posix.fd_t) !?shared.Response {
    var header: [4]u8 = undefined;
    var got: usize = 0;
    var tries: u32 = 0;
    while (got < 4) : (tries += 1) {
        if (tries > 200) return error.Timeout;
        const n = posix.read(fd, header[got..]) catch |err| switch (err) {
            error.WouldBlock => {
                std.time.sleep(5 * std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };
        if (n == 0) return if (got == 0) null else error.TruncatedResponse;
        got += n;
    }
    const size = std.mem.readInt(u32, &header, .little);
    if (size > protocol.max_payload_size) return error.PayloadTooLarge;
    const body = try a.alloc(u8, 4 + size);
    defer a.free(body);
    @memcpy(body[0..4], &header);
    got = 4;
    tries = 0;
    while (got < body.len) : (tries += 1) {
        if (tries > 2000) return error.Timeout;
        const n = posix.read(fd, body[got..]) catch |err| switch (err) {
            error.WouldBlock => {
                std.time.sleep(5 * std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };
        if (n == 0) return error.TruncatedResponse;
        got += n;
    }
    var rs = std.io.fixedBufferStream(body);
    return try protocol.deserializeResponse(rs.reader(), a);
}

fn expectEof(fd: posix.fd_t) !void {
    var buf: [16]u8 = undefined;
    var tries: u32 = 0;
    while (tries < 200) : (tries += 1) {
        const n = posix.read(fd, &buf) catch |err| switch (err) {
            error.WouldBlock => {
                std.time.sleep(5 * std.time.ns_per_ms);
                continue;
            },
            error.ConnectionResetByPeer => return,
            else => return err,
        };
        if (n == 0) return;
        return error.UnexpectedBytes;
    }
    return error.Timeout;
}

fn frameOf(buf: []u8, body: []const u8) []const u8 {
    std.mem.writeInt(u32, buf[0..4], @intCast(body.len), .little);
    @memcpy(buf[4 .. 4 + body.len], body);
    return buf[0 .. 4 + body.len];
}

const Recorder = struct {
    plain_calls: usize = 0,
    auth_calls: usize = 0,
    last_peer: ?ipc.Peer = null,
    last_tag: ?shared.protocol.CommandId = null,
    payload_len: usize = 16,

    fn dispatch(ctx: ?*anyopaque, cmd: shared.Command, a: std.mem.Allocator) anyerror!shared.Response {
        const self: *Recorder = @ptrCast(@alignCast(ctx.?));
        self.plain_calls += 1;
        self.last_tag = std.meta.activeTag(cmd);
        return self.reply(a);
    }

    fn dispatchAuth(ctx: ?*anyopaque, cmd: shared.Command, peer: ipc.Peer, a: std.mem.Allocator) anyerror!shared.Response {
        const self: *Recorder = @ptrCast(@alignCast(ctx.?));
        self.auth_calls += 1;
        self.last_peer = peer;
        self.last_tag = std.meta.activeTag(cmd);
        return self.reply(a);
    }

    fn reply(self: *Recorder, a: std.mem.Allocator) !shared.Response {
        const payload = try a.alloc(u8, self.payload_len);
        @memset(payload, 'x');
        return .{ .ok = .{ .payload = payload } };
    }

    fn plainHandler(self: *Recorder) ipc.CommandHandler {
        return .{ .ctx = @ptrCast(self), .dispatch = Recorder.dispatch };
    }

    fn authHandler(self: *Recorder) ipc.CommandHandler {
        return .{ .ctx = @ptrCast(self), .dispatch = Recorder.dispatch, .dispatch_auth = Recorder.dispatchAuth };
    }
};

const Fixture = struct {
    loop: EventLoop,
    server: IpcServer,
    fds: [2]i32,

    fn init(self: *Fixture, a: std.mem.Allocator, handler: ipc.CommandHandler, cred: auth.PeerCred) !void {
        self.loop = try EventLoop.init(a);
        errdefer self.loop.deinit();
        try socketpairNonblock(&self.fds);
        errdefer posix.close(self.fds[1]);
        self.server = try IpcServer.initDetached(a, &self.loop);
        errdefer self.server.deinit();
        self.server.setCommandHandler(handler);
        try self.server.admitTestPeerAs(self.fds[0], cred);
    }

    fn deinit(self: *Fixture) void {
        posix.close(self.fds[1]);
        self.server.deinit();
        self.loop.deinit();
    }

    fn client(self: *Fixture) posix.fd_t {
        return self.fds[1];
    }
};

const root_cred: auth.PeerCred = .{ .pid = 1, .uid = 0, .gid = 0 };
const monitor_cred: auth.PeerCred = .{ .pid = 4242, .uid = 65534, .gid = 65534 };

fn banFrame(buf: []u8) ![]const u8 {
    var ws = std.io.fixedBufferStream(buf);
    try protocol.serializeCommand(.{ .ban = .{
        .ip = try shared.IpAddress.parse("203.0.113.9"),
        .jail = try shared.JailId.fromSlice("sshd"),
        .duration = 60,
    } }, ws.writer());
    return ws.getWritten();
}

fn statusFrame(buf: []u8) ![]const u8 {
    var ws = std.io.fixedBufferStream(buf);
    try protocol.serializeCommand(.{ .status = {} }, ws.writer());
    return ws.getWritten();
}

const SocketDir = struct {
    tmp: testing.TmpDir,
    abs: []u8,
    path: []u8,

    fn init(a: std.mem.Allocator) !SocketDir {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
        const abs_tmp = try tmp.dir.realpath(".", &abs_buf);
        const abs = try a.dupe(u8, abs_tmp);
        errdefer a.free(abs);
        try posix.fchmodat(posix.AT.FDCWD, abs, 0o750, 0);
        const path = try std.fmt.allocPrint(a, "{s}/ipc.sock", .{abs});
        errdefer a.free(path);
        if (path.len >= 108) return error.SkipZigTest;
        return .{ .tmp = tmp, .abs = abs, .path = path };
    }

    fn chmod(self: *SocketDir, mode: u32) !void {
        try posix.fchmodat(posix.AT.FDCWD, self.abs, mode, 0);
    }

    fn deinit(self: *SocketDir, a: std.mem.Allocator) void {
        posix.fchmodat(posix.AT.FDCWD, self.abs, 0o750, 0) catch {};
        a.free(self.path);
        a.free(self.abs);
        self.tmp.cleanup();
    }
};

fn connectUnix(path: []const u8) !posix.fd_t {
    const stype: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const fd = try posix.socket(posix.AF.UNIX, stype, 0);
    errdefer posix.close(fd);
    var addr: linux.sockaddr.un = .{ .path = [_]u8{0} ** 108 };
    @memcpy(addr.path[0..path.len], path);
    const addr_len: posix.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + 1);
    try posix.connect(fd, @ptrCast(&addr), addr_len);
    return fd;
}

fn setSockBuf(fd: posix.fd_t, opt: u32, bytes: u32) !void {
    const val: [4]u8 = @bitCast(bytes);
    try posix.setsockopt(fd, posix.SOL.SOCKET, opt, &val);
}

test "native ipc auth: peer class is uid-only; gid is never authority" {
    const daemon_uid: u32 = 998;
    try testing.expectEqual(auth.PeerClass.admin, auth.classifyPeer(.{ .pid = 1, .uid = 0, .gid = 0 }, daemon_uid));
    try testing.expectEqual(auth.PeerClass.admin, auth.classifyPeer(.{ .pid = 1, .uid = 998, .gid = 12 }, daemon_uid));
    try testing.expectEqual(auth.PeerClass.monitor, auth.classifyPeer(.{ .pid = 1, .uid = 1000, .gid = 999 }, daemon_uid));
    try testing.expectEqual(auth.PeerClass.monitor, auth.classifyPeer(.{ .pid = 1, .uid = 1000, .gid = 1000 }, daemon_uid));
    try testing.expectEqual(auth.PeerClass.monitor, auth.classifyPeer(.{ .pid = 1, .uid = 1001, .gid = 0 }, daemon_uid));
    try testing.expectEqual(auth.PeerClass.monitor, auth.classifyPeer(.{ .pid = 1, .uid = 998, .gid = 0 }, 0));
}

test "native ipc auth: raw tag classes match the frozen command table" {
    const read_only = [_]u8{ 0, 3, 4, 6, 7 };
    const mutation = [_]u8{ 1, 2, 5, 8, 9 };
    for (read_only) |t| try testing.expectEqual(auth.CommandClass.read_only, auth.classifyTag(t));
    for (mutation) |t| try testing.expectEqual(auth.CommandClass.mutation, auth.classifyTag(t));
    var t: u16 = 10;
    while (t <= 255) : (t += 1) try testing.expectEqual(auth.CommandClass.unknown, auth.classifyTag(@intCast(t)));
}

test "native ipc auth: request_id extraction for tags 8/9 and legacy null" {
    var body: [40]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @intCast(i);
    body[0] = 8;
    const id8 = (try auth.extractRequestId(body[0..33])).?;
    try testing.expectEqualSlices(u8, body[1..33], &id8);
    const id8_long = (try auth.extractRequestId(&body)).?;
    try testing.expectEqualSlices(u8, body[1..33], &id8_long);
    body[0] = 9;
    try testing.expect((try auth.extractRequestId(body[0..33])) != null);
    try testing.expectError(error.FrameTooShort, auth.extractRequestId(body[0..32]));
    try testing.expectError(error.FrameTooShort, auth.extractRequestId(body[0..1]));
    for ([_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 }) |tag| {
        body[0] = tag;
        try testing.expectEqual(@as(?[32]u8, null), try auth.extractRequestId(body[0..1]));
    }
    try testing.expectError(error.FrameTooShort, auth.extractRequestId(body[0..0]));
}

test "native ipc auth: monitor mutation gets 403 and the connection stays open" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), monitor_cred);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    try writeAllFd(fx.client(), try banFrame(&buf));
    try runLoopBriefly(&fx.loop, 150);

    const resp = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 403), resp.err.code);
    try testing.expectEqualStrings("mutation requires root or daemon uid", resp.err.message);
    try testing.expectEqual(@as(usize, 0), rec.auth_calls);
    try testing.expectEqual(@as(usize, 1), fx.server.activeClients());

    try writeAllFd(fx.client(), try statusFrame(&buf));
    try runLoopBriefly(&fx.loop, 150);
    const resp2 = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp2.deinit(a);
    try testing.expect(resp2 == .ok);
    try testing.expectEqual(@as(usize, 1), rec.auth_calls);
    try testing.expectEqual(auth.PeerClass.monitor, rec.last_peer.?.class);
    try testing.expectEqual(@as(u32, 65534), rec.last_peer.?.uid);
    try testing.expectEqual(@as(i32, 4242), rec.last_peer.?.pid);
    try testing.expectEqual(@as(?[32]u8, null), rec.last_peer.?.request_id);
}

test "native ipc auth: monitor read-only reaches the plain handler when no auth handler is set" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.plainHandler(), monitor_cred);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    try writeAllFd(fx.client(), try statusFrame(&buf));
    try runLoopBriefly(&fx.loop, 150);
    const resp = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expectEqual(@as(usize, 1), rec.plain_calls);
    try testing.expectEqual(shared.protocol.CommandId.status, rec.last_tag.?);
}

test "native ipc auth: admin mutation is refused with 403 until an auth handler is installed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.plainHandler(), root_cred);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    try writeAllFd(fx.client(), try banFrame(&buf));
    try runLoopBriefly(&fx.loop, 150);
    const resp = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 403), resp.err.code);
    try testing.expectEqual(@as(usize, 0), rec.plain_calls);
}

test "native ipc auth: admin mutation via auth handler carries peer and null legacy request_id" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), .{ .pid = 77, .uid = linux.geteuid(), .gid = 5 });
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    try writeAllFd(fx.client(), try banFrame(&buf));
    try runLoopBriefly(&fx.loop, 150);
    const resp = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expectEqual(@as(usize, 1), rec.auth_calls);
    try testing.expectEqual(shared.protocol.CommandId.ban, rec.last_tag.?);
    const peer = rec.last_peer.?;
    try testing.expectEqual(auth.PeerClass.admin, peer.class);
    try testing.expectEqual(@as(u32, linux.geteuid()), peer.uid);
    try testing.expectEqual(@as(u32, 5), peer.gid);
    try testing.expectEqual(@as(i32, 77), peer.pid);
    try testing.expectEqual(@as(?[32]u8, null), peer.request_id);
}

test "native ipc auth: tag 8 frame shorter than 33 bytes gets 400 request_id error" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    const body = [_]u8{8} ++ [_]u8{0xAB} ** 31;
    try writeAllFd(fx.client(), frameOf(&buf, &body));
    try runLoopBriefly(&fx.loop, 150);
    const resp = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 400), resp.err.code);
    try testing.expectEqualStrings("mutation frame requires request_id", resp.err.message);
    try testing.expectEqual(@as(usize, 1), fx.server.activeClients());
}

test "native ipc auth: tag 9 frame with 32-byte request_id passes auth and fails as undecodable (400)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    const body = [_]u8{9} ++ [_]u8{0xCD} ** 32;
    try writeAllFd(fx.client(), frameOf(&buf, &body));
    try runLoopBriefly(&fx.loop, 150);
    const resp = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 400), resp.err.code);
    try testing.expectEqualStrings("bad command", resp.err.message);
    try testing.expectEqual(@as(usize, 0), rec.auth_calls);
}

test "native ipc auth: monitor sending reserved tag 8 is refused 403 before request_id checks" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), monitor_cred);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    const body = [_]u8{8};
    try writeAllFd(fx.client(), frameOf(&buf, &body));
    try runLoopBriefly(&fx.loop, 150);
    const resp = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 403), resp.err.code);
}

test "native ipc auth: malformed tag gets 400 and empty frame gets 400" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    try writeAllFd(fx.client(), frameOf(&buf, &[_]u8{0xFE}));
    try runLoopBriefly(&fx.loop, 150);
    const resp = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expectEqual(@as(u16, 400), resp.err.code);

    try writeAllFd(fx.client(), frameOf(&buf, &[_]u8{}));
    try runLoopBriefly(&fx.loop, 150);
    const resp2 = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp2.deinit(a);
    try testing.expectEqual(@as(u16, 400), resp2.err.code);
    try testing.expectEqual(@as(usize, 1), fx.server.activeClients());
}

test "native ipc auth: oversized frame closes without reply" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();

    var prefix: [4]u8 = undefined;
    std.mem.writeInt(u32, &prefix, protocol.max_payload_size + 1, .little);
    try writeAllFd(fx.client(), &prefix);
    try runLoopBriefly(&fx.loop, 150);
    try expectEof(fx.client());
    try testing.expectEqual(@as(usize, 0), fx.server.activeClients());
}

test "native ipc auth: exactly 1 MiB frame is accepted and answered" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();

    const frame = try a.alloc(u8, 4 + protocol.max_payload_size);
    defer a.free(frame);
    std.mem.writeInt(u32, frame[0..4], protocol.max_payload_size, .little);
    @memset(frame[4..], 0);
    frame[4] = 0;
    const Writer = struct {
        fn run(fd: posix.fd_t, bytes: []const u8) void {
            writeAllFd(fd, bytes) catch {};
        }
    };
    const th = try std.Thread.spawn(.{}, Writer.run, .{ fx.client(), frame });
    try runLoopBriefly(&fx.loop, 400);
    th.join();
    const resp = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expectEqual(@as(usize, 1), rec.auth_calls);
}

test "native ipc auth: EOF mid-frame closes the connection" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    const full = try banFrame(&buf);
    try writeAllFd(fx.client(), full[0 .. full.len - 3]);
    try posix.shutdown(fx.client(), .send);
    try runLoopBriefly(&fx.loop, 150);
    try testing.expectEqual(@as(usize, 0), fx.server.activeClients());
    try testing.expectEqual(@as(usize, 0), rec.auth_calls);
    try expectEof(fx.client());
}

test "native ipc auth: slow-loris partial frame is closed at the frame deadline only" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    const full = try banFrame(&buf);
    try writeAllFd(fx.client(), full[0..3]);
    try runLoopBriefly(&fx.loop, 100);
    try testing.expectEqual(@as(usize, 1), fx.server.activeClients());

    const now = fx.server.clock();
    fx.server.checkDeadlines(now + ipc.default_frame_deadline_ms - 1000);
    try testing.expectEqual(@as(usize, 1), fx.server.activeClients());
    fx.server.checkDeadlines(now + ipc.default_frame_deadline_ms + 1);
    try testing.expectEqual(@as(usize, 0), fx.server.activeClients());
    try expectEof(fx.client());
}

test "native ipc auth: idle connection uses its own bound rather than the frame deadline" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    try writeAllFd(fx.client(), try statusFrame(&buf));
    try runLoopBriefly(&fx.loop, 150);
    const resp = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    resp.deinit(a);
    const now = fx.server.clock();
    fx.server.checkDeadlines(now + ipc.default_frame_deadline_ms + 1);
    try testing.expectEqual(@as(usize, 1), fx.server.activeClients());
    fx.server.checkDeadlines(now + ipc.default_idle_deadline_ms + 1);
    try testing.expectEqual(@as(usize, 0), fx.server.activeClients());
    try expectEof(fx.client());
}

fn makeSlowDrain(fx: *Fixture, rec: *Recorder) !void {
    try setSockBuf(fx.fds[0], posix.SO.SNDBUF, 4096);
    try setSockBuf(fx.fds[1], posix.SO.RCVBUF, 4096);
    rec.payload_len = 512 * 1024;
}

test "native ipc auth: second request before drain closes the connection" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();
    try makeSlowDrain(&fx, &rec);

    var buf: [64]u8 = undefined;
    try writeAllFd(fx.client(), try statusFrame(&buf));
    try runLoopBriefly(&fx.loop, 150);
    try testing.expect(fx.server.clients[0].?.pending != null);

    try writeAllFd(fx.client(), try statusFrame(&buf));
    try runLoopBriefly(&fx.loop, 150);
    try testing.expectEqual(@as(usize, 0), fx.server.activeClients());
    try testing.expectEqual(@as(usize, 1), rec.auth_calls);
}

test "native ipc auth: response drain deadline closes a client that stops reading" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();
    try makeSlowDrain(&fx, &rec);

    var buf: [64]u8 = undefined;
    try writeAllFd(fx.client(), try statusFrame(&buf));
    try runLoopBriefly(&fx.loop, 150);
    const cli = fx.server.clients[0].?;
    try testing.expect(cli.pending != null);
    try testing.expect(cli.sent < cli.pending.?.len);

    fx.server.checkDeadlines(cli.drain_deadline_ms - 1);
    try testing.expectEqual(@as(usize, 1), fx.server.activeClients());
    fx.server.checkDeadlines(cli.drain_deadline_ms);
    try testing.expectEqual(@as(usize, 0), fx.server.activeClients());
}

test "native ipc auth: large response drains fully once the client reads" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{};
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();
    try makeSlowDrain(&fx, &rec);

    var buf: [64]u8 = undefined;
    try writeAllFd(fx.client(), try statusFrame(&buf));
    try runLoopBriefly(&fx.loop, 100);
    try testing.expect(fx.server.clients[0].?.pending != null);

    const Reader = struct {
        fn run(alloc: std.mem.Allocator, fd: posix.fd_t, out: *?shared.Response) void {
            out.* = readResponse(alloc, fd) catch null;
        }
    };
    var got: ?shared.Response = null;
    const th = try std.Thread.spawn(.{}, Reader.run, .{ a, fx.client(), &got });
    try runLoopBriefly(&fx.loop, 500);
    th.join();
    const resp = got orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expectEqual(@as(usize, 512 * 1024), resp.ok.payload.len);
    try testing.expect(fx.server.clients[0].?.pending == null);
    try testing.expectEqual(@as(usize, 1), fx.server.activeClients());
}

test "native ipc auth: handler response above 1 MiB is replaced by err 500" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var rec = Recorder{ .payload_len = protocol.max_payload_size };
    var fx: Fixture = undefined;
    try fx.init(a, rec.authHandler(), root_cred);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    try writeAllFd(fx.client(), try statusFrame(&buf));
    try runLoopBriefly(&fx.loop, 200);
    const resp = (try readResponse(a, fx.client())) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 500), resp.err.code);
    try testing.expectEqualStrings("response too large", resp.err.message);
}

test "native ipc auth: ninth connection is refused while eight are held" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var loop = try EventLoop.init(a);
    defer loop.deinit();
    var server = try IpcServer.initDetached(a, &loop);
    defer server.deinit();

    var pairs: [ipc.max_clients + 1][2]i32 = undefined;
    var opened: usize = 0;
    defer for (pairs[0..opened]) |p| posix.close(p[1]);

    while (opened < ipc.max_clients) : (opened += 1) {
        try socketpairNonblock(&pairs[opened]);
        try server.admitTestPeerAs(pairs[opened][0], root_cred);
    }
    try socketpairNonblock(&pairs[opened]);
    opened += 1;
    try testing.expectError(error.TooManyClients, server.admitTestPeerAs(pairs[opened - 1][0], root_cred));
    posix.close(pairs[opened - 1][0]);
    try testing.expectEqual(ipc.max_clients, server.activeClients());
}

test "native ipc auth: correct 0750 directory and 0660 socket verify" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try SocketDir.init(a);
    defer dir.deinit(a);
    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = try IpcServer.init(a, &loop, dir.path);
    defer server.deinit();
    try auth.verifySocketPath(dir.path, linux.geteuid());
    try testing.expect(server.isServing());
}

test "native ipc auth: directory writable or listable by others is refused" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try SocketDir.init(a);
    defer dir.deinit(a);
    var loop = try EventLoop.init(a);
    defer loop.deinit();

    for ([_]u32{ 0o757, 0o770, 0o755, 0o751, 0o754 }) |mode| {
        try dir.chmod(mode);
        try testing.expectError(error.ParentTooPermissive, auth.verifyParentDir(dir.path, linux.geteuid()));
        try testing.expectError(error.SocketPathInsecure, IpcServer.init(a, &loop, dir.path));
        try testing.expectError(error.FileNotFound, std.fs.cwd().access(dir.path, .{}));
    }
    for ([_]u32{ 0o750, 0o710, 0o700 }) |mode| {
        try dir.chmod(mode);
        try auth.verifyParentDir(dir.path, linux.geteuid());
    }
}

test "native ipc auth: directory owned by a foreign uid is refused" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const candidate = "/var/cache/man/ipc.sock";
    const st = posix.fstatat(posix.AT.FDCWD, "/var/cache/man", 0) catch return error.SkipZigTest;
    if (st.uid == 0 or st.uid == linux.geteuid()) return error.SkipZigTest;
    try testing.expectError(error.ParentWrongOwner, auth.verifyParentDir(candidate, linux.geteuid()));
    try testing.expectError(error.ParentTooPermissive, auth.verifyParentDir("/tmp/x.sock", linux.geteuid()));
}

test "native ipc auth: symlinked socket path is refused at bind and by verification" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try SocketDir.init(a);
    defer dir.deinit(a);
    var loop = try EventLoop.init(a);
    defer loop.deinit();

    const target = try std.fmt.allocPrint(a, "{s}/real.sock", .{dir.abs});
    defer a.free(target);
    try std.fs.cwd().symLink(target, dir.path, .{});
    try testing.expectError(error.SocketPathRefused, IpcServer.init(a, &loop, dir.path));
    try testing.expectError(error.IsSymlink, auth.inspectBindPath(dir.path));
    try testing.expectError(error.SocketIsSymlink, auth.verifySocketFile(dir.path, linux.geteuid()));
    const st = try posix.fstatat(posix.AT.FDCWD, dir.path, posix.AT.SYMLINK_NOFOLLOW);
    try testing.expect(posix.S.ISLNK(st.mode));
}

test "native ipc auth: live socket at path refuses startup and stale socket is replaced" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try SocketDir.init(a);
    defer dir.deinit(a);
    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var first = try IpcServer.init(a, &loop, dir.path);
    try testing.expectEqual(auth.BindPathState.live_socket, try auth.inspectBindPath(dir.path));
    try testing.expectError(error.SocketPathInUse, IpcServer.init(a, &loop, dir.path));
    try std.fs.cwd().access(dir.path, .{});

    posix.close(first.listen_fd);
    first.listen_fd = -1;
    first.socket_path = "";
    first.deinit();
    try std.fs.cwd().access(dir.path, .{});
    try testing.expectEqual(auth.BindPathState.stale_socket, try auth.inspectBindPath(dir.path));

    var second = try IpcServer.init(a, &loop, dir.path);
    defer second.deinit();
    try testing.expectEqual(auth.BindPathState.live_socket, try auth.inspectBindPath(dir.path));
}

test "native ipc auth: absent path inspects as absent and regular file is refused" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try SocketDir.init(a);
    defer dir.deinit(a);
    try testing.expectEqual(auth.BindPathState.absent, try auth.inspectBindPath(dir.path));
    const f = try std.fs.cwd().createFile(dir.path, .{});
    f.close();
    try testing.expectError(error.NotSocket, auth.inspectBindPath(dir.path));
    try testing.expectError(error.SocketNotSocket, auth.verifySocketFile(dir.path, linux.geteuid()));
}

test "native ipc auth: socket mode drift after bind is detected by verification" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try SocketDir.init(a);
    defer dir.deinit(a);
    var loop = try EventLoop.init(a);
    defer loop.deinit();
    var server = try IpcServer.init(a, &loop, dir.path);
    defer server.deinit();

    try posix.fchmodat(posix.AT.FDCWD, dir.path, 0o666, 0);
    try testing.expectError(error.SocketWrongMode, auth.verifySocketFile(dir.path, linux.geteuid()));
    try posix.fchmodat(posix.AT.FDCWD, dir.path, 0o660, 0);
    try auth.verifySocketFile(dir.path, linux.geteuid());
}

test "native ipc auth: post-bind directory widening stops new connections while an existing one drains" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try SocketDir.init(a);
    defer dir.deinit(a);
    var loop = try EventLoop.init(a);
    defer loop.deinit();
    var rec = Recorder{};
    var server = try IpcServer.init(a, &loop, dir.path);
    defer server.deinit();
    server.setCommandHandler(rec.authHandler());
    try server.start();

    const early = try connectUnix(dir.path);
    defer posix.close(early);
    try runLoopBriefly(&loop, 100);
    try testing.expectEqual(@as(usize, 1), server.activeClients());
    try testing.expect(server.serving);

    try dir.chmod(0o777);
    const late = try connectUnix(dir.path);
    defer posix.close(late);
    try runLoopBriefly(&loop, 100);
    try testing.expect(!server.isServing());
    try testing.expectEqual(@as(usize, 1), server.activeClients());
    try expectEof(late);

    try dir.chmod(0o750);
    const later = try connectUnix(dir.path);
    defer posix.close(later);
    try runLoopBriefly(&loop, 100);
    try testing.expect(server.isServing());
    try testing.expectEqual(@as(usize, 2), server.activeClients());

    var buf: [64]u8 = undefined;
    try writeAllFd(early, try statusFrame(&buf));
    try runLoopBriefly(&loop, 150);
    const resp = (try readResponse(a, early)) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expectEqual(auth.PeerClass.admin, rec.last_peer.?.class);
    try testing.expectEqual(@as(u32, linux.geteuid()), rec.last_peer.?.uid);
    try testing.expectEqual(@as(i32, linux.getpid()), rec.last_peer.?.pid);
}

test "native ipc auth: ninth listener connection is closed unanswered on the real socket" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try SocketDir.init(a);
    defer dir.deinit(a);
    var loop = try EventLoop.init(a);
    defer loop.deinit();
    var rec = Recorder{};
    var server = try IpcServer.init(a, &loop, dir.path);
    defer server.deinit();
    server.setCommandHandler(rec.authHandler());
    try server.start();

    var held: [ipc.max_clients + 1]posix.fd_t = undefined;
    var opened: usize = 0;
    defer for (held[0..opened]) |fd| posix.close(fd);
    while (opened < held.len) : (opened += 1) {
        held[opened] = try connectUnix(dir.path);
        try runLoopBriefly(&loop, 50);
    }
    try testing.expectEqual(ipc.max_clients, server.activeClients());
    try expectEof(held[ipc.max_clients]);

    var buf: [64]u8 = undefined;
    try writeAllFd(held[0], try statusFrame(&buf));
    try runLoopBriefly(&loop, 150);
    const resp = (try readResponse(a, held[0])) orelse return error.UnexpectedEof;
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
}

test "native ipc auth: deadline timer on the started server closes a real slow-loris client" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try SocketDir.init(a);
    defer dir.deinit(a);
    var loop = try EventLoop.init(a);
    defer loop.deinit();
    var rec = Recorder{};
    var server = try IpcServer.init(a, &loop, dir.path);
    defer server.deinit();
    server.setCommandHandler(rec.authHandler());
    server.setDeadlines(200, 200);
    try server.start();

    const fd = try connectUnix(dir.path);
    defer posix.close(fd);
    try writeAllFd(fd, &[_]u8{ 0x05, 0x00 });
    try runLoopBriefly(&loop, 1500);
    try testing.expectEqual(@as(usize, 0), server.activeClients());
    try expectEof(fd);
}
