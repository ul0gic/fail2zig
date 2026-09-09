// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const shared = @import("shared");
const protocol = shared.protocol;
const event_loop_mod = @import("../core/event_loop.zig");

const EventLoop = event_loop_mod.EventLoop;

pub const max_clients: usize = 8;

pub const client_buffer_size: usize = protocol.max_payload_size + 4;

pub const Error = error{
    SocketCreateFailed,
    BindFailed,
    ListenFailed,
    ChmodFailed,
    PathTooLong,
    UnlinkFailed,
    AlreadyStarted,
    OutOfMemory,
    EventLoopError,
    NotLinux,
};

pub const CommandHandler = struct {
    ctx: ?*anyopaque = null,
    dispatch: *const fn (
        ctx: ?*anyopaque,
        cmd: shared.Command,
        allocator: std.mem.Allocator,
    ) anyerror!shared.Response,
};

const ClientReg = struct {
    server: *IpcServer,
    fd: posix.fd_t,
    peer_uid: u32,
    peer_pid: i32,
    peer_gid: u32,
    buf: []u8,
    len: usize = 0,
    need: usize = 0,

    fn reset(self: *ClientReg) void {
        self.len = 0;
        self.need = 0;
    }
};

const ucred = extern struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

const c_group = extern struct {
    gr_name: [*:0]const u8,
    gr_passwd: [*:0]const u8,
    gr_gid: u32,
    gr_mem: [*:null]?[*:0]const u8,
};

extern "c" fn getgrnam(name: [*:0]const u8) callconv(.C) ?*c_group;

extern "c" fn umask(mask: u32) callconv(.C) u32;

pub const IpcServer = struct {
    allocator: std.mem.Allocator,
    loop: *EventLoop,
    socket_path: []const u8,
    listen_fd: posix.fd_t = -1,
    started: bool = false,
    allowed_gid: ?u32 = null,
    allow_any_peer: bool = false,
    handler: CommandHandler = .{
        .ctx = null,
        .dispatch = defaultDispatch,
    },
    clients: [max_clients]?*ClientReg = [_]?*ClientReg{null} ** max_clients,

    pub fn init(
        allocator: std.mem.Allocator,
        loop: *EventLoop,
        socket_path: []const u8,
    ) Error!IpcServer {
        if (builtin.os.tag != .linux) return error.NotLinux;
        if (socket_path.len >= 108) return error.PathTooLong;

        const stype: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
        const fd = posix.socket(posix.AF.UNIX, stype, 0) catch
            return error.SocketCreateFailed;
        errdefer posix.close(fd);

        std.fs.cwd().deleteFile(socket_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => {
                std.log.err(
                    "ipc: unlink '{s}' failed before bind: {s}",
                    .{ socket_path, @errorName(err) },
                );
                return error.UnlinkFailed;
            },
        };

        var addr: linux.sockaddr.un = .{ .path = [_]u8{0} ** 108 };
        @memcpy(addr.path[0..socket_path.len], socket_path);
        const sun_path_offset = @offsetOf(linux.sockaddr.un, "path");
        const addr_len: posix.socklen_t =
            @intCast(sun_path_offset + socket_path.len + 1);

        const prev_umask: u32 = umask(0o117);
        const bind_result = posix.bind(fd, @ptrCast(&addr), addr_len);
        _ = umask(prev_umask);
        bind_result catch return error.BindFailed;

        std.posix.fchmodat(std.posix.AT.FDCWD, socket_path, 0o660, 0) catch |err| {
            std.log.err("ipc: chmod '{s}' failed: {s}", .{ socket_path, @errorName(err) });
            return error.ChmodFailed;
        };

        posix.listen(fd, @intCast(max_clients)) catch return error.ListenFailed;

        var allowed_gid: ?u32 = null;
        const group_name = "fail2zig";
        const c_name: [*:0]const u8 = @ptrCast(group_name.ptr);
        if (getgrnam(c_name)) |grp| {
            allowed_gid = grp.gr_gid;
        } else {
            std.log.warn(
                "ipc: group 'fail2zig' not found; only uid=0 may connect",
                .{},
            );
        }

        return .{
            .allocator = allocator,
            .loop = loop,
            .socket_path = socket_path,
            .listen_fd = fd,
            .allowed_gid = allowed_gid,
        };
    }

    pub fn deinit(self: *IpcServer) void {
        for (&self.clients) |*slot| {
            if (slot.*) |cli| {
                self.loop.removeFd(cli.fd) catch {};
                posix.close(cli.fd);
                self.allocator.free(cli.buf);
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
        std.fs.cwd().deleteFile(self.socket_path) catch {};
        self.* = undefined;
    }

    pub fn setCommandHandler(self: *IpcServer, h: CommandHandler) void {
        self.handler = h;
    }

    pub fn setAllowAnyPeer(self: *IpcServer, allow: bool) void {
        self.allow_any_peer = allow;
    }

    pub fn admitTestPeer(self: *IpcServer, fd: posix.fd_t) !void {
        std.debug.assert(self.allow_any_peer);
        return self.admitClient(fd, .{ .pid = 0, .uid = 0, .gid = 0 });
    }

    pub fn start(self: *IpcServer) Error!void {
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
        const self: *IpcServer = @ptrCast(@alignCast(userdata.?));
        self.acceptPending(fd);
    }

    fn acceptPending(self: *IpcServer, listen_fd: posix.fd_t) void {
        while (true) {
            const accept_flags: u32 = posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
            const client_fd = posix.accept(listen_fd, null, null, accept_flags) catch |err| switch (err) {
                error.WouldBlock => return,
                else => {
                    std.log.warn("ipc: accept failed: {s}", .{@errorName(err)});
                    return;
                },
            };

            const cred = readPeerCred(client_fd) catch {
                posix.close(client_fd);
                continue;
            };

            if (!self.peerAllowed(cred)) {
                std.log.warn(
                    "ipc: rejecting peer pid={d} uid={d} gid={d}",
                    .{ cred.pid, cred.uid, cred.gid },
                );
                posix.close(client_fd);
                continue;
            }

            self.admitClient(client_fd, cred) catch |err| {
                std.log.warn("ipc: admit failed (fd={d}): {s}", .{ client_fd, @errorName(err) });
                posix.close(client_fd);
                continue;
            };
        }
    }

    fn peerAllowed(self: *const IpcServer, cred: ucred) bool {
        if (self.allow_any_peer) return true;
        if (cred.uid == 0) return true;
        if (self.allowed_gid) |gid| {
            if (cred.gid == gid) return true;
        }
        return false;
    }

    fn admitClient(self: *IpcServer, fd: posix.fd_t, cred: ucred) !void {
        var idx: ?usize = null;
        for (self.clients, 0..) |slot, i| {
            if (slot == null) {
                idx = i;
                break;
            }
        }
        if (idx == null) {
            std.log.warn("ipc: max_clients={d} reached; dropping", .{max_clients});
            return error.TooManyClients;
        }

        const cli = try self.allocator.create(ClientReg);
        errdefer self.allocator.destroy(cli);

        const buf = try self.allocator.alloc(u8, client_buffer_size);
        errdefer self.allocator.free(buf);

        cli.* = .{
            .server = self,
            .fd = fd,
            .peer_uid = cred.uid,
            .peer_pid = cred.pid,
            .peer_gid = cred.gid,
            .buf = buf,
        };

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
        cli.server.handleClientReadable(cli);
    }

    fn handleClientReadable(self: *IpcServer, cli: *ClientReg) void {
        while (true) {
            const target = if (cli.need == 0) 4 else cli.need;
            if (cli.len >= target) {
                if (cli.need == 0) {
                    const size = std.mem.readInt(u32, cli.buf[0..4], .little);
                    if (size > protocol.max_payload_size) {
                        std.log.warn(
                            "ipc: client fd={d} sent oversize frame {d}; closing",
                            .{ cli.fd, size },
                        );
                        self.closeClient(cli);
                        return;
                    }
                    cli.need = 4 + @as(usize, size);
                    if (cli.need > cli.buf.len) {
                        std.log.warn(
                            "ipc: client fd={d} frame exceeds buffer; closing",
                            .{cli.fd},
                        );
                        self.closeClient(cli);
                        return;
                    }
                    continue;
                } else {
                    self.processFrame(cli) catch |err| {
                        std.log.warn(
                            "ipc: client fd={d} frame dispatch failed: {s}",
                            .{ cli.fd, @errorName(err) },
                        );
                        self.closeClient(cli);
                        return;
                    };
                    cli.reset();
                    continue;
                }
            }

            const want = target - cli.len;
            const dst = cli.buf[cli.len .. cli.len + want];
            const n = posix.read(cli.fd, dst) catch |err| switch (err) {
                error.WouldBlock => return,
                else => {
                    std.log.info(
                        "ipc: client fd={d} read error {s}; closing",
                        .{ cli.fd, @errorName(err) },
                    );
                    self.closeClient(cli);
                    return;
                },
            };
            if (n == 0) {
                self.closeClient(cli);
                return;
            }
            cli.len += n;
        }
    }

    fn processFrame(self: *IpcServer, cli: *ClientReg) !void {
        var stream = std.io.fixedBufferStream(cli.buf[0..cli.need]);
        const cmd = protocol.deserializeCommand(stream.reader()) catch |err| {
            std.log.warn("ipc: bad command from fd={d}: {s}", .{ cli.fd, @errorName(err) });
            try self.writeErrResponse(cli, 400, "bad command");
            return;
        };

        const resp = self.handler.dispatch(self.handler.ctx, cmd, self.allocator) catch |err| {
            std.log.warn("ipc: handler error fd={d}: {s}", .{ cli.fd, @errorName(err) });
            try self.writeErrResponse(cli, 500, "handler error");
            return;
        };
        defer resp.deinit(self.allocator);

        try self.writeResponse(cli, resp);
    }

    fn writeResponse(self: *IpcServer, cli: *ClientReg, resp: shared.Response) !void {
        const tmp = try self.allocator.alloc(u8, protocol.max_payload_size + 16);
        defer self.allocator.free(tmp);
        var stream = std.io.fixedBufferStream(tmp);
        try protocol.serializeResponse(resp, stream.writer());
        const bytes = stream.getWritten();
        try writeAll(cli.fd, bytes);
    }

    fn writeErrResponse(self: *IpcServer, cli: *ClientReg, code: u16, msg: []const u8) !void {
        const owned = try self.allocator.dupe(u8, msg);
        defer self.allocator.free(owned);
        const resp: shared.Response = .{ .err = .{ .code = code, .message = owned } };
        try self.writeResponse(cli, resp);
    }

    fn closeClient(self: *IpcServer, cli: *ClientReg) void {
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

fn readPeerCred(fd: posix.fd_t) !ucred {
    // Raw syscall: std.posix.getsockopt leaves optlen uninitialized, the kernel EINVALs and the wrapper hits unreachable.
    var cred: ucred = undefined;
    var len: posix.socklen_t = @sizeOf(ucred);
    const rc = linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&cred),
        &len,
    );
    switch (posix.errno(rc)) {
        .SUCCESS => return cred,
        else => |e| {
            std.log.warn("ipc: SO_PEERCRED failed: errno={d}", .{@intFromEnum(e)});
            return error.PeerCredFailed;
        },
    }
}

fn writeAll(fd: posix.fd_t, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try posix.write(fd, bytes[written..]);
        if (n == 0) return error.ShortWrite;
        written += n;
    }
}

fn defaultDispatch(
    ctx: ?*anyopaque,
    cmd: shared.Command,
    allocator: std.mem.Allocator,
) anyerror!shared.Response {
    _ = ctx;
    _ = cmd;
    const msg = try allocator.dupe(u8, "no command handler installed");
    return .{ .err = .{ .code = 503, .message = msg } };
}

const testing = std.testing;

fn makeTestPath(allocator: std.mem.Allocator) ![]u8 {
    const seed: u64 = @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())));
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random().int(u32);
    return try std.fmt.allocPrint(
        allocator,
        "/tmp/fail2zig-test-{d}-{x}.sock",
        .{ linux.getpid(), rnd },
    );
}

test "ipc: init creates socket, deinit removes it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    const path = try makeTestPath(a);
    defer a.free(path);

    {
        var server = try IpcServer.init(a, &loop, path);
        defer server.deinit();

        try std.fs.cwd().access(path, .{});
    }

    const exists = blk: {
        std.fs.cwd().access(path, .{}) catch break :blk false;
        break :blk true;
    };
    try testing.expect(!exists);
}

test "ipc: init with stale socket file unlinks and rebinds" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    const path = try makeTestPath(a);
    defer a.free(path);

    {
        const f = try std.fs.cwd().createFile(path, .{});
        f.close();
    }

    var server = try IpcServer.init(a, &loop, path);
    defer server.deinit();
}

test "ipc: socket has mode 0660 immediately after init (SEC-002)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    const path = try makeTestPath(a);
    defer a.free(path);

    var server = try IpcServer.init(a, &loop, path);
    defer server.deinit();

    var path_z: [128]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    var stbuf: linux.Stat = undefined;
    const rc = linux.stat(@ptrCast(&path_z[0]), &stbuf);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
    const perm = stbuf.mode & 0o777;
    try testing.expectEqual(@as(u32, 0o660), perm);
}

fn statPerm(path: []const u8) !u32 {
    var path_z: [128]u8 = undefined;
    if (path.len >= path_z.len) return error.SkipZigTest;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    var stbuf: linux.Stat = undefined;
    const rc = linux.stat(@ptrCast(&path_z[0]), &stbuf);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
    return stbuf.mode & 0o777;
}

fn statGid(path: []const u8) !u32 {
    var path_z: [128]u8 = undefined;
    if (path.len >= path_z.len) return error.SkipZigTest;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    var stbuf: linux.Stat = undefined;
    const rc = linux.stat(@ptrCast(&path_z[0]), &stbuf);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
    return stbuf.gid;
}

fn statRawMode(path: []const u8) !u32 {
    var path_z: [128]u8 = undefined;
    if (path.len >= path_z.len) return error.SkipZigTest;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    var stbuf: linux.Stat = undefined;
    const rc = linux.stat(@ptrCast(&path_z[0]), &stbuf);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
    return stbuf.mode;
}

test "ipc: init succeeds and socket stays 0660 with no fail2zig group (SYS-018)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    const path = try makeTestPath(a);
    defer a.free(path);

    var server = try IpcServer.init(a, &loop, path);
    defer server.deinit();

    const expected_gid: ?u32 = blk: {
        if (getgrnam("fail2zig")) |grp| break :blk grp.gr_gid;
        break :blk null;
    };
    try testing.expectEqual(expected_gid, server.allowed_gid);

    try std.fs.cwd().access(path, .{});
    try testing.expectEqual(@as(u32, 0o660), try statPerm(path));

    const parent = std.fs.path.dirname(path) orelse return error.SkipZigTest;
    const parent_mode = try statRawMode(parent);
    const s_isgid: u32 = 0o2000;
    if ((parent_mode & s_isgid) != 0) return error.SkipZigTest;

    const socket_gid = try statGid(path);
    try testing.expectEqual(@as(u32, linux.getegid()), socket_gid);
}

test "ipc: listener socket is non-blocking (SYS-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    const path = try makeTestPath(a);
    defer a.free(path);

    var server = try IpcServer.init(a, &loop, path);
    defer server.deinit();

    const flags = try posix.fcntl(server.listen_fd, posix.F.GETFL, 0);
    try testing.expect((flags & @as(usize, linux.SOCK.NONBLOCK)) != 0);
}

test "ipc: init rejects path that is too long" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    const long = [_]u8{'a'} ** 200;
    try testing.expectError(
        error.PathTooLong,
        IpcServer.init(a, &loop, &long),
    );
}

const CaptureDispatch = struct {
    saw_version: bool = false,

    fn dispatch(
        ctx: ?*anyopaque,
        cmd: shared.Command,
        allocator: std.mem.Allocator,
    ) anyerror!shared.Response {
        const self: *CaptureDispatch = @ptrCast(@alignCast(ctx.?));
        switch (cmd) {
            .version => self.saw_version = true,
            else => {},
        }
        const payload = try allocator.dupe(u8, "{\"version\":\"test\"}");
        return .{ .ok = .{ .payload = payload } };
    }
};

test "ipc: end-to-end version command through unix socketpair" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

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

    var server: IpcServer = .{
        .allocator = a,
        .loop = &loop,
        .socket_path = "",
        .listen_fd = -1,
        .started = false,
        .allowed_gid = null,
        .allow_any_peer = true,
    };
    defer {
        for (&server.clients) |*slot| {
            if (slot.*) |cli| {
                loop.removeFd(cli.fd) catch {};
                posix.close(cli.fd);
                a.free(cli.buf);
                a.destroy(cli);
                slot.* = null;
            }
        }
    }

    var capture = CaptureDispatch{};
    server.setCommandHandler(.{
        .ctx = @ptrCast(&capture),
        .dispatch = CaptureDispatch.dispatch,
    });

    try server.admitClient(fds[0], .{ .pid = 0, .uid = 0, .gid = 0 });

    var wbuf: [64]u8 = undefined;
    var ws = std.io.fixedBufferStream(&wbuf);
    try protocol.serializeCommand(.{ .version = {} }, ws.writer());
    const wire = ws.getWritten();
    var written: usize = 0;
    while (written < wire.len) {
        written += try posix.write(fds[1], wire[written..]);
    }

    const Watchdog = struct {
        fn run(l: *EventLoop) void {
            std.time.sleep(500 * std.time.ns_per_ms);
            l.stop();
        }
    };
    const wd = try std.Thread.spawn(.{}, Watchdog.run, .{&loop});
    try loop.run();
    wd.join();

    var rbuf: [256]u8 = undefined;
    const n = try posix.read(fds[1], &rbuf);
    try testing.expect(n >= 5);

    var rs = std.io.fixedBufferStream(rbuf[0..n]);
    const resp = try protocol.deserializeResponse(rs.reader(), a);
    defer resp.deinit(a);
    switch (resp) {
        .ok => |o| try testing.expect(std.mem.indexOf(u8, o.payload, "version") != null),
        .err => return error.UnexpectedErrResponse,
    }

    try testing.expect(capture.saw_version);
}

fn initFakeServer(
    server: *IpcServer,
    a: std.mem.Allocator,
    loop: *EventLoop,
    fds: *[2]i32,
    handler: CommandHandler,
) !void {
    const stype_u32: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const rc = linux.socketpair(
        @as(i32, linux.AF.UNIX),
        @as(i32, @intCast(stype_u32)),
        0,
        fds,
    );
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }

    server.* = .{
        .allocator = a,
        .loop = loop,
        .socket_path = "",
        .listen_fd = -1,
        .started = false,
        .allowed_gid = null,
        .allow_any_peer = true,
    };
    server.setCommandHandler(handler);
    try server.admitClient(fds[0], .{ .pid = 0, .uid = 0, .gid = 0 });
}

fn drainFakeServer(a: std.mem.Allocator, loop: *EventLoop, server: *IpcServer) void {
    _ = a;
    for (&server.clients) |*slot| {
        if (slot.*) |cli| {
            loop.removeFd(cli.fd) catch {};
            posix.close(cli.fd);
            server.allocator.free(cli.buf);
            server.allocator.destroy(cli);
            slot.* = null;
        }
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

test "ipc: malformed command receives err response and client stays open" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var capture = CaptureDispatch{};
    const handler: CommandHandler = .{
        .ctx = @ptrCast(&capture),
        .dispatch = CaptureDispatch.dispatch,
    };

    var fds: [2]i32 = undefined;
    var server: IpcServer = undefined;
    try initFakeServer(&server, a, &loop, &fds, handler);
    defer drainFakeServer(a, &loop, &server);
    defer posix.close(fds[1]);

    const bad: [5]u8 = [_]u8{ 0x01, 0x00, 0x00, 0x00, 0xFE };
    _ = try posix.write(fds[1], &bad);

    try runLoopBriefly(&loop, 300);

    var rbuf: [256]u8 = undefined;
    const n = try posix.read(fds[1], &rbuf);
    try testing.expect(n > 0);
    var rs = std.io.fixedBufferStream(rbuf[0..n]);
    const resp = try protocol.deserializeResponse(rs.reader(), a);
    defer resp.deinit(a);
    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 400), resp.err.code);
}

test "ipc: defaultDispatch returns 503 when no handler installed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    const resp = try defaultDispatch(null, .{ .version = {} }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 503), resp.err.code);
}

test "ipc: oversized length prefix closes the client" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var capture = CaptureDispatch{};
    const handler: CommandHandler = .{
        .ctx = @ptrCast(&capture),
        .dispatch = CaptureDispatch.dispatch,
    };

    var fds: [2]i32 = undefined;
    var server: IpcServer = undefined;
    try initFakeServer(&server, a, &loop, &fds, handler);
    defer drainFakeServer(a, &loop, &server);
    defer posix.close(fds[1]);

    var prefix: [4]u8 = undefined;
    std.mem.writeInt(u32, &prefix, protocol.max_payload_size + 1, .little);
    _ = try posix.write(fds[1], &prefix);

    try runLoopBriefly(&loop, 200);

    var buf: [4]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try testing.expectEqual(@as(usize, 0), n);
}
