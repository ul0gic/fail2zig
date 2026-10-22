// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const shared = @import("shared");
const protocol = shared.protocol;
const event_loop_mod = @import("../core/event_loop.zig");
pub const auth = @import("ipc_auth.zig");

const EventLoop = event_loop_mod.EventLoop;

pub const max_clients: usize = 8;

pub const client_buffer_size: usize = protocol.max_payload_size + 4;

pub const max_response_bytes: usize = protocol.max_payload_size + 4;

pub const default_frame_deadline_ms: u64 = 5_000;
pub const default_drain_deadline_ms: u64 = 5_000;
pub const default_idle_deadline_ms: u64 = 30_000;
const deadline_tick_ms: u64 = 1_000;

pub const Error = error{
    SocketCreateFailed,
    BindFailed,
    ListenFailed,
    ChmodFailed,
    PathTooLong,
    UnlinkFailed,
    SocketPathInUse,
    SocketPathRefused,
    SocketPathInsecure,
    AlreadyStarted,
    OutOfMemory,
    EventLoopError,
    NotLinux,
};

pub const Peer = struct {
    class: auth.PeerClass,
    uid: u32,
    gid: u32,
    pid: i32,
    request_id: ?[auth.request_id_len]u8,
};

pub const DispatchFn = *const fn (
    ctx: ?*anyopaque,
    cmd: shared.Command,
    allocator: std.mem.Allocator,
) anyerror!shared.Response;

pub const DispatchAuthFn = *const fn (
    ctx: ?*anyopaque,
    cmd: shared.Command,
    peer: Peer,
    allocator: std.mem.Allocator,
) anyerror!shared.Response;

pub const CommandHandler = struct {
    ctx: ?*anyopaque = null,
    dispatch: DispatchFn,
    dispatch_auth: ?DispatchAuthFn = null,
};

const ClientReg = struct {
    server: *IpcServer,
    fd: posix.fd_t,
    cred: auth.PeerCred,
    class: auth.PeerClass,
    buf: []u8,
    len: usize = 0,
    need: usize = 0,
    frame_started_ms: ?u64 = null,
    pending: ?[]u8 = null,
    sent: usize = 0,
    drain_deadline_ms: u64 = 0,
    idle_deadline_ms: u64 = 0,

    fn reset(self: *ClientReg) void {
        self.len = 0;
        self.need = 0;
        self.frame_started_ms = null;
    }
};

extern "c" fn umask(mask: u32) callconv(.C) u32;

pub const ClockFn = *const fn () u64;

fn monotonicMs() u64 {
    const ts = posix.clock_gettime(.MONOTONIC) catch return std.math.maxInt(u64);
    const sec: u64 = @intCast(ts.sec);
    const nsec: u64 = @intCast(ts.nsec);
    return sec * std.time.ms_per_s + nsec / std.time.ns_per_ms;
}

pub const IpcServer = struct {
    allocator: std.mem.Allocator,
    loop: *EventLoop,
    socket_path: []const u8,
    listen_fd: posix.fd_t = -1,
    started: bool = false,
    self_uid: u32 = 0,
    detached: bool = false,
    serving: bool = true,
    frame_deadline_ms: u64 = default_frame_deadline_ms,
    drain_deadline_ms: u64 = default_drain_deadline_ms,
    idle_deadline_ms: u64 = default_idle_deadline_ms,
    clock: ClockFn = monotonicMs,
    deadline_timer: event_loop_mod.TimerHandle = .invalid,
    handler: CommandHandler = .{
        .ctx = null,
        .dispatch = defaultDispatch,
    },
    pool: []u8 = &.{},
    clients: [max_clients]?*ClientReg = [_]?*ClientReg{null} ** max_clients,
    slots: [max_clients]ClientReg = undefined,

    pub fn init(
        allocator: std.mem.Allocator,
        loop: *EventLoop,
        socket_path: []const u8,
    ) Error!IpcServer {
        if (builtin.os.tag != .linux) return error.NotLinux;
        if (socket_path.len >= 108) return error.PathTooLong;
        const self_uid = linux.geteuid();

        auth.verifyParentDir(socket_path, self_uid) catch |err| {
            std.log.warn("ipc: refusing to serve '{s}': {s}", .{ socket_path, @errorName(err) });
            return error.SocketPathInsecure;
        };
        try prepareBindPath(socket_path);

        const stype: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
        const fd = posix.socket(posix.AF.UNIX, stype, 0) catch
            return error.SocketCreateFailed;
        errdefer posix.close(fd);

        var addr: linux.sockaddr.un = .{ .path = [_]u8{0} ** 108 };
        @memcpy(addr.path[0..socket_path.len], socket_path);
        const sun_path_offset = @offsetOf(linux.sockaddr.un, "path");
        const addr_len: posix.socklen_t =
            @intCast(sun_path_offset + socket_path.len + 1);

        const prev_umask: u32 = umask(0o117);
        const bind_result = posix.bind(fd, @ptrCast(&addr), addr_len);
        _ = umask(prev_umask);
        bind_result catch return error.BindFailed;
        errdefer std.fs.cwd().deleteFile(socket_path) catch {};

        std.posix.fchmodat(std.posix.AT.FDCWD, socket_path, 0o660, 0) catch |err| {
            std.log.warn("ipc: chmod '{s}' failed: {s}", .{ socket_path, @errorName(err) });
            return error.ChmodFailed;
        };

        auth.verifySocketPath(socket_path, self_uid) catch |err| {
            std.log.warn("ipc: refusing to serve '{s}': {s}", .{ socket_path, @errorName(err) });
            return error.SocketPathInsecure;
        };

        posix.listen(fd, @intCast(max_clients)) catch return error.ListenFailed;

        const pool = try allocator.alloc(u8, max_clients * client_buffer_size);

        return .{
            .allocator = allocator,
            .loop = loop,
            .socket_path = socket_path,
            .listen_fd = fd,
            .self_uid = self_uid,
            .pool = pool,
        };
    }

    fn prepareBindPath(socket_path: []const u8) Error!void {
        const state = auth.inspectBindPath(socket_path) catch |err| {
            std.log.warn("ipc: refusing socket path '{s}': {s}", .{ socket_path, @errorName(err) });
            return switch (err) {
                error.PathTooLong => error.PathTooLong,
                else => error.SocketPathRefused,
            };
        };
        switch (state) {
            .absent => {},
            .live_socket => {
                std.log.warn("ipc: '{s}' is served by another process", .{socket_path});
                return error.SocketPathInUse;
            },
            .stale_socket => std.fs.cwd().deleteFile(socket_path) catch |err| switch (err) {
                error.FileNotFound => {},
                else => {
                    std.log.warn("ipc: unlink stale '{s}' failed: {s}", .{ socket_path, @errorName(err) });
                    return error.UnlinkFailed;
                },
            },
        }
    }

    pub fn initDetached(allocator: std.mem.Allocator, loop: *EventLoop) Error!IpcServer {
        const pool = try allocator.alloc(u8, max_clients * client_buffer_size);
        return .{
            .allocator = allocator,
            .loop = loop,
            .socket_path = "",
            .detached = true,
            .self_uid = linux.geteuid(),
            .pool = pool,
        };
    }

    pub fn deinit(self: *IpcServer) void {
        for (&self.clients) |*slot| {
            if (slot.*) |cli| {
                self.loop.removeFd(cli.fd) catch {};
                posix.close(cli.fd);
                self.dropPending(cli);
                slot.* = null;
            }
        }
        if (self.deadline_timer != .invalid) {
            self.loop.cancelTimer(self.deadline_timer) catch {};
            self.deadline_timer = .invalid;
        }
        if (self.started) {
            self.loop.removeFd(self.listen_fd) catch {};
            self.started = false;
        }
        if (self.listen_fd != -1) {
            posix.close(self.listen_fd);
            self.listen_fd = -1;
        }
        if (self.socket_path.len != 0) std.fs.cwd().deleteFile(self.socket_path) catch {};
        self.allocator.free(self.pool);
        self.* = undefined;
    }

    pub fn setCommandHandler(self: *IpcServer, h: CommandHandler) void {
        self.handler = h;
    }

    pub fn setDeadlines(self: *IpcServer, frame_ms: u64, drain_ms: u64) void {
        self.frame_deadline_ms = frame_ms;
        self.drain_deadline_ms = drain_ms;
    }

    pub fn admitTestPeer(self: *IpcServer, fd: posix.fd_t) !void {
        std.debug.assert(self.detached);
        return self.admitClient(fd, .{ .pid = 0, .uid = 0, .gid = 0 });
    }

    pub fn admitTestPeerAs(self: *IpcServer, fd: posix.fd_t, cred: auth.PeerCred) !void {
        std.debug.assert(self.detached);
        return self.admitClient(fd, cred);
    }

    pub fn isServing(self: *const IpcServer) bool {
        return self.serving;
    }

    pub fn activeClients(self: *const IpcServer) usize {
        var n: usize = 0;
        for (self.clients) |slot| {
            if (slot != null) n += 1;
        }
        return n;
    }

    pub fn start(self: *IpcServer) Error!void {
        if (self.started) return error.AlreadyStarted;
        self.loop.addFd(
            self.listen_fd,
            linux.EPOLL.IN,
            onListenReadable,
            @ptrCast(self),
        ) catch return error.EventLoopError;
        errdefer self.loop.removeFd(self.listen_fd) catch {};
        self.deadline_timer = self.loop.addTimer(deadline_tick_ms, onDeadlineTick, @ptrCast(self), false) catch
            return error.EventLoopError;
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

    fn onDeadlineTick(expirations: u64, userdata: ?*anyopaque) void {
        _ = expirations;
        const self: *IpcServer = @ptrCast(@alignCast(userdata.?));
        self.checkDeadlines(self.clock());
    }

    pub fn checkDeadlines(self: *IpcServer, now_ms: u64) void {
        for (self.clients) |slot| {
            const cli = slot orelse continue;
            if (cli.pending != null) {
                if (now_ms >= cli.drain_deadline_ms) {
                    std.log.warn("ipc: client fd={d} uid={d} did not drain response within {d} ms; closing", .{ cli.fd, cli.cred.uid, self.drain_deadline_ms });
                    self.closeClient(cli);
                }
                continue;
            }
            if (cli.frame_started_ms) |started| {
                if (now_ms -| started >= self.frame_deadline_ms) {
                    std.log.warn("ipc: client fd={d} uid={d} did not complete frame within {d} ms; closing", .{ cli.fd, cli.cred.uid, self.frame_deadline_ms });
                    self.closeClient(cli);
                }
            } else if (now_ms >= cli.idle_deadline_ms) {
                std.log.warn("ipc: client fd={d} uid={d} stayed idle for {d} ms; closing", .{ cli.fd, cli.cred.uid, self.idle_deadline_ms });
                self.closeClient(cli);
            }
        }
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

            if (!self.verifyServing()) {
                posix.close(client_fd);
                continue;
            }

            const cred = readPeerCred(client_fd) catch {
                posix.close(client_fd);
                continue;
            };

            self.admitClient(client_fd, cred) catch |err| {
                std.log.warn("ipc: admit failed (fd={d} uid={d}): {s}", .{ client_fd, cred.uid, @errorName(err) });
                posix.close(client_fd);
                continue;
            };
        }
    }

    fn verifyServing(self: *IpcServer) bool {
        auth.verifySocketPath(self.socket_path, self.self_uid) catch |err| {
            if (self.serving) std.log.warn("ipc: socket path '{s}' no longer trustworthy ({s}); refusing new connections", .{ self.socket_path, @errorName(err) });
            self.serving = false;
            return false;
        };
        if (!self.serving) {
            std.log.info("ipc: socket path '{s}' verified again; accepting connections", .{self.socket_path});
            self.serving = true;
        }
        return true;
    }

    fn admitClient(self: *IpcServer, fd: posix.fd_t, cred: auth.PeerCred) !void {
        self.checkDeadlines(self.clock());
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

        const i = idx.?;
        const cli = &self.slots[i];
        cli.* = .{
            .server = self,
            .fd = fd,
            .cred = cred,
            .class = auth.classifyPeer(cred, self.self_uid),
            .buf = self.pool[i * client_buffer_size ..][0..client_buffer_size],
            .idle_deadline_ms = self.clock() +| self.idle_deadline_ms,
        };

        try self.loop.addFd(fd, linux.EPOLL.IN, onClientEvent, @ptrCast(cli));
        self.clients[i] = cli;
        std.log.debug("ipc: admitted pid={d} uid={d} gid={d} class={s}", .{ cred.pid, cred.uid, cred.gid, @tagName(cli.class) });
    }

    fn onClientEvent(
        fd: posix.fd_t,
        events: u32,
        userdata: ?*anyopaque,
    ) void {
        _ = fd;
        const cli: *ClientReg = @ptrCast(@alignCast(userdata.?));
        cli.server.handleClientEvent(cli, events);
    }

    fn handleClientEvent(self: *IpcServer, cli: *ClientReg, events: u32) void {
        if (cli.pending != null) {
            if (events & linux.EPOLL.OUT != 0) {
                self.flushPending(cli) catch |err| {
                    std.log.info("ipc: client fd={d} write failed ({s}); closing", .{ cli.fd, @errorName(err) });
                    self.closeClient(cli);
                    return;
                };
            }
            if (cli.pending == null) return;
            if (events & (linux.EPOLL.IN | linux.EPOLL.HUP | linux.EPOLL.ERR) != 0) {
                self.rejectInputDuringDrain(cli);
            }
            return;
        }
        if (events & linux.EPOLL.IN != 0) {
            self.handleClientReadable(cli);
            return;
        }
        if (events & (linux.EPOLL.HUP | linux.EPOLL.ERR) != 0) self.closeClient(cli);
    }

    fn rejectInputDuringDrain(self: *IpcServer, cli: *ClientReg) void {
        var probe: [64]u8 = undefined;
        const n = posix.read(cli.fd, &probe) catch |err| switch (err) {
            error.WouldBlock => return,
            else => {
                self.closeClient(cli);
                return;
            },
        };
        if (n > 0) {
            std.log.warn("ipc: client fd={d} uid={d} sent a request before draining the previous response; closing", .{ cli.fd, cli.cred.uid });
        }
        self.closeClient(cli);
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
                    if (cli.pending != null) return;
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
                if (cli.len != 0) {
                    std.log.info("ipc: client fd={d} closed mid-frame ({d}/{d} bytes); closing", .{ cli.fd, cli.len, target });
                }
                self.closeClient(cli);
                return;
            }
            if (cli.len == 0) cli.frame_started_ms = self.clock();
            cli.len += n;
        }
    }

    fn processFrame(self: *IpcServer, cli: *ClientReg) !void {
        const body = cli.buf[4..cli.need];
        if (body.len == 0) {
            std.log.warn("ipc: empty frame from fd={d}", .{cli.fd});
            return self.queueErr(cli, 400, "bad command");
        }
        const tag = body[0];
        const decision = auth.decide(.{ .class = cli.class, .command = auth.classifyTag(tag) });
        switch (decision) {
            .bad_command => {
                std.log.warn("ipc: unknown command tag {d} from fd={d}", .{ tag, cli.fd });
                return self.queueErr(cli, 400, "bad command");
            },
            .forbid_mutation => {
                std.log.warn("ipc: monitor pid={d} uid={d} gid={d} attempted mutation tag {d}; refused", .{ cli.cred.pid, cli.cred.uid, cli.cred.gid, tag });
                return self.queueErr(cli, 403, "mutation requires root or daemon uid");
            },
            .allow => {},
        }

        const request_id = auth.extractRequestId(body) catch {
            std.log.warn("ipc: mutation tag {d} from fd={d} lacks request_id", .{ tag, cli.fd });
            return self.queueErr(cli, 400, "mutation frame requires request_id");
        };

        var stream = std.io.fixedBufferStream(cli.buf[0..cli.need]);
        const cmd = protocol.deserializeCommand(stream.reader()) catch |err| {
            std.log.warn("ipc: bad command from fd={d}: {s}", .{ cli.fd, @errorName(err) });
            return self.queueErr(cli, 400, "bad command");
        };

        const peer: Peer = .{
            .class = cli.class,
            .uid = cli.cred.uid,
            .gid = cli.cred.gid,
            .pid = cli.cred.pid,
            .request_id = request_id,
        };
        const result = if (self.handler.dispatch_auth) |f|
            f(self.handler.ctx, cmd, peer, self.allocator)
        else if (auth.classifyTag(tag) == .mutation)
            @as(anyerror!shared.Response, error.MutationHandlerNotInstalled)
        else
            self.handler.dispatch(self.handler.ctx, cmd, self.allocator);

        const resp = result catch |err| switch (err) {
            error.MutationHandlerNotInstalled => {
                std.log.warn("ipc: mutation tag {d} refused: no authenticated handler installed", .{tag});
                return self.queueErr(cli, 403, "mutation requires root or daemon uid");
            },
            else => {
                std.log.warn("ipc: handler error fd={d}: {s}", .{ cli.fd, @errorName(err) });
                return self.queueErr(cli, 500, "handler error");
            },
        };
        defer resp.deinit(self.allocator);

        try self.queueResponse(cli, resp);
    }

    const QueueError = std.mem.Allocator.Error || posix.WriteError || error{ NoSpaceLeft, ShortWrite, EventLoopError };

    fn responseSize(resp: shared.Response) usize {
        return switch (resp) {
            .ok => |o| 4 + 1 + 4 + o.payload.len,
            .err => |e| 4 + 1 + 2 + 4 + e.message.len,
        };
    }

    fn queueResponse(self: *IpcServer, cli: *ClientReg, resp: shared.Response) QueueError!void {
        std.debug.assert(cli.pending == null);
        const size = responseSize(resp);
        if (size > max_response_bytes) {
            std.log.warn("ipc: response of {d} bytes exceeds bound {d}; replacing with error", .{ size, max_response_bytes });
            return self.queueErr(cli, 500, "response too large");
        }
        const buf = try self.allocator.alloc(u8, size);
        errdefer self.allocator.free(buf);
        var stream = std.io.fixedBufferStream(buf);
        try protocol.serializeResponse(resp, stream.writer());
        std.debug.assert(stream.getWritten().len == size);

        cli.pending = buf;
        cli.sent = 0;
        cli.drain_deadline_ms = self.clock() +| self.drain_deadline_ms;
        try self.flushPending(cli);
    }

    fn queueErr(self: *IpcServer, cli: *ClientReg, code: u16, msg: []const u8) QueueError!void {
        const resp: shared.Response = .{ .err = .{ .code = code, .message = msg } };
        try self.queueResponse(cli, resp);
    }

    fn flushPending(self: *IpcServer, cli: *ClientReg) QueueError!void {
        const buf = cli.pending orelse return;
        while (cli.sent < buf.len) {
            const n = posix.write(cli.fd, buf[cli.sent..]) catch |err| switch (err) {
                error.WouldBlock => {
                    try self.setInterest(cli, linux.EPOLL.IN | linux.EPOLL.OUT);
                    return;
                },
                else => return err,
            };
            if (n == 0) return error.ShortWrite;
            cli.sent += n;
        }
        self.dropPending(cli);
        cli.idle_deadline_ms = self.clock() +| self.idle_deadline_ms;
        try self.setInterest(cli, linux.EPOLL.IN);
    }

    fn dropPending(self: *IpcServer, cli: *ClientReg) void {
        if (cli.pending) |buf| self.allocator.free(buf);
        cli.pending = null;
        cli.sent = 0;
    }

    fn setInterest(self: *IpcServer, cli: *ClientReg, events: u32) error{EventLoopError}!void {
        var ev: linux.epoll_event = .{ .events = events, .data = .{ .fd = cli.fd } };
        posix.epoll_ctl(self.loop.epoll_fd, linux.EPOLL.CTL_MOD, cli.fd, &ev) catch return error.EventLoopError;
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
        self.dropPending(cli);
        self.loop.removeFd(cli.fd) catch {};
        posix.close(cli.fd);
    }
};

fn readPeerCred(fd: posix.fd_t) !auth.PeerCred {
    var cred: auth.PeerCred = undefined;
    var len: posix.socklen_t = @sizeOf(auth.PeerCred);
    const rc = linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&cred),
        &len,
    );
    switch (linux.E.init(rc)) {
        .SUCCESS => return cred,
        else => |e| {
            std.log.warn("ipc: SO_PEERCRED failed: errno={d}", .{@intFromEnum(e)});
            return error.PeerCredFailed;
        },
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
