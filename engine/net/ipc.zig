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

/// Serialized response bound: length prefix plus a body no larger than a request frame.
pub const max_response_bytes: usize = protocol.max_payload_size + 4;

pub const default_frame_deadline_ms: u64 = 5_000;
pub const default_drain_deadline_ms: u64 = 5_000;
/// Command-line clients reconnect for each request; an accepted peer that sends nothing must
/// not retain one of the bounded connection slots indefinitely.
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
    /// Present only for mutation tags that carry one on the wire (8/9); legacy 1/2/5 → null.
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

/// `dispatch_auth`, when set, receives every authorized command with its peer. Without it
/// only read-only commands reach `dispatch`; every mutation is refused with 403.
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
    /// Monotonic ms when the first byte of the current frame arrived; null between frames.
    frame_started_ms: ?u64 = null,
    /// Owned serialized response awaiting drain; at most one per connection.
    pending: ?[]u8 = null,
    sent: usize = 0,
    drain_deadline_ms: u64 = 0,
    /// Absolute monotonic deadline while waiting between frames.
    idle_deadline_ms: u64 = 0,

    fn reset(self: *ClientReg) void {
        self.len = 0;
        self.need = 0;
        self.frame_started_ms = null;
    }
};

extern "c" fn umask(mask: u32) callconv(.C) u32;

pub const ClockFn = *const fn () u64;

/// A failed clock read returns the maximum so every armed deadline counts as expired:
/// without a trustworthy clock the server cannot bound a stalled peer any other way.
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
    /// Detached servers (socketpair tests) skip path verification and accept injected creds.
    detached: bool = false,
    /// Cleared once post-bind path verification fails; new connections are then closed
    /// unanswered until a later accept finds the path trustworthy again.
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

        // Directory verification precedes the stale-socket unlink so no other principal
        // can place an object at the path between the liveness probe and the unlink.
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

    /// Readiness input: false while the socket path fails verification.
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

    /// Closes clients that exceeded the idle, frame or drain deadline. Public so tests can drive
    /// it with an injected clock instead of waiting on the periodic timer.
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

    /// Re-verifies the socket directory and path on every accept. A failure logs once and
    /// refuses new connections while existing ones drain; a later accept that verifies
    /// again logs the recovery once and resumes serving.
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
        // The timer may not have fired yet at the deadline boundary. Reap first so expired
        // monitor connections cannot make a newly authenticated administrator lose the race.
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

    /// One in-flight response per connection: any bytes (or EOF) arriving before the
    /// previous response drained end the connection.
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
                    // The response (if any) owns the connection until drained.
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

    /// Serializes into an owned buffer, then writes as much as the socket accepts now;
    /// the remainder drains on EPOLLOUT under the drain deadline.
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
    // Raw syscall: std.posix.getsockopt leaves optlen uninitialized, the kernel EINVALs and the wrapper hits unreachable.
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

const testing = std.testing;

/// Socket parent must satisfy the 0750 contract, so tests bind inside a private directory.
const TestSocketDir = struct {
    tmp: testing.TmpDir,
    path: []u8,

    fn init(a: std.mem.Allocator) !TestSocketDir {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
        const abs = try tmp.dir.realpath(".", &abs_buf);
        try posix.fchmodat(posix.AT.FDCWD, abs, 0o750, 0);
        const path = try std.fmt.allocPrint(a, "{s}/ipc.sock", .{abs});
        if (path.len >= 108) {
            a.free(path);
            return error.SkipZigTest;
        }
        return .{ .tmp = tmp, .path = path };
    }

    fn deinit(self: *TestSocketDir, a: std.mem.Allocator) void {
        a.free(self.path);
        self.tmp.cleanup();
    }
};

test "ipc: init creates socket, deinit removes it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var dir = try TestSocketDir.init(a);
    defer dir.deinit(a);

    {
        var server = try IpcServer.init(a, &loop, dir.path);
        defer server.deinit();

        try std.fs.cwd().access(dir.path, .{});
    }

    const exists = blk: {
        std.fs.cwd().access(dir.path, .{}) catch break :blk false;
        break :blk true;
    };
    try testing.expect(!exists);
}

test "ipc: init refuses a regular file at the socket path" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var dir = try TestSocketDir.init(a);
    defer dir.deinit(a);

    {
        const f = try std.fs.cwd().createFile(dir.path, .{});
        f.close();
    }

    try testing.expectError(error.SocketPathRefused, IpcServer.init(a, &loop, dir.path));
    try std.fs.cwd().access(dir.path, .{});
}

test "ipc: socket has mode 0660 immediately after init (SEC-002)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var dir = try TestSocketDir.init(a);
    defer dir.deinit(a);

    var server = try IpcServer.init(a, &loop, dir.path);
    defer server.deinit();

    const st = try posix.fstatat(posix.AT.FDCWD, dir.path, posix.AT.SYMLINK_NOFOLLOW);
    try testing.expectEqual(@as(u32, 0o660), st.mode & 0o777);
    try testing.expectEqual(@as(u32, linux.geteuid()), st.uid);
}

test "ipc: listener socket is non-blocking (SYS-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var dir = try TestSocketDir.init(a);
    defer dir.deinit(a);

    var server = try IpcServer.init(a, &loop, dir.path);
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

test "ipc: init records the daemon euid and allocates the client pool once" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var dir = try TestSocketDir.init(a);
    defer dir.deinit(a);

    var server = try IpcServer.init(a, &loop, dir.path);
    defer server.deinit();

    try testing.expectEqual(@as(u32, linux.geteuid()), server.self_uid);
    try testing.expectEqual(max_clients * client_buffer_size, server.pool.len);
}

fn socketpairNonblock(fds: *[2]i32) !void {
    const stype_u32: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const rc = linux.socketpair(@as(i32, linux.AF.UNIX), @as(i32, @intCast(stype_u32)), 0, fds);
    switch (linux.E.init(rc)) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
}

test "ipc: admit and close reuse the pooled slot without allocating (PRF-002)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = try IpcServer.initDetached(a, &loop);
    defer server.deinit();

    var failing = testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    server.allocator = failing.allocator();
    defer server.allocator = a;

    var round: usize = 0;
    while (round < 3) : (round += 1) {
        var fds: [2]i32 = undefined;
        try socketpairNonblock(&fds);
        defer posix.close(fds[1]);

        try server.admitClient(fds[0], .{ .pid = 0, .uid = 0, .gid = 0 });
        const cli = server.clients[0].?;
        try testing.expectEqual(@as(usize, client_buffer_size), cli.buf.len);
        try testing.expectEqual(@intFromPtr(server.pool.ptr), @intFromPtr(cli.buf.ptr));
        server.closeClient(cli);
        try testing.expect(server.clients[0] == null);
    }
    try testing.expectEqual(@as(usize, 0), failing.allocations);
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

const CaptureAuthDispatch = struct {
    saw_admin_reload: bool = false,

    fn dispatch(
        ctx: ?*anyopaque,
        cmd: shared.Command,
        peer: Peer,
        allocator: std.mem.Allocator,
    ) anyerror!shared.Response {
        const self: *CaptureAuthDispatch = @ptrCast(@alignCast(ctx.?));
        switch (cmd) {
            .reload_v1 => self.saw_admin_reload = peer.class == .admin,
            else => {},
        }
        return .{ .ok = .{ .payload = try allocator.dupe(u8, "{\"outcome\":\"noop\"}") } };
    }
};

const IdleTestClock = struct {
    var now_ms: u64 = 0;

    fn read() u64 {
        return now_ms;
    }
};

fn initFakeServer(
    server: *IpcServer,
    a: std.mem.Allocator,
    loop: *EventLoop,
    fds: *[2]i32,
    handler: CommandHandler,
) !void {
    try socketpairNonblock(fds);
    server.* = try IpcServer.initDetached(a, loop);
    errdefer server.deinit();
    server.setCommandHandler(handler);
    try server.admitClient(fds[0], .{ .pid = 0, .uid = 0, .gid = 0 });
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

test "ipc: end-to-end version command through unix socketpair" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var capture = CaptureDispatch{};
    var fds: [2]i32 = undefined;
    var server: IpcServer = undefined;
    try initFakeServer(&server, a, &loop, &fds, .{ .ctx = @ptrCast(&capture), .dispatch = CaptureDispatch.dispatch });
    defer server.deinit();
    defer posix.close(fds[1]);

    var wbuf: [64]u8 = undefined;
    var ws = std.io.fixedBufferStream(&wbuf);
    try protocol.serializeCommand(.{ .version = {} }, ws.writer());
    const wire = ws.getWritten();
    var written: usize = 0;
    while (written < wire.len) {
        written += try posix.write(fds[1], wire[written..]);
    }

    try runLoopBriefly(&loop, 300);

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
    try testing.expect(server.clients[0].?.pending == null);
}

test "ipc: malformed command receives err response and client stays open" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var capture = CaptureDispatch{};
    var fds: [2]i32 = undefined;
    var server: IpcServer = undefined;
    try initFakeServer(&server, a, &loop, &fds, .{ .ctx = @ptrCast(&capture), .dispatch = CaptureDispatch.dispatch });
    defer server.deinit();
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
    try testing.expectEqual(@as(usize, 1), server.activeClients());
}

test "native ipc auth: SEC-014 expired silent monitors cannot lock out an authenticated request" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var server = try IpcServer.initDetached(a, &loop);
    defer server.deinit();
    var capture = CaptureAuthDispatch{};
    server.setCommandHandler(.{ .ctx = @ptrCast(&capture), .dispatch = defaultDispatch, .dispatch_auth = CaptureAuthDispatch.dispatch });
    server.idle_deadline_ms = 50;
    IdleTestClock.now_ms = 100;
    server.clock = IdleTestClock.read;

    const monitor_uid = if (server.self_uid == std.math.maxInt(u32)) server.self_uid - 1 else server.self_uid + 1;
    var silent: [max_clients][2]i32 = undefined;
    var silent_count: usize = 0;
    defer for (silent[0..silent_count]) |fds| posix.close(fds[1]);
    while (silent_count < max_clients) {
        var fds: [2]i32 = undefined;
        try socketpairNonblock(&fds);
        server.admitTestPeerAs(fds[0], .{ .pid = 10, .uid = monitor_uid, .gid = 10 }) catch |err| {
            posix.close(fds[0]);
            posix.close(fds[1]);
            return err;
        };
        silent[silent_count] = fds;
        silent_count += 1;
    }
    try testing.expectEqual(max_clients, server.activeClients());
    for (server.clients) |slot| {
        try testing.expectEqual(auth.PeerClass.monitor, slot.?.class);
        try testing.expectEqual(@as(u64, 150), slot.?.idle_deadline_ms);
    }

    server.checkDeadlines(149);
    try testing.expectEqual(max_clients, server.activeClients());
    IdleTestClock.now_ms = 150;
    var admin: [2]i32 = undefined;
    try socketpairNonblock(&admin);
    defer posix.close(admin[1]);
    server.admitTestPeerAs(admin[0], .{ .pid = 1, .uid = server.self_uid, .gid = 0 }) catch |err| {
        posix.close(admin[0]);
        return err;
    };
    try testing.expectEqual(@as(usize, 1), server.activeClients());
    for (silent) |fds| {
        var closed: [1]u8 = undefined;
        try testing.expectEqual(@as(usize, 0), try posix.read(fds[1], &closed));
    }

    var wire_buf: [128]u8 = undefined;
    var wire = std.io.fixedBufferStream(&wire_buf);
    try protocol.serializeCommand(.{ .reload_v1 = .{ .request_id = [_]u8{7} ** protocol.request_id_bytes, .body = .{} } }, wire.writer());
    try testing.expectEqual(wire.getWritten().len, try posix.write(admin[1], wire.getWritten()));
    server.handleClientReadable(server.clients[0].?);

    var response_buf: [256]u8 = undefined;
    const response_len = try posix.read(admin[1], &response_buf);
    var response_stream = std.io.fixedBufferStream(response_buf[0..response_len]);
    const response = try protocol.deserializeResponse(response_stream.reader(), a);
    defer response.deinit(a);
    try testing.expect(response == .ok);
    try testing.expect(capture.saw_admin_reload);
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
    var fds: [2]i32 = undefined;
    var server: IpcServer = undefined;
    try initFakeServer(&server, a, &loop, &fds, .{ .ctx = @ptrCast(&capture), .dispatch = CaptureDispatch.dispatch });
    defer server.deinit();
    defer posix.close(fds[1]);

    var prefix: [4]u8 = undefined;
    std.mem.writeInt(u32, &prefix, protocol.max_payload_size + 1, .little);
    _ = try posix.write(fds[1], &prefix);

    try runLoopBriefly(&loop, 200);

    var buf: [4]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try testing.expectEqual(@as(usize, 0), n);
    try testing.expectEqual(@as(usize, 0), server.activeClients());
}
