// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const shared = @import("shared");
const protocol = shared.protocol;

const engine = @import("engine");
const event_loop = engine.event_loop_mod;
const tracker_map = engine.tracker_map_mod;
const firewall = engine.firewall;
const nftables = firewall.nftables;
const config_mod = engine.config_mod;
const commands = engine.commands_mod;
const ipc = engine.ipc_mod;

const testing = std.testing;

fn socketpairNonblock(fds: *[2]i32) !void {
    const stype_u32: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const rc = linux.socketpair(
        @as(i32, linux.AF.UNIX),
        @as(i32, @intCast(stype_u32)),
        0,
        fds,
    );
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SocketpairFailed,
    }
}

fn runLoopBriefly(loop: *event_loop.EventLoop, ms: u64) !void {
    const Wd = struct {
        fn run(l: *event_loop.EventLoop, m: u64) void {
            std.time.sleep(m * std.time.ns_per_ms);
            l.stop();
        }
    };
    const th = try std.Thread.spawn(.{}, Wd.run, .{ loop, ms });
    try loop.run();
    th.join();
}

fn readResponse(fd: posix.fd_t, buf: []u8) !usize {
    var tries: u32 = 0;
    while (tries < 50) : (tries += 1) {
        const n = posix.read(fd, buf) catch |err| switch (err) {
            error.WouldBlock => {
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };
        return n;
    }
    return error.Timeout;
}

test "integration: status command round-trips from client wire bytes to daemon JSON" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var trackers = tracker_map.TrackerMap.init(a);
    defer trackers.deinit();
    const sshd_tracker = try trackers.addTracker("sshd", .{});

    const ip = try shared.IpAddress.parse("198.51.100.17");
    const jail = try shared.JailId.fromSlice("sshd");
    _ = try sshd_tracker.recordAttempt(ip, jail, 1);
    if (sshd_tracker.map.getPtr(ip)) |s| s.ban_state = .banned;

    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true },
    };
    var cfg = config_mod.Config{
        .global = .{},
        .defaults = .{},
        .jails = &jails,
        .diag = .{},
    };

    var be: firewall.Backend = .{ .nftables = nftables.NftablesBackend{} };
    defer be.deinit();

    var cmd_ctx = commands.Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .start_time = std.time.timestamp() - 17,
        .version = "integration-test",
    };

    var loop = try event_loop.EventLoop.init(a);
    defer loop.deinit();

    var fds: [2]i32 = undefined;
    try socketpairNonblock(&fds);
    defer posix.close(fds[1]);

    var server: ipc.IpcServer = .{
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

    server.setCommandHandler(cmd_ctx.asHandler());
    try server.admitTestPeer(fds[0]);

    var wire: [64]u8 = undefined;
    var ws = std.io.fixedBufferStream(&wire);
    try protocol.serializeCommand(.{ .status = {} }, ws.writer());
    const framed = ws.getWritten();
    var written: usize = 0;
    while (written < framed.len) {
        written += try posix.write(fds[1], framed[written..]);
    }

    try runLoopBriefly(&loop, 300);

    var rbuf: [4096]u8 = undefined;
    const n = try readResponse(fds[1], &rbuf);
    try testing.expect(n >= 5);

    var rs = std.io.fixedBufferStream(rbuf[0..n]);
    const resp = try protocol.deserializeResponse(rs.reader(), a);
    defer resp.deinit(a);

    try testing.expect(resp == .ok);
    const payload = resp.ok.payload;
    try testing.expect(std.mem.indexOf(u8, payload, "\"uptime_seconds\":") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "\"version\":\"integration-test\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "\"active_bans\":1") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "\"backend\":\"nftables\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "\"jail_count\":1") != null);
}

test "integration: version command round-trips and echoes supplied version" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var trackers = tracker_map.TrackerMap.init(a);
    defer trackers.deinit();
    var cfg = config_mod.Config{
        .global = .{},
        .defaults = .{},
        .jails = &.{},
        .diag = .{},
    };
    var be: firewall.Backend = .{ .nftables = nftables.NftablesBackend{} };
    defer be.deinit();

    var cmd_ctx = commands.Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .version = "ipc-roundtrip-version",
    };

    var loop = try event_loop.EventLoop.init(a);
    defer loop.deinit();

    var fds: [2]i32 = undefined;
    try socketpairNonblock(&fds);
    defer posix.close(fds[1]);

    var server: ipc.IpcServer = .{
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

    server.setCommandHandler(cmd_ctx.asHandler());
    try server.admitTestPeer(fds[0]);

    var wire: [32]u8 = undefined;
    var ws = std.io.fixedBufferStream(&wire);
    try protocol.serializeCommand(.{ .version = {} }, ws.writer());
    const framed = ws.getWritten();
    var written: usize = 0;
    while (written < framed.len) {
        written += try posix.write(fds[1], framed[written..]);
    }

    try runLoopBriefly(&loop, 300);

    var rbuf: [1024]u8 = undefined;
    const n = try readResponse(fds[1], &rbuf);
    var rs = std.io.fixedBufferStream(rbuf[0..n]);
    const resp = try protocol.deserializeResponse(rs.reader(), a);
    defer resp.deinit(a);

    try testing.expect(resp == .ok);
    try testing.expect(
        std.mem.indexOf(u8, resp.ok.payload, "\"daemon_version\":\"ipc-roundtrip-version\"") != null,
    );
}
