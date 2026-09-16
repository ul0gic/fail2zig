// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const PeerCred = extern struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

pub const PeerClass = enum { admin, monitor };

pub fn classifyPeer(cred: PeerCred, daemon_uid: u32) PeerClass {
    if (cred.uid == 0 or cred.uid == daemon_uid) return .admin;
    return .monitor;
}

pub const CommandClass = enum { read_only, mutation, unknown };

pub const request_id_len: usize = 32;

pub fn classifyTag(tag: u8) CommandClass {
    return switch (tag) {
        0, 3, 4, 6, 7 => .read_only,
        1, 2, 5, 8, 9 => .mutation,
        else => .unknown,
    };
}

pub fn extractRequestId(body: []const u8) error{FrameTooShort}!?[request_id_len]u8 {
    if (body.len == 0) return error.FrameTooShort;
    switch (body[0]) {
        8, 9 => {
            if (body.len < 1 + request_id_len) return error.FrameTooShort;
            var id: [request_id_len]u8 = undefined;
            @memcpy(&id, body[1 .. 1 + request_id_len]);
            return id;
        },
        else => return null,
    }
}

pub const PeerPolicyInput = struct {
    class: PeerClass,
    command: CommandClass,
};

pub const PolicyDecision = enum { allow, forbid_mutation, bad_command };

pub fn decide(input: PeerPolicyInput) PolicyDecision {
    return switch (input.command) {
        .unknown => .bad_command,
        .read_only => .allow,
        .mutation => if (input.class == .admin) .allow else .forbid_mutation,
    };
}

pub const SocketPathError = error{
    PathTooLong,
    ParentStatFailed,
    ParentNotDirectory,
    ParentWrongOwner,
    ParentTooPermissive,
    SocketStatFailed,
    SocketIsSymlink,
    SocketNotSocket,
    SocketWrongOwner,
    SocketWrongMode,
};

pub const forbidden_parent_bits: u32 = 0o027;
pub const required_socket_mode: u32 = 0o660;

const max_path: usize = 108;

fn lstatPath(path: []const u8) error{ PathTooLong, StatFailed }!linux.Stat {
    if (path.len >= max_path) return error.PathTooLong;
    var z: [max_path]u8 = undefined;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    var st: linux.Stat = undefined;
    const rc = linux.fstatat(linux.AT.FDCWD, @ptrCast(&z[0]), &st, linux.AT.SYMLINK_NOFOLLOW);
    switch (linux.E.init(rc)) {
        .SUCCESS => return st,
        else => return error.StatFailed,
    }
}

pub fn verifyParentDir(path: []const u8, daemon_uid: u32) SocketPathError!void {
    const parent = std.fs.path.dirname(path) orelse ".";
    const st = lstatPath(parent) catch |err| switch (err) {
        error.PathTooLong => return error.PathTooLong,
        error.StatFailed => return error.ParentStatFailed,
    };
    if (!posix.S.ISDIR(st.mode)) return error.ParentNotDirectory;
    if (st.uid != 0 and st.uid != daemon_uid) return error.ParentWrongOwner;
    if ((st.mode & forbidden_parent_bits) != 0) return error.ParentTooPermissive;
}

pub fn verifySocketFile(path: []const u8, daemon_uid: u32) SocketPathError!void {
    const st = lstatPath(path) catch |err| switch (err) {
        error.PathTooLong => return error.PathTooLong,
        error.StatFailed => return error.SocketStatFailed,
    };
    if (posix.S.ISLNK(st.mode)) return error.SocketIsSymlink;
    if (!posix.S.ISSOCK(st.mode)) return error.SocketNotSocket;
    if (st.uid != daemon_uid) return error.SocketWrongOwner;
    if ((st.mode & 0o777) != required_socket_mode) return error.SocketWrongMode;
}

pub fn verifySocketPath(path: []const u8, daemon_uid: u32) SocketPathError!void {
    try verifyParentDir(path, daemon_uid);
    try verifySocketFile(path, daemon_uid);
}

pub const BindPathState = enum { absent, stale_socket, live_socket };

pub const BindPathError = error{
    PathTooLong,
    StatFailed,
    IsSymlink,
    NotSocket,
    ProbeFailed,
};

pub fn inspectBindPath(path: []const u8) BindPathError!BindPathState {
    if (path.len >= max_path) return error.PathTooLong;
    var z: [max_path]u8 = undefined;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    var st: linux.Stat = undefined;
    switch (linux.E.init(linux.fstatat(linux.AT.FDCWD, @ptrCast(&z[0]), &st, linux.AT.SYMLINK_NOFOLLOW))) {
        .SUCCESS => {},
        .NOENT => return .absent,
        else => return error.StatFailed,
    }
    if (posix.S.ISLNK(st.mode)) return error.IsSymlink;
    if (!posix.S.ISSOCK(st.mode)) return error.NotSocket;

    const stype: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const fd = posix.socket(posix.AF.UNIX, stype, 0) catch return error.ProbeFailed;
    defer posix.close(fd);
    var addr: linux.sockaddr.un = .{ .path = [_]u8{0} ** max_path };
    @memcpy(addr.path[0..path.len], path);
    const addr_len: posix.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + 1);
    const rc = linux.connect(fd, @ptrCast(&addr), addr_len);
    return switch (linux.E.init(rc)) {
        .SUCCESS, .AGAIN, .INPROGRESS => .live_socket,
        .CONNREFUSED => .stale_socket,
        .NOENT => .absent,
        else => error.ProbeFailed,
    };
}

const testing = std.testing;

test "ipc_auth: peer class from uid only" {
    try testing.expectEqual(PeerClass.admin, classifyPeer(.{ .pid = 1, .uid = 0, .gid = 9 }, 1000));
    try testing.expectEqual(PeerClass.admin, classifyPeer(.{ .pid = 1, .uid = 1000, .gid = 9 }, 1000));
    try testing.expectEqual(PeerClass.monitor, classifyPeer(.{ .pid = 1, .uid = 1001, .gid = 0 }, 1000));
    try testing.expectEqual(PeerClass.monitor, classifyPeer(.{ .pid = 1, .uid = 1001, .gid = 1000 }, 1000));
}

test "ipc_auth: tag classes cover 0-9 and reject the rest" {
    for ([_]u8{ 0, 3, 4, 6, 7 }) |t| try testing.expectEqual(CommandClass.read_only, classifyTag(t));
    for ([_]u8{ 1, 2, 5, 8, 9 }) |t| try testing.expectEqual(CommandClass.mutation, classifyTag(t));
    try testing.expectEqual(CommandClass.unknown, classifyTag(10));
    try testing.expectEqual(CommandClass.unknown, classifyTag(0xFF));
}

test "ipc_auth: request_id only for tags 8/9 and only with 33+ bytes" {
    var body: [33]u8 = undefined;
    body[0] = 8;
    for (body[1..], 0..) |*b, i| b.* = @intCast(i);
    const id = (try extractRequestId(&body)).?;
    try testing.expectEqual(@as(u8, 0), id[0]);
    try testing.expectEqual(@as(u8, 31), id[31]);
    body[0] = 9;
    try testing.expect((try extractRequestId(&body)) != null);
    try testing.expectError(error.FrameTooShort, extractRequestId(body[0..32]));
    try testing.expectError(error.FrameTooShort, extractRequestId(body[0..1]));
    try testing.expectError(error.FrameTooShort, extractRequestId(body[0..0]));
    body[0] = 1;
    try testing.expectEqual(@as(?[32]u8, null), try extractRequestId(body[0..1]));
    body[0] = 0;
    try testing.expectEqual(@as(?[32]u8, null), try extractRequestId(body[0..1]));
}

test "ipc_auth: policy decision" {
    try testing.expectEqual(PolicyDecision.allow, decide(.{ .class = .monitor, .command = .read_only }));
    try testing.expectEqual(PolicyDecision.forbid_mutation, decide(.{ .class = .monitor, .command = .mutation }));
    try testing.expectEqual(PolicyDecision.allow, decide(.{ .class = .admin, .command = .mutation }));
    try testing.expectEqual(PolicyDecision.bad_command, decide(.{ .class = .admin, .command = .unknown }));
}
