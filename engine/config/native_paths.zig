// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const builtin = @import("builtin");
const config = @import("native.zig");

fn canonical(a: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.realpathAlloc(a, path) catch |err| switch (err) {
        error.FileNotFound => blk: {
            const parent = try std.fs.realpathAlloc(a, std.fs.path.dirname(path) orelse ".");
            defer a.free(parent);
            break :blk try std.fs.path.join(a, &.{ parent, std.fs.path.basename(path) });
        },
        else => return err,
    };
}
fn same(a: std.mem.Allocator, left: []const u8, right: []const u8) !bool {
    const first = try canonical(a, left);
    defer a.free(first);
    const second = try canonical(a, right);
    defer a.free(second);
    if (std.mem.eql(u8, first, second)) return true;
    const one = std.posix.fstatat(std.posix.AT.FDCWD, first, 0) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    const two = std.posix.fstatat(std.posix.AT.FDCWD, second, 0) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return one.dev == two.dev and one.ino == two.ino;
}
pub fn validate(a: std.mem.Allocator, cfg: *const config.Config) !void {
    try config.validate(cfg);
    const socket = cfg.global.socket_path;
    const stat = std.posix.fstatat(std.posix.AT.FDCWD, socket, std.posix.AT.SYMLINK_NOFOLLOW) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (stat) |value| if (!std.posix.S.ISSOCK(value.mode) or value.uid != std.os.linux.geteuid()) return error.UnsafeNativeSocket;
    var parent = try std.fs.cwd().openDir(std.fs.path.dirname(socket) orelse ".", .{ .no_follow = true });
    defer parent.close();
    const parent_stat = try std.posix.fstat(parent.fd);
    if (parent_stat.uid != std.os.linux.geteuid() or parent_stat.mode & 0o022 != 0) return error.UnsafeNativeSocket;
    if (try same(a, socket, cfg.global.state_file)) return error.NativePathAlias;
    for ([_][]const u8{ "-wal", "-shm", "-journal" }) |suffix| {
        const sidecar = try std.fmt.allocPrint(a, "{s}{s}", .{ cfg.global.state_file, suffix });
        defer a.free(sidecar);
        if (try same(a, socket, sidecar)) return error.NativePathAlias;
    }
    for (cfg.jails) |jail| for (jail.logpath) |path| {
        for ([_][]const u8{ socket, cfg.global.state_file }) |target| {
            const aliases = same(a, path, target) catch |err| switch (err) {
                error.FileNotFound => false,
                else => return err,
            };
            if (aliases) return error.NativePathAlias;
        }
    };
}
const StateOpen = enum { existing, absent };

fn openState(path: []const u8, mode: StateOpen) !std.posix.fd_t {
    const terminated = try std.posix.toPosixPath(path);
    const open = if (builtin.link_libc and (builtin.abi.isGnu() or builtin.abi.isAndroid())) std.posix.system.open64 else std.posix.system.open;
    while (true) {
        const flags: std.posix.O = switch (mode) {
            .existing => .{ .ACCMODE = .RDWR, .CLOEXEC = true, .NOFOLLOW = true },
            .absent => .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true, .CLOEXEC = true, .NOFOLLOW = true },
        };
        const result = open(&terminated, flags, @as(std.posix.mode_t, 0o600));
        switch (std.posix.errno(result)) {
            .SUCCESS => return @intCast(result),
            .INTR => continue,
            .ROFS => return error.ReadOnlyFileSystem,
            .IO => return error.InputOutput,
            .DQUOT => return error.DiskQuota,
            .ACCES, .PERM => return error.AccessDenied,
            .INVAL => return error.BadPathName,
            .FBIG, .OVERFLOW => return error.FileTooBig,
            .ISDIR => return error.IsDir,
            .LOOP => return error.SymLinkLoop,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NAMETOOLONG => return error.NameTooLong,
            .NODEV, .NXIO => return error.NoDevice,
            .NOENT => return error.FileNotFound,
            .NOMEM => return error.SystemResources,
            .NOSPC => return error.NoSpaceLeft,
            .NOTDIR => return error.NotDir,
            .EXIST => return error.PathAlreadyExists,
            .BUSY => return error.DeviceBusy,
            .TXTBSY => return error.FileBusy,
            .AGAIN => return error.WouldBlock,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn validateStateParent(path: []const u8) !void {
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidNativePath;
    var parent = try std.fs.cwd().openDir(std.fs.path.dirname(path) orelse ".", .{ .no_follow = true });
    defer parent.close();
    const p = try std.posix.fstat(parent.fd);
    if (p.uid != std.os.linux.geteuid() or p.mode & 0o022 != 0) return error.UnsafePermissions;
}

fn validateAndLockState(file: std.fs.File) !std.fs.File {
    errdefer file.close();
    const stat = try std.posix.fstat(file.handle);
    if (!std.posix.S.ISREG(stat.mode) or stat.uid != std.os.linux.geteuid() or stat.mode & 0o077 != 0) return error.UnsafePermissions;
    if (!try file.tryLock(.exclusive)) return error.NativeAuthorityAlreadyRunning;
    var header: [16]u8 = undefined;
    const length = try file.preadAll(&header, 0);
    if (std.mem.startsWith(u8, header[0..length], "F2ZS")) return error.NativeStateMigrationRequired;
    if (length != 0 and !std.mem.eql(u8, header[0..length], "SQLite format 3\x00")) return error.CorruptDatabase;
    return file;
}

pub fn lockStateIfPresent(path: []const u8) !?std.fs.File {
    try validateStateParent(path);
    const fd = openState(path, .existing) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    return try validateAndLockState(.{ .handle = fd });
}

pub fn lockAbsentState(path: []const u8) !std.fs.File {
    try validateStateParent(path);
    return validateAndLockState(.{ .handle = openState(path, .absent) catch |err| switch (err) {
        error.PathAlreadyExists => return error.NativeStateChanged,
        else => return err,
    } });
}

pub fn lockState(path: []const u8) !std.fs.File {
    if (try lockStateIfPresent(path)) |file| return file;
    return lockAbsentState(path) catch |err| switch (err) {
        error.NativeStateChanged => (try lockStateIfPresent(path)) orelse return error.NativeStateChanged,
        else => return err,
    };
}
