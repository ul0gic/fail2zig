// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Read-only activation checks precede SQLite creation and IPC unlink. The
//! protected parent and held inode lock remain required throughout operation.
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
    // A stale socket may be removed; no regular file or symlink is disposable.
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
        // Missing nested source directories are repaired by ingestion. Existing
        // or directly creatable paths still receive complete alias checks.
        for ([_][]const u8{ socket, cfg.global.state_file }) |target| {
            const aliases = same(a, path, target) catch |err| switch (err) {
                error.FileNotFound => false,
                else => return err,
            };
            if (aliases) return error.NativePathAlias;
        }
    };
}
fn openState(path: []const u8) !std.posix.fd_t {
    const terminated = try std.posix.toPosixPath(path);
    // Zig 0.14.1 posix.open maps EROFS to Unexpected. Preserve the actual
    // storage cause while using the same libc/large-file ABI and one open FD.
    const open = if (builtin.link_libc and (builtin.abi.isGnu() or builtin.abi.isAndroid())) std.posix.system.open64 else std.posix.system.open;
    while (true) {
        const result = open(&terminated, .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true, .NOFOLLOW = true }, @as(std.posix.mode_t, 0o600));
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

pub fn lockState(path: []const u8) !std.fs.File {
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidNativePath;
    var parent = try std.fs.cwd().openDir(std.fs.path.dirname(path) orelse ".", .{ .no_follow = true });
    defer parent.close();
    const p = try std.posix.fstat(parent.fd);
    if (p.uid != std.os.linux.geteuid() or p.mode & 0o022 != 0) return error.UnsafePermissions;
    const file = std.fs.File{ .handle = try openState(path) };
    errdefer file.close();
    const stat = try std.posix.fstat(file.handle);
    if (!std.posix.S.ISREG(stat.mode) or stat.uid != std.os.linux.geteuid() or stat.mode & 0o077 != 0) return error.UnsafePermissions;
    if (!try file.tryLock(.exclusive)) return error.NativeAuthorityAlreadyRunning;
    // SQLite can recover/delete a journal or initialize shared memory even
    // before reporting NOTADB. Reject foreign formats through the held lock FD
    // first; opening/closing another FD later would release SQLite POSIX locks.
    var header: [16]u8 = undefined;
    const length = try file.preadAll(&header, 0);
    if (std.mem.startsWith(u8, header[0..length], "F2ZS")) return error.NativeStateMigrationRequired;
    if (length != 0 and !std.mem.eql(u8, header[0..length], "SQLite format 3\x00")) return error.CorruptDatabase;
    return file;
}

test "native: state format admission precedes SQLite sidecar recovery" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state" });
    defer a.free(path);
    const fixtures = .{
        .{ "F2ZS\x04\x00\x00\x00legacy", error.NativeStateMigrationRequired },
        .{ "unrecognized-state", error.CorruptDatabase },
        .{ "SQLite format", error.CorruptDatabase },
    };
    inline for (fixtures) |fixture| {
        const file = try tmp.dir.createFile("state", .{ .mode = 0o600 });
        try file.writeAll(fixture[0]);
        file.close();
        try std.testing.expectError(fixture[1], lockState(path));
        const retained = try tmp.dir.readFileAlloc(a, "state", 128);
        defer a.free(retained);
        try std.testing.expectEqualStrings(fixture[0], retained);
    }
    // The format check is only admission; SQLite still validates application,
    // schema and content after this exact signature.
    const file = try tmp.dir.createFile("state", .{ .mode = 0o600 });
    try file.writeAll("SQLite format 3\x00");
    file.close();
    const admitted = try lockState(path);
    admitted.close();
}

test "native: path checks refuse aliases and preserve existing files before mutation" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const state = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(state);
    const socket = try std.fs.path.join(a, &.{ root, "ipc" });
    defer a.free(socket);
    var cfg = config.Config{ .global = .{ .native_ingestion = true, .state_file = state, .socket_path = socket }, .defaults = .{}, .jails = &.{} };
    try validate(a, &cfg);
    cfg.global.socket_path = state;
    try std.testing.expectError(error.NativePathAlias, validate(a, &cfg));
    cfg.global.socket_path = socket;
    try tmp.dir.writeFile(.{ .sub_path = "ipc", .data = "retained" });
    try std.testing.expectError(error.UnsafeNativeSocket, validate(a, &cfg));
    const bytes = try tmp.dir.readFileAlloc(a, "ipc", 100);
    defer a.free(bytes);
    try std.testing.expectEqualStrings("retained", bytes);
    cfg.global.socket_path = "bad\x00path";
    try std.testing.expectError(error.InvalidNativePath, validate(a, &cfg));
}

test "native: state authority is exclusive and does not truncate existing data" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const state = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(state);
    const held = try lockState(state);
    defer held.close();
    try held.writeAll("retained");
    try std.testing.expectError(error.NativeAuthorityAlreadyRunning, lockState(state));
    const bytes = try tmp.dir.readFileAlloc(a, "state.sqlite", 100);
    defer a.free(bytes);
    try std.testing.expectEqualStrings("retained", bytes);
}
