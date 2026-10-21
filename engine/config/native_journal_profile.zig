// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const posix = std.posix;

pub const max_executables = 8;
// Ordering preserves the existing Debian listener/session profile when both exist.
pub const catalog = [_][]const u8{
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/usr/lib/openssh/sshd-session",
    "/usr/lib/openssh/sshd-auth",
    "/usr/lib/ssh/sshd-session",
    "/usr/lib/ssh/sshd-auth",
    "/usr/libexec/openssh/sshd-session",
    "/usr/libexec/openssh/sshd-auth",
};

pub const Resolved = struct {
    allocator: std.mem.Allocator,
    paths: [max_executables][]const u8 = undefined,
    len: usize = 0,
    has_auth_helper: bool = false,

    pub fn executables(self: *const Resolved) []const []const u8 {
        return self.paths[0..self.len];
    }

    pub fn deinit(self: *Resolved) void {
        for (self.executables()) |path| self.allocator.free(path);
        self.len = 0;
    }

    fn append(self: *Resolved, path: []const u8) !void {
        for (self.executables()) |present| if (std.mem.eql(u8, present, path)) return;
        if (self.len == max_executables) return error.InvalidJournalExecutables;
        self.paths[self.len] = try self.allocator.dupe(u8, path);
        self.len += 1;
    }
};

pub fn discover(allocator: std.mem.Allocator) !Resolved {
    const root = try posix.open("/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0);
    defer posix.close(root);
    return discoverAt(allocator, root, 0, &catalog);
}

fn discoverAt(allocator: std.mem.Allocator, root: posix.fd_t, uid: posix.uid_t, entries: []const []const u8) !Resolved {
    if (entries.len > catalog.len) return error.InvalidJournalExecutables;
    var result = Resolved{ .allocator = allocator };
    errdefer result.deinit();
    var output: [std.fs.max_path_bytes]u8 = undefined;
    for (entries) |path| {
        const canonical = walk(root, path, &output, uid) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => {
                std.log.err("cannot qualify default SSH journal executable {s}: {s}", .{ path, @errorName(err) });
                return err;
            },
        };
        try result.append(canonical);
        if (std.mem.endsWith(u8, path, "/sshd-auth")) result.has_auth_helper = true;
    }
    if (result.len == 0) return error.InvalidJournalExecutables;
    return result;
}

// O_PATH inspects special files without opening a device or waiting for a FIFO writer.
pub fn qualifyExplicit(path: []const u8) !void {
    try validatePath(path);
    const fd = try posix.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
    defer posix.close(fd);
    try qualifyLeaf(try posix.fstat(fd), 0);
}

fn validatePath(path: []const u8) !void {
    if (path.len == 0 or path[0] != '/' or path.len >= std.fs.max_path_bytes or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidJournalExecutables;
}

fn qualifyDirectory(stat: posix.Stat, uid: posix.uid_t) !void {
    if (!posix.S.ISDIR(stat.mode) or stat.uid != uid or stat.mode & 0o022 != 0) return error.UnqualifiedJournalExecutable;
}

fn qualifyLeaf(stat: posix.Stat, uid: posix.uid_t) !void {
    if (!posix.S.ISREG(stat.mode) or stat.uid != uid or stat.mode & 0o022 != 0 or stat.mode & 0o111 == 0) return error.UnqualifiedJournalExecutable;
}

// Each component is opened relative to a verified directory with NOFOLLOW; symlink contents are
// read from that exact O_PATH fd, so neither lookup nor readlink can bypass a verified directory.
fn walk(root: posix.fd_t, path: []const u8, output: []u8, uid: posix.uid_t) ![]const u8 {
    try validatePath(path);
    try qualifyDirectory(try posix.fstat(root), uid);
    var pending: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(pending[0..path.len], path);
    var pending_len = path.len;
    var links: usize = 0;
    var steps: usize = 0;
    var required_end: usize = 0;
    restart: while (true) {
        var current = try posix.openat(root, ".", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0);
        defer posix.close(current);
        var canonical_len: usize = 0;
        var iterator = std.mem.tokenizeScalar(u8, pending[0..pending_len], '/');
        while (iterator.next()) |component| {
            const component_start = @intFromPtr(component.ptr) - @intFromPtr(&pending);
            const rest_start = @intFromPtr(iterator.rest().ptr) - @intFromPtr(&pending);
            steps += 1;
            if (steps > 1024) return error.UnqualifiedJournalExecutable;
            if (std.mem.eql(u8, component, ".")) continue;
            if (std.mem.eql(u8, component, "..")) {
                // Restart at the verified root using the canonical parent;
                // never let '..' escape a test root or bypass component checks.
                canonical_len = if (std.mem.lastIndexOfScalar(u8, output[0..canonical_len], '/')) |index| index else 0;
                var next: [std.fs.max_path_bytes]u8 = undefined;
                const expanded = try std.fmt.bufPrint(&next, "{s}/{s}", .{ output[0..canonical_len], iterator.rest() });
                required_end = if (required_end > rest_start) canonical_len + 1 + required_end - rest_start else 0;
                @memcpy(pending[0..expanded.len], expanded);
                pending_len = expanded.len;
                continue :restart;
            }
            const fd = posix.openat(current, component, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0) catch |err| {
                if (err == error.FileNotFound and component_start < required_end) return error.UnqualifiedJournalExecutable;
                return err;
            };
            defer posix.close(fd);
            const stat = try posix.fstat(fd);
            if (posix.S.ISLNK(stat.mode)) {
                if (stat.uid != uid or links == 40) return error.UnqualifiedJournalExecutable;
                // Symlink mode bits have no access-control meaning on Linux.
                // Ownership plus its verified, non-writable parent establish trust.
                links += 1;
                var target: [std.fs.max_path_bytes]u8 = undefined;
                const value = try posix.readlinkat(fd, "", &target);
                if (value.len == 0 or value.len == target.len) return error.UnqualifiedJournalExecutable;
                var next: [std.fs.max_path_bytes]u8 = undefined;
                const prefix = if (value[0] == '/') "" else output[0..canonical_len];
                const expanded = try std.fmt.bufPrint(&next, "{s}/{s}/{s}", .{ prefix, value, iterator.rest() });
                const target_end = prefix.len + 1 + value.len;
                required_end = if (required_end > rest_start) target_end + 1 + required_end - rest_start else target_end;
                @memcpy(pending[0..expanded.len], expanded);
                pending_len = expanded.len;
                continue :restart;
            }
            const is_last = iterator.peek() == null;
            if (is_last) {
                try qualifyLeaf(stat, uid);
            } else {
                try qualifyDirectory(stat, uid);
            }
            if (canonical_len + 1 + component.len >= output.len) return error.NameTooLong;
            output[canonical_len] = '/';
            canonical_len += 1;
            @memcpy(output[canonical_len..][0..component.len], component);
            canonical_len += component.len;
            if (is_last) return output[0..canonical_len];
            const next = try posix.openat(fd, ".", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0);
            posix.close(current);
            current = next;
        }
        return error.UnqualifiedJournalExecutable;
    }
}
