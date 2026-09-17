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

// No retained descriptors. At most four descriptors and four max_path_bytes
// stack buffers are live while walking; heap is at most eight path copies.
pub fn discover(allocator: std.mem.Allocator) !Resolved {
    const root = try posix.open("/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0);
    defer posix.close(root);
    return discoverAt(allocator, root, 0, &catalog);
}

// Private seam: production provides only the fixed catalog and the real root.
fn discoverAt(allocator: std.mem.Allocator, root: posix.fd_t, uid: posix.uid_t, entries: []const []const u8) !Resolved {
    if (entries.len > catalog.len) return error.InvalidJournalExecutables;
    var result = Resolved{ .allocator = allocator };
    errdefer result.deinit();
    var output: [std.fs.max_path_bytes]u8 = undefined;
    for (entries) |path| {
        const canonical = walk(root, path, &output, uid) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => {
                if (!@import("builtin").is_test) std.log.err("cannot qualify default SSH journal executable {s}: {s}", .{ path, @errorName(err) });
                return err;
            },
        };
        try result.append(canonical);
        if (std.mem.endsWith(u8, path, "/sshd-auth")) result.has_auth_helper = true;
    }
    if (result.len == 0) return error.InvalidJournalExecutables;
    return result;
}

// Explicit profiles retain their historical leaf-only qualification and exact
// configured spelling. O_PATH inspects special files without opening a device
// or waiting for a FIFO writer; it does not read or execute the file.
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

// The supplied root/uid are a private filesystem-test seam. Production always
// starts at / and requires UID 0. Each component is opened relative to a verified
// directory with NOFOLLOW; symlink contents are read from that exact O_PATH fd.
// Thus neither lookup nor readlink can redirect through an unverified directory.
fn walk(root: posix.fd_t, path: []const u8, output: []u8, uid: posix.uid_t) ![]const u8 {
    try validatePath(path);
    try qualifyDirectory(try posix.fstat(root), uid);
    var pending: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(pending[0..path.len], path);
    var pending_len = path.len;
    var links: usize = 0;
    var steps: usize = 0;
    // Bytes introduced as symlink targets must exist; an optional suffix
    // beyond that boundary may be absent under a valid directory alias.
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

fn allocationCase(allocator: std.mem.Allocator) !void {
    var result = Resolved{ .allocator = allocator };
    defer result.deinit();
    try result.append("/usr/sbin/sshd");
    try result.append("/usr/sbin/sshd");
    try result.append("/usr/lib/openssh/sshd-session");
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("/usr/sbin/sshd", result.executables()[0]);
}

test "native: journal profile allocation failure cleanup and deterministic deduplication" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

test "native: journal profile trusted filesystem walk and unsafe components" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writable_root = try tmp.dir.openDir(".", .{ .iterate = true });
    defer writable_root.close();
    try writable_root.chmod(0o700);
    try tmp.dir.makeDir("bin");
    var file = try tmp.dir.createFile("bin/sshd", .{ .mode = 0o755 });
    file.close();
    try tmp.dir.symLink("bin", "alias", .{});
    try tmp.dir.symLink("alias", "nested-alias", .{});
    try tmp.dir.symLink("../bin/sshd", "bin/relative", .{});
    try tmp.dir.symLink("../../bin/sshd", "bin/clamped", .{});
    try tmp.dir.symLink("../bin/missing", "bin/dangling-parent", .{});
    try tmp.dir.symLink("../../bin/missing", "bin/dangling-clamped", .{});
    try tmp.dir.symLink("../alias/missing", "bin/dangling-nested-parent", .{});
    try tmp.dir.symLink("../bin", "bin/parent-alias", .{});
    try tmp.dir.symLink("/bin/sshd", "absolute", .{});
    try tmp.dir.symLink("absent", "dangling", .{});
    try tmp.dir.symLink("loop", "loop", .{});
    try tmp.dir.symLink("alias/missing", "nested-dangling", .{});
    try tmp.dir.symLink("missing-dir", "dangling-dir", .{});
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.mknodat(tmp.dir.fd, "fifo", posix.S.IFIFO | 0o600, 0));
    var output: [std.fs.max_path_bytes]u8 = undefined;
    const uid = (try posix.fstat(tmp.dir.fd)).uid;
    try std.testing.expectEqualStrings("/bin/sshd", try walk(tmp.dir.fd, "/alias/sshd", &output, uid));
    try std.testing.expectEqualStrings("/bin/sshd", try walk(tmp.dir.fd, "/absolute", &output, uid));
    for ([_][]const u8{ "/nested-alias/sshd", "/bin/relative", "/bin/clamped" }) |path|
        try std.testing.expectEqualStrings("/bin/sshd", try walk(tmp.dir.fd, path, &output, uid));
    for ([_][]const u8{ "/bin/dangling-parent", "/bin/dangling-clamped", "/bin/dangling-nested-parent" }) |path|
        try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, path, &output, uid));
    try std.testing.expectError(error.FileNotFound, walk(tmp.dir.fd, "/bin/parent-alias/missing", &output, uid));
    try std.testing.expectError(error.FileNotFound, walk(tmp.dir.fd, "/absent", &output, uid));
    try std.testing.expectError(error.FileNotFound, walk(tmp.dir.fd, "/alias/absent", &output, uid));
    try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, "/nested-dangling", &output, uid));
    try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, "/dangling-dir/absent", &output, uid));
    try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, "/fifo", &output, uid));
    try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, "/bin/sshd", &output, if (uid == 0) 1 else 0));
    try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, "/dangling", &output, uid));
    try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, "/loop", &output, uid));
    try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, "/bin", &output, uid));
    const before = try descriptorCount();
    for (0..32) |_| {
        _ = try walk(tmp.dir.fd, "/alias/sshd", &output, uid);
        try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, "/loop", &output, uid));
        try std.testing.expectError(error.FileNotFound, walk(tmp.dir.fd, "/alias/absent", &output, uid));
    }
    try std.testing.expectEqual(before, try descriptorCount());
    var bin = try tmp.dir.openDir("bin", .{ .iterate = true });
    defer bin.close();
    try bin.chmod(0o777);
    try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, "/bin/sshd", &output, uid));
    try bin.chmod(0o755);
    file = try tmp.dir.openFile("bin/sshd", .{});
    defer file.close();
    try file.chmod(0o666);
    try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, "/bin/sshd", &output, uid));
    try file.chmod(0o644);
    try std.testing.expectError(error.UnqualifiedJournalExecutable, walk(tmp.dir.fd, "/bin/sshd", &output, uid));
}

test "native: journal profile explicit nonregular and invalid paths" {
    try std.testing.expectError(error.UnqualifiedJournalExecutable, qualifyExplicit("/dev/null"));
    try std.testing.expectError(error.UnqualifiedJournalExecutable, qualifyExplicit("/"));
    try std.testing.expectError(error.InvalidJournalExecutables, qualifyExplicit("relative"));
    try std.testing.expectError(error.InvalidJournalExecutables, qualifyExplicit("/bad\x00path"));
}

test "native: journal profile owns copies and bounds retained paths" {
    var result = Resolved{ .allocator = std.testing.allocator };
    defer result.deinit();
    var path = [_]u8{ '/', 'a' };
    for (0..max_executables) |index| {
        path[1] = @as(u8, @intCast(index)) + 'a';
        try result.append(&path);
    }
    path[1] = 'z';
    try std.testing.expectEqualStrings("/a", result.executables()[0]);
    try std.testing.expectError(error.InvalidJournalExecutables, result.append(&path));
    try result.append("/a");
    try std.testing.expectEqual(@as(usize, max_executables), result.len);
}

fn descriptorCount() !usize {
    var directory = try std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true });
    defer directory.close();
    var iterator = directory.iterate();
    var count: usize = 0;
    while (try iterator.next()) |_| count += 1;
    return count;
}

fn discoveryAllocationCase(allocator: std.mem.Allocator, root: posix.fd_t, uid: posix.uid_t) !void {
    var result = try discoverAt(allocator, root, uid, &.{ "/missing", "/alias/sshd", "/bin/sshd", "/bin/sshd-session", "/alias/sshd-auth" });
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("/bin/sshd", result.executables()[0]);
    try std.testing.expectEqualStrings("/bin/sshd-session", result.executables()[1]);
    try std.testing.expect(result.has_auth_helper);
}

test "native: journal profile discovery optional paths roles ordering and allocation cleanup" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var directory = try tmp.dir.openDir(".", .{ .iterate = true });
    defer directory.close();
    try directory.chmod(0o700);
    try tmp.dir.makeDir("bin");
    for ([_][]const u8{ "bin/sshd", "bin/sshd-session" }) |path| {
        const file = try tmp.dir.createFile(path, .{ .mode = 0o755 });
        file.close();
    }
    try tmp.dir.symLink("bin", "alias", .{});
    try tmp.dir.symLink("sshd", "bin/sshd-auth", .{});
    const uid = (try posix.fstat(tmp.dir.fd)).uid;
    try std.testing.expectError(error.InvalidJournalExecutables, discoverAt(std.testing.allocator, tmp.dir.fd, uid, &.{}));
    try std.testing.expectError(error.InvalidJournalExecutables, discoverAt(std.testing.allocator, tmp.dir.fd, uid, &.{ "/missing", "/alias/missing" }));
    const oversized = [_][]const u8{"/missing"} ** (catalog.len + 1);
    try std.testing.expectError(error.InvalidJournalExecutables, discoverAt(std.testing.allocator, tmp.dir.fd, uid, &oversized));
    const before = try descriptorCount();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, discoveryAllocationCase, .{ tmp.dir.fd, uid });
    try std.testing.expectEqual(before, try descriptorCount());
    var without_auth = try discoverAt(std.testing.allocator, tmp.dir.fd, uid, &.{ "/bin/sshd-session", "/bin/sshd", "/alias/missing" });
    defer without_auth.deinit();
    try std.testing.expectEqualStrings("/bin/sshd-session", without_auth.executables()[0]);
    try std.testing.expect(!without_auth.has_auth_helper);
    // An unsafe present candidate fails even after an earlier valid allocation;
    // allocator and descriptor checks cover that partially populated cleanup.
    const unsafe = try tmp.dir.createFile("unsafe", .{ .mode = 0o644 });
    unsafe.close();
    try std.testing.expectError(error.UnqualifiedJournalExecutable, discoverAt(std.testing.allocator, tmp.dir.fd, uid, &.{ "/bin/sshd", "/unsafe", "/bin/sshd-session" }));
    try std.testing.expectEqual(before, try descriptorCount());
}
