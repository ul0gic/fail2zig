// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const db = @import("fail2ban_db.zig");

pub const Error = db.Error || error{
    NotRegularFile,
    SourceTooLarge,
    ConcurrentWriter,
    PageBudgetExceeded,
    RowLimitExceeded,
    StagingUnavailable,
    StagingUnsafe,
    InjectedFailure,
    PathTooLong,
};

pub const Limits = struct {
    pub const max_source_bytes: u64 = 1024 * 1024 * 1024;
    pub const max_pages_per_step: u32 = 4096;
    pub const max_total_pages: u64 = 1024 * 1024;
    pub const max_restarts: u32 = 64;
    pub const max_ban_rows: u64 = 200_000;
    pub const max_log_rows: u64 = 4096;
    pub const busy_timeout_ms: c_int = 1000;
    pub const max_busy_retries: u32 = 200;
};

pub const RowCounts = db.RowCounts;

pub const Snapshot = struct {
    source_path: []u8,
    source_dev: u64,
    source_ino: u64,
    source_size: u64,
    source_mtime_us: i64,
    journal_mode_observed: []u8,
    version: i64,
    row_counts: RowCounts,
    destination_path: []u8,
    destination_sha256: [32]u8,
    captured_us: i64,
    backup_steps: u32,
    pages_copied: u64,
    restarts: u32,

    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.source_path);
        allocator.free(self.journal_mode_observed);
        allocator.free(self.destination_path);
        self.* = undefined;
    }
};

pub const IdentityHookStage = enum { before_open, after_open };

pub const Options = struct {
    pages_per_step: u32 = Limits.max_pages_per_step,
    fail_after_steps: ?u32 = null,
    between_steps: ?struct {
        context: *anyopaque,
        func: *const fn (*anyopaque, u32) void,
    } = null,
    identity_hook: ?struct {
        context: *anyopaque,
        func: *const fn (*anyopaque, IdentityHookStage) void,
    } = null,
};

const SourceIdentity = struct { dev: u64, ino: u64, size: u64, mtime_us: i64 };

pub const StagingDirError = error{ NotFound, AccessDenied, SymlinkRefused, NotDirectory, ForeignOwner, PermissiveMode, StorageIo };

pub fn verifyStagingDir(path: []const u8) StagingDirError!void {
    const stat = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch |err| return switch (err) {
        error.FileNotFound => error.NotFound,
        error.AccessDenied => error.AccessDenied,
        else => error.StorageIo,
    };
    if (std.posix.S.ISLNK(stat.mode)) return error.SymlinkRefused;
    if (!std.posix.S.ISDIR(stat.mode)) return error.NotDirectory;
    if (stat.uid != std.os.linux.geteuid()) return error.ForeignOwner;
    if (stat.mode & 0o077 != 0) return error.PermissiveMode;
}

pub fn capture(allocator: std.mem.Allocator, source_path: []const u8, staging_dir: []const u8, options: Options) Error!Snapshot {
    const pages_per_step: c_int = @intCast(@min(@max(options.pages_per_step, 1), Limits.max_pages_per_step));

    verifyStagingDir(staging_dir) catch |err| return switch (err) {
        error.NotFound => error.StagingUnavailable,
        error.AccessDenied => error.AccessDenied,
        error.StorageIo => error.StorageIo,
        else => error.StagingUnsafe,
    };
    const identity = try statSource(source_path);
    if (identity.size > Limits.max_source_bytes) return error.SourceTooLarge;
    std.posix.access(source_path, std.posix.R_OK) catch |err| return switch (err) {
        error.PermissionDenied => error.AccessDenied,
        error.FileNotFound => error.OpenFailed,
        else => error.StorageIo,
    };

    const absolute = absolutePath(allocator, source_path) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.OpenFailed,
    };
    errdefer allocator.free(absolute);

    const uri = try buildUri(allocator, absolute);
    defer allocator.free(uri);

    if (options.identity_hook) |hook| hook.func(hook.context, .before_open);
    var source = try db.Connection.open(uri, db.open_flags.readonly | db.open_flags.uri);
    defer source.close();
    if (options.identity_hook) |hook| hook.func(hook.context, .after_open);
    try source.busyTimeoutMs(Limits.busy_timeout_ms);
    const reopened = try statSource(source_path);
    if (reopened.dev != identity.dev or reopened.ino != identity.ino) return error.NotRegularFile;
    if (try sourceHasMoved(source)) return error.NotRegularFile;

    var mode_buffer: [32]u8 = undefined;
    const journal_mode = try source.journalMode(&mode_buffer);
    const journal_mode_owned = allocator.dupe(u8, journal_mode) catch return error.OutOfMemory;
    errdefer allocator.free(journal_mode_owned);

    try source.integrityCheck();
    try db.validateSchema(source);
    _ = try db.readVersion(source);

    const captured_us = std.time.microTimestamp();
    var staging = std.fs.cwd().openDir(staging_dir, .{}) catch return error.StagingUnavailable;
    defer staging.close();
    const destination_path = try createDestination(allocator, staging, staging_dir, captured_us);
    errdefer allocator.free(destination_path);
    var keep_destination = false;
    defer if (!keep_destination) std.fs.cwd().deleteFile(destination_path) catch {};

    const destination_z = allocator.dupeZ(u8, destination_path) catch return error.OutOfMemory;
    defer allocator.free(destination_z);

    var progress = try runBackup(source, destination_z, pages_per_step, options);
    progress.captured_us = captured_us;

    const row_counts = try finalizeDestination(destination_z);

    if (row_counts.bans + row_counts.bips > Limits.max_ban_rows) return error.RowLimitExceeded;
    if (row_counts.logs > Limits.max_log_rows) return error.RowLimitExceeded;

    const digest = try sha256File(destination_path);
    const final_identity = try statSource(source_path);
    if (final_identity.dev != identity.dev or final_identity.ino != identity.ino) return error.NotRegularFile;
    if (try sourceHasMoved(source)) return error.NotRegularFile;

    keep_destination = true;
    return .{
        .source_path = absolute,
        .source_dev = identity.dev,
        .source_ino = identity.ino,
        .source_size = identity.size,
        .source_mtime_us = identity.mtime_us,
        .journal_mode_observed = journal_mode_owned,
        .version = db.expected_version,
        .row_counts = row_counts,
        .destination_path = destination_path,
        .destination_sha256 = digest,
        .captured_us = captured_us,
        .backup_steps = progress.steps,
        .pages_copied = progress.pages,
        .restarts = progress.restarts,
    };
}

fn sourceHasMoved(source: db.Connection) Error!bool {
    const file_control = @extern(*const fn (*db.Db, ?[*:0]const u8, c_int, ?*anyopaque) callconv(.c) c_int, .{ .name = "sqlite3_file_control" });
    var moved: c_int = 1;
    const code = file_control(source.db, "main", 20, &moved);
    if (code != db.rc.ok) return db.sqliteError(code);
    return moved != 0;
}

pub fn sha256File(path: []const u8) Error![32]u8 {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| return switch (err) {
        error.AccessDenied => error.AccessDenied,
        else => error.StorageIo,
    };
    defer file.close();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const n = file.read(&buffer) catch return error.StorageIo;
        if (n == 0) break;
        hasher.update(buffer[0..n]);
    }
    return hasher.finalResult();
}

fn statSource(path: []const u8) Error!SourceIdentity {
    const stat = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch |err| return switch (err) {
        error.AccessDenied => error.AccessDenied,
        error.FileNotFound => error.OpenFailed,
        error.NameTooLong => error.PathTooLong,
        else => error.StorageIo,
    };
    if (!std.posix.S.ISREG(stat.mode)) return error.NotRegularFile;
    const size = std.math.cast(u64, stat.size) orelse return error.StorageIo;
    const mtime_us = std.math.mul(i64, @as(i64, @intCast(stat.mtim.sec)), std.time.us_per_s) catch return error.StorageIo;
    const mtime_frac = @divTrunc(@as(i64, @intCast(stat.mtim.nsec)), std.time.ns_per_us);
    return .{
        .dev = @intCast(stat.dev),
        .ino = @intCast(stat.ino),
        .size = size,
        .mtime_us = std.math.add(i64, mtime_us, mtime_frac) catch return error.StorageIo,
    };
}

fn absolutePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(path)) return allocator.dupe(u8, path);
    const cwd = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd);
    return std.fs.path.resolve(allocator, &.{ cwd, path });
}

fn buildUri(allocator: std.mem.Allocator, absolute: []const u8) Error![:0]u8 {
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("file:") catch return error.OutOfMemory;
    for (absolute) |byte| {
        switch (byte) {
            '%', '?', '#' => {
                const hex = "0123456789ABCDEF";
                out.appendSlice(&.{ '%', hex[byte >> 4], hex[byte & 0xf] }) catch return error.OutOfMemory;
            },
            else => out.append(byte) catch return error.OutOfMemory,
        }
    }
    out.appendSlice("?mode=ro") catch return error.OutOfMemory;
    return out.toOwnedSliceSentinel(0) catch return error.OutOfMemory;
}

fn createDestination(allocator: std.mem.Allocator, staging: std.fs.Dir, staging_dir: []const u8, captured_us: i64) Error![]u8 {
    var name_buffer: [96]u8 = undefined;
    const name = std.fmt.bufPrint(&name_buffer, "fail2ban-snapshot-{d}-{d}.sqlite3", .{ captured_us, std.os.linux.getpid() }) catch return error.StagingUnavailable;
    const file = staging.createFile(name, .{ .exclusive = true, .mode = 0o600 }) catch return error.StagingUnavailable;
    file.close();
    errdefer staging.deleteFile(name) catch {};
    const staging_abs = absolutePath(allocator, staging_dir) catch return error.StagingUnavailable;
    defer allocator.free(staging_abs);
    return std.fs.path.join(allocator, &.{ staging_abs, name }) catch return error.OutOfMemory;
}

const Progress = struct { steps: u32 = 0, pages: u64 = 0, restarts: u32 = 0, captured_us: i64 = 0 };

fn runBackup(source: db.Connection, destination_z: [*:0]const u8, pages_per_step: c_int, options: Options) Error!Progress {
    var destination = try db.Connection.open(destination_z, db.open_flags.readwrite);
    defer destination.close();

    const backup = db.api.backup_init(destination.db, "main", source.db, "main") orelse
        return db.sqliteError(db.api.extended_errcode(destination.db));
    var finished = false;
    defer if (!finished) {
        _ = db.api.backup_finish(backup);
    };

    var progress = Progress{};
    var last_remaining: ?u64 = null;
    var busy_retries: u32 = 0;
    while (true) {
        const code = db.api.backup_step(backup, pages_per_step);
        switch (code & 0xff) {
            db.rc.ok, db.rc.done => {},
            db.rc.busy, db.rc.locked => {
                busy_retries += 1;
                if (busy_retries > Limits.max_busy_retries) return error.Busy;
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            },
            else => return db.sqliteError(code),
        }
        progress.steps += 1;
        const remaining: u64 = @intCast(@max(db.api.backup_remaining(backup), 0));
        const pagecount: u64 = @intCast(@max(db.api.backup_pagecount(backup), 0));
        const before = last_remaining orelse pagecount;
        const expected = before -| @as(u64, @intCast(pages_per_step));
        if (remaining > expected) {
            progress.restarts += 1;
            if (progress.restarts > Limits.max_restarts) return error.ConcurrentWriter;
            progress.pages += pagecount -| remaining;
        } else {
            progress.pages += before -| remaining;
        }
        if (progress.pages > Limits.max_total_pages) return error.PageBudgetExceeded;
        last_remaining = remaining;

        if (options.fail_after_steps) |limit| {
            if (progress.steps >= limit) return error.InjectedFailure;
        }
        if (options.between_steps) |hook| hook.func(hook.context, progress.steps);
        if ((code & 0xff) == db.rc.done) break;
    }
    finished = true;
    const finish = db.api.backup_finish(backup);
    if (finish != db.rc.ok) return db.sqliteError(finish);
    return progress;
}

fn finalizeDestination(destination_z: [*:0]const u8) Error!RowCounts {
    var destination = try db.Connection.open(destination_z, db.open_flags.readwrite);
    defer destination.close();
    try destination.exec("PRAGMA journal_mode=DELETE");
    try destination.integrityCheck();
    try db.validateSchema(destination);
    _ = try db.readVersion(destination);
    return db.countRows(destination);
}
