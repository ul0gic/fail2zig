// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Opens the SQLite state file in plain, existing, runtime, read-only or preflight mode and reads a preflight installation snapshot.
// Holds: A refused open fills the OpenDiagnostic with its stage and error, and a successful open leaves the diagnostic cleared.

const std = @import("std");
const effects = @import("../effect/effect.zig");
const Error = @import("store.zig").Error;
const OpenStage = @import("store.zig").OpenStage;
const OpenPosixCause = @import("store.zig").OpenPosixCause;
const OpenDiagnostic = @import("store.zig").OpenDiagnostic;
const Limits = @import("store.zig").Limits;
const Db = @import("store.zig").Db;
const embedded_api = @import("store.zig").embedded_api;
const sqliteError = @import("store.zig").sqliteError;
const latest_schema = @import("store.zig").latest_schema;
const load_repair_schema = @import("store.zig").load_repair_schema;
const load_repair = @import("store.zig").load_repair;

fn openPosixCause(failure: anyerror) OpenPosixCause {
    if (failure == error.AccessDenied) return .access_denied;
    if (failure == error.FileNotFound) return .file_not_found;
    if (failure == error.NotDir) return .not_directory;
    if (failure == error.SymLinkLoop) return .symbolic_link_loop;
    if (failure == error.NameTooLong) return .name_too_long;
    if (failure == error.PathAlreadyExists) return .path_already_exists;
    if (failure == error.NoSpaceLeft) return .no_space_left;
    if (failure == error.ProcessFdQuotaExceeded) return .process_file_descriptor_limit;
    if (failure == error.SystemFdQuotaExceeded) return .system_file_descriptor_limit;
    if (failure == error.NoDevice) return .no_device;
    if (failure == error.SystemResources) return .system_resources;
    if (failure == error.FileTooBig) return .file_too_big;
    if (failure == error.IsDir) return .is_directory;
    if (failure == error.DeviceBusy or failure == error.FileBusy) return .device_busy;
    if (failure == error.BadPathName) return .invalid_path;
    return .unexpected;
}

fn openFailure(diagnostic: *OpenDiagnostic, stage: OpenStage, failure: Error, posix_cause: ?OpenPosixCause, sqlite_code: ?c_int) Error {
    diagnostic.* = .{
        .stage = stage,
        .public_error = failure,
        .posix_cause = posix_cause,
        .sqlite_code = sqlite_code,
    };
    return failure;
}

pub fn Methods(comptime Store: type) type {
    return struct {
        const attribution_ring = Store.attribution_ring;
        const AttributedChange = Store.AttributedChange;
        const configureHeapLimit = Store.configureHeapLimit;
        const workProgress = Store.workProgress;
        pub fn open(allocator: std.mem.Allocator, path: []const u8) Error!Store {
            var ignored = OpenDiagnostic{};
            return openImpl(allocator, path, .plain, &ignored);
        }

        pub fn openExisting(allocator: std.mem.Allocator, path: []const u8) Error!Store {
            var ignored = OpenDiagnostic{};
            return openImpl(allocator, path, .existing, &ignored);
        }

        pub fn openRuntime(allocator: std.mem.Allocator, path: []const u8) Error!Store {
            var ignored = OpenDiagnostic{};
            return openImpl(allocator, path, .runtime, &ignored);
        }
        pub fn openRuntimeDetailed(allocator: std.mem.Allocator, path: []const u8, diagnostic: *OpenDiagnostic) Error!Store {
            return openImpl(allocator, path, .runtime, diagnostic);
        }
        pub fn openReadOnly(allocator: std.mem.Allocator, path: []const u8) Error!Store {
            var ignored = OpenDiagnostic{};
            return openImpl(allocator, path, .readonly, &ignored);
        }
        pub fn openReadOnlyDetailed(allocator: std.mem.Allocator, path: []const u8, diagnostic: *OpenDiagnostic) Error!Store {
            return openImpl(allocator, path, .readonly, diagnostic);
        }

        pub const InstallationSnapshot = struct {
            schema_version: i64,
            installation: ?effects.Installation,
        };

        pub fn installationSnapshotDetailed(allocator: std.mem.Allocator, path: []const u8, diagnostic: *OpenDiagnostic) Error!InstallationSnapshot {
            var store = try openImpl(allocator, path, .preflight, diagnostic);
            defer store.close();
            store.last_error_code = null;
            const installation = if (store.schema_version >= 11)
                store.readInstallation() catch |failure| return openFailure(diagnostic, .installation_read, failure, null, store.last_error_code)
            else
                null;
            return .{
                .schema_version = store.schema_version,
                .installation = installation,
            };
        }

        const OpenMode = enum { plain, runtime, readonly, preflight, existing };
        // Holds: Opens only a regular file owned by the caller's euid, mode 0600 or tighter, in a parent no group or other user can write.
        fn openImpl(allocator: std.mem.Allocator, path: []const u8, open_mode: OpenMode, diagnostic: *OpenDiagnostic) Error!Store {
            diagnostic.* = .{};
            const runtime = open_mode == .runtime;
            if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null)
                return openFailure(diagnostic, .path_validation, error.OpenFailed, null, null);
            var parent = std.fs.cwd().openDir(std.fs.path.dirname(path) orelse ".", .{ .no_follow = true }) catch |failure|
                return openFailure(diagnostic, .parent_open, error.OpenFailed, openPosixCause(failure), null);
            defer parent.close();
            const parent_stat = std.posix.fstat(parent.fd) catch |failure|
                return openFailure(diagnostic, .parent_stat, error.OpenFailed, openPosixCause(failure), null);
            const reader_uid = std.os.linux.geteuid();
            const root_reader = open_mode == .readonly and reader_uid == 0;
            if ((parent_stat.uid != reader_uid and !root_reader) or parent_stat.mode & 0o022 != 0)
                return openFailure(diagnostic, .parent_permissions, error.UnsafePermissions, null, null);
            const stat = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch |failure| blk: {
                if (failure != error.FileNotFound or open_mode == .readonly or open_mode == .preflight or open_mode == .existing)
                    return openFailure(diagnostic, .file_stat, error.OpenFailed, openPosixCause(failure), null);
                const created = std.posix.open(path, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true, .CLOEXEC = true, .NOFOLLOW = true }, 0o600) catch |create_failure|
                    return openFailure(diagnostic, .file_create, error.OpenFailed, openPosixCause(create_failure), null);
                defer std.posix.close(created);
                break :blk std.posix.fstat(created) catch |stat_failure|
                    return openFailure(diagnostic, .created_file_stat, error.OpenFailed, openPosixCause(stat_failure), null);
            };
            if (!std.posix.S.ISREG(stat.mode))
                return openFailure(diagnostic, .file_type, error.UnsafePermissions, null, null);
            if (stat.mode & 0o077 != 0 or (stat.uid != reader_uid and !root_reader))
                return openFailure(diagnostic, .file_permissions, error.UnsafePermissions, null, null);
            const api = embedded_api;
            const filename = allocator.dupeZ(u8, path) catch
                return openFailure(diagnostic, .path_copy, error.OutOfMemory, null, null);
            defer allocator.free(filename);
            var db: ?*Db = null;
            const access_flags: c_int = if (open_mode == .readonly or open_mode == .preflight) 1 else 2;
            // Why: Flags are SQLITE_OPEN_READONLY 1 or READWRITE 2, with FULLMUTEX 0x10000 and NOFOLLOW 0x01000000 (sqlite3.h).
            const opened = api.open(filename, &db, access_flags | 0x10000 | 0x01000000, null);
            if (opened != 0 or db == null) {
                if (db) |handle| _ = api.close(handle);
                const failure = if (opened != 0) sqliteError(opened) else error.OpenFailed;
                return openFailure(diagnostic, .sqlite_open, failure, null, if (opened != 0) opened else null);
            }
            const ring = allocator.create([attribution_ring]AttributedChange) catch {
                _ = api.close(db.?);
                return openFailure(diagnostic, .connection_setup, error.OutOfMemory, null, null);
            };
            @memset(ring, .{});
            var self = Store{ .allocator = allocator, .api = api, .db = db.?, .attributed_changes = ring };
            errdefer {
                self.releaseStatementCache();
                _ = self.api.close(self.db);
                allocator.destroy(ring);
            }
            const db_config = @extern(*const fn (*Db, c_int, ...) callconv(.c) c_int, .{ .name = "sqlite3_db_config" });
            self.last_error_code = null;
            // Why: 1006 is SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE (sqlite3.h); closing a refused handle never checkpoints into the file.
            self.check(db_config(self.db, 1006, @as(c_int, 1), @as(?*c_int, null))) catch |failure|
                return openFailure(diagnostic, .connection_setup, failure, null, self.last_error_code);
            const selected = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch |failure|
                return openFailure(diagnostic, .file_identity_recheck, error.OpenFailed, openPosixCause(failure), null);
            // Why: The path is stat'd again after sqlite3_open_v2, so a file swapped in after the checks above is refused.
            if (selected.dev != stat.dev or selected.ino != stat.ino or selected.uid != stat.uid or selected.mode != stat.mode)
                return openFailure(diagnostic, .file_identity_changed, error.OpenFailed, null, null);
            const file_control = @extern(*const fn (*Db, ?[*:0]const u8, c_int, ?*anyopaque) callconv(.c) c_int, .{ .name = "sqlite3_file_control" });
            var moved: c_int = 1;
            // Why: 20 is SQLITE_FCNTL_HAS_MOVED (sqlite3.h); a file renamed, moved or deleted since SQLite opened it is refused.
            self.last_error_code = null;
            self.check(file_control(self.db, "main", 20, &moved)) catch |failure|
                return openFailure(diagnostic, .sqlite_file_identity, failure, null, self.last_error_code);
            if (moved != 0) return openFailure(diagnostic, .sqlite_file_identity, error.OpenFailed, null, null);
            // Why: Limit 0 is SQLITE_LIMIT_LENGTH (sqlite3.h), the largest string, blob or row; this caps it at a checkpoint plus 128 KiB.
            _ = api.limit(self.db, 0, Limits.sqlite_row_bytes);
            if (api.limit(self.db, 0, -1) != Limits.sqlite_row_bytes)
                return openFailure(diagnostic, .sqlite_limits, error.StorageLimit, null, null);
            self.last_error_code = null;
            self.check(api.busy_timeout(self.db, 1000)) catch |failure|
                return openFailure(diagnostic, .sqlite_limits, failure, null, self.last_error_code);
            const progress = @extern(*const fn (*Db, c_int, ?*const fn (?*anyopaque) callconv(.c) c_int, ?*anyopaque) callconv(.c) void, .{ .name = "sqlite3_progress_handler" });
            defer if (runtime) progress(self.db, 0, null, null);
            if (runtime) {
                self.runtime_path = path;
                configureHeapLimit();
                self.runtime_limits = true;
                progress(self.db, 1000, workProgress, &self);
            }
            self.last_error_code = null;
            self.exec("PRAGMA trusted_schema=OFF;") catch |failure|
                return openFailure(diagnostic, .schema_inspection, failure, null, self.last_error_code);
            const application = self.integer("PRAGMA application_id;") catch |failure|
                return openFailure(diagnostic, .schema_inspection, failure, null, self.last_error_code);
            const schema = self.integer("PRAGMA user_version;") catch |failure|
                return openFailure(diagnostic, .schema_inspection, failure, null, self.last_error_code);
            // Why: 0x46325a31 is ASCII "F2Z1", the application_id this program writes (1177705009 in decimal).
            if (application == 0) {
                if (schema != 0)
                    return openFailure(diagnostic, .schema_validation, error.ForeignDatabase, null, null);
                const objects = self.integer("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%';") catch |failure|
                    return openFailure(diagnostic, .schema_inspection, failure, null, self.last_error_code);
                if (objects != 0) return openFailure(diagnostic, .schema_validation, error.ForeignDatabase, null, null);
            } else if (application != 0x46325a31) return openFailure(diagnostic, .schema_validation, error.ForeignDatabase, null, null);
            if (schema < 0 or schema > latest_schema)
                return openFailure(diagnostic, .schema_validation, error.UnsupportedSchema, null, null);
            if (schema == load_repair_schema) {
                const migration_rows = self.integer("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='load_repair_migration';") catch |failure|
                    return openFailure(diagnostic, .schema_inspection, failure, null, self.last_error_code);
                if (migration_rows != 1) return openFailure(diagnostic, .schema_validation, error.UnsupportedSchema, null, null);
            }
            self.schema_version = if (open_mode == .preflight or (runtime and schema == 0)) schema else @max(schema, 2);
            if (open_mode == .readonly or open_mode == .preflight) {
                if (application == 0 and open_mode == .readonly)
                    return openFailure(diagnostic, .schema_validation, error.ForeignDatabase, null, null);
                self.last_error_code = null;
                self.exec("PRAGMA foreign_keys=ON;") catch |failure|
                    return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
                diagnostic.* = .{};
                return self;
            }
            if (runtime) {
                self.last_error_code = null;
                self.configureRuntimeLimits() catch |failure|
                    return openFailure(diagnostic, .runtime_setup, failure, null, self.last_error_code);
                self.last_error_code = null;
                self.maintainWal(path) catch |failure|
                    return openFailure(diagnostic, .runtime_setup, failure, null, self.last_error_code);
            }
            self.last_error_code = null;
            self.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;") catch |failure|
                return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
            {
                var mode = self.statement("PRAGMA journal_mode;") catch |failure|
                    return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
                defer mode.deinit();
                const has_mode = mode.row() catch |failure|
                    return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
                if (!has_mode) return openFailure(diagnostic, .schema_setup, error.DatabaseFailure, null, null);
                const mode_name = mode.bytes(0) catch |failure|
                    return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
                if (!std.mem.eql(u8, mode_name, "wal"))
                    return openFailure(diagnostic, .schema_setup, error.DatabaseFailure, null, null);
                // Why: PRAGMA synchronous reads back 2 for FULL; the open fails unless both WAL and FULL took effect.
                const synchronous = self.integer("PRAGMA synchronous;") catch |failure|
                    return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
                if (synchronous != 2) return openFailure(diagnostic, .schema_setup, error.DatabaseFailure, null, null);
            }
            if (!runtime or (schema != 0 and schema < load_repair.runtime_schema)) {
                self.beginWrite() catch |failure|
                    return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
                self.exec(
                    \\CREATE TABLE IF NOT EXISTS records(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,raw_hash BLOB NOT NULL CHECK(length(raw_hash)=32),cursor BLOB NOT NULL,event_time BLOB CHECK(event_time IS NULL OR length(event_time)=8),timestamp_us TEXT,disposition TEXT NOT NULL,PRIMARY KEY(jail,source,occurrence));
                    \\CREATE TABLE IF NOT EXISTS source_cursors(jail TEXT NOT NULL,source TEXT NOT NULL,cursor BLOB NOT NULL,occurrence TEXT NOT NULL,path TEXT,PRIMARY KEY(jail,source));
                    \\CREATE TABLE IF NOT EXISTS checkpoints(jail TEXT PRIMARY KEY NOT NULL,payload BLOB NOT NULL,revision INTEGER NOT NULL CHECK(revision>0));
                    \\CREATE TABLE IF NOT EXISTS shared_checkpoints(name TEXT PRIMARY KEY NOT NULL,payload BLOB NOT NULL,revision INTEGER NOT NULL CHECK(revision>0));
                    \\CREATE TABLE IF NOT EXISTS action_intents(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,payload BLOB NOT NULL,status TEXT NOT NULL DEFAULT 'pending',PRIMARY KEY(jail,source,occurrence),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
                    \\PRAGMA application_id=1177705009;
                ) catch |err| {
                    self.rollback();
                    return openFailure(diagnostic, .schema_setup, err, null, self.last_error_code);
                };
                if (schema < 2) self.exec("PRAGMA user_version=2;") catch |err| {
                    self.rollback();
                    return openFailure(diagnostic, .schema_setup, err, null, self.last_error_code);
                };
                self.commitTransaction() catch |err| {
                    self.rollback();
                    return openFailure(diagnostic, .schema_setup, err, null, self.last_error_code);
                };
            }
            self.last_error_code = null;
            self.check(db_config(self.db, 1006, @as(c_int, 0), @as(?*c_int, null))) catch |failure|
                return openFailure(diagnostic, .connection_setup, failure, null, self.last_error_code);
            if (runtime) self.runtime_limits = false;
            diagnostic.* = .{};
            return self;
        }
    };
}
