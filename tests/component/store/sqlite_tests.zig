// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const support = @import("support.zig");
const std = support.std;
const builtin = support.builtin;
const engine = support.engine;
const store_mod = support.store_mod;
const Store = support.Store;
const Error = support.Error;
const Limits = support.Limits;
const Record = support.Record;
const ReceiptIdentity = support.ReceiptIdentity;
const CommitStage = support.CommitStage;
const CommitResult = support.CommitResult;
const Db = support.Db;
const OpenDiagnostic = support.OpenDiagnostic;
const OpenStage = support.OpenStage;
const OpenPosixCause = support.OpenPosixCause;
const latest_schema = support.latest_schema;
const sqliteError = support.sqliteError;
const embedded_api = support.embedded_api;
const native_time = support.native_time;
const time_policy = support.time_policy;
const native_record = support.native_record;
const detection = support.detection;
const retry = support.retry;
const action_context = support.action_context;
const consumers = support.consumers;
const effects = support.effects;
const effect_history = support.effect_history;
const application_history = support.application_history;
const action_outcome = support.action_outcome;
const ReceiptFixture = support.ReceiptFixture;
const DetectionFixture = support.DetectionFixture;

test "record store: extended SQLite failures retain distinct operational causes" {
    const cases = .{
        .{ 5 | (2 << 8), error.Busy },
        .{ 6 | (1 << 8), error.Busy },
        .{ 7, error.OutOfMemory },
        .{ 8 | (6 << 8), error.ReadOnly },
        .{ 9, error.Interrupted },
        .{ 10 | (4 << 8), error.StorageIo },
        .{ 11 | (3 << 8), error.CorruptDatabase },
        .{ 13, error.StorageFull },
        .{ 14 | (1 << 8), error.OpenFailed },
        .{ 18, error.StorageLimit },
        .{ 26, error.CorruptDatabase },
        .{ 23, error.AccessDenied },
        .{ 19, error.DatabaseFailure },
    };
    inline for (cases) |case| try std.testing.expectEqual(@as(Error, case[1]), sqliteError(case[0]));
}

test "record store: detailed open resets caller diagnostics and preserves allocation failure" {
    const t = std.testing;
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "diagnostic.sqlite" });
    defer a.free(path);

    var diagnostic = OpenDiagnostic{
        .stage = .sqlite_open,
        .public_error = error.StorageFull,
        .posix_cause = .no_space_left,
        .sqlite_code = 13,
    };
    var store = try Store.openDetailed(a, path, &diagnostic);
    store.close();
    try t.expectEqualDeep(OpenDiagnostic{}, diagnostic);

    diagnostic = .{ .stage = .path_validation, .public_error = error.OpenFailed };
    var runtime = try Store.openRuntimeDetailed(a, path, &diagnostic);
    runtime.close();
    try t.expectEqualDeep(OpenDiagnostic{}, diagnostic);

    diagnostic = .{ .stage = .path_validation, .public_error = error.OpenFailed };
    var reader = try Store.openReadOnlyDetailed(a, path, &diagnostic);
    reader.close();
    try t.expectEqualDeep(OpenDiagnostic{}, diagnostic);

    diagnostic = .{ .stage = .path_validation, .public_error = error.OpenFailed };
    _ = try Store.installationSnapshotDetailed(a, path, &diagnostic);
    try t.expectEqualDeep(OpenDiagnostic{}, diagnostic);

    var failing = t.FailingAllocator.init(a, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, Store.openDetailed(failing.allocator(), path, &diagnostic));
    try t.expectEqual(OpenStage.path_copy, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.OutOfMemory), diagnostic.public_error.?);
    try t.expectEqual(@as(?OpenPosixCause, null), diagnostic.posix_cause);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);

    var legacy_failing = t.FailingAllocator.init(a, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, Store.open(legacy_failing.allocator(), path));
}

test "record store: detailed open distinguishes path access type and permission failures" {
    const t = std.testing;
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    var diagnostic = OpenDiagnostic{};

    try t.expectError(error.OpenFailed, Store.openDetailed(a, "invalid\x00path", &diagnostic));
    try t.expectEqual(OpenStage.path_validation, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.OpenFailed), diagnostic.public_error.?);
    try t.expectEqual(@as(?OpenPosixCause, null), diagnostic.posix_cause);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);

    const missing_parent = try std.fs.path.join(a, &.{ base, "missing", "state.sqlite" });
    defer a.free(missing_parent);
    try t.expectError(error.OpenFailed, Store.openDetailed(a, missing_parent, &diagnostic));
    try t.expectEqual(OpenStage.parent_open, diagnostic.stage.?);
    try t.expectEqual(OpenPosixCause.file_not_found, diagnostic.posix_cause.?);

    const parent_file = try std.fs.path.join(a, &.{ base, "ordinary-file" });
    defer a.free(parent_file);
    var ordinary = try std.fs.cwd().createFile(parent_file, .{ .mode = 0o600 });
    ordinary.close();
    const below_file = try std.fs.path.join(a, &.{ parent_file, "state.sqlite" });
    defer a.free(below_file);
    try t.expectError(error.OpenFailed, Store.openDetailed(a, below_file, &diagnostic));
    try t.expectEqual(OpenStage.parent_open, diagnostic.stage.?);
    try t.expectEqual(OpenPosixCause.not_directory, diagnostic.posix_cause.?);

    try temp.dir.makeDir("unsafe-parent");
    var unsafe_parent = try temp.dir.openDir("unsafe-parent", .{ .iterate = true });
    defer unsafe_parent.close();
    try unsafe_parent.chmod(0o770);
    defer unsafe_parent.chmod(0o700) catch {};
    const unsafe_parent_path = try std.fs.path.join(a, &.{ base, "unsafe-parent", "state.sqlite" });
    defer a.free(unsafe_parent_path);
    try t.expectError(error.UnsafePermissions, Store.openDetailed(a, unsafe_parent_path, &diagnostic));
    try t.expectEqual(OpenStage.parent_permissions, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.UnsafePermissions), diagnostic.public_error.?);
    try t.expectEqual(@as(?OpenPosixCause, null), diagnostic.posix_cause);

    try temp.dir.makeDir("create-denied");
    var create_denied = try temp.dir.openDir("create-denied", .{ .iterate = true });
    defer create_denied.close();
    try create_denied.chmod(0o500);
    defer create_denied.chmod(0o700) catch {};
    const create_denied_path = try std.fs.path.join(a, &.{ base, "create-denied", "state.sqlite" });
    defer a.free(create_denied_path);
    try t.expectError(error.OpenFailed, Store.openDetailed(a, create_denied_path, &diagnostic));
    try t.expectEqual(OpenStage.file_create, diagnostic.stage.?);
    try t.expectEqual(OpenPosixCause.access_denied, diagnostic.posix_cause.?);

    try temp.dir.makeDir("directory.sqlite");
    const directory_path = try std.fs.path.join(a, &.{ base, "directory.sqlite" });
    defer a.free(directory_path);
    try t.expectError(error.UnsafePermissions, Store.openDetailed(a, directory_path, &diagnostic));
    try t.expectEqual(OpenStage.file_type, diagnostic.stage.?);

    const permissive_path = try std.fs.path.join(a, &.{ base, "permissive.sqlite" });
    defer a.free(permissive_path);
    var permissive = try std.fs.cwd().createFile(permissive_path, .{ .mode = 0o640 });
    permissive.close();
    try t.expectError(error.UnsafePermissions, Store.openDetailed(a, permissive_path, &diagnostic));
    try t.expectEqual(OpenStage.file_permissions, diagnostic.stage.?);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);
}

test "record store: detailed open detects deterministic file identity replacement" {
    const t = std.testing;
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "selected.sqlite" });
    defer a.free(path);
    const moved = try std.fs.path.join(a, &.{ base, "selected.sqlite.saved" });
    defer a.free(moved);
    var initial = try Store.open(a, path);
    initial.close();

    const Race = struct {
        path: []const u8,
        moved: []const u8,
        ran: bool = false,
        failed: bool = false,

        fn replace(context: ?*anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.ran = true;
            std.posix.rename(self.path, self.moved) catch {
                self.failed = true;
                return;
            };
            const replacement = std.posix.open(self.path, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true, .CLOEXEC = true, .NOFOLLOW = true }, 0o600) catch {
                self.failed = true;
                return;
            };
            std.posix.close(replacement);
        }
    };
    var race = Race{ .path = path, .moved = moved };
    var diagnostic = OpenDiagnostic{};
    try t.expectError(error.OpenFailed, Store.TestAccess.openImpl(a, path, .plain, &diagnostic, .{ .context = &race, .before_identity_recheck = Race.replace }));
    try t.expect(race.ran);
    try t.expect(!race.failed);
    try t.expectEqual(OpenStage.file_identity_changed, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.OpenFailed), diagnostic.public_error.?);
    try t.expectEqual(@as(?OpenPosixCause, null), diagnostic.posix_cause);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);
}

test "record store: detailed open separates corrupt foreign unsupported and installation failures" {
    const t = std.testing;
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    var diagnostic = OpenDiagnostic{};

    const corrupt_path = try std.fs.path.join(a, &.{ base, "corrupt.sqlite" });
    defer a.free(corrupt_path);
    const corrupt_bytes = [_]u8{0xa5} ** 64;
    var corrupt_file = try std.fs.cwd().createFile(corrupt_path, .{ .mode = 0o600 });
    try corrupt_file.writeAll(&corrupt_bytes);
    corrupt_file.close();
    try t.expectError(error.CorruptDatabase, Store.openDetailed(a, corrupt_path, &diagnostic));
    try t.expectEqual(OpenStage.schema_inspection, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.CorruptDatabase), diagnostic.public_error.?);
    try t.expect(diagnostic.sqlite_code != null);
    try t.expectEqual(@as(Error, error.CorruptDatabase), sqliteError(diagnostic.sqlite_code.?));

    const foreign_path = try std.fs.path.join(a, &.{ base, "foreign.sqlite" });
    defer a.free(foreign_path);
    var foreign = try Store.open(a, foreign_path);
    try foreign.exec("PRAGMA application_id=1;");
    foreign.close();
    try t.expectError(error.ForeignDatabase, Store.openDetailed(a, foreign_path, &diagnostic));
    try t.expectEqual(OpenStage.schema_validation, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.ForeignDatabase), diagnostic.public_error.?);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);
    try t.expectError(error.ForeignDatabase, Store.open(a, foreign_path));

    const unsupported_path = try std.fs.path.join(a, &.{ base, "unsupported.sqlite" });
    defer a.free(unsupported_path);
    var unsupported = try Store.open(a, unsupported_path);
    var version_sql: [64]u8 = undefined;
    const set_version = try std.fmt.bufPrintZ(&version_sql, "PRAGMA user_version={d};", .{latest_schema + 1});
    try unsupported.exec(set_version);
    unsupported.close();
    try t.expectError(error.UnsupportedSchema, Store.openDetailed(a, unsupported_path, &diagnostic));
    try t.expectEqual(OpenStage.schema_validation, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.UnsupportedSchema), diagnostic.public_error.?);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);
    try t.expectError(error.UnsupportedSchema, Store.installationSnapshot(a, unsupported_path));

    const installation_path = try std.fs.path.join(a, &.{ base, "installation.sqlite" });
    defer a.free(installation_path);
    var installation = try Store.open(a, installation_path);
    try installation.exec("CREATE TABLE effect_installation(broken INTEGER); PRAGMA user_version=11;");
    installation.close();
    try t.expectError(error.DatabaseFailure, Store.installationSnapshotDetailed(a, installation_path, &diagnostic));
    try t.expectEqual(OpenStage.installation_read, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.DatabaseFailure), diagnostic.public_error.?);
    try t.expect(diagnostic.sqlite_code != null);
    try t.expectEqual(@as(c_int, 1), diagnostic.sqlite_code.? & 0xff);
}

test "record store: oversized restored values fail before caller allocation and leave saved bytes intact" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "restore-limits.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    _ = try store.commitRecord(.{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "saved", .shared_state = .{ .name = "shared", .expected_revision = 0, .payload = "saved" } });
    var no_memory = std.heap.FixedBufferAllocator.init(&.{});
    const denied = no_memory.allocator();
    try store.exec("UPDATE checkpoints SET payload=zeroblob(16777217);");
    try std.testing.expectError(error.StorageLimit, store.snapshot(denied, "fixture"));
    try std.testing.expectError(error.StorageLimit, store.checkpoint(denied, "fixture"));
    try std.testing.expectEqual(@as(i64, Limits.checkpoint_bytes + 1), try store.integer("SELECT length(payload) FROM checkpoints;"));
    try store.exec("UPDATE shared_checkpoints SET payload=zeroblob(4194305);");
    try std.testing.expectError(error.StorageLimit, store.sharedSnapshot(denied, "shared"));
    try store.exec("UPDATE source_cursors SET cursor=zeroblob(65537);");
    try std.testing.expectError(error.StorageLimit, store.sourceCursor(denied, "fixture", "file"));
    const Visitor = struct {
        fn visit(_: []const u8, _: []const u8, _: []const u8, context: ?*anyopaque) !void {
            const called: *bool = @ptrCast(@alignCast(context.?));
            called.* = true;
        }
    };
    var called = false;
    try std.testing.expectError(error.StorageLimit, store.visitSources("fixture", Visitor.visit, &called));
    try std.testing.expect(!called);
    try store.exec("UPDATE checkpoints SET payload=x''; UPDATE shared_checkpoints SET payload=x''; UPDATE source_cursors SET cursor=x'31';");
    const empty = try store.snapshot(denied, "fixture");
    defer empty.deinit(denied);
    try std.testing.expectEqual(@as(usize, 0), empty.payload.?.len);
    try std.testing.expectEqual(@as(u64, 1), empty.revision);
    try std.testing.expectError(error.OutOfMemory, store.sourceCursor(denied, "fixture", "file"));
}

test "record store: opening and closing peers preserves SQLite process locks" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "locks.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    for (0..2) |pass| {
        if (pass == 1) {
            var peer = try Store.open(a, path);
            peer.close();
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            const fd = std.posix.open(path, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0) catch std.process.exit(2);
            var lock: std.posix.Flock = std.mem.zeroes(std.posix.Flock);
            lock.type = std.posix.F.WRLCK;
            lock.whence = std.posix.SEEK.SET;
            lock.start = 0x40000002;
            lock.len = 510;
            _ = std.posix.fcntl(fd, std.posix.F.SETLK, @intFromPtr(&lock)) catch |failure| {
                std.posix.close(fd);
                std.process.exit(if (failure == error.Locked or failure == error.AccessDenied) 0 else 3);
            };
            std.posix.close(fd);
            std.process.exit(4);
        }
        const result = std.posix.waitpid(pid, 0);
        try std.testing.expectEqual(@as(u32, 0), result.status);
    }
}

test "record store: SQLite row bound permits maximum admitted record and rejects oversized stored rows" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "row-limit.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    const payload = try a.alloc(u8, Limits.checkpoint_bytes);
    defer a.free(payload);
    @memset(payload, 'x');
    const record = Record{ .jail = payload[0..4096], .source = payload[0..Limits.source_bytes], .source_path = payload[0..Limits.source_bytes], .occurrence = payload[0..16384], .cursor = payload[0..Limits.cursor_bytes], .raw_hash = [_]u8{1} ** 32, .disposition = payload[0..64], .checkpoint = payload, .action_intent = payload[0 .. 1024 * 1024], .shared_state = .{ .name = payload[0..4096], .expected_revision = 0, .payload = payload[0..Limits.shared_bytes] } };
    try std.testing.expectEqual(CommitResult.committed, try store.commitRecord(record));
    const saved = try store.snapshot(a, record.jail);
    defer saved.deinit(a);
    try std.testing.expectEqualSlices(u8, payload, saved.payload.?);
    try std.testing.expectEqual(@as(c_int, Limits.sqlite_row_bytes), store.api.limit(store.db, 0, -1));
    _ = store.api.limit(store.db, 0, 32 * 1024 * 1024);
    try store.exec("UPDATE checkpoints SET payload=zeroblob(17825792);");
    _ = store.api.limit(store.db, 0, Limits.sqlite_row_bytes);
    var no_memory = std.heap.FixedBufferAllocator.init(&.{});
    try std.testing.expectError(error.StorageLimit, store.snapshot(no_memory.allocator(), record.jail));
    try std.testing.expectEqual(@as(?c_int, 18), store.last_error_code);
    try std.testing.expectEqual(@as(i64, 17825792), try store.integer("SELECT length(payload) FROM checkpoints;"));
}

test "record store: SQLite heap budget feasibility and recovery after allocation denial" {
    const Memory = struct {
        extern "c" fn sqlite3_hard_heap_limit64(i64) i64;
        extern "c" fn sqlite3_soft_heap_limit64(i64) i64;
        extern "c" fn sqlite3_memory_used() i64;
        extern "c" fn sqlite3_memory_highwater(c_int) i64;
    };
    const old_soft = Memory.sqlite3_soft_heap_limit64(-1);
    const old_hard = Memory.sqlite3_hard_heap_limit64(64 * 1024 * 1024);
    defer {
        _ = Memory.sqlite3_hard_heap_limit64(old_hard);
        _ = Memory.sqlite3_soft_heap_limit64(old_soft);
    }
    _ = Memory.sqlite3_memory_highwater(1);
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "heap-budget.sqlite" });
    defer a.free(path);
    const large = try a.alloc(u8, Limits.checkpoint_bytes);
    defer a.free(large);
    @memset(large, 'x');
    var record = Record{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = large, .action_intent = "saved-intent" };
    {
        var store = try Store.open(a, path);
        defer store.close();
        _ = try store.commitRecord(record);
        const saved = try store.snapshot(a, "fixture");
        defer saved.deinit(a);
        try std.testing.expectEqualSlices(u8, large, saved.payload.?);
        const peak = Memory.sqlite3_memory_highwater(0);
        try std.testing.expect(peak <= 64 * 1024 * 1024);
        std.debug.print("SQLite heap peak for 16 MiB checkpoint commit/restore: {d} bytes\n", .{peak});
        _ = Memory.sqlite3_hard_heap_limit64(Memory.sqlite3_memory_used());
        record.occurrence = "2";
        record.cursor = "2";
        record.expected_revision = 1;
        try std.testing.expectError(error.OutOfMemory, store.commitRecord(record));
        _ = Memory.sqlite3_hard_heap_limit64(64 * 1024 * 1024);
    }
    var recovered = try Store.open(a, path);
    defer recovered.close();
    try std.testing.expectEqual(@as(u64, 1), try recovered.revision("fixture"));
    try std.testing.expect(!try recovered.hasRecord("fixture", "file", "2", record.raw_hash, "2"));
    try std.testing.expectEqual(@as(i64, 1), try recovered.pendingIntents());
    try std.testing.expectEqual(CommitResult.committed, try recovered.commitRecord(record));
    try std.testing.expectEqual(CommitResult.already_committed, try recovered.commitRecord(record));
    try std.testing.expectEqual(@as(i64, 2), try recovered.pendingIntents());
}

test "record store: SQLite work budget feasibility interrupts excessive query and releases statements" {
    const Progress = struct {
        remaining: u32,
        extern "c" fn sqlite3_progress_handler(*Db, c_int, ?*const fn (?*anyopaque) callconv(.c) c_int, ?*anyopaque) void;
        fn tick(context: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.remaining -|= 1;
            return @intFromBool(self.remaining == 0);
        }
    };
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "work-budget.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    var budget = Progress{ .remaining = 1000 };
    Progress.sqlite3_progress_handler(store.db, 1000, Progress.tick, &budget);
    defer Progress.sqlite3_progress_handler(store.db, 0, null, null);
    const record = Record{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "saved", .action_intent = "saved-intent" };
    _ = try store.commitRecord(record);
    try std.testing.expectError(error.Interrupted, store.integer("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000000) SELECT sum(x) FROM n;"));
    try std.testing.expectEqual(@as(u32, 0), budget.remaining);
    try std.testing.expectEqual(@as(?c_int, 9), store.last_error_code);
    budget.remaining = 1000;
    try std.testing.expectEqual(@as(u64, 1), try store.revision("fixture"));
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try std.testing.expectEqual(CommitResult.already_committed, try store.commitRecord(record));
}

test "record store: capacity failure preserves every committed component and retry is atomic" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "capacity.sqlite" });
    defer allocator.free(path);
    var store = try Store.open(allocator, path);
    defer store.close();
    var record = Record{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "saved", .action_intent = "saved-intent", .shared_state = .{ .name = "shared", .expected_revision = 0, .payload = "saved-shared" } };
    _ = try store.commitRecord(record);
    const pages = try store.integer("PRAGMA page_count;");
    var sql: [80]u8 = undefined;
    try std.testing.expectEqual(pages, try store.integer(try std.fmt.bufPrintZ(&sql, "PRAGMA max_page_count={d};", .{pages})));
    const large = try allocator.alloc(u8, 256 * 1024);
    defer allocator.free(large);
    @memset(large, 'x');
    record.occurrence = "2";
    record.cursor = "2";
    record.checkpoint = "next";
    record.expected_revision = 1;
    record.shared_state.?.expected_revision = 1;
    record.shared_state.?.payload = "next-shared";
    record.action_intent = large;
    try std.testing.expectError(error.StorageFull, store.commitRecord(record));
    try std.testing.expectEqual(@as(?c_int, 13), store.last_error_code);
    try std.testing.expect(store.api.get_autocommit(store.db) != 0);
    try std.testing.expect(!store.reopen_required);
    try std.testing.expectEqual(@as(?c_int, null), store.rollback_error_code);
    try std.testing.expect(!try store.hasRecord("fixture", "file", "2", record.raw_hash, "2"));
    const saved = try store.snapshot(allocator, "fixture");
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("saved", saved.payload.?);
    try std.testing.expectEqual(@as(u64, 1), saved.revision);
    const shared = try store.sharedSnapshot(allocator, "shared");
    defer shared.deinit(allocator);
    try std.testing.expectEqualStrings("saved-shared", shared.payload.?);
    try std.testing.expectEqual(@as(u64, 1), shared.revision);
    const cursor = (try store.sourceCursor(allocator, "fixture", "file")).?;
    defer allocator.free(cursor);
    try std.testing.expectEqualStrings("1", cursor);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try std.testing.expectEqual(@as(?c_int, 13), store.last_error_code);
    _ = try store.integer("PRAGMA max_page_count=10000;");
    try std.testing.expectEqual(CommitResult.committed, try store.commitRecord(record));
    try std.testing.expectEqual(CommitResult.already_committed, try store.commitRecord(record));
    try std.testing.expectEqual(@as(u64, 2), try store.revision("fixture"));
    try std.testing.expectEqual(@as(i64, 2), try store.pendingIntents());
}

test "record store: rollback failure blocks reads and writes until close and recovery" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "rollback.sqlite" });
    defer allocator.free(path);
    const record = Record{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "uncommitted", .action_intent = "uncommitted-intent" };
    {
        var store = try Store.open(allocator, path);
        defer store.close();
        const Fault = struct {
            fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) return 10 | (3 << 8);
                if (std.mem.eql(u8, std.mem.span(sql), "ROLLBACK;")) return 10 | (4 << 8);
                return embedded_api.exec(db, sql, callback, context, message);
            }
        };
        store.api.exec = Fault.exec;
        try std.testing.expectError(error.StorageIo, store.commitRecord(record));
        try std.testing.expectEqual(@as(?c_int, 10 | (3 << 8)), store.last_error_code);
        try std.testing.expectEqual(@as(?c_int, 10 | (4 << 8)), store.rollback_error_code);
        try std.testing.expect(store.api.get_autocommit(store.db) == 0);
        try std.testing.expectError(error.ReopenRequired, store.snapshot(allocator, "fixture"));
        try std.testing.expectError(error.ReopenRequired, store.sourceCursor(allocator, "fixture", "file"));
        try std.testing.expectError(error.ReopenRequired, store.pendingIntents());
        try std.testing.expectError(error.ReopenRequired, store.commitRecord(record));
    }
    var recovered = try Store.open(allocator, path);
    defer recovered.close();
    try std.testing.expectEqual(@as(u64, 0), try recovered.revision("fixture"));
    try std.testing.expectEqual(@as(i64, 0), try recovered.pendingIntents());
    try std.testing.expectEqual(CommitResult.committed, try recovered.commitRecord(record));
}

test "record store: malformed database is reported without replacing its contents" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "malformed.sqlite" });
    defer allocator.free(path);
    const original = [_]u8{'x'} ** 4096;
    var file = try temp.dir.createFile("malformed.sqlite", .{ .mode = 0o600 });
    try file.writeAll(&original);
    file.close();
    try std.testing.expectError(error.CorruptDatabase, Store.open(allocator, path));
    const after = try temp.dir.readFileAlloc(allocator, "malformed.sqlite", original.len + 1);
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, &original, after);
}

test "record store: embedded release and extension loading policy" {
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const path = try std.fs.path.join(std.testing.allocator, &.{ base, "embedded.sqlite" });
    defer std.testing.allocator.free(path);
    var store = try Store.open(std.testing.allocator, path);
    defer store.close();
    var version = try store.statement("SELECT sqlite_version();");
    defer version.deinit();
    try std.testing.expect(try version.row());
    try std.testing.expectEqualStrings("3.53.4", try version.bytes(0));
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT sqlite_compileoption_used('OMIT_LOAD_EXTENSION');"));
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT sqlite_compileoption_used('THREADSAFE=1');"));
}
