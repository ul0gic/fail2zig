// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const engine = @import("engine_test");
const store_mod = engine.core.record_store;
const Store = store_mod.Store;
const repair = store_mod.load_repair;
const t = std.testing;

// Production-built states (for example the load reproduction fixtures) are copied from
// this directory when set: each `<name>/*.sqlite` becomes an additional shape. A shape
// directory may hold the `config.toml` its state was built with, and the directory root
// holds the `fail2zig-v0.4.4` release binary used for the rollback checks.
const fixtures_env = "F2Z_LOAD_REPAIR_FIXTURES";
// Optional JSON-lines file receiving per-phase callback measurements.
const measure_env = "F2Z_LOAD_REPAIR_MEASURE";
const now_us: i64 = 1_767_225_600_000_000;
const max_matches: u16 = 4;

extern fn sqlite3_open_v2(path: [*:0]const u8, db: *?*anyopaque, flags: c_int, vfs: ?[*:0]const u8) c_int;
extern fn sqlite3_close_v2(db: *anyopaque) c_int;
extern fn sqlite3_prepare_v2(db: *anyopaque, sql: [*:0]const u8, bytes: c_int, statement: *?*anyopaque, tail: ?*anyopaque) c_int;
extern fn sqlite3_step(statement: *anyopaque) c_int;
extern fn sqlite3_finalize(statement: *anyopaque) c_int;
extern fn sqlite3_column_count(statement: *anyopaque) c_int;
extern fn sqlite3_column_type(statement: *anyopaque, column: c_int) c_int;
extern fn sqlite3_column_int64(statement: *anyopaque, column: c_int) i64;
extern fn sqlite3_column_blob(statement: *anyopaque, column: c_int) ?*const anyopaque;
extern fn sqlite3_column_bytes(statement: *anyopaque, column: c_int) c_int;
extern fn sqlite3_column_text(statement: *anyopaque, column: c_int) ?[*:0]const u8;

const Shape = struct {
    name: []const u8,
    // Null builds the constructed schema-23 state in place.
    source: ?[]const u8,
    // Small windows make the constructed state cross many page boundaries.
    window_rows: ?i64,
};

const Workspace = struct {
    temp: t.TmpDir,
    root: []u8,

    fn init() !Workspace {
        var temp = t.tmpDir(.{});
        errdefer temp.cleanup();
        return .{ .temp = temp, .root = try temp.dir.realpathAlloc(t.allocator, ".") };
    }
    fn deinit(self: *Workspace) void {
        t.allocator.free(self.root);
        self.temp.cleanup();
    }
    fn path(self: *const Workspace, buffer: []u8, name: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buffer, "{s}/{s}", .{ self.root, name });
    }
};

fn shapes(buffer: []Shape, names: *std.ArrayListUnmanaged([]u8)) ![]Shape {
    var count: usize = 0;
    buffer[count] = .{ .name = "constructed", .source = null, .window_rows = 64 };
    count += 1;
    const root = std.process.getEnvVarOwned(t.allocator, fixtures_env) catch |failure| switch (failure) {
        error.EnvironmentVariableNotFound => return buffer[0..count],
        else => return failure,
    };
    defer t.allocator.free(root);
    var directory = try std.fs.cwd().openDir(root, .{ .iterate = true });
    defer directory.close();
    var walker = try directory.walk(t.allocator);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.basename, ".sqlite")) continue;
        if (count == buffer.len) return error.TooManyFixtures;
        const full = try std.fs.path.join(t.allocator, &.{ root, entry.path });
        try names.append(t.allocator, full);
        buffer[count] = .{ .name = full, .source = full, .window_rows = null };
        count += 1;
    }
    return buffer[0..count];
}

fn freeNames(names: *std.ArrayListUnmanaged([]u8)) void {
    for (names.items) |name| t.allocator.free(name);
    names.deinit(t.allocator);
}

fn options(shape: Shape, state_path: []const u8) repair.Options {
    return .{ .state_path = state_path, .now_us = now_us, .history_max_matches = max_matches, .hooks = .{ .window_rows = shape.window_rows } };
}

// The progress handler keeps a pointer to the store, so limits are configured in place.
fn openState(store: *Store, path: []const u8) !void {
    store.* = try Store.openRuntime(t.allocator, path);
    errdefer store.close();
    try store.configureRuntimeLimits();
}

// Places a schema-23 state for `shape` at `path`.
fn prepare(shape: Shape, path: []const u8) !void {
    if (shape.source) |source| {
        try std.fs.cwd().copyFile(source, std.fs.cwd(), path, .{});
        const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
        defer file.close();
        try file.chmod(0o600);
        return;
    }
    try construct(path);
}

fn exec(store: *Store, comptime format: []const u8, arguments: anytype) !void {
    var buffer: [4096]u8 = undefined;
    try store.inspectExec(try std.fmt.bufPrintZ(&buffer, format, arguments));
}

// A schema-23 state covering every migrated relationship: reused scopes with obsolete
// revisions/intents/observations, an intent above the observation bound, retired and
// current action targets (one retired target still unsettled), live and absent owners,
// joinable and legacy (NULL subject) details, and an activating migration run.
fn construct(path: []const u8) !void {
    const scopes = 240;
    const cycles = 3;
    var store = try Store.open(t.allocator, path);
    defer store.close();
    try store.enableReceipts(8);
    try store.enableNativeTime();
    try store.enableYearInference();
    try store.enableDetection();
    try store.enableClockRecovery();
    try store.enableJournalDetection();
    try store.enableRetry();
    try store.enableConsumers();
    try store.enableEffects();
    try store.enableTimeProvenance();
    try store.enableConsumerManifests();
    try store.enableConfirmedHistory();
    try store.enableMaintenance();
    try store.enableCleanup();
    try store.enableRetryLeases();
    try store.enableApplicationHistory();
    try store.enableEscalation();
    try store.enableCanonicalEffects();
    try store.enableHistoryResets();
    try store.enableActionTargets();
    try store.enableAdminState();
    try store.enableMigrationState();
    try t.expectEqual(@as(i64, 23), try store.inspectInteger("PRAGMA user_version;"));
    try store.inspectExec("BEGIN IMMEDIATE;");
    try store.inspectExec("INSERT INTO effect_installation VALUES(1,CAST(printf('%016d',1) AS BLOB),1,'fixture');");
    try exec(&store,
        \\WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{d})
        \\INSERT INTO native_effects(scope_key,scope,revision,lease_kind,deadline_us,intent_id,canonical_scope)
        \\SELECT CAST(printf('sk%030d',i) AS BLOB),CAST(printf('%024d',i) AS BLOB),{d},CASE WHEN i%2=1 THEN 1 ELSE 0 END,CASE WHEN i%2=1 THEN {d} END,CAST(printf('i{d}%030d',i) AS BLOB),CAST(printf('%092d',i) AS BLOB) FROM n;
    , .{ scopes, cycles, now_us + 3_600_000_000, cycles });
    try exec(&store,
        \\WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{d})
        \\INSERT INTO effect_owners SELECT CAST(printf('sk%030d',i) AS BLOB),'jail',CAST(printf('%032d',0) AS BLOB),CAST(printf('d1%030d',i) AS BLOB),1,1,{d},{d}+i FROM n;
    , .{ scopes, now_us + 3_600_000_000, now_us - 3_600_000_000 });
    for (2..cycles + 1) |cycle| try exec(&store, "UPDATE effect_owners SET decision_id=CAST(printf('d{d}%030d',CAST(substr(CAST(scope_key AS TEXT),3) AS INTEGER)) AS BLOB),revision={d};", .{ cycle, cycle });
    try exec(&store, "UPDATE effect_owners SET lease_kind=0,deadline_us=NULL,revision={d} WHERE CAST(substr(CAST(scope_key AS TEXT),3) AS INTEGER)%2=0;", .{cycles + 1});
    for (1..cycles + 1) |cycle| {
        try exec(&store,
            \\WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{d})
            \\INSERT INTO effect_intents(intent_id,scope_key,revision,decision_id,lease_kind,deadline_us,status,created_us,dispatch_us,observed_us,fingerprint)
            \\SELECT CAST(printf('i{d}%030d',i) AS BLOB),CAST(printf('sk%030d',i) AS BLOB),{d},CAST(printf('d{d}%030d',i) AS BLOB),1,{d},CASE WHEN {d}={d} THEN 3 ELSE 5 END,{d}+i,{d}+i,{d}+i,CAST(printf('fp%030d',i) AS BLOB) FROM n;
        , .{ scopes, cycle, cycle, cycle, now_us + 3_600_000_000, cycle, cycles, now_us + @as(i64, @intCast(cycle)), now_us + @as(i64, @intCast(cycle)), now_us + @as(i64, @intCast(cycle)) });
        for (0..2) |ordinal| try exec(&store,
            \\INSERT INTO effect_observations SELECT CAST(printf('o{d}{d}%029d',rowid) AS BLOB),intent_id,dispatch_us,observed_us+{d},fingerprint,0,NULL,1 FROM effect_intents WHERE revision={d};
        , .{ cycle, ordinal, ordinal, cycle });
    }
    try store.inspectExec("INSERT INTO effect_intents(intent_id,scope_key,revision,decision_id,lease_kind,deadline_us,status,created_us) SELECT CAST(printf('pending%025d',rowid) AS BLOB),scope_key,100,decision_id,1,deadline_us,1,decided_us FROM effect_owners WHERE lease_kind=1 AND CAST(substr(CAST(scope_key AS TEXT),3) AS INTEGER)%5=0;");
    for (0..7) |extra| try exec(&store, "INSERT INTO effect_observations VALUES(CAST(printf('x%031d',{d}) AS BLOB),CAST(printf('i{d}%030d',1) AS BLOB),{d},{d},CAST(printf('fp%030d',1) AS BLOB),0,NULL,2);", .{ extra, cycles, now_us, now_us + @as(i64, @intCast(extra)) + 10 });
    for (1..cycles + 1) |cycle| {
        try exec(&store,
            \\WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{d})
            \\INSERT INTO confirmed_effect_events SELECT CAST(printf('e{d}%030d',i) AS BLOB),CAST(printf('sk%030d',i) AS BLOB),'jail',CAST(printf('d{d}%030d',i) AS BLOB),{d}+i FROM n ORDER BY i;
        , .{ scopes, cycle, cycle, now_us + @as(i64, @intCast(cycle)) * 1000 });
        try exec(&store,
            \\WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{d})
            \\INSERT INTO retry_decision_details SELECT 'jail','src',printf('occ{d}-%d',i),4,CAST(printf('%04d',i%5) AS BLOB),1,{d}+i,CAST(printf('d{d}%030d',i) AS BLOB),CASE WHEN i%3=0 THEN NULL ELSE printf('%0300d',i) END FROM n WHERE i%7<>0;
        , .{ scopes, cycle, now_us, cycle });
        try exec(&store,
            \\WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{d})
            \\INSERT INTO confirmed_event_details SELECT CAST(printf('e{d}%030d',i) AS BLOB),'src',printf('occ{d}-%d',i),{d}+i,1,CASE WHEN i%3=0 THEN NULL ELSE printf('%0300d',i) END FROM n;
        , .{ scopes, cycle, cycle, now_us });
        try exec(&store,
            \\INSERT INTO action_targets SELECT decision_id,k.kind,scope_key,'jail',k.kind=1,0,3,decided_us,decided_us,decided_us,NULL FROM effect_owner_revisions,(SELECT 1 AS kind UNION ALL SELECT 2) k WHERE revision={d};
        , .{cycle});
    }
    try store.inspectExec("UPDATE action_targets SET status=1,dispatch_us=NULL,settled_us=NULL WHERE CAST(substr(CAST(scope_key AS TEXT),3) AS INTEGER)%6=0 AND substr(CAST(action_id AS TEXT),1,2)='d1';");
    try store.inspectExec(
        \\INSERT INTO migration_runs VALUES(CAST(printf('run%029d',1) AS BLOB),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),'point',zeroblob(32),6,1,2);
        \\INSERT INTO migration_runs VALUES(CAST(printf('run%029d',2) AS BLOB),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),'point',zeroblob(32),5,1,2);
        \\INSERT INTO migration_staged_owners SELECT run_id,s.seq,'jail',CAST(printf('%092d',s.seq) AS BLOB),2,NULL,1,s.seq FROM migration_runs,(SELECT 1 AS seq UNION ALL SELECT 2 UNION ALL SELECT 3) s;
        \\INSERT INTO admin_requests VALUES(CAST(printf('req%029d',1) AS BLOB),1,x'01',1,zeroblob(32),0,1,x'');
        \\COMMIT;
    );
    try t.expectEqual(@as(i64, 0), try store.inspectInteger("SELECT count(*) FROM pragma_foreign_key_check;"));
}

const Digest = [32]u8;

fn rawOpen(path: []const u8) !*anyopaque {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const name = try std.fmt.bufPrintZ(&buffer, "{s}", .{path});
    var handle: ?*anyopaque = null;
    const rc = sqlite3_open_v2(name, &handle, 0x01, null);
    const db = handle orelse return error.OpenFailed;
    if (rc != 0) {
        _ = sqlite3_close_v2(db);
        return error.OpenFailed;
    }
    return db;
}

fn prepareRaw(db: *anyopaque, sql: [:0]const u8) !*anyopaque {
    var statement: ?*anyopaque = null;
    if (sqlite3_prepare_v2(db, sql, -1, &statement, null) != 0) return error.PrepareFailed;
    return statement orelse error.PrepareFailed;
}

fn hashColumn(hash: *std.crypto.hash.sha2.Sha256, statement: *anyopaque, column: c_int) void {
    const kind = sqlite3_column_type(statement, column);
    hash.update(&[_]u8{@intCast(kind)});
    if (kind == 1) {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(i64, &bytes, sqlite3_column_int64(statement, column), .little);
        hash.update(&bytes);
    } else if (kind != 5) {
        const length: usize = @intCast(sqlite3_column_bytes(statement, column));
        var size: [8]u8 = undefined;
        std.mem.writeInt(u64, &size, length, .little);
        hash.update(&size);
        if (length > 0) hash.update(@as([*]const u8, @ptrCast(sqlite3_column_blob(statement, column).?))[0..length]);
    }
}

// Order-independent content digest of every table plus the schema text and version. The
// progress row is excluded because it names the per-copy backup path.
fn digest(path: []const u8) !Digest {
    const db = try rawOpen(path);
    defer _ = sqlite3_close_v2(db);
    var total = std.crypto.hash.sha2.Sha256.init(.{});
    {
        const schema = try prepareRaw(db, "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name;");
        defer _ = sqlite3_finalize(schema);
        while (sqlite3_step(schema) == 100) for (0..4) |column| hashColumn(&total, schema, @intCast(column));
    }
    {
        const version = try prepareRaw(db, "PRAGMA user_version;");
        defer _ = sqlite3_finalize(version);
        if (sqlite3_step(version) != 100) return error.DigestFailed;
        hashColumn(&total, version, 0);
    }
    var tables = std.ArrayListUnmanaged([]u8){};
    defer {
        for (tables.items) |name| t.allocator.free(name);
        tables.deinit(t.allocator);
    }
    {
        const list = try prepareRaw(db, "SELECT name FROM sqlite_schema WHERE type='table' AND name<>'load_repair_migration' ORDER BY name;");
        defer _ = sqlite3_finalize(list);
        while (sqlite3_step(list) == 100) try tables.append(t.allocator, try t.allocator.dupe(u8, std.mem.span(sqlite3_column_text(list, 0).?)));
    }
    var rows = std.ArrayListUnmanaged(Digest){};
    defer rows.deinit(t.allocator);
    for (tables.items) |name| {
        rows.clearRetainingCapacity();
        var sql: [256]u8 = undefined;
        const statement = try prepareRaw(db, try std.fmt.bufPrintZ(&sql, "SELECT * FROM \"{s}\";", .{name}));
        defer _ = sqlite3_finalize(statement);
        while (sqlite3_step(statement) == 100) {
            var row = std.crypto.hash.sha2.Sha256.init(.{});
            for (0..@intCast(sqlite3_column_count(statement))) |column| hashColumn(&row, statement, @intCast(column));
            try rows.append(t.allocator, row.finalResult());
        }
        std.mem.sortUnstable(Digest, rows.items, {}, struct {
            fn less(_: void, left: Digest, right: Digest) bool {
                return std.mem.order(u8, &left, &right) == .lt;
            }
        }.less);
        total.update(name);
        for (rows.items) |row| total.update(&row);
    }
    return total.finalResult();
}

const Measurement = struct {
    worst: [256]u32 = [_]u32{0} ** 256,
    commits: usize = 0,

    fn add(self: *Measurement, step: repair.Step) void {
        const slot: usize = if (step.phase) |phase| @intFromEnum(phase) else 0;
        self.worst[slot] = @max(self.worst[slot], step.callbacks);
        self.commits += 1;
    }
    fn write(self: *const Measurement, shape: []const u8, mode: []const u8) !void {
        const target = std.process.getEnvVarOwned(t.allocator, measure_env) catch return;
        defer t.allocator.free(target);
        const file = try std.fs.cwd().createFile(target, .{ .truncate = false, .mode = 0o600 });
        defer file.close();
        try file.seekFromEnd(0);
        var writer = file.writer();
        try writer.print("{{\"shape\":\"{s}\",\"mode\":\"{s}\",\"commits\":{d},\"worst_callbacks\":{{", .{ shape, mode, self.commits });
        var first = true;
        for (self.worst, 0..) |value, slot| {
            if (value == 0) continue;
            const label = if (slot == 0) "fence" else if (std.meta.intToEnum(repair.Phase, slot)) |phase| @tagName(phase) else |_| "unknown";
            try writer.print("{s}\"{s}\":{d}", .{ if (first) "" else ",", label, value });
            first = false;
        }
        try writer.writeAll("}}\n");
    }
};

// Uninterrupted reference run on a fresh copy of the shape.
fn reference(shape: Shape, space: *Workspace, name: []const u8) !Digest {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try space.path(&buffer, name);
    try prepare(shape, path);
    {
        var store: Store = undefined;
        try openState(&store, path);
        defer store.close();
        var measured = Measurement{};
        while (try store.loadRepairStatus() != .complete) measured.add(try store.stepLoadRepairMigration(options(shape, path)));
        try measured.write(shape.name, "uninterrupted");
    }
    return digest(path);
}

test "load repair migration: stop at every page boundary resumes to the uninterrupted digest" {
    var names = std.ArrayListUnmanaged([]u8){};
    defer freeNames(&names);
    var list: [8]Shape = undefined;
    for (try shapes(&list, &names)) |shape| {
        var space = try Workspace.init();
        defer space.deinit();
        const expected = try reference(shape, &space, "reference.sqlite");
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = try space.path(&buffer, "resumed.sqlite");
        try prepare(shape, path);
        const original = try digest(path);
        var commits: usize = 0;
        while (true) : (commits += 1) {
            var store: Store = undefined;
            try openState(&store, path);
            defer store.close();
            if (try store.loadRepairStatus() == .complete) {
                try store.requireLoadRepairAdmission();
                break;
            }
            if (commits > 0) try t.expectError(error.LoadRepairMigrationIncomplete, store.requireLoadRepairAdmission());
            _ = try store.stepLoadRepairMigration(options(shape, path));
        }
        try t.expect(commits > 20);
        try t.expectEqualSlices(u8, &expected, &try digest(path));
        // The recorded backup is the untouched schema-23 state.
        var backup_buffer: [std.fs.max_path_bytes]u8 = undefined;
        try t.expectEqualSlices(u8, &original, &try digest(try repair.backupPath(&backup_buffer, path)));
    }
}

const Crash = struct {
    phase: ?repair.Phase,
    fn hook(context: ?*anyopaque, phase: ?repair.Phase) void {
        const self: *const Crash = @ptrCast(@alignCast(context.?));
        if (phase == self.phase) std.posix.exit(42);
    }
};

// Dies with the named transaction open, as a process crash would leave it.
fn crashInside(shape: Shape, path: []const u8, phase: ?repair.Phase) !void {
    const child = try std.posix.fork();
    if (child == 0) {
        var crash = Crash{ .phase = phase };
        var store: Store = undefined;
        openState(&store, path) catch std.posix.exit(3);
        var value = options(shape, path);
        value.hooks.context = &crash;
        value.hooks.before_commit = Crash.hook;
        store.completeLoadRepairMigration(value) catch |failure| {
            std.debug.print("crash child {?}: {s}\n", .{ phase, @errorName(failure) });
            std.posix.exit(4);
        };
        std.posix.exit(5);
    }
    const result = std.posix.waitpid(child, 0);
    try t.expect(std.posix.W.IFEXITED(result.status));
    try t.expectEqual(@as(u8, 42), std.posix.W.EXITSTATUS(result.status));
}

test "load repair migration: a crash inside every swap, index build and final commit resumes to the reference digest" {
    const points = [_]?repair.Phase{ null, .detail_sequence_index, .detail_age_index, .detail_subject_index, .detail_evidence_index, .targets_swap, .observations_swap, .spent_index, .pending_intent_index, .events_swap, .verify };
    var names = std.ArrayListUnmanaged([]u8){};
    defer freeNames(&names);
    var list: [8]Shape = undefined;
    for (try shapes(&list, &names)) |shape| {
        var space = try Workspace.init();
        defer space.deinit();
        const expected = try reference(shape, &space, "reference.sqlite");
        for (points) |point| {
            var buffer: [std.fs.max_path_bytes]u8 = undefined;
            const path = try space.path(&buffer, "crashed.sqlite");
            var backup_buffer: [std.fs.max_path_bytes]u8 = undefined;
            const backup = try repair.backupPath(&backup_buffer, path);
            try prepare(shape, path);
            try crashInside(shape, path, point);
            var store: Store = undefined;
            try openState(&store, path);
            defer store.close();
            if (point == null) {
                // The fence never committed, so the backup is unrecorded and is refused
                // rather than adopted; the operator moves it aside.
                try t.expectEqual(repair.Status.ready, try store.loadRepairStatus());
                try t.expectError(error.LoadRepairBackupExists, store.stepLoadRepairMigration(options(shape, path)));
                try std.fs.cwd().deleteFile(backup);
            } else try t.expectEqual(point.?, (try store.loadRepairProgress()).phase);
            try store.completeLoadRepairMigration(options(shape, path));
            try t.expectEqualSlices(u8, &expected, &try digest(path));
            try std.fs.cwd().deleteFile(path);
            try std.fs.cwd().deleteFile(backup);
            for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
                var side: [std.fs.max_path_bytes]u8 = undefined;
                std.fs.cwd().deleteFile(try std.fmt.bufPrint(&side, "{s}{s}", .{ path, suffix })) catch {};
            }
        }
    }
}

fn stepUntil(store: *Store, value: repair.Options, phase: repair.Phase) !void {
    while ((try store.loadRepairProgress()).phase != phase) _ = try store.stepLoadRepairMigration(value);
}

fn startAndStepUntil(store: *Store, value: repair.Options, phase: repair.Phase) !void {
    _ = try store.stepLoadRepairMigration(value);
    try stepUntil(store, value, phase);
}

test "load repair migration: an injected failure mid-swap restores foreign key enforcement" {
    var space = try Workspace.init();
    defer space.deinit();
    const shape = Shape{ .name = "constructed", .source = null, .window_rows = null };
    const expected = try reference(shape, &space, "reference.sqlite");
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try space.path(&buffer, "swap.sqlite");
    try prepare(shape, path);
    var store: Store = undefined;
    try openState(&store, path);
    defer store.close();
    try startAndStepUntil(&store, options(shape, path), .events_swap);
    const events = try store.inspectInteger("SELECT count(*) FROM confirmed_effect_events;");
    store.fail_at = .during_load_repair_events_swap;
    try t.expectError(error.InjectedFailure, store.stepLoadRepairMigration(options(shape, path)));
    store.fail_at = null;
    try t.expectEqual(@as(i64, 1), try store.inspectInteger("PRAGMA foreign_keys;"));
    try t.expectEqual(@as(i64, 24), try store.inspectInteger("PRAGMA user_version;"));
    try t.expectEqual(repair.Phase.events_swap, (try store.loadRepairProgress()).phase);
    try t.expectEqual(events, try store.inspectInteger("SELECT count(*) FROM confirmed_effect_events;"));
    try store.completeLoadRepairMigration(options(shape, path));
    try t.expectEqualSlices(u8, &expected, &try digest(path));
}

// A swap only frees pages, so the file-growing steps are the backup, a copy and a backfill.
const FullPoint = enum { backup, events_copy, details };

test "load repair migration: SQLITE_FULL during backup, copy and swap refuses and later resumes" {
    var space = try Workspace.init();
    defer space.deinit();
    const shape = Shape{ .name = "constructed", .source = null, .window_rows = null };
    const expected = try reference(shape, &space, "reference.sqlite");
    for (std.enums.values(FullPoint)) |point| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = try space.path(&buffer, @tagName(point));
        try prepare(shape, path);
        var store: Store = undefined;
        try openState(&store, path);
        defer store.close();
        var value = options(shape, path);
        switch (point) {
            .backup => {
                value.hooks.backup_max_page_count = 2;
                try t.expectError(error.StorageFull, store.stepLoadRepairMigration(value));
                try t.expectEqual(repair.Status.ready, try store.loadRepairStatus());
                var backup_buffer: [std.fs.max_path_bytes]u8 = undefined;
                try t.expectError(error.FileNotFound, std.fs.cwd().access(try repair.backupPath(&backup_buffer, path), .{}));
                value.hooks.backup_max_page_count = null;
            },
            .events_copy, .details => {
                try startAndStepUntil(&store, value, if (point == .events_copy) .events_copy else .details);
                // Consume the free list so the page must grow the file, then cap it there.
                const free = try store.inspectInteger("PRAGMA freelist_count;");
                const page_size = try store.inspectInteger("PRAGMA page_size;");
                try exec(&store, "CREATE TABLE filler(x); INSERT INTO filler VALUES(zeroblob({d}));", .{free * page_size});
                const pages = try store.inspectInteger("PRAGMA page_count;");
                try exec(&store, "PRAGMA max_page_count={d};", .{pages});
                const before = try store.loadRepairProgress();
                try t.expectError(error.StorageFull, store.stepLoadRepairMigration(value));
                try t.expectEqual(@as(i64, 1), try store.inspectInteger("PRAGMA foreign_keys;"));
                try t.expectEqual(repair.Status.incomplete, try store.loadRepairStatus());
                try t.expectEqualDeep(before, try store.loadRepairProgress());
                try store.inspectExec("DROP TABLE filler;");
                try store.configureRuntimeLimits();
            },
        }
        try store.completeLoadRepairMigration(value);
        try t.expectEqualSlices(u8, &expected, &try digest(path));
    }
}

test "load repair migration: a stale partial backup is replaced; a recorded backup is verified and never retaken" {
    var space = try Workspace.init();
    defer space.deinit();
    const shape = Shape{ .name = "constructed", .source = null, .window_rows = 64 };
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try space.path(&buffer, "backup.sqlite");
    var backup_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const backup = try repair.backupPath(&backup_buffer, path);
    try prepare(shape, path);
    // A backup interrupted before its rename leaves only the partial file.
    var partial_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const partial = try std.fmt.bufPrint(&partial_buffer, "{s}.partial", .{backup});
    try std.fs.cwd().writeFile(.{ .sub_path = partial, .data = "interrupted" });
    const identity = blk: {
        var store: Store = undefined;
        try openState(&store, path);
        defer store.close();
        _ = try store.stepLoadRepairMigration(options(shape, path));
        try t.expectError(error.FileNotFound, std.fs.cwd().access(partial, .{}));
        const stat = try std.fs.cwd().statFile(backup);
        try t.expectEqual(@as(std.fs.File.Mode, 0o600), stat.mode & 0o777);
        break :blk .{ stat.inode, stat.mtime };
    };
    for (0..3) |_| {
        var store: Store = undefined;
        try openState(&store, path);
        defer store.close();
        _ = try store.stepLoadRepairMigration(options(shape, path));
    }
    const stat = try std.fs.cwd().statFile(backup);
    try t.expectEqual(identity[0], stat.inode);
    try t.expectEqual(identity[1], stat.mtime);
    {
        const file = try std.fs.cwd().openFile(backup, .{ .mode = .read_write });
        defer file.close();
        try file.seekFromEnd(0);
        try file.writeAll("x");
    }
    var store: Store = undefined;
    try openState(&store, path);
    defer store.close();
    try t.expectError(error.LoadRepairBackupInvalid, store.stepLoadRepairMigration(options(shape, path)));
    try std.fs.cwd().deleteFile(backup);
    try t.expectError(error.LoadRepairBackupInvalid, store.stepLoadRepairMigration(options(shape, path)));
}

test "load repair migration: summaries, candidates, markers and superseded targets equal an independent recomputation" {
    var names = std.ArrayListUnmanaged([]u8){};
    defer freeNames(&names);
    var list: [8]Shape = undefined;
    for (try shapes(&list, &names)) |shape| {
        var space = try Workspace.init();
        defer space.deinit();
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = try space.path(&buffer, "validated.sqlite");
        try prepare(shape, path);
        var store: Store = undefined;
        try openState(&store, path);
        defer store.close();
        const live_confirmed = try store.inspectInteger("SELECT count(*) FROM effect_owners o JOIN confirmed_effect_events e ON e.scope_key=o.scope_key AND e.jail=o.jail AND e.decision_id=o.decision_id WHERE o.lease_kind<>0;");
        const details = try store.inspectInteger("SELECT count(*) FROM confirmed_event_details;");
        const orphaned = try store.inspectInteger("SELECT count(*) FROM action_targets a WHERE a.status IN(1,2,5) AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=a.scope_key AND o.jail=a.jail AND o.decision_id=a.action_id);");
        const current_unsettled = try store.inspectInteger("SELECT count(*) FROM action_targets a JOIN effect_owners o ON o.scope_key=a.scope_key AND o.jail=a.jail AND o.decision_id=a.action_id WHERE a.status IN(1,2,5);");
        if (shape.source == null) try t.expect(orphaned > 0);
        try store.completeLoadRepairMigration(options(shape, path));
        try t.expectEqual(orphaned, try store.inspectInteger("SELECT superseded_targets FROM load_repair_migration;"));
        try t.expectEqual(orphaned, try store.inspectInteger("SELECT count(*) FROM action_targets WHERE status=7;"));
        try t.expectEqual(current_unsettled, try store.inspectInteger("SELECT count(*) FROM action_targets WHERE status IN(1,2,5);"));
        try t.expectEqual(@as(i64, 0), try store.inspectInteger(
            \\SELECT count(*) FROM (SELECT d.family,d.subject,count(*) c,coalesce(sum(length(CAST(d.evidence AS BLOB))),0) b,min(s.sequence) m,min(CASE WHEN d.evidence IS NOT NULL THEN s.sequence END) me
            \\FROM confirmed_event_details d JOIN confirmed_history_sequence s ON s.event_id=d.event_id WHERE d.family IS NOT NULL GROUP BY d.family,d.subject) x
            \\FULL OUTER JOIN retained_subject_summaries r ON r.family=x.family AND r.subject=x.subject
            \\WHERE r.detail_count IS NOT x.c OR r.evidence_bytes IS NOT x.b OR r.earliest_sequence IS NOT x.m OR r.earliest_evidence_sequence IS NOT x.me
            \\OR r.candidate_sequence IS NOT (CASE WHEN x.c>4 THEN x.m WHEN x.b>16384 THEN x.me END);
        ));
        try t.expectEqual(details, try store.inspectInteger("SELECT count(*) FROM confirmed_event_details d JOIN confirmed_effect_events e ON e.event_id=d.event_id LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE d.family IS r.family AND d.subject IS r.subject AND d.confirmed_us=e.confirmed_us;"));
        try t.expectEqual(live_confirmed, try store.inspectInteger("SELECT count(*) FROM confirmation_markers m JOIN effect_owners o ON o.scope_key=m.scope_key AND o.jail=m.jail JOIN confirmed_effect_events e ON e.event_id=m.event_id WHERE o.decision_id=m.decision_id AND e.decision_id=m.decision_id AND o.lease_kind<>0;"));
        try t.expectEqual(@as(i64, 1), try store.inspectInteger("SELECT (SELECT live FROM effect_owner_live)=(SELECT count(*) FROM effect_owners WHERE lease_kind<>0);"));
        try t.expectEqual(@as(i64, 0), try store.inspectInteger("SELECT count(*) FROM (SELECT intent_id FROM effect_observations GROUP BY intent_id HAVING count(*)>4);"));
    }
    // A summary disagreeing with its details is refused before completion.
    var space = try Workspace.init();
    defer space.deinit();
    const shape = Shape{ .name = "constructed", .source = null, .window_rows = null };
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try space.path(&buffer, "mismatch.sqlite");
    try prepare(shape, path);
    var store: Store = undefined;
    try openState(&store, path);
    defer store.close();
    try startAndStepUntil(&store, options(shape, path), .validate);
    try store.inspectExec("UPDATE retained_subject_summaries SET evidence_bytes=evidence_bytes+1 WHERE rowid=(SELECT max(rowid) FROM retained_subject_summaries);");
    try t.expectError(error.LoadRepairVerificationFailed, store.stepLoadRepairMigration(options(shape, path)));
    try t.expectEqual(repair.Status.incomplete, try store.loadRepairStatus());
}

test "load repair migration: the verify allowance interrupts one callback short and passes at the measured cost" {
    var names = std.ArrayListUnmanaged([]u8){};
    defer freeNames(&names);
    var list: [8]Shape = undefined;
    for (try shapes(&list, &names)) |shape| {
        var space = try Workspace.init();
        defer space.deinit();
        var measured: u32 = 0;
        for ([_][]const u8{ "measured.sqlite", "bounded.sqlite" }) |name| {
            var buffer: [std.fs.max_path_bytes]u8 = undefined;
            const path = try space.path(&buffer, name);
            try prepare(shape, path);
            var store: Store = undefined;
            try openState(&store, path);
            defer store.close();
            var value = options(shape, path);
            try startAndStepUntil(&store, value, .verify);
            if (measured == 0) {
                measured = (try store.stepLoadRepairMigration(value)).callbacks;
                std.debug.print("verify callbacks {s}: {d}\n", .{ shape.name, measured });
                try t.expect(measured > 0 and measured <= repair.migration_verify);
                continue;
            }
            value.hooks.verify_allowance = measured - 1;
            try t.expectError(error.Interrupted, store.stepLoadRepairMigration(value));
            try t.expectEqual(repair.Status.incomplete, try store.loadRepairStatus());
            try t.expectEqual(@as(i64, 1), try store.inspectInteger("SELECT state FROM retention_policy;"));
            value.hooks.verify_allowance = measured;
            try t.expectEqual(measured, (try store.stepLoadRepairMigration(value)).callbacks);
            try t.expectEqual(repair.Status.complete, try store.loadRepairStatus());
        }
    }
}

const OldRun = enum { refused, admitted };

// Minimal configuration for fixtures built without a daemon: v0.4.4 refuses a schema-24
// file while opening state, before any source or policy comparison.
const generic_config =
    \\[global]
    \\native_ingestion = true
    \\log_level = "info"
    \\metrics_enabled = false
    \\firewall = "nftables"
    \\[jails.sshd]
    \\enabled = true
    \\filter = "sshd"
    \\source = "file"
    \\timestamp = "undated"
    \\logpath = ["{s}/sshd.log"]
    \\
;

// Writes `template` with its state, socket and log target moved into `work`. Source paths
// stay as recorded because v0.4.4 refuses a changed source configuration.
fn writeConfig(work: []const u8, template: []const u8) ![]u8 {
    var output = std.ArrayList(u8).init(t.allocator);
    defer output.deinit();
    const writer = output.writer();
    var lines = std.mem.splitScalar(u8, template, '\n');
    while (lines.next()) |line| {
        const key = std.mem.trim(u8, line[0 .. std.mem.indexOfScalar(u8, line, '=') orelse 0], " ");
        if (std.mem.eql(u8, key, "log_target") or std.mem.eql(u8, key, "socket_path") or std.mem.eql(u8, key, "state_file")) continue;
        try writer.print("{s}\n", .{line});
        if (std.mem.eql(u8, line, "[global]")) try writer.print("log_target = \"{s}/daemon.log\"\nsocket_path = \"{s}/f.sock\"\nstate_file = \"{s}/state/fail2zig.sqlite\"\n", .{ work, work, work });
    }
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    try std.fs.cwd().writeFile(.{ .sub_path = try std.fmt.bufPrint(&buffer, "{s}/config.toml", .{work}), .data = output.items });
    return std.fmt.allocPrint(t.allocator, "{s}/config.toml", .{work});
}

fn fileContains(path: []const u8, needle: []const u8) !bool {
    const text = std.fs.cwd().readFileAlloc(t.allocator, path, 1 << 20) catch |failure| switch (failure) {
        error.FileNotFound => return false,
        else => return failure,
    };
    defer t.allocator.free(text);
    return std.mem.indexOf(u8, text, needle) != null;
}

// Runs the release binary on `state` in a private rootless network namespace and classifies
// the outcome from its log: an exit before admission, or admission without a startup failure.
fn runOldBinary(binary: []const u8, work: []const u8, template: []const u8, state: []const u8) !OldRun {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const state_dir = try std.fmt.bufPrint(&buffer, "{s}/state", .{work});
    try std.fs.cwd().makePath(state_dir);
    {
        var directory = try std.fs.cwd().openDir(state_dir, .{ .iterate = true });
        defer directory.close();
        try directory.chmod(0o700);
    }
    var target_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buffer, "{s}/fail2zig.sqlite", .{state_dir});
    try std.fs.cwd().copyFile(state, std.fs.cwd(), target, .{});
    {
        const file = try std.fs.cwd().openFile(target, .{ .mode = .read_write });
        defer file.close();
        try file.chmod(0o600);
    }
    const installed = try fileSha256(target);
    const config = try writeConfig(work, template);
    defer t.allocator.free(config);
    var log_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const log = try std.fmt.bufPrint(&log_buffer, "{s}/daemon.log", .{work});
    var child = std.process.Child.init(&.{ "unshare", "-Urn", binary, "--config", config }, t.allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    var outcome: ?OldRun = null;
    var exited = false;
    for (0..600) |_| {
        if (std.posix.waitpid(child.id, std.posix.W.NOHANG).pid != 0) {
            exited = true;
            outcome = .refused;
            break;
        }
        if (try fileContains(log, "protection admission pending")) {
            // Hold briefly so a failure right after admission is still observed.
            std.time.sleep(3 * std.time.ns_per_s);
            outcome = .admitted;
            break;
        }
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    if (!exited) {
        std.posix.kill(child.id, std.posix.SIG.TERM) catch {};
        _ = std.posix.waitpid(child.id, 0);
    }
    const result = outcome orelse return error.OldBinaryTimeout;
    if (try fileContains(log, "startup failed")) {
        if (result == .admitted) return error.OldBinaryFailedAfterAdmission;
        // Refusal must leave the installed file untouched.
        try t.expectEqualSlices(u8, &installed, &try fileSha256(target));
        return .refused;
    }
    if (result == .refused) return error.OldBinaryExitedWithoutRefusal;
    return result;
}

fn fileSha256(path: []const u8) !Digest {
    const bytes = try std.fs.cwd().readFileAlloc(t.allocator, path, 1 << 30);
    defer t.allocator.free(bytes);
    var hash: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    return hash;
}

test "load repair migration: v0.4.4 refuses the migrated state and admits the restored backup" {
    const root = std.process.getEnvVarOwned(t.allocator, fixtures_env) catch |failure| switch (failure) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return failure,
    };
    defer t.allocator.free(root);
    const binary = try std.fs.path.join(t.allocator, &.{ root, "fail2zig-v0.4.4" });
    defer t.allocator.free(binary);
    try std.fs.cwd().access(binary, .{});
    var names = std.ArrayListUnmanaged([]u8){};
    defer freeNames(&names);
    var list: [8]Shape = undefined;
    var restored: usize = 0;
    for (try shapes(&list, &names)) |shape| {
        const source = shape.source orelse continue;
        var space = try Workspace.init();
        defer space.deinit();
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = try space.path(&path_buffer, "migrated.sqlite");
        _ = try reference(shape, &space, "migrated.sqlite");
        const recorded_path = try std.fs.path.join(t.allocator, &.{ std.fs.path.dirname(source).?, "config.toml" });
        defer t.allocator.free(recorded_path);
        const recorded: ?[]u8 = std.fs.cwd().readFileAlloc(t.allocator, recorded_path, 1 << 16) catch |failure| switch (failure) {
            error.FileNotFound => null,
            else => return failure,
        };
        defer if (recorded) |value| t.allocator.free(value);
        const generic = try std.fmt.allocPrint(t.allocator, generic_config, .{space.root});
        defer t.allocator.free(generic);
        const template = recorded orelse generic;
        var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
        try t.expectEqual(OldRun.refused, try runOldBinary(binary, try space.path(&work_buffer, "refuse"), template, path));
        var log_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const refusal_log = try std.fmt.bufPrint(&log_buffer, "{s}/refuse/daemon.log", .{space.root});
        if (!try fileContains(refusal_log, "UnsupportedSchema")) {
            const text = try std.fs.cwd().readFileAlloc(t.allocator, refusal_log, 1 << 20);
            defer t.allocator.free(text);
            std.debug.print("v0.4.4 refusal without UnsupportedSchema for {s}:\n{s}\n", .{ shape.name, text });
            return error.TestUnexpectedResult;
        }
        // Rollback restores the recorded backup under the release that wrote it. Fixtures
        // built without a daemon carry a synthetic firewall selector and are not admissible.
        if (recorded == null) continue;
        var backup_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const backup = try repair.backupPath(&backup_buffer, path);
        try t.expectEqual(OldRun.admitted, try runOldBinary(binary, try space.path(&work_buffer, "restore"), template, backup));
        restored += 1;
    }
    try t.expect(restored > 0);
}
