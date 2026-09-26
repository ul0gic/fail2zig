// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const engine = @import("engine_test");
const Store = engine.core.record_store.Store;
const files = engine.core.durable_file_source;
const native_paths = engine.config.native_paths;
const repair = engine.store.source_repair;
const cli = engine.cli.repair_source;
const t = std.testing;

const jail = "portsentry";
const now_us: i64 = 1_767_225_600_000_000;
const generation = [_]u8{0x47} ** 32;
const prior_revision: u64 = 5;
const occurrence = "file:v1:prior";

const Fixture = struct {
    temp: t.TmpDir,
    root: []u8,
    state: []u8,
    config: []u8,
    log: []u8,
    source: []u8,

    fn init() !Fixture {
        var temp = t.tmpDir(.{});
        errdefer temp.cleanup();
        const root = try temp.dir.realpathAlloc(t.allocator, ".");
        errdefer t.allocator.free(root);
        // The state parent must not be group writable, whatever the umask.
        try chmod(root, 0o700);
        const state = try std.fmt.allocPrint(t.allocator, "{s}/state.sqlite", .{root});
        errdefer t.allocator.free(state);
        const config = try std.fmt.allocPrint(t.allocator, "{s}/config.toml", .{root});
        errdefer t.allocator.free(config);
        const log = try std.fmt.allocPrint(t.allocator, "{s}/portsentry.history", .{root});
        errdefer t.allocator.free(log);
        {
            const text = try std.fmt.allocPrint(t.allocator, "[global]\nstate_file = \"{s}\"\n\n[jails.portsentry]\nfilter = \"portsentry\"\nlogpath = [\"{s}\"]\n", .{ state, log });
            defer t.allocator.free(text);
            try std.fs.cwd().writeFile(.{ .sub_path = config, .data = text });
            try chmod(config, 0o640);
        }
        try std.fs.cwd().writeFile(.{ .sub_path = log, .data = "old line 1\n" ** 20 });
        const stat = try std.posix.fstatat(std.posix.AT.FDCWD, log, 0);
        const source = try std.fmt.allocPrint(t.allocator, "{s}:{s}:{d}:{d}", .{ jail, log, stat.dev, stat.ino });
        return .{ .temp = temp, .root = root, .state = state, .config = config, .log = log, .source = source };
    }

    fn deinit(self: *Fixture) void {
        for ([_][]u8{ self.root, self.state, self.config, self.log, self.source }) |value| t.allocator.free(value);
        self.temp.cleanup();
    }

    // A schema-23 state whose file cursor sits at the end of the current log, migrated to 24.
    fn build(self: *Fixture) !void {
        {
            var store = try Store.open(t.allocator, self.state);
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

            const file = try std.fs.cwd().openFile(self.log, .{});
            defer file.close();
            const stat = try std.posix.fstat(file.handle);
            const size: u64 = @intCast(stat.size);
            const length: u8 = @intCast(@min(size, 64));
            const committed = files.Resume{ .incarnation = [_]u8{0x11} ** 16, .device = @intCast(stat.dev), .inode = @intCast(stat.ino), .offset = size, .prefix_len = length, .prefix_hash = try files.prefixDigest(file, length) };
            const cursor = try std.json.stringifyAlloc(t.allocator, committed, .{});
            defer t.allocator.free(cursor);
            var payload = [_]u8{0} ** 104;
            @memcpy(payload[0..4], "F2NT");
            payload[4] = 1;
            @memcpy(payload[8..40], &generation);
            const sql = try std.fmt.allocPrintZ(t.allocator,
                \\BEGIN IMMEDIATE;
                \\INSERT INTO checkpoints VALUES('{s}',x'{s}',{d});
                \\INSERT INTO records(jail,source,occurrence,raw_hash,cursor,disposition) VALUES('{s}','{s}','{s}',zeroblob(32),CAST('{s}' AS BLOB),'eligible');
                \\INSERT INTO source_cursors VALUES('{s}','{s}',CAST('{s}' AS BLOB),'{s}','{s}');
                \\INSERT INTO consumer_manifests VALUES('{s}','{s}',x'{s}',zeroblob(32),1,0);
                \\COMMIT;
            , .{
                jail,   std.fmt.fmtSliceHexLower(&payload), prior_revision,
                jail,   self.source,                        occurrence,
                cursor, jail,                               self.source,
                cursor, occurrence,                         self.log,
                jail,   self.source,                        std.fmt.fmtSliceHexLower(&generation),
            });
            defer t.allocator.free(sql);
            try store.inspectExec(sql);
        }
        var store = try Store.openRuntime(t.allocator, self.state);
        defer store.close();
        try store.configureRuntimeLimits();
        try store.completeLoadRepairMigration(.{ .state_path = self.state, .now_us = now_us, .history_max_matches = 4 });
        try t.expectEqual(.complete, try store.loadRepairStatus());
    }

    // Same inode, shorter than the committed offset: what PortSentry does on start.
    fn truncate(self: *const Fixture, data: []const u8) !void {
        const file = try std.fs.cwd().openFile(self.log, .{ .mode = .read_write });
        defer file.close();
        try file.setEndPos(0);
        try file.pwriteAll(data, 0);
    }

    fn append(self: *const Fixture, data: []const u8) !void {
        const file = try std.fs.cwd().openFile(self.log, .{ .mode = .read_write });
        defer file.close();
        try file.pwriteAll(data, try file.getEndPos());
    }

    fn request(self: *const Fixture, token: []const u8) repair.Request {
        return .{ .jail = jail, .path = self.log, .token = token };
    }

    fn apply(self: *const Fixture, value: repair.Request, hooks: repair.Hooks) !repair.Outcome {
        var store = try Store.open(t.allocator, self.state);
        defer store.close();
        var diagnostic: repair.Diagnostic = .{};
        return repair.repair(&store, t.allocator, value, now_us, hooks, &diagnostic);
    }

    fn integer(self: *const Fixture, comptime sql: [:0]const u8) !i64 {
        var store = try Store.open(t.allocator, self.state);
        defer store.close();
        return store.inspectInteger(sql);
    }

    fn currentCursor(self: *const Fixture) ![]u8 {
        var store = try Store.open(t.allocator, self.state);
        defer store.close();
        return (try store.sourceCursor(t.allocator, jail, self.source)).?;
    }

    fn exec(self: *const Fixture, sql: [:0]const u8) void {
        var store = Store.open(t.allocator, self.state) catch return;
        defer store.close();
        store.inspectExec(sql) catch {};
    }
};

fn chmod(path: []const u8, mode: std.posix.mode_t) !void {
    try std.posix.fchmodat(std.posix.AT.FDCWD, path, mode, 0);
}

fn runCli(fx: *const Fixture, token: []const u8, out: *std.ArrayList(u8), err: *std.ArrayList(u8)) cli.ExitClass {
    return cli.execute(t.allocator, .{ .config = fx.config, .jail = jail, .source = fx.log, .token = token }, now_us, out.writer(), err.writer());
}

fn expectRefused(expected: anyerror, result: anytype) !void {
    if (result) |outcome| {
        outcome.deinit(t.allocator);
        return error.TestUnexpectedResult;
    } else |failure| try t.expectEqual(expected, failure);
}

// Store.open creates a missing file; the CLI must refuse before opening anything.
test "offline source repair: missing state is refused without creating it" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var out = std.ArrayList(u8).init(t.allocator);
    defer out.deinit();
    var err = std.ArrayList(u8).init(t.allocator);
    defer err.deinit();
    try t.expectEqual(cli.ExitClass.rejected, runCli(&fx, "repair-1", &out, &err));
    try t.expectError(error.FileNotFound, std.fs.cwd().access(fx.state, .{}));
    try t.expect(std.mem.indexOf(u8, err.items, "no state was created") != null);
}

// A running daemon holds the authority lock; the repair must not write under it.
test "offline source repair: a held state authority refuses, then the released state repairs" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.build();
    try fx.truncate("new 1\n");
    const before = try fx.currentCursor();
    defer t.allocator.free(before);
    var out = std.ArrayList(u8).init(t.allocator);
    defer out.deinit();
    var err = std.ArrayList(u8).init(t.allocator);
    defer err.deinit();
    {
        const held = (try native_paths.lockStateIfPresent(fx.state)).?;
        defer held.close();
        try t.expectEqual(cli.ExitClass.rejected, runCli(&fx, "repair-1", &out, &err));
        try t.expect(std.mem.indexOf(u8, err.items, "stop fail2zig first") != null);
        const unchanged = try fx.currentCursor();
        defer t.allocator.free(unchanged);
        try t.expectEqualStrings(before, unchanged);
    }
    try t.expectEqual(cli.ExitClass.success, runCli(&fx, "repair-1", &out, &err));
    try t.expect(std.mem.indexOf(u8, out.items, "truncation acknowledged") != null);
    try t.expect(std.mem.indexOf(u8, out.items, "extent is unknown") != null);
    try t.expect(std.mem.indexOf(u8, out.items, "protection for every jail may be absent") != null);
}

const Mutation = struct {
    fx: *const Fixture,
    kind: enum { generation, checkpoint, file },
    fn run(context: ?*anyopaque) void {
        const self: *Mutation = @ptrCast(@alignCast(context.?));
        switch (self.kind) {
            .generation => self.fx.exec("UPDATE checkpoints SET payload=CAST('F2NT' AS BLOB)||x'01000000'||randomblob(32)||substr(payload,41);"),
            .checkpoint => self.fx.exec("UPDATE checkpoints SET revision=revision+1;"),
            .file => self.fx.append("raced\n") catch {},
        }
    }
};

// Observation and commit are separate reads; a change between them must refuse unchanged.
test "offline source repair: stale generation, checkpoint and file identity refuse the commit" {
    const cases = .{ .{ .generation, error.StaleGeneration }, .{ .checkpoint, error.StaleCheckpoint }, .{ .file, error.SourceChanged } };
    inline for (cases) |case| {
        var fx = try Fixture.init();
        defer fx.deinit();
        try fx.build();
        try fx.truncate("new 1\n");
        const before = try fx.currentCursor();
        defer t.allocator.free(before);
        var mutation = Mutation{ .fx = &fx, .kind = case[0] };
        try expectRefused(case[1], fx.apply(fx.request("repair-1"), .{ .context = &mutation, .after_observe = Mutation.run }));
        const after = try fx.currentCursor();
        defer t.allocator.free(after);
        try t.expectEqualStrings(before, after);
        try t.expectEqual(@as(i64, 0), try fx.integer("SELECT count(*) FROM source_repairs;"));
    }
}

// An admitted receipt is an unfinished processing obligation, never discarded by repair.
test "offline source repair: a pending receipt refuses and is preserved" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.build();
    try fx.truncate("new 1\n");
    const sql = try std.fmt.allocPrintZ(t.allocator, "INSERT INTO pending_receipts VALUES('{s}','{s}',x'{s}','file:v1:pending',zeroblob(32),CAST('c' AS BLOB),{d});", .{ jail, fx.source, std.fmt.fmtSliceHexLower(&generation), now_us });
    defer t.allocator.free(sql);
    fx.exec(sql);
    try t.expectEqual(@as(i64, 1), try fx.integer("SELECT count(*) FROM pending_receipts;"));
    try expectRefused(error.PendingReceipt, fx.apply(fx.request("repair-1"), .{}));
    try t.expectEqual(@as(i64, 1), try fx.integer("SELECT count(*) FROM pending_receipts;"));
    try t.expectEqual(@as(i64, prior_revision), try fx.integer("SELECT revision FROM checkpoints;"));
}

// A token names one repair; reusing it elsewhere must not report someone else's outcome.
test "offline source repair: a token reused with different arguments fails" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.build();
    try fx.truncate("new 1\n");
    const first = try fx.apply(fx.request("repair-1"), .{});
    first.deinit(t.allocator);
    try expectRefused(error.RepairTokenMismatch, fx.apply(.{ .jail = jail, .path = "/var/log/other.history", .token = "repair-1" }, .{}));
    try expectRefused(error.RepairTokenMismatch, fx.apply(.{ .jail = "sshd", .path = fx.log, .token = "repair-1" }, .{}));
}

// The operator cannot tell whether an interrupted command committed; rerunning must be exact.
test "offline source repair: crash before and after commit replays the committed outcome" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.build();
    try fx.truncate("new 1\n");
    try expectRefused(error.InjectedFailure, fx.apply(fx.request("repair-1"), .{ .fail_at = .before_commit }));
    try t.expectEqual(@as(i64, 0), try fx.integer("SELECT count(*) FROM source_repairs;"));
    try t.expectEqual(@as(i64, prior_revision), try fx.integer("SELECT revision FROM checkpoints;"));

    try expectRefused(error.InjectedFailure, fx.apply(fx.request("repair-1"), .{ .fail_at = .after_commit }));
    const committed = try fx.currentCursor();
    defer t.allocator.free(committed);
    const replayed = try fx.apply(fx.request("repair-1"), .{});
    defer replayed.deinit(t.allocator);
    try t.expect(replayed.replayed);
    try t.expectEqual(prior_revision, replayed.prior_checkpoint_revision);
    const parsed = try std.json.parseFromSlice(files.Resume, t.allocator, committed, .{});
    defer parsed.deinit();
    try t.expectEqualSlices(u8, &parsed.value.incarnation, &replayed.new_incarnation);
    try t.expectEqual(@as(i64, prior_revision + 1), try fx.integer("SELECT revision FROM checkpoints;"));
    const unchanged = try fx.currentCursor();
    defer t.allocator.free(unchanged);
    try t.expectEqualStrings(committed, unchanged);
}

// Retention is by count, so an old token eventually disappears; its replay must refuse.
test "offline source repair: a replay after eviction refuses as an evicted token" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.build();
    try fx.truncate("new 1\n");
    const first = try fx.apply(fx.request("evicted"), .{});
    first.deinit(t.allocator);
    const filler = try std.fmt.allocPrintZ(t.allocator,
        \\WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{d})
        \\INSERT INTO source_repairs SELECT CAST(printf('%032d',i) AS BLOB),'{s}','filler',zeroblob(32),zeroblob(32),1,1,i,0,zeroblob(32),zeroblob(16),1,{d}+i FROM n;
    , .{ repair.retained_repairs, jail, now_us });
    defer t.allocator.free(filler);
    fx.exec(filler);
    // A second in-place truncation below the new prefix; its repair applies retention.
    try fx.truncate("");
    const second = try fx.apply(fx.request("later"), .{});
    second.deinit(t.allocator);
    try t.expectEqual(repair.retained_repairs, try fx.integer("SELECT count(*) FROM source_repairs WHERE outcome=1;"));
    var diagnostic: repair.Diagnostic = .{};
    var store = try Store.open(t.allocator, fx.state);
    defer store.close();
    try expectRefused(error.RepairTokenEvicted, repair.repair(&store, t.allocator, fx.request("evicted"), now_us, .{}, &diagnostic));
}

// An evicted token keeps a tombstone, so replaying it can never commit a second repair.
test "offline source repair: an evicted token never commits again and tombstones are bounded" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.build();
    try fx.truncate("new 1\n");
    const first = try fx.apply(fx.request("evicted"), .{});
    first.deinit(t.allocator);
    const filler = try std.fmt.allocPrintZ(t.allocator,
        \\WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{d})
        \\INSERT INTO source_repairs SELECT CAST(printf('%032d',i) AS BLOB),'{s}','filler',zeroblob(32),zeroblob(32),1,1,i,0,zeroblob(32),zeroblob(16),1,{d}+i FROM n;
    , .{ 256, jail, now_us });
    defer t.allocator.free(filler);
    fx.exec(filler);
    try fx.truncate("ab\n");
    const second = try fx.apply(fx.request("later"), .{});
    second.deinit(t.allocator);
    // The same source is truncated in place again, so only the tombstone can refuse the replay.
    try fx.truncate("");
    const rows = try fx.integer("SELECT count(*) FROM source_repairs;");
    const revision = try fx.integer("SELECT revision FROM checkpoints;");
    try expectRefused(error.RepairTokenEvicted, fx.apply(fx.request("evicted"), .{}));
    try t.expectEqual(rows, try fx.integer("SELECT count(*) FROM source_repairs;"));
    try t.expectEqual(revision, try fx.integer("SELECT revision FROM checkpoints;"));

    const tombstones = try std.fmt.allocPrintZ(t.allocator,
        \\WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{d})
        \\INSERT INTO source_repairs SELECT CAST(printf('t%031d',i) AS BLOB),'{s}','-',zeroblob(32),zeroblob(32),1,1,i,0,zeroblob(32),zeroblob(16),2,{d}-i FROM n;
    , .{ 4096, jail, now_us });
    defer t.allocator.free(tombstones);
    fx.exec(tombstones);
    try expectRefused(error.RepairHistoryFull, fx.apply(fx.request("fresh"), .{}));
    try t.expectEqual(revision, try fx.integer("SELECT revision FROM checkpoints;"));
}

// Only a path the jail is configured to read may be repaired under that jail.
test "offline source repair: a source outside the jail logpath is refused" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.build();
    const other = try std.fmt.allocPrint(t.allocator, "{s}/other.history", .{fx.root});
    defer t.allocator.free(other);
    try std.fs.cwd().writeFile(.{ .sub_path = other, .data = "x\n" });
    var out = std.ArrayList(u8).init(t.allocator);
    defer out.deinit();
    var err = std.ArrayList(u8).init(t.allocator);
    defer err.deinit();
    try t.expectEqual(cli.ExitClass.rejected, cli.execute(t.allocator, .{ .config = fx.config, .jail = jail, .source = other, .token = "repair-1" }, now_us, out.writer(), err.writer()));
    try t.expect(std.mem.indexOf(u8, err.items, "not a configured logpath") != null);
}

test "offline source repair: --help prints usage and succeeds" {
    var out = std.ArrayList(u8).init(t.allocator);
    defer out.deinit();
    var err = std.ArrayList(u8).init(t.allocator);
    defer err.deinit();
    try t.expectEqual(cli.ExitClass.success, cli.run(t.allocator, &.{"--help"}, out.writer(), err.writer()));
    try t.expect(std.mem.indexOf(u8, out.items, "repair-source --jail") != null);
}

const Collected = struct {
    messages: std.ArrayList([]u8),
    fn add(record: engine.core.source_record.Record, context: ?*anyopaque) anyerror!void {
        const self: *Collected = @ptrCast(@alignCast(context.?));
        if (record.kind == .data) try self.messages.append(try t.allocator.dupe(u8, record.message));
    }
};

// The repaired cursor must satisfy the same continuity check the daemon runs at start.
test "offline source repair: an acknowledged truncation passes the next start continuity check" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.build();
    try fx.truncate("new 1\n");
    const prior = try fx.currentCursor();
    defer t.allocator.free(prior);
    {
        const parsed = try std.json.parseFromSlice(files.Resume, t.allocator, prior, .{});
        defer parsed.deinit();
        var source = try files.FileSource.init(t.allocator, fx.log, fx.source, .head, parsed.value);
        defer source.deinit();
        try t.expectError(error.ResumeLost, source.verifyContinuity());
        try t.expectEqual(files.Discontinuity.truncated, source.continuity_failure.?.kind);
    }
    const records_before = try fx.integer("SELECT count(*) FROM records;");
    const outcome = try fx.apply(fx.request("repair-1"), .{});
    defer outcome.deinit(t.allocator);
    try t.expect(!outcome.replayed);
    try t.expectEqual(@as(u64, 220), outcome.prior_offset.?);
    try t.expectEqual(@as(u64, 6), outcome.file.size);
    try t.expectEqual(@as(i64, prior_revision + 1), try fx.integer("SELECT revision FROM checkpoints;"));
    try t.expectEqual(records_before, try fx.integer("SELECT count(*) FROM records;"));
    try t.expectEqual(@as(i64, 1), try fx.integer("SELECT count(*) FROM consumer_manifests WHERE ready=1;"));
    try t.expectEqual(@as(i64, 1), try fx.integer("SELECT count(*) FROM source_cursors WHERE occurrence='" ++ occurrence ++ "';"));

    try fx.append("new 2\n");
    const repaired = try fx.currentCursor();
    defer t.allocator.free(repaired);
    const parsed = try std.json.parseFromSlice(files.Resume, t.allocator, repaired, .{});
    defer parsed.deinit();
    try t.expectEqual(@as(u64, 0), parsed.value.offset);
    var source = try files.FileSource.init(t.allocator, fx.log, fx.source, .head, parsed.value);
    defer source.deinit();
    try t.expect(try source.verifyContinuity());
    var collected = Collected{ .messages = std.ArrayList([]u8).init(t.allocator) };
    defer {
        for (collected.messages.items) |message| t.allocator.free(message);
        collected.messages.deinit();
    }
    while (try source.pollTurn(Collected.add, &collected, true)) {}
    try t.expectEqual(@as(usize, 2), collected.messages.items.len);
    try t.expectEqualStrings("new 1", collected.messages.items[0]);
    try t.expectEqualStrings("new 2", collected.messages.items[1]);
}
