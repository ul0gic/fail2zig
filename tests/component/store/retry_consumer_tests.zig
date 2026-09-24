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

test "native retry: runtime SQL limits interrupt bounded work and WAL maintenance refuses pinned readers" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "budgets.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    const hard_limit = @extern(*const fn (i64) callconv(.c) i64, .{ .name = "sqlite3_hard_heap_limit64" });
    const prior = hard_limit(-1);
    defer _ = hard_limit(prior);
    try store.configureRuntimeLimits();
    try std.testing.expectEqual(@as(i64, 0), try store.integer("PRAGMA wal_autocheckpoint;"));
    try std.testing.expectEqual(@as(i64, -2048), try store.integer("PRAGMA cache_size;"));
    try std.testing.expectError(error.Interrupted, store.integer("WITH RECURSIVE work(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM work WHERE n<2000000) SELECT sum(n) FROM work;"));
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT 1;"));
    try store.exec("CREATE TABLE volume(payload BLOB);");
    var reader = try Store.open(a, path);
    defer reader.close();
    try reader.exec("BEGIN;");
    _ = try reader.integer("SELECT count(*) FROM volume;");
    try store.exec("INSERT INTO volume WITH RECURSIVE data(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM data WHERE n<18000) SELECT zeroblob(1024) FROM data;");
    try std.testing.expectError(error.Busy, store.maintainWal(path));
    try reader.exec("COMMIT;");
    try store.maintainWal(path);
    const wal = try std.fmt.allocPrint(a, "{s}-wal", .{path});
    defer a.free(wal);
    try std.testing.expectEqual(@as(u64, 0), (try std.fs.cwd().statFile(wal)).size);
    try std.testing.expectEqual(@as(i64, 18000), try store.integer("SELECT count(*) FROM volume;"));
}

test "native retry: killed schema and decision commits reopen wholly before or after the boundary" {
    const a = std.testing.allocator;
    const policy = retry.Policy{ .maxretry = 1, .window_us = 600_000_000, .duration = .{ .finite_us = 60_000_000 }, .max_subjects = 8 };
    for ([_]bool{ false, true }) |migration| for ([_]bool{ false, true }) |after| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "killed-retry.sqlite" });
        defer a.free(path);
        {
            var store = try Store.open(a, path);
            defer store.close();
            try store.enableReceipts(1);
            try store.enableNativeTime();
            try store.enableDetection();
            try store.enableClockRecovery();
            try store.enableJournalDetection();
            if (!migration) {
                try store.enableRetry();
                try store.admitRetry("fixture", ReceiptFixture.identity.generation, policy);
            }
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            child.enableReceipts(1) catch std.process.exit(3);
            var record = DetectionFixture.record() catch std.process.exit(4);
            record.native_retry = .{ .generation = ReceiptFixture.identity.generation, .policy = policy, .processing_us = DetectionFixture.stamp };
            if (!migration) _ = child.beginReceipt(ReceiptFixture.identity, .{ .us = DetectionFixture.stamp }, 0) catch std.process.exit(5);
            const Kill = struct {
                var after_commit: bool = false;
                fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (!std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) return embedded_api.exec(db, sql, callback, context, message);
                    if (after_commit and embedded_api.exec(db, sql, callback, context, message) != 0) std.process.exit(6);
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(7);
                    unreachable;
                }
            };
            Kill.after_commit = after;
            child.api.exec = Kill.exec;
            if (migration) child.enableRetry() catch std.process.exit(8) else _ = child.commitRecord(record) catch std.process.exit(9);
            std.process.exit(10);
        }
        const ended = std.posix.waitpid(pid, 0);
        try std.testing.expect(std.posix.W.IFSIGNALED(ended.status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.posix.W.TERMSIG(ended.status));
        var restored = try Store.open(a, path);
        defer restored.close();
        if (migration) {
            try std.testing.expectEqual(@as(i64, if (after) 9 else 8), restored.schema_version);
            try std.testing.expectEqual(@as(i64, if (after) 1 else 0), try restored.integer("SELECT count(*) FROM sqlite_master WHERE name='retry_states';"));
        } else {
            try std.testing.expectEqual(@as(u64, @intFromBool(after)), try restored.revision("fixture"));
            const state = try restored.retryState("fixture", .{ .v4 = .{ 203, 0, 113, 7 } });
            const decision = try restored.retryDecision("fixture", "ordinary", null);
            try std.testing.expectEqual(after, state != null);
            try std.testing.expectEqual(after, decision != null);
            if (decision) |value| {
                try std.testing.expectEqualDeep(retry.Lease{ .finite = DetectionFixture.stamp + policy.duration.finite_us }, value.lease);
                try std.testing.expectEqual(@as(u64, 1), state.?.decisions);
            }
            try std.testing.expectEqual(@as(usize, @intFromBool(!after)), try restored.pendingReceiptCount());
        }
    };
}

test "native consumers: killed migration and multi-state commits retain original receipt" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |migration| for ([_]bool{ false, true }) |after| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "consumer-kill.sqlite" });
        defer a.free(path);
        const identity = ReceiptIdentity{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .generation = [_]u8{2} ** 32 };
        const key = consumers.Key{ .kind = .correlation, .jail = "fixture", .source = "file", .rule = "pair", .generation = [_]u8{3} ** 32 };
        {
            var store = try Store.open(a, path);
            defer store.close();
            try store.enableReceipts(1);
            try store.enableNativeTime();
            try store.enableDetection();
            try store.enableClockRecovery();
            try store.enableJournalDetection();
            try store.enableRetry();
            if (!migration) {
                try store.enableConsumers();
                _ = try store.beginReceipt(identity, .{ .us = 100 }, 0);
            }
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            const Kill = struct {
                var after_commit: bool = false;
                fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (!std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) return embedded_api.exec(db, sql, callback, context, message);
                    if (after_commit and embedded_api.exec(db, sql, callback, context, message) != 0) std.process.exit(3);
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(4);
                    unreachable;
                }
                fn clock(_: ?*anyopaque) i64 {
                    return 100;
                }
            };
            Kill.after_commit = after;
            child.api.exec = Kill.exec;
            if (migration) child.enableConsumers() catch std.process.exit(5) else {
                _ = child.commitRecord(.{ .jail = identity.jail, .source = identity.source, .occurrence = identity.occurrence, .cursor = identity.cursor, .raw_hash = identity.raw_hash, .receipt = .{ .time = .{ .us = 100 }, .generation = identity.generation }, .disposition = "counted", .checkpoint = "source", .consumers = .{ .prepared_us = 100, .clock = Kill.clock, .deltas = &.{.{ .key = key, .format_version = 1, .expected_revision = 0, .payload = "context" }} } }) catch std.process.exit(6);
            }
            std.process.exit(7);
        }
        const ended = std.posix.waitpid(pid, 0);
        try std.testing.expect(std.posix.W.IFSIGNALED(ended.status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.posix.W.TERMSIG(ended.status));
        var restored = try Store.open(a, path);
        defer restored.close();
        if (migration) {
            try std.testing.expectEqual(@as(i64, if (after) 10 else 9), restored.schema_version);
            try std.testing.expectEqual(@as(i64, @intFromBool(after)), try restored.integer("SELECT count(*) FROM sqlite_master WHERE name='consumer_checkpoints';"));
        } else {
            const state = try restored.consumerSnapshot(a, key);
            defer state.deinit(a);
            try std.testing.expectEqual(@as(u64, @intFromBool(after)), state.revision);
            try std.testing.expectEqual(@as(u64, @intFromBool(after)), try restored.revision("fixture"));
            try std.testing.expectEqual(@as(usize, @intFromBool(!after)), try restored.pendingReceiptCount());
            const original = if (after) try restored.committedReceipt(identity) else try restored.pendingReceipt(identity);
            try std.testing.expectEqual(@as(i64, 100), original.?.us);
            if (after) {
                var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
                try std.testing.expectError(error.OutOfMemory, restored.consumerSnapshot(failing.allocator(), key));
                try restored.exec("PRAGMA ignore_check_constraints=ON; UPDATE consumer_checkpoints SET payload='foreign-text';");
                try std.testing.expectError(error.InvalidConsumer, restored.consumerSnapshot(a, key));
                try std.testing.expectEqual(@as(i64, 1), try restored.integer("SELECT count(*) FROM consumer_checkpoints;"));
            }
        }
    };
}
