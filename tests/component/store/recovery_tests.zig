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

test "clock recovery: pending verification releases its read before source work and rejects concurrent changes" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "detached.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(3);
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = 100 }, 0);
    var writer = try Store.open(a, path);
    defer writer.close();
    try writer.enableReceipts(3);
    const Visitor = struct {
        writer: *Store,
        checkpoint: bool = false,
        mutate: bool = false,
        count: usize = 0,
        fn check(identity: ReceiptIdentity, stamp: native_time.Timestamp, context: ?*anyopaque) !void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.count += 1;
            if (self.checkpoint) try std.testing.expectEqual(@as(i64, 0), try self.writer.integer("PRAGMA wal_checkpoint(TRUNCATE);"));
            if (self.mutate) {
                var next = identity;
                next.source = "second";
                _ = try self.writer.beginReceipt(next, .{ .us = 200 }, 0);
            }
            try std.testing.expectEqualStrings("fixture", identity.jail);
            try std.testing.expectEqualStrings("ordinary", identity.source);
            try std.testing.expectEqualStrings("next", identity.cursor);
            try std.testing.expectEqual(@as(i64, 100), stamp.us);
        }
    };
    var visitor = Visitor{ .writer = &writer };
    try store.visitPendingReceipts(Visitor.check, &visitor);
    try std.testing.expectEqual(@as(usize, 1), visitor.count);
    visitor.count = 0;
    visitor.checkpoint = true;
    try std.testing.expectError(error.StaleCheckpoint, store.visitPendingReceipts(Visitor.check, &visitor));
    try std.testing.expectEqual(@as(usize, 1), visitor.count);
    try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    visitor.count = 0;
    visitor.checkpoint = false;
    visitor.mutate = true;
    try std.testing.expectError(error.StaleCheckpoint, store.visitPendingReceipts(Visitor.check, &visitor));
    try std.testing.expectEqual(@as(usize, 1), visitor.count);
    try std.testing.expectEqual(@as(usize, 2), try store.pendingReceiptCount());
}

test "clock recovery: detached pending traversal stays bounded and cleans allocation failure" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "bounded.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(3);
    for ([_][]const u8{ "a", "b", "c" }) |source| {
        var identity = ReceiptFixture.identity;
        identity.source = source;
        _ = try store.beginReceipt(identity, .{ .us = 100 }, 0);
    }
    const Visitor = struct {
        count: usize = 0,
        fn check(identity: ReceiptIdentity, _: native_time.Timestamp, context: ?*anyopaque) !void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            try std.testing.expectEqual(@as(u8, @intCast('a' + self.count)), identity.source[0]);
            self.count += 1;
        }
        fn allocate(allocator: std.mem.Allocator, target: *Store) !void {
            const prior = target.allocator;
            target.allocator = allocator;
            defer target.allocator = prior;
            var visitor = @This(){};
            try target.visitPendingReceipts(check, &visitor);
            try std.testing.expectEqual(@as(usize, 3), visitor.count);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Visitor.allocate, .{&store});
    store.receipt_limit = 1;
    var visitor = Visitor{};
    try std.testing.expectError(error.ReceiptLimit, store.visitPendingReceipts(Visitor.check, &visitor));
    try std.testing.expectEqual(@as(usize, 1), visitor.count);
    try std.testing.expectEqual(@as(u64, 0), try store.revision("fixture"));
}

test "clock recovery: schema seven seeds exact durable floor and receipt failures cannot change it" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "clock.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try DetectionFixture.admit(&store);
    try store.enableDetection();
    _ = try store.commitRecord(try DetectionFixture.record());
    var next = ReceiptFixture.identity;
    next.source = "pending";
    next.occurrence = "two";
    next.cursor = "later";
    try store.enableReceipts(2);
    const greatest = DetectionFixture.stamp + 17;
    _ = try store.beginReceipt(next, .{ .us = greatest }, 1);
    store.fail_at = .before_clock_schema_commit;
    try std.testing.expectError(error.InjectedFailure, store.enableClockRecovery());
    try std.testing.expectEqual(@as(i64, 6), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 0), try store.integer("SELECT count(*) FROM sqlite_master WHERE name='receipt_clock';"));
    store.fail_at = null;
    try store.enableClockRecovery();
    try std.testing.expectEqual(greatest, (try store.receiptClock()).?.us);
    try store.enableDetection();
    try store.enableYearInference();
    try store.enableNativeTime();
    try std.testing.expectEqual(@as(i64, 7), store.schema_version);
    var third = next;
    third.source = "third";
    third.occurrence = "three";
    third.cursor = "last";
    store.fail_at = .before_receipt_commit;
    try std.testing.expectError(error.InjectedFailure, store.beginReceipt(third, .{ .us = greatest + 1 }, 1));
    try std.testing.expectEqual(greatest, (try store.receiptClock()).?.us);
    try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    store.fail_at = .after_receipt_commit;
    try std.testing.expectError(error.InjectedFailure, store.beginReceipt(third, .{ .us = greatest + 1 }, 1));
    try std.testing.expectEqual(greatest + 1, (try store.receiptClock()).?.us);
    store.fail_at = null;
    try std.testing.expectEqual(greatest + 1, (try store.beginReceipt(third, .{ .us = 1 }, 1)).us);
    try store.exec("DELETE FROM record_detections; DELETE FROM source_cursors; DELETE FROM records; DELETE FROM pending_receipts;");
    var reopened = try Store.open(a, path);
    defer reopened.close();
    try std.testing.expectEqual(greatest + 1, (try reopened.receiptClock()).?.us);
}

test "clock recovery: empty store and corrupt clock metadata remain distinguishable" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "empty.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(1);
    try store.enableNativeTime();
    try std.testing.expectError(error.UnsupportedSchema, store.enableClockRecovery());
    try store.enableDetection();
    try store.enableClockRecovery();
    try std.testing.expect((try store.receiptClock()) == null);
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = std.math.minInt(i64) }, 0);
    try std.testing.expectEqual(std.math.minInt(i64), (try store.receiptClock()).?.us);
    try store.exec("PRAGMA ignore_check_constraints=ON; UPDATE receipt_clock SET floor_us='bad';");
    try std.testing.expectError(error.DatabaseFailure, store.receiptClock());
    try std.testing.expectError(error.DatabaseFailure, store.beginReceipt(ReceiptFixture.identity, .{ .us = 0 }, 0));
    try store.exec("DELETE FROM receipt_clock;");
    try std.testing.expectError(error.DatabaseFailure, store.receiptClock());
    try std.testing.expectError(error.DatabaseFailure, store.enableClockRecovery());
}

test "clock recovery: killed migration and receipt transaction preserve the durable floor" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    for (0..3) |phase| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "crash-clock.sqlite" });
        defer a.free(path);
        {
            var store = try Store.open(a, path);
            defer store.close();
            try store.enableReceipts(1);
            try store.enableNativeTime();
            try store.enableDetection();
            if (phase != 0) try store.enableClockRecovery();
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            child.enableReceipts(1) catch std.process.exit(3);
            const Kill = struct {
                var after: bool = false;
                fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (!std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) return embedded_api.exec(db, sql, callback, context, message);
                    if (after and embedded_api.exec(db, sql, callback, context, message) != 0) std.process.exit(4);
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(5);
                    unreachable;
                }
            };
            Kill.after = phase == 2;
            child.api.exec = Kill.exec;
            if (phase == 0) child.enableClockRecovery() catch std.process.exit(6) else {
                _ = child.beginReceipt(ReceiptFixture.identity, .{ .us = DetectionFixture.stamp }, 0) catch std.process.exit(7);
            }
            std.process.exit(8);
        }
        const status = std.posix.waitpid(pid, 0).status;
        try std.testing.expect(std.os.linux.W.IFSIGNALED(status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(status));
        var reopened = try Store.open(a, path);
        defer reopened.close();
        try std.testing.expectEqual(@as(i64, if (phase == 0) 6 else 7), reopened.schema_version);
        try reopened.enableReceipts(1);
        try reopened.enableClockRecovery();
        const floor = try reopened.receiptClock();
        if (phase == 2) try std.testing.expectEqual(DetectionFixture.stamp, floor.?.us) else try std.testing.expect(floor == null);
        try std.testing.expectEqual(@as(usize, if (phase == 2) 1 else 0), try reopened.pendingReceiptCount());
        try std.testing.expectEqual(@as(u64, 0), try reopened.revision("fixture"));
    }
}

test "receipt recovery: explicit schema activation rolls back and preserves candidate data" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    {
        var store = try Store.open(a, path);
        defer store.close();
        var old_record = ReceiptFixture.record(0);
        old_record.receipt = null;
        _ = try store.commitRecord(old_record);
        try std.testing.expectError(error.ReceiptStorageRequired, store.beginReceipt(ReceiptFixture.identity, .{ .us = 0 }, 1));
        store.fail_at = .before_receipt_schema_commit;
        try std.testing.expectError(error.InjectedFailure, store.enableReceipts(2));
        try std.testing.expectEqual(@as(i64, 2), try store.integer("PRAGMA user_version;"));
        try std.testing.expectEqual(@as(i64, 0), try store.integer("SELECT count(*) FROM sqlite_master WHERE name='pending_receipts';"));
        try std.testing.expectEqual(@as(i64, 8), try store.integer("SELECT count(*) FROM pragma_table_info('records');"));
        try std.testing.expect(store.receipt_limit == null);
    }
    var store = try Store.open(a, path);
    defer store.close();
    try std.testing.expectEqual(@as(i64, 2), store.schema_version);
    try store.enableReceipts(2);
    try std.testing.expectEqual(@as(i64, 3), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 10), try store.integer("SELECT count(*) FROM pragma_table_info('records');"));
    try std.testing.expectEqual(@as(u64, 1), try store.revision("fixture"));
    const snapshot = try store.snapshot(a, "fixture");
    defer snapshot.deinit(a);
    try std.testing.expectEqualStrings("state", snapshot.payload.?);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT count(*) FROM records WHERE receipt_us IS NULL AND receipt_generation IS NULL;"));
    var reopened = try Store.open(a, path);
    defer reopened.close();
    try std.testing.expectEqual(@as(i64, 3), try reopened.integer("PRAGMA user_version;"));
    try std.testing.expect(reopened.receipt_limit == null);
    try reopened.enableReceipts(2);
    try std.testing.expectEqual(@as(usize, 0), try reopened.pendingReceiptCount());
}

test "receipt recovery: identity limits atomic deletion and signed receipt history" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    var earlier = try Store.open(a, path);
    defer earlier.close();
    try store.enableReceipts(1);
    for ([_]i64{ std.math.minInt(i64), -1, 0, 9_007_199_254_740_993, std.math.maxInt(i64) }, 0..) |stamp, index| {
        var id = ReceiptFixture.identity;
        var key: [32]u8 = undefined;
        id.occurrence = try std.fmt.bufPrint(&key, "ordinary-{d}", .{index});
        var record = ReceiptFixture.record(stamp);
        record.occurrence = id.occurrence;
        record.expected_revision = index;
        store.fail_at = .before_receipt_commit;
        try std.testing.expectError(error.InjectedFailure, store.beginReceipt(id, .{ .us = stamp }, index));
        try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
        store.fail_at = .after_receipt_commit;
        try std.testing.expectError(error.InjectedFailure, store.beginReceipt(id, .{ .us = stamp }, index));
        try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        try std.testing.expectEqual(@as(u64, index), try store.revision("fixture"));
        store.fail_at = null;
        try std.testing.expectEqual(stamp, (try store.beginReceipt(id, .{ .us = 123 }, index)).us);
        try std.testing.expectError(error.StaleCheckpoint, store.beginReceipt(id, .{ .us = 123 }, index + 1));
        for (0..4) |variant| {
            var changed = id;
            switch (variant) {
                0 => changed.generation[0] ^= 1,
                1 => changed.raw_hash[0] ^= 1,
                2 => changed.occurrence = "other",
                3 => changed.cursor = "changed",
                else => unreachable,
            }
            try std.testing.expectError(error.ReceiptConflict, store.beginReceipt(changed, .{ .us = 123 }, index));
        }
        var another = id;
        another.source = "other-source";
        try std.testing.expectError(error.ReceiptLimit, store.beginReceipt(another, .{ .us = 123 }, index));
        try std.testing.expectError(error.ReceiptConflict, store.validateReceiptGeneration(id.jail, [_]u8{0} ** 32));
        var missing = record;
        missing.receipt = null;
        try std.testing.expectError(error.ReceiptRequired, earlier.commitRecord(missing));
        var wrong = record;
        wrong.receipt.?.time.us = stamp ^ 1;
        try std.testing.expectError(error.ReceiptConflict, store.commitRecord(wrong));
        for ([_]CommitStage{ .after_record, .after_checkpoint, .after_receipt_delete, .before_commit }) |stage| {
            store.fail_at = stage;
            try std.testing.expectError(error.InjectedFailure, store.commitRecord(record));
            try std.testing.expectEqual(stamp, (try store.pendingReceipt(id)).?.us);
            try std.testing.expectEqual(@as(u64, index), try store.revision("fixture"));
            try std.testing.expectEqual(@as(i64, @intCast(index)), try store.pendingIntents());
            try std.testing.expect(!try store.hasRecord(id.jail, id.source, id.occurrence, id.raw_hash, id.cursor));
        }
        store.fail_at = null;
        _ = try store.commitRecord(record);
        try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
        try std.testing.expectEqual(stamp, (try store.committedReceipt(id)).?.us);
        try std.testing.expectEqual(CommitResult.already_committed, try store.commitRecord(record));
        try std.testing.expectError(error.ReceiptConflict, store.commitRecord(wrong));
        try std.testing.expectError(error.ReceiptAlreadyCommitted, store.beginReceipt(id, .{ .us = 123 }, index + 1));
    }
}

test "receipt recovery: real read-only and capacity errors preserve the observation boundary" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(2);
    try store.exec("PRAGMA query_only=ON;");
    try std.testing.expectError(error.ReadOnly, store.beginReceipt(ReceiptFixture.identity, .{ .us = 100 }, 0));
    try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    try store.exec("PRAGMA query_only=OFF;");
    const pages = try store.integer("PRAGMA page_count;");
    var sql: [80]u8 = undefined;
    _ = try store.integer(try std.fmt.bufPrintZ(&sql, "PRAGMA max_page_count={d};", .{pages}));
    var large_id = ReceiptFixture.identity;
    const large_cursor = [_]u8{'x'} ** Limits.cursor_bytes;
    large_id.cursor = &large_cursor;
    try std.testing.expectError(error.StorageFull, store.beginReceipt(large_id, .{ .us = 100 }, 0));
    try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    try std.testing.expectEqual(@as(u64, 0), try store.revision("fixture"));
    _ = try store.integer("PRAGMA max_page_count=10000;");
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = 100 }, 0);
    try store.exec("PRAGMA query_only=ON;");
    try std.testing.expectError(error.ReadOnly, store.commitRecord(ReceiptFixture.record(100)));
    try std.testing.expectEqual(@as(i64, 100), (try store.pendingReceipt(ReceiptFixture.identity)).?.us);
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    try store.exec("PRAGMA query_only=OFF;");
    _ = try store.commitRecord(ReceiptFixture.record(100));
    try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
}

test "receipt recovery: killed writer preserves pending time and atomic final publication" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    for (0..4) |phase| {
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            child.enableReceipts(1) catch std.process.exit(3);
            if (phase == 0) {
                child.exec("BEGIN IMMEDIATE; INSERT INTO pending_receipts VALUES('fixture','ordinary',zeroblob(32),'one',zeroblob(32),'next',100);") catch std.process.exit(4);
            } else if (phase == 1) {
                _ = child.beginReceipt(ReceiptFixture.identity, .{ .us = 100 }, 0) catch std.process.exit(5);
            } else if (phase == 2) {
                const Kill = struct {
                    fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                        if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) {
                            std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(6);
                            unreachable;
                        }
                        return embedded_api.exec(db, sql, callback, context, message);
                    }
                };
                child.api.exec = Kill.exec;
                _ = child.commitRecord(ReceiptFixture.record(100)) catch std.process.exit(7);
            } else {
                _ = child.commitRecord(ReceiptFixture.record(100)) catch std.process.exit(8);
            }
            std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(9);
            unreachable;
        }
        const result = std.posix.waitpid(pid, 0);
        try std.testing.expect(std.os.linux.W.IFSIGNALED(result.status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(result.status));
        var recovered = try Store.open(a, path);
        defer recovered.close();
        try recovered.enableReceipts(1);
        if (phase == 0) {
            try std.testing.expectEqual(@as(usize, 0), try recovered.pendingReceiptCount());
        } else if (phase < 3) {
            try std.testing.expectEqual(@as(i64, 100), (try recovered.pendingReceipt(ReceiptFixture.identity)).?.us);
            try std.testing.expectEqual(@as(i64, 100), (try recovered.beginReceipt(ReceiptFixture.identity, .{ .us = 900 }, 0)).us);
        } else {
            try std.testing.expectEqual(@as(usize, 0), try recovered.pendingReceiptCount());
            try std.testing.expectEqual(@as(i64, 100), (try recovered.committedReceipt(ReceiptFixture.identity)).?.us);
        }
        try std.testing.expectEqual(@as(u64, if (phase == 3) 1 else 0), try recovered.revision("fixture"));
        try std.testing.expectEqual(@as(i64, if (phase == 3) 1 else 0), try recovered.pendingIntents());
    }
}

test "receipt recovery: recovery enumeration is bounded and rejects malformed stored values" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(2);
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = -123 }, 0);
    const Visitor = struct {
        fn visit(identity: ReceiptIdentity, stamp: native_time.Timestamp, context: ?*anyopaque) !void {
            const called: *bool = @ptrCast(@alignCast(context.?));
            try std.testing.expectEqualDeep(ReceiptFixture.identity, identity);
            try std.testing.expectEqual(@as(i64, -123), stamp.us);
            called.* = true;
        }
        fn fail(_: ReceiptIdentity, _: native_time.Timestamp, _: ?*anyopaque) !void {
            return error.OutOfMemory;
        }
    };
    var called = false;
    try store.visitPendingReceipts(Visitor.visit, &called);
    try std.testing.expect(called);
    try std.testing.expectError(error.OutOfMemory, store.visitPendingReceipts(Visitor.fail, null));
    try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    var second = ReceiptFixture.identity;
    second.source = "second";
    _ = try store.beginReceipt(second, .{ .us = 456 }, 0);
    try std.testing.expectError(error.ReceiptLimit, store.enableReceipts(1));
    try store.exec("PRAGMA ignore_check_constraints=ON; UPDATE pending_receipts SET receipt_us='not-an-integer' WHERE source='ordinary';");
    called = false;
    try std.testing.expectError(error.DatabaseFailure, store.visitPendingReceipts(Visitor.visit, &called));
    try std.testing.expect(!called);
    try std.testing.expectError(error.DatabaseFailure, store.pendingReceipt(ReceiptFixture.identity));
    try store.exec("UPDATE pending_receipts SET receipt_us=-123,cursor=zeroblob(65537) WHERE source='ordinary';");
    try std.testing.expectError(error.StorageLimit, store.visitPendingReceipts(Visitor.visit, &called));
    try std.testing.expect(!called);
}

test "receipt recovery: killed schema upgrade leaves version two data usable" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    {
        var store = try Store.open(a, path);
        defer store.close();
        var record = ReceiptFixture.record(0);
        record.receipt = null;
        _ = try store.commitRecord(record);
    }
    const pid = try std.posix.fork();
    if (pid == 0) {
        var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
        const Kill = struct {
            fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) {
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(3);
                    unreachable;
                }
                return embedded_api.exec(db, sql, callback, context, message);
            }
        };
        child.api.exec = Kill.exec;
        child.enableReceipts(1) catch std.process.exit(4);
        std.process.exit(5);
    }
    const result = std.posix.waitpid(pid, 0);
    try std.testing.expect(std.os.linux.W.IFSIGNALED(result.status));
    try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(result.status));
    var recovered = try Store.open(a, path);
    defer recovered.close();
    try std.testing.expectEqual(@as(i64, 2), try recovered.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 8), try recovered.integer("SELECT count(*) FROM pragma_table_info('records');"));
    try std.testing.expectEqual(@as(u64, 1), try recovered.revision("fixture"));
    try std.testing.expectEqual(@as(i64, 1), try recovered.pendingIntents());
    try recovered.enableReceipts(1);
    try std.testing.expectEqual(@as(i64, 3), try recovered.integer("PRAGMA user_version;"));
}
