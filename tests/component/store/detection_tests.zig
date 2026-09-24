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

test "native detection: journal schema migration preserves prior evidence and clock through rollback" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "journal-upgrade.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try DetectionFixture.admit(&store);
    try store.enableDetection();
    try std.testing.expectError(error.UnsupportedSchema, store.enableJournalDetection());
    const record = try DetectionFixture.record();
    _ = try store.commitRecord(record);
    try store.enableClockRecovery();
    const original_maximum = try store.integer("PRAGMA max_page_count;");
    const pages = try store.integer("PRAGMA page_count;");
    const limited = try std.fmt.allocPrintZ(a, "PRAGMA max_page_count={d};", .{pages});
    defer a.free(limited);
    try store.exec(limited);
    try std.testing.expectError(error.StorageFull, store.enableJournalDetection());
    try std.testing.expectEqual(@as(i64, 7), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqualDeep(record.native_detection.?, (try store.nativeDetection("fixture", "ordinary", null)).?);
    const unlimited = try std.fmt.allocPrintZ(a, "PRAGMA max_page_count={d};", .{original_maximum});
    defer a.free(unlimited);
    try store.exec(unlimited);
    store.fail_at = .before_journal_detection_schema_commit;
    try std.testing.expectError(error.InjectedFailure, store.enableJournalDetection());
    try std.testing.expectEqual(@as(i64, 7), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 0), try store.integer("SELECT count(*) FROM sqlite_master WHERE name='record_detections_v8';"));
    try std.testing.expectEqualDeep(record.native_detection.?, (try store.nativeDetection("fixture", "ordinary", null)).?);
    try std.testing.expectEqual(DetectionFixture.stamp, (try store.receiptClock()).?.us);
    store.fail_at = null;
    try store.enableJournalDetection();
    try store.enableDetection();
    try store.enableNativeTime();
    try store.enableClockRecovery();
    try store.enableJournalDetection();
    try std.testing.expectEqual(@as(i64, 8), store.schema_version);
    var reopened = try Store.open(a, path);
    defer reopened.close();
    try std.testing.expectEqual(@as(i64, 8), reopened.schema_version);
    try std.testing.expectEqualDeep(record.native_detection.?, (try reopened.nativeDetection("fixture", "ordinary", null)).?);
    try std.testing.expectEqual(DetectionFixture.stamp, (try reopened.receiptClock()).?.us);
    try std.testing.expectEqual(@as(u64, 1), try reopened.revision("fixture"));
}

test "native detection: killed journal schema migration is atomic on reopen" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |after| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "killed-journal.sqlite" });
        defer a.free(path);
        {
            var store = try Store.open(a, path);
            defer store.close();
            try DetectionFixture.admit(&store);
            try store.enableDetection();
            _ = try store.commitRecord(try DetectionFixture.record());
            try store.enableClockRecovery();
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            child.enableReceipts(1) catch std.process.exit(3);
            const Kill = struct {
                var after_commit: bool = false;
                fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (!std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) return embedded_api.exec(db, sql, callback, context, message);
                    if (after_commit and embedded_api.exec(db, sql, callback, context, message) != 0) std.process.exit(4);
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(5);
                    unreachable;
                }
            };
            Kill.after_commit = after;
            child.api.exec = Kill.exec;
            child.enableJournalDetection() catch std.process.exit(6);
            std.process.exit(7);
        }
        const status = std.posix.waitpid(pid, 0).status;
        try std.testing.expect(std.os.linux.W.IFSIGNALED(status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(status));
        var recovered = try Store.open(a, path);
        defer recovered.close();
        try std.testing.expectEqual(@as(i64, if (after) 8 else 7), recovered.schema_version);
        try std.testing.expectEqualDeep((try DetectionFixture.record()).native_detection.?, (try recovered.nativeDetection("fixture", "ordinary", null)).?);
        try std.testing.expectEqual(DetectionFixture.stamp, (try recovered.receiptClock()).?.us);
        try std.testing.expectEqual(@as(u64, 1), try recovered.revision("fixture"));
    }
}

test "native detection: schema six migration and typed outcomes commit atomically" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |inference| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "detection.sqlite" });
        defer a.free(path);
        var store = try Store.open(a, path);
        defer store.close();
        try DetectionFixture.admit(&store);
        if (inference) try store.enableYearInference();
        var old_reader = try Store.open(a, path);
        defer old_reader.close();
        const record = try DetectionFixture.record();
        try std.testing.expectError(error.DetectionStorageRequired, store.commitRecord(record));
        store.fail_at = .before_detection_schema_commit;
        try std.testing.expectError(error.InjectedFailure, store.enableDetection());
        try std.testing.expectEqual(@as(i64, if (inference) 5 else 4), try store.integer("PRAGMA user_version;"));
        try std.testing.expectEqual(@as(i64, 0), try store.integer("SELECT count(*) FROM sqlite_master WHERE name='record_detections';"));
        try std.testing.expectEqual(@as(i64, if (inference) 14 else 13), try store.integer("SELECT count(*) FROM pragma_table_info('records');"));
        store.fail_at = null;
        try store.enableDetection();
        try store.enableNativeTime();
        try store.enableYearInference();
        try std.testing.expectEqual(@as(i64, 6), store.schema_version);
        for ([_]CommitStage{ .after_record, .after_detection, .after_checkpoint, .after_receipt_delete, .before_commit }) |stage| {
            store.fail_at = stage;
            try std.testing.expectError(error.InjectedFailure, store.commitRecord(record));
            try std.testing.expect((try old_reader.nativeDetection("fixture", "ordinary", "one")) == null);
            try std.testing.expectEqual(@as(u64, 0), try store.revision("fixture"));
            try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        }
        store.fail_at = null;
        try std.testing.expectEqual(CommitResult.committed, try store.commitRecord(record));
        try std.testing.expectEqual(CommitResult.already_committed, try store.commitRecord(record));
        try std.testing.expectEqualDeep(record.native_detection.?, (try old_reader.nativeDetection("fixture", "ordinary", null)).?);
        try std.testing.expectEqualDeep(record.native_time_outcome.?, (try old_reader.nativeTime("fixture", "ordinary", null)).?);
        try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT count(*) FROM record_detections;"));
        try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
        try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
        var reopened = try Store.open(a, path);
        defer reopened.close();
        try std.testing.expectEqualDeep(record.native_detection.?, (try reopened.nativeDetection("fixture", "ordinary", "one")).?);
    }
}

test "native detection: all typed outcomes preserve nulls and address family on reopen" {
    const a = std.testing.allocator;
    for (std.enums.values(detection.Kind)) |kind| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "outcome.sqlite" });
        defer a.free(path);
        var record = try DetectionFixture.record();
        record.native_detection.?.kind = kind;
        switch (kind) {
            .time_excluded, .malformed_body, .no_match, .origin_missing, .origin_ambiguous, .origin_machine, .origin_uid, .origin_executable, .origin_transport => {
                record.native_detection.?.subject = null;
                record.native_detection.?.pattern = null;
                record.native_detection.?.pattern_index = null;
            },
            .unenforceable => record.native_detection.?.subject = .{ .v4 = .{ 127, 0, 0, 1 } },
            .candidate => record.native_detection.?.subject = .{ .v6 = .{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 } },
            .ignored => {},
        }
        if (kind == .time_excluded) {
            record.native_time_outcome = .{ .obsolete = record.native_time_outcome.?.eligible };
            record.disposition = record.native_time_outcome.?.disposition();
        }
        {
            var store = try Store.open(a, path);
            defer store.close();
            try DetectionFixture.admit(&store);
            try store.enableDetection();
            if (@intFromEnum(kind) >= 7) {
                try std.testing.expectError(error.DetectionStorageRequired, store.commitRecord(record));
                try store.enableClockRecovery();
                try store.enableJournalDetection();
            }
            _ = try store.commitRecord(record);
        }
        var reopened = try Store.open(a, path);
        defer reopened.close();
        try std.testing.expectEqualDeep(record.native_detection.?, (try reopened.nativeDetection("fixture", "ordinary", null)).?);
        try std.testing.expectEqual(@as(i64, 0), try reopened.pendingIntents());
    }
}

test "native detection: invalid typed evidence cannot advance progress" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "invalid.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try DetectionFixture.admit(&store);
    try store.enableDetection();
    for (0..7) |case| {
        var record = try DetectionFixture.record();
        switch (case) {
            0 => record.native_time_outcome = null,
            1 => {
                record.native_time_outcome = .{ .obsolete = record.native_time_outcome.?.eligible };
                record.disposition = record.native_time_outcome.?.disposition();
            },
            2 => record.native_detection.?.subject = null,
            3 => record.native_detection.?.subject = .{ .v4 = .{ 127, 0, 0, 1 } },
            4 => record.native_detection.?.pattern = null,
            5 => record.native_detection.?.filter.len = 65,
            6 => record.native_detection.?.kind = .no_match,
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidRecord, store.commitRecord(record));
        try std.testing.expectEqual(@as(u64, 0), try store.revision("fixture"));
        try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    }
}

test "native detection: malformed stored fields and inconsistent time refuse reads" {
    const a = std.testing.allocator;
    const changes = [_][:0]const u8{
        "UPDATE record_detections SET version=2;",
        "UPDATE record_detections SET kind=99;",
        "UPDATE record_detections SET generation='12345678901234567890123456789012';",
        "UPDATE record_detections SET filter=CAST('sshd' AS BLOB);",
        "UPDATE record_detections SET pattern_index='bad';",
        "UPDATE record_detections SET pattern_index=65536;",
        "UPDATE record_detections SET family=5;",
        "UPDATE record_detections SET family=NULL;",
        "UPDATE record_detections SET subject=x'7f000001';",
        "UPDATE record_detections SET subject=zeroblob(3);",
        "UPDATE record_detections SET family=6,subject=x'00000000000000000000ffffcb007107';",
        "UPDATE record_detections SET filter='invalid name';",
        "UPDATE record_detections SET pattern=NULL;",
        "UPDATE records SET native_time_kind=4,disposition='time-obsolete-event';",
    };
    for (changes) |change| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "corrupt.sqlite" });
        defer a.free(path);
        var store = try Store.open(a, path);
        defer store.close();
        try DetectionFixture.admit(&store);
        try store.enableDetection();
        _ = try store.commitRecord(try DetectionFixture.record());
        try store.exec("PRAGMA ignore_check_constraints=ON;");
        try store.exec(change);
        try std.testing.expectError(error.DatabaseFailure, store.nativeDetection("fixture", "ordinary", null));
    }
}

test "native detection: process death around migration and outcome commit preserves acknowledgment" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    for (0..3) |phase| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "crash.sqlite" });
        defer a.free(path);
        {
            var store = try Store.open(a, path);
            defer store.close();
            try DetectionFixture.admit(&store);
            if (phase != 0) try store.enableDetection();
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
            if (phase == 0) child.enableDetection() catch std.process.exit(6) else {
                const record = DetectionFixture.record() catch std.process.exit(7);
                _ = child.commitRecord(record) catch std.process.exit(8);
            }
            std.process.exit(9);
        }
        const status = std.posix.waitpid(pid, 0).status;
        try std.testing.expect(std.os.linux.W.IFSIGNALED(status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(status));
        var recovered = try Store.open(a, path);
        defer recovered.close();
        try std.testing.expectEqual(@as(i64, if (phase == 0) 4 else 6), recovered.schema_version);
        try recovered.enableReceipts(1);
        try recovered.enableDetection();
        try std.testing.expectEqual(@as(usize, if (phase == 2) 0 else 1), try recovered.pendingReceiptCount());
        try std.testing.expectEqual(@as(u64, if (phase == 2) 1 else 0), try recovered.revision("fixture"));
        const found = try recovered.nativeDetection("fixture", "ordinary", null);
        if (phase == 2) try std.testing.expectEqualDeep((try DetectionFixture.record()).native_detection.?, found.?) else try std.testing.expect(found == null);
        _ = try recovered.commitRecord(try DetectionFixture.record());
        try std.testing.expectEqual(@as(u64, 1), try recovered.revision("fixture"));
        try std.testing.expectEqual(@as(i64, 0), try recovered.pendingIntents());
    }
}

test "native processor: schema four preserves pending receipts and typed time is atomic and validated" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(1);
    const stamp: i64 = 9_007_199_254_740_993;
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = stamp }, 0);
    store.fail_at = .before_native_time_schema_commit;
    try std.testing.expectError(error.InjectedFailure, store.enableNativeTime());
    try std.testing.expectEqual(@as(i64, 3), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 10), try store.integer("SELECT count(*) FROM pragma_table_info('records');"));
    try std.testing.expectEqual(stamp, (try store.pendingReceipt(ReceiptFixture.identity)).?.us);
    store.fail_at = null;
    try store.enableNativeTime();
    var record = ReceiptFixture.record(stamp);
    record.native_time_outcome = try time_policy.evaluate(.timestamped, .{ .parsed = .{ .us = stamp + 1 } }, .{ .us = stamp }, .{ .us = stamp }, 600_000_000);
    record.disposition = record.native_time_outcome.?.disposition();
    store.fail_at = .after_checkpoint;
    try std.testing.expectError(error.InjectedFailure, store.commitRecord(record));
    try std.testing.expect((try store.nativeTime("fixture", "ordinary", "one")) == null);
    try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    store.fail_at = null;
    _ = try store.commitRecord(record);
    try std.testing.expectEqualDeep(record.native_time_outcome.?, (try store.nativeTime("fixture", "ordinary", "one")).?);
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT count(*) FROM records WHERE typeof(original_us)='integer' AND typeof(effective_us)='integer' AND event_time IS NULL;"));
    {
        var reopened = try Store.open(a, path);
        defer reopened.close();
        try reopened.enableReceipts(1);
        try std.testing.expectEqual(@as(i64, 4), reopened.schema_version);
        try std.testing.expectEqualDeep(record.native_time_outcome.?, (try reopened.nativeTime("fixture", "ordinary", null)).?);
    }
    try store.exec("PRAGMA ignore_check_constraints=ON; UPDATE records SET native_time_kind=99;");
    try std.testing.expectError(error.DatabaseFailure, store.nativeTime("fixture", "ordinary", null));
    try store.exec("UPDATE records SET native_time_kind=3,effective_us='bad';");
    try std.testing.expectError(error.DatabaseFailure, store.nativeTime("fixture", "ordinary", null));
    try store.exec("UPDATE records SET native_time_kind=NULL;");
    try std.testing.expectError(error.DatabaseFailure, store.nativeTime("fixture", "ordinary", null));
}

test "native processor: killed native time migration preserves version three and its pending observation" {
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
        try store.enableReceipts(1);
        _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = 123 }, 0);
    }
    const pid = try std.posix.fork();
    if (pid == 0) {
        var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
        child.enableReceipts(1) catch std.process.exit(3);
        const Kill = struct {
            fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) {
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(4);
                    unreachable;
                }
                return embedded_api.exec(db, sql, callback, context, message);
            }
        };
        child.api.exec = Kill.exec;
        child.enableNativeTime() catch std.process.exit(5);
        std.process.exit(6);
    }
    const result = std.posix.waitpid(pid, 0);
    try std.testing.expect(std.os.linux.W.IFSIGNALED(result.status));
    try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(result.status));
    var recovered = try Store.open(a, path);
    defer recovered.close();
    try recovered.enableReceipts(1);
    try std.testing.expectEqual(@as(i64, 3), recovered.schema_version);
    try std.testing.expectEqual(@as(i64, 123), (try recovered.pendingReceipt(ReceiptFixture.identity)).?.us);
    try recovered.enableNativeTime();
    try std.testing.expectEqual(@as(i64, 4), recovered.schema_version);
}

test "year inference: explicit schema five migration preserves old rows and atomically stores provenance" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(1);
    try std.testing.expectError(error.UnsupportedSchema, store.enableYearInference());
    try store.enableNativeTime();
    const stamp = (try native_time.parse(.iso8601, "2026-01-01T00:00:10Z", .{})).us;
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = stamp }, 0);
    var old = ReceiptFixture.record(stamp);
    old.action_intent = null;
    old.native_time_outcome = try time_policy.evaluate(.timestamped, .{ .parsed = .{ .us = stamp } }, .{ .us = stamp }, .{ .us = stamp }, 600_000_000);
    old.disposition = old.native_time_outcome.?.disposition();
    _ = try store.commitRecord(old);
    var identity = ReceiptFixture.identity;
    identity.occurrence = "two";
    identity.cursor = "later";
    _ = try store.beginReceipt(identity, .{ .us = stamp }, 1);
    var record = old;
    record.occurrence = identity.occurrence;
    record.cursor = identity.cursor;
    record.expected_revision = 1;
    record.native_time_outcome.?.eligible.inferred_year = 2026;
    try std.testing.expectError(error.InferenceStorageRequired, store.commitRecord(record));
    var prior_reader = try Store.open(a, path);
    defer prior_reader.close();
    try std.testing.expectEqual(@as(i64, 4), prior_reader.schema_version);
    store.fail_at = .before_inference_schema_commit;
    try std.testing.expectError(error.InjectedFailure, store.enableYearInference());
    try std.testing.expectEqual(@as(i64, 4), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 13), try store.integer("SELECT count(*) FROM pragma_table_info('records');"));
    try std.testing.expectEqual(stamp, (try store.pendingReceipt(identity)).?.us);
    store.fail_at = null;
    try store.enableYearInference();
    try std.testing.expectEqual(@as(i64, 5), store.schema_version);
    try std.testing.expectEqualDeep(old.native_time_outcome.?, (try store.nativeTime("fixture", "ordinary", "one")).?);
    store.fail_at = .after_receipt_delete;
    try std.testing.expectError(error.InjectedFailure, store.commitRecord(record));
    try std.testing.expect((try store.nativeTime("fixture", "ordinary", "two")) == null);
    try std.testing.expectEqual(@as(u64, 1), try store.revision("fixture"));
    try std.testing.expectEqual(stamp, (try store.pendingReceipt(identity)).?.us);
    store.fail_at = null;
    _ = try store.commitRecord(record);
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT count(*) FROM records WHERE inferred_year=2026 AND typeof(inferred_year)='integer';"));
    try std.testing.expectEqualDeep(record.native_time_outcome.?, (try prior_reader.nativeTime("fixture", "ordinary", "two")).?);
    try std.testing.expectEqual(@as(i64, 5), prior_reader.schema_version);
    {
        var reopened = try Store.open(a, path);
        defer reopened.close();
        try reopened.enableReceipts(1);
        try reopened.enableNativeTime();
        try reopened.enableYearInference();
        try std.testing.expectEqual(@as(i64, 5), reopened.schema_version);
        try std.testing.expectEqualDeep(record.native_time_outcome.?, (try reopened.nativeTime("fixture", "ordinary", null)).?);
        try std.testing.expectEqualDeep(old.native_time_outcome.?, (try reopened.nativeTime("fixture", "ordinary", "one")).?);
    }
    try store.exec("PRAGMA ignore_check_constraints=ON;");
    for ([_][:0]const u8{
        "UPDATE records SET inferred_year='bad' WHERE occurrence='two';",
        "UPDATE records SET inferred_year=-1 WHERE occurrence='two';",
        "UPDATE records SET inferred_year=0 WHERE occurrence='two';",
        "UPDATE records SET inferred_year=10000 WHERE occurrence='two';",
        "UPDATE records SET inferred_year=65536 WHERE occurrence='two';",
        "UPDATE records SET inferred_year=2026,original_us=NULL WHERE occurrence='two';",
        "UPDATE records SET native_time_kind=NULL,effective_us=NULL WHERE occurrence='two';",
    }) |sql| {
        try store.exec(sql);
        try std.testing.expectError(error.DatabaseFailure, store.nativeTime("fixture", "ordinary", "two"));
    }
}

test "year inference: killed migration leaves schema four and pending receipt recoverable" {
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
        try store.enableReceipts(1);
        try store.enableNativeTime();
        _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = 123 }, 0);
    }
    const pid = try std.posix.fork();
    if (pid == 0) {
        var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
        child.enableReceipts(1) catch std.process.exit(3);
        const Kill = struct {
            fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) {
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(4);
                    unreachable;
                }
                return embedded_api.exec(db, sql, callback, context, message);
            }
        };
        child.api.exec = Kill.exec;
        child.enableYearInference() catch std.process.exit(5);
        std.process.exit(6);
    }
    const result = std.posix.waitpid(pid, 0);
    try std.testing.expect(std.os.linux.W.IFSIGNALED(result.status));
    try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(result.status));
    var recovered = try Store.open(a, path);
    defer recovered.close();
    try recovered.enableReceipts(1);
    try std.testing.expectEqual(@as(i64, 4), recovered.schema_version);
    try std.testing.expectEqual(@as(i64, 13), try recovered.integer("SELECT count(*) FROM pragma_table_info('records');"));
    try std.testing.expectEqual(@as(i64, 123), (try recovered.pendingReceipt(ReceiptFixture.identity)).?.us);
    try recovered.enableYearInference();
    try std.testing.expectEqual(@as(i64, 5), recovered.schema_version);
}
