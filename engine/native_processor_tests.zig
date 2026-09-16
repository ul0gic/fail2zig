// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const native = @import("core/native_source_processor.zig");
const sessions = @import("core/native_file_session.zig");
const files = @import("core/durable_file_source.zig");
const store_mod = @import("core/record_store.zig");
const records = @import("core/source_record.zig");
const text = @import("core/source_text.zig");
const time = @import("core/native_time.zig");
const policy = @import("core/source_time_policy.zig");

const Clock = struct {
    now: i64 = 1_000_000_000,
    fn read(context: ?*anyopaque) !time.Timestamp {
        const self: *Clock = @ptrCast(@alignCast(context.?));
        return .{ .us = self.now };
    }
};
fn options() native.Options {
    return .{ .jail = "ordinary", .parent_generation = [_]u8{1} ** 32, .timestamp = .{ .field = .{ .format = .epoch_seconds, .boundary = .{ .delimiter = '|' } } } };
}
fn record(message: []const u8) records.Record {
    return .{ .source = "ordinary", .occurrence = "one", .cursor = "next", .message = message, .raw_hash = [_]u8{1} ** 32, .receipt_time = .{ .us = 1_000_000_000 }, .byte_start = 0 };
}

test "native processor: preparation is bounded and checkpoints reject foreign or changed state" {
    var scratch: [2048]u8 = undefined;
    var processor = try native.Processor.init(std.testing.allocator, options(), &scratch, .{ .us = 1_000_000_000 });
    const adapter = processor.adapter();
    var prepared = try adapter.prepare(record("1000|ordinary event"), adapter.context);
    try std.testing.expectEqual(@as(u64, 0), processor.timeHealth().eligible);
    try std.testing.expectEqual(@as(i64, 1_000_000_000), prepared.native_time.?.eligible.timestamp.us);
    try std.testing.expect(prepared.event_time == null and prepared.intent == null);
    try std.testing.expectError(error.ProcessorBusy, processor.setClock(.{ .us = 0 }));
    try std.testing.expectError(error.ProcessorBusy, adapter.prepare(record("1000|ordinary event"), adapter.context));
    prepared.release(prepared.context);
    try std.testing.expectEqual(@as(u64, 0), processor.timeHealth().eligible);
    prepared = try adapter.prepare(record("1000|ordinary event"), adapter.context);
    var saved: [native.checkpoint_bytes]u8 = undefined;
    @memcpy(&saved, prepared.checkpoint);
    prepared.publish(prepared.context);
    prepared.release(prepared.context);
    try std.testing.expectEqual(@as(u64, 1), processor.timeHealth().eligible);
    for (0..4) |variant| {
        var invalid = saved;
        switch (variant) {
            0 => invalid[0] = '{',
            1 => invalid[4] += 1,
            2 => invalid[8] ^= 1,
            3 => std.mem.writeInt(u64, invalid[40..48], std.math.maxInt(u64), .little),
            else => unreachable,
        }
        const result = adapter.prepare_restore(&invalid, adapter.context);
        if (result) |staged| {
            staged.release(staged.context);
            return error.InvalidCheckpointAccepted;
        } else |_| {}
        try std.testing.expectEqual(@as(u64, 1), processor.timeHealth().eligible);
        try std.testing.expect(!processor.in_flight);
    }
    try std.testing.expectError(error.ForeignSourceCheckpoint, adapter.prepare_restore("{\"schema_version\":2}", adapter.context));
    try std.testing.expectError(error.ForeignSourceCheckpoint, adapter.prepare_restore(saved[0..95], adapter.context));
    var altered_options = options();
    altered_options.window_us -= 1;
    var other = try native.Processor.init(std.testing.allocator, altered_options, &scratch, .{ .us = 1_000_000_000 });
    try std.testing.expectError(error.SourceGenerationMismatch, other.adapter().prepare_restore(&saved, &other));
    const restored = try adapter.prepare_restore(&saved, adapter.context);
    restored.publish(restored.context);
    restored.release(restored.context);
    try std.testing.expectEqual(@as(u64, 1), processor.timeHealth().eligible);
    try std.testing.expectError(error.InvalidEncoding, adapter.prepare(record("1000|\xff"), adapter.context));
    var missing_receipt = record("1000|ordinary");
    missing_receipt.receipt_time = null;
    try std.testing.expectError(error.MissingReceiptTime, adapter.prepare(missing_receipt, adapter.context));
    try std.testing.expect(!processor.in_flight);
}

test "native processor: explicit undated and journal timestamps preserve their distinct meaning" {
    var scratch: [2048]u8 = undefined;
    var config = options();
    config.timestamp = .undated;
    var processor = try native.Processor.init(std.testing.allocator, config, &scratch, .{ .us = 1_000_000_000 });
    var prepared = try processor.adapter().prepare(record("ordinary undated input"), &processor);
    try std.testing.expectEqual(policy.Origin.receipt, prepared.native_time.?.eligible.origin);
    prepared.publish(prepared.context);
    prepared.release(prepared.context);
    try std.testing.expectEqual(@as(u64, 1), processor.timeHealth().receipt);
    config.timestamp = .journal;
    processor = try native.Processor.init(std.testing.allocator, config, &scratch, .{ .us = 1_000_000_000 });
    var journal = record("ordinary journal input");
    journal.byte_start = null;
    journal.timestamp_us = 999_123_456;
    prepared = try processor.adapter().prepare(journal, &processor);
    try std.testing.expectEqual(@as(i64, 999_123_456), prepared.native_time.?.eligible.timestamp.us);
    prepared.release(prepared.context);
    journal.timestamp_us = std.math.maxInt(u64);
    prepared = try processor.adapter().prepare(journal, &processor);
    try std.testing.expectEqual(policy.Reason.out_of_range, prepared.native_time.?.rejected.reason);
    prepared.release(prepared.context);
    config.timestamp = .{ .field = .{ .format = .syslog, .boundary = .{ .length = 15 } } };
    try std.testing.expectError(error.SourceTimeContextRequired, native.Processor.init(std.testing.allocator, config, &scratch, .{ .us = 0 }));
}

test "native processor: file sessions recover native state and pending time without replaying evidence" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "ordinary.log" });
    defer a.free(path);
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(database);
    const file = try temp.dir.createFile("ordinary.log", .{});
    defer file.close();
    var clock = Clock{};
    const config = sessions.Options{ .processing = options(), .max_sources = 2, .clock = Clock.read, .clock_context = &clock };
    const specs = [_]sessions.Spec{.{ .pattern = path }};
    {
        var store = try store_mod.Store.open(a, database);
        defer store.close();
        try store.enableReceipts(2);
        try std.testing.expectError(error.NativeTimeStorageRequired, sessions.Session.create(a, &store, config, &specs));
        try store.enableNativeTime();
        const session = try sessions.Session.create(a, &store, config, &specs);
        defer session.destroy();
        try std.testing.expectEqual(@as(usize, 0), try session.poll(1));
        try file.writeAll("1000.000000|ordinary valid event\n");
        try std.testing.expectEqual(@as(usize, 1), try session.poll(1));
        const source = &session.sources.sources.items[0];
        const value = (try store.nativeTime("ordinary", source.source_id, null)).?.eligible;
        try std.testing.expectEqual(@as(i64, 1_000_000_000), value.original.?.us);
        const committed_offset = source.acknowledgedCheckpoint().?.offset;
        try file.writeAll("1060.000001|ordinary excessive future event\n");
        store.fail_at = .after_receipt_delete;
        try std.testing.expectError(error.InjectedFailure, session.poll(1));
        try std.testing.expectEqual(@as(u64, 0), session.processor.timeHealth().future);
        try std.testing.expectEqual(committed_offset, source.acknowledgedCheckpoint().?.offset);
        try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    }
    clock.now = 2_000_000_000;
    var store = try store_mod.Store.open(a, database);
    defer store.close();
    try store.enableReceipts(2);
    try store.enableNativeTime();
    const session = try sessions.Session.create(a, &store, config, &specs);
    defer session.destroy();
    try std.testing.expectEqual(@as(u64, 1), session.processor.timeHealth().eligible);
    const before = session.pipe.revision;
    try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    try std.testing.expectEqual(before, try store.revision("ordinary"));
    try std.testing.expectEqual(@as(usize, 1), try session.poll(1));
    const source = &session.sources.sources.items[0];
    const rejected = (try store.nativeTime("ordinary", source.source_id, null)).?.rejected;
    try std.testing.expectEqual(policy.Reason.future, rejected.reason);
    try std.testing.expectEqual(@as(i64, 1_000_000_000), rejected.receipt.?.us);
    try file.writeAll("|ordinary missing timestamp\nbad|ordinary malformed timestamp\n100|ordinary obsolete event\n2000|ordinary current event\n");
    for (0..4) |_| try std.testing.expectEqual(@as(usize, 1), try session.poll(1));
    try std.testing.expectEqualDeep(policy.Counters{ .eligible = 2, .obsolete = 1, .missing = 1, .malformed = 1, .future = 1 }, session.processor.timeHealth());
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    try std.testing.expectEqual(@as(usize, 0), try session.poll(1));
    const saved = (try store.checkpoint(a, "ordinary")).?;
    defer a.free(saved);
    try std.testing.expectEqual(native.checkpoint_bytes, saved.len);
    try std.testing.expectEqualStrings("F2NT", saved[0..4]);
    var changed = config;
    changed.processing.window_us += 1;
    try std.testing.expectError(error.SourceGenerationMismatch, sessions.Session.create(a, &store, changed, &specs));
}

test "native processor: saved tail cursors and rotated incarnations survive downtime and missing anchors refuse startup" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "ordinary.log" });
    defer a.free(path);
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(database);
    const file = try temp.dir.createFile("ordinary.log", .{});
    defer file.close();
    try file.writeAll("1000|ordinary initial tail content\n");
    var clock = Clock{};
    const config = sessions.Options{ .processing = options(), .max_sources = 3, .clock = Clock.read, .clock_context = &clock };
    const specs = [_]sessions.Spec{.{ .pattern = path, .start = .tail }};
    var store = try store_mod.Store.open(a, database);
    defer store.close();
    try store.enableReceipts(3);
    try store.enableNativeTime();
    const oversized = [_]u8{'x'} ** (store_mod.Limits.source_bytes + 1);
    try std.testing.expectError(error.InvalidSourceSpecification, sessions.Session.create(std.testing.failing_allocator, &store, config, &.{.{ .pattern = &oversized }}));
    {
        const session = try sessions.Session.create(a, &store, config, &specs);
        defer session.destroy();
        try std.testing.expectEqual(@as(usize, 0), try session.poll(1));
        try std.testing.expectEqual(@as(u64, 0), session.processor.timeHealth().eligible);
    }
    try file.writeAll("1000|ordinary downtime append\n");
    {
        const session = try sessions.Session.create(a, &store, config, &specs);
        defer session.destroy();
        try std.testing.expectEqual(@as(usize, 1), try session.poll(1));
        try std.testing.expectEqual(@as(u64, 1), session.processor.timeHealth().eligible);
    }
    try temp.dir.rename("ordinary.log", "ordinary.rotated");
    try temp.dir.writeFile(.{ .sub_path = "ordinary.log", .data = "1000|ordinary replacement baseline\n" });
    try file.writeAll("1000|ordinary late append\n");
    {
        const session = try sessions.Session.create(a, &store, config, &specs);
        defer session.destroy();
        try std.testing.expectEqual(@as(usize, 2), session.sources.sources.items.len);
        try std.testing.expectEqual(@as(usize, 1), try session.poll(2));
        try std.testing.expectEqual(@as(u64, 2), session.processor.timeHealth().eligible);
    }
    const revision = try store.revision("ordinary");
    try temp.dir.deleteFile("ordinary.rotated");
    try std.testing.expectError(error.ResumeLost, sessions.Session.create(a, &store, config, &specs));
    try std.testing.expectEqual(revision, try store.revision("ordinary"));
}

fn encoded(allocator: std.mem.Allocator, encoding: text.Encoding, input: []const u8) ![]u8 {
    var output = std.ArrayList(u8).init(allocator);
    errdefer output.deinit();
    var it = (try std.unicode.Utf8View.init(input)).iterator();
    while (it.nextCodepoint()) |cp| {
        switch (encoding) {
            .utf8 => {
                var bytes: [4]u8 = undefined;
                const count = try std.unicode.utf8Encode(cp, &bytes);
                try output.appendSlice(bytes[0..count]);
            },
            .ascii, .latin1 => try output.append(@intCast(cp)),
            .utf16le, .utf16be => {
                var bytes: [2]u8 = undefined;
                std.mem.writeInt(u16, &bytes, @intCast(cp), if (encoding == .utf16le) .little else .big);
                try output.appendSlice(&bytes);
            },
            .utf32le, .utf32be => {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, cp, if (encoding == .utf32le) .little else .big);
                try output.appendSlice(&bytes);
            },
        }
    }
    return output.toOwnedSlice();
}

test "native processor: actual file sessions decode every admitted encoding before time admission" {
    const a = std.testing.allocator;
    for (std.enums.values(text.Encoding)) |encoding| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "ordinary.log" });
        defer a.free(path);
        const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
        defer a.free(database);
        const input = if (encoding == .ascii) "1000|ordinary cafe\n" else "1000|ordinary café\n";
        const bytes = try encoded(a, encoding, input);
        defer a.free(bytes);
        try temp.dir.writeFile(.{ .sub_path = "ordinary.log", .data = bytes });
        var store = try store_mod.Store.open(a, database);
        defer store.close();
        try store.enableReceipts(1);
        try store.enableNativeTime();
        var clock = Clock{};
        var config = sessions.Options{ .processing = options(), .max_sources = 1, .clock = Clock.read, .clock_context = &clock };
        config.processing.encoding = encoding;
        const session = try sessions.Session.create(a, &store, config, &.{.{ .pattern = path }});
        defer session.destroy();
        try std.testing.expectEqual(@as(usize, 1), try session.poll(1));
        try std.testing.expectEqual(@as(u64, 1), session.processor.timeHealth().eligible);
        const source = &session.sources.sources.items[0];
        try std.testing.expectEqual(@as(u64, bytes.len), source.acknowledgedCheckpoint().?.offset);
        try std.testing.expectEqual(@as(i64, 1_000_000_000), (try store.nativeTime("ordinary", source.source_id, null)).?.eligible.original.?.us);
    }
    var scratch: [5]u8 = undefined;
    var config = options();
    config.encoding = .latin1;
    config.max_decoded_bytes = scratch.len;
    var processor = try native.Processor.init(a, config, &scratch, .{ .us = 1_000_000_000 });
    try std.testing.expectError(error.OutputTooSmall, processor.adapter().prepare(record("1|\xe9\xe9"), &processor));
    try std.testing.expectEqual(policy.Counters{}, processor.timeHealth());
}

test "native processor: pending source verification fails before activation and allocation failures leave state intact" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "ordinary.log" });
    defer a.free(path);
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(database);
    const file = try temp.dir.createFile("ordinary.log", .{});
    defer file.close();
    var clock = Clock{};
    const config = sessions.Options{ .processing = options(), .max_sources = 1, .clock = Clock.read, .clock_context = &clock };
    const specs = [_]sessions.Spec{.{ .pattern = path }};
    var store = try store_mod.Store.open(a, database);
    defer store.close();
    try store.enableReceipts(1);
    try store.enableNativeTime();
    {
        const session = try sessions.Session.create(a, &store, config, &specs);
        defer session.destroy();
        _ = try session.poll(1);
        try file.writeAll("1000|ordinary event\n");
        store.fail_at = .after_receipt_commit;
        try std.testing.expectError(error.InjectedFailure, session.poll(1));
    }
    store.fail_at = null;
    const revision = try store.revision("ordinary");
    try file.pwriteAll("2", 0);
    try std.testing.expectError(error.PendingRecordMismatch, sessions.Session.create(a, &store, config, &specs));
    try file.pwriteAll("1", 0);
    const Exercise = struct {
        fn create(allocator: std.mem.Allocator, durable_store: *store_mod.Store, session_options: sessions.Options, specifications: []const sessions.Spec) !void {
            const session = try sessions.Session.create(allocator, durable_store, session_options, specifications);
            defer session.destroy();
            try std.testing.expectEqual(@as(u64, 0), session.processor.timeHealth().eligible);
            try std.testing.expectEqual(@as(u64, 0), session.sources.sources.items[0].acknowledgedCheckpoint().?.offset);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Exercise.create, .{ &store, config, @as([]const sessions.Spec, &specs) });
    try std.testing.expectEqual(revision, try store.revision("ordinary"));
    try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    try file.setEndPos(5);
    try std.testing.expectError(error.PendingRecordUnavailable, sessions.Session.create(a, &store, config, &specs));
    try std.testing.expectEqual(revision, try store.revision("ordinary"));
}

test "native processor: session samples processing time after durable receipt with an advancing clock" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "ordinary.log" });
    defer a.free(path);
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(database);
    try temp.dir.writeFile(.{ .sub_path = "ordinary.log", .data = "ordinary undated input\n" });
    const Advancing = struct {
        value: i64 = 1_000_000_000,
        fn read(context: ?*anyopaque) !time.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            defer self.value += 1;
            return .{ .us = self.value };
        }
    };
    var clock = Advancing{};
    var config = sessions.Options{ .processing = options(), .max_sources = 1, .clock = Advancing.read, .clock_context = &clock };
    config.processing.timestamp = .undated;
    config.processing.window_us = 0;
    var store = try store_mod.Store.open(a, database);
    defer store.close();
    try store.enableReceipts(1);
    try store.enableNativeTime();
    const session = try sessions.Session.create(a, &store, config, &.{.{ .pattern = path }});
    defer session.destroy();
    try std.testing.expectEqual(@as(usize, 1), try session.poll(1));
    const source = &session.sources.sources.items[0];
    const outcome = (try store.nativeTime("ordinary", source.source_id, null)).?.obsolete;
    try std.testing.expectEqual(@as(i64, 1_000_000_001), outcome.receipt.us);
    try std.testing.expectEqual(outcome.receipt.us, outcome.timestamp.us);
    try std.testing.expectEqual(@as(i64, 1_000_000_003), clock.value);
    try std.testing.expectEqual(@as(u64, 1), session.processor.timeHealth().obsolete);
}

fn syslogOptions() native.Options {
    var config = options();
    config.timestamp = .{ .field = .{ .format = .syslog, .boundary = .{ .length = 15 }, .context = .{ .offset_seconds = 0 }, .infer_year = true } };
    return config;
}

test "year inference: native admission preserves inferred provenance and rejects ambiguous dates" {
    var scratch: [2048]u8 = undefined;
    var config = syslogOptions();
    const receipt = try time.parse(.iso8601, "2025-12-31T23:59:50Z", .{});
    var processor = try native.Processor.init(std.testing.allocator, config, &scratch, receipt);
    var input = record("Jan  1 00:00:00 ordinary");
    input.receipt_time = receipt;
    var prepared = try processor.adapter().prepare(input, &processor);
    try std.testing.expectEqual(@as(?u16, 2026), prepared.native_time.?.eligible.inferred_year);
    try std.testing.expectEqual(policy.Origin.clock_adjusted, prepared.native_time.?.eligible.origin);
    try std.testing.expectEqual(receipt.us, prepared.native_time.?.eligible.timestamp.us);
    prepared.release(prepared.context);
    input.receipt_time.?.us -= 120_000_000;
    prepared = try processor.adapter().prepare(input, &processor);
    try std.testing.expectEqual(policy.Reason.future, prepared.native_time.?.rejected.reason);
    try std.testing.expectEqual(@as(?u16, 2026), prepared.native_time.?.rejected.inferred_year);
    prepared.release(prepared.context);
    const midpoint = try time.parse(.iso8601, "2025-07-02T12:00:00Z", .{});
    input.receipt_time = midpoint;
    try processor.setClock(midpoint);
    prepared = try processor.adapter().prepare(input, &processor);
    try std.testing.expectEqual(policy.Reason.malformed, prepared.native_time.?.rejected.reason);
    try std.testing.expect(prepared.native_time.?.rejected.inferred_year == null);
    prepared.release(prepared.context);
    config.timestamp.field.infer_year = false;
    try std.testing.expectError(error.SourceTimeContextRequired, native.Processor.init(std.testing.allocator, config, &scratch, receipt));
    config.timestamp.field.infer_year = true;
    config.timestamp.field.context.year = 2025;
    try std.testing.expectError(error.InvalidYearInference, native.Processor.init(std.testing.allocator, config, &scratch, receipt));
    config.timestamp.field.context.year = null;
    config.timestamp.field.context.offset_seconds = null;
    try std.testing.expectError(error.SourceTimeContextRequired, native.Processor.init(std.testing.allocator, config, &scratch, receipt));
    config.timestamp.field.context.offset_seconds = 0;
    config.timestamp.field.format = .iso8601;
    try std.testing.expectError(error.InvalidYearInference, native.Processor.init(std.testing.allocator, config, &scratch, receipt));
}

test "year inference: actual file restart retains the original year and rejection then continues" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |future| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "ordinary.log" });
        defer a.free(path);
        const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
        defer a.free(database);
        const file = try temp.dir.createFile("ordinary.log", .{});
        defer file.close();
        var clock = Clock{ .now = (try time.parse(.iso8601, if (future) "2025-12-31T23:58:00Z" else "2026-01-01T00:00:10Z", .{})).us };
        const receipt = clock.now;
        const config = sessions.Options{ .processing = syslogOptions(), .max_sources = 1, .clock = Clock.read, .clock_context = &clock };
        const specs = [_]sessions.Spec{.{ .pattern = path }};
        {
            var store = try store_mod.Store.open(a, database);
            defer store.close();
            try store.enableReceipts(1);
            try store.enableNativeTime();
            try std.testing.expectError(error.InferenceStorageRequired, sessions.Session.create(a, &store, config, &specs));
            try store.enableYearInference();
            const session = try sessions.Session.create(a, &store, config, &specs);
            defer session.destroy();
            _ = try session.poll(1);
            try file.writeAll(if (future) "Jan  1 00:00:00 ordinary future\n" else "Dec 31 23:59:59 ordinary past\n");
            store.fail_at = .after_checkpoint;
            try std.testing.expectError(error.InjectedFailure, session.poll(1));
            try std.testing.expectEqualDeep(policy.Counters{}, session.processor.timeHealth());
            try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        }
        clock.now = (try time.parse(.iso8601, "2027-01-01T00:00:00Z", .{})).us;
        var store = try store_mod.Store.open(a, database);
        defer store.close();
        try store.enableReceipts(1);
        try store.enableNativeTime();
        try std.testing.expectEqual(@as(i64, 5), store.schema_version);
        const session = try sessions.Session.create(a, &store, config, &specs);
        defer session.destroy();
        try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        try std.testing.expectEqual(@as(usize, 1), try session.poll(1));
        const source = &session.sources.sources.items[0];
        const outcome = (try store.nativeTime("ordinary", source.source_id, null)).?;
        if (future) {
            try std.testing.expectEqual(policy.Reason.future, outcome.rejected.reason);
            try std.testing.expectEqual(@as(?u16, 2026), outcome.rejected.inferred_year);
            try std.testing.expectEqual(receipt, outcome.rejected.receipt.?.us);
        } else {
            try std.testing.expectEqual(@as(?u16, 2025), outcome.obsolete.inferred_year);
            try std.testing.expectEqual(receipt, outcome.obsolete.receipt.us);
        }
        try file.writeAll("Jan 32 00:00:00 bad day\nJan  1 00:00:00 current event\n");
        try std.testing.expectEqual(@as(usize, 1), try session.poll(1));
        try std.testing.expectEqual(@as(usize, 1), try session.poll(1));
        try std.testing.expectEqual(@as(?u16, 2027), (try store.nativeTime("ordinary", source.source_id, null)).?.eligible.inferred_year);
        try std.testing.expectEqual(@as(u64, 1), session.processor.timeHealth().malformed);
        try std.testing.expectEqual(@as(u64, 1), session.processor.timeHealth().eligible);
        try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
        var changed = config;
        changed.processing.timestamp.field.infer_year = false;
        changed.processing.timestamp.field.context.year = 2027;
        try std.testing.expectError(error.SourceGenerationMismatch, sessions.Session.create(a, &store, changed, &specs));
        changed = config;
        changed.processing.timestamp.field.context.offset_seconds = 3600;
        try std.testing.expectError(error.SourceGenerationMismatch, sessions.Session.create(a, &store, changed, &specs));
    }
}
