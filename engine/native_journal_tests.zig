// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const transport = @import("core/native_journal_transport.zig");
const sessions = @import("core/native_journal_session.zig");
const native = @import("core/native_source_processor.zig");
const durable = @import("core/record_store.zig");
const time = @import("core/native_time.zig");
const policy = @import("core/source_time_policy.zig");
const records = @import("core/source_record.zig");
const row1 = "{\"__CURSOR\":\"one\",\"__REALTIME_TIMESTAMP\":\"1000000000\",\"MESSAGE\":\"ordinary first\",\"_UID\":\"0\"}\n";
const row2 = "{\"__CURSOR\":\"two\",\"__REALTIME_TIMESTAMP\":\"1000000001\",\"MESSAGE\":\"ordinary second\",\"_UID\":\"0\"}\n";
const row3 = "{\"__CURSOR\":\"three\",\"__REALTIME_TIMESTAMP\":\"1000000002\",\"MESSAGE\":\"ordinary third\",\"_UID\":\"0\"}\n";
const Clock = struct {
    now: i64 = 1_000_000_010,
    fn read(context: ?*anyopaque) !time.Timestamp {
        const self: *Clock = @ptrCast(@alignCast(context.?));
        return .{ .us = self.now };
    }
};

test "clock recovery: empty journal baseline survives backward clock and automatic validated recovery" {
    const health = @import("core/storage_health.zig");
    const recovery = @import("core/native_recovery.zig");
    const Mono = struct {
        ms: u64 = 0,
        fn read(context: ?*anyopaque) u64 {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return self.ms;
        }
    };
    const Owner = struct {
        store: *durable.Store,
        options: sessions.Options,
        session: ?*sessions.Session = null,
        fn cast(context: ?*anyopaque) *@This() {
            return @ptrCast(@alignCast(context.?));
        }
        fn storage(context: ?*anyopaque) !void {
            _ = try cast(context).store.receiptClock();
        }
        fn state(context: ?*anyopaque) !void {
            const self = cast(context);
            if (self.session) |old| old.destroy();
            self.session = null;
            self.session = try sessions.Session.create(t.allocator, self.store, self.options);
        }
        fn ownership(context: ?*anyopaque) !void {
            try t.expectEqual(@as(i64, 0), try cast(context).store.pendingIntents());
        }
        fn sources(context: ?*anyopaque) !void {
            try cast(context).session.?.verifyRecoverySources();
        }
    };
    for ([_]bool{ false, true }) |recreate| {
        var temp = t.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const database = try std.fs.path.join(t.allocator, &.{ root, "journal-clock.sqlite" });
        defer t.allocator.free(database);
        var store = try durable.Store.open(t.allocator, database);
        defer store.close();
        try store.enableReceipts(1);
        try store.enableNativeTime();
        try store.enableDetection();
        try store.enableClockRecovery();
        var clock = Clock{};
        var mono = Mono{};
        var gate = health.Gate.init(.{ .context = &mono, .read = Mono.read });
        var mock = Mock{};
        var owner = Owner{ .store = &store, .options = .{ .processing = processing(), .clock = Clock.read, .clock_context = &clock, .gate = &gate, .executor = mock.executor() } };
        defer if (owner.session) |session| session.destroy();
        var driver = recovery.Driver{ .store = &store, .gate = &gate, .clock = .{ .generation = [_]u8{0} ** 32, .clock = Clock.read, .clock_context = &clock }, .hooks = .{ .context = &owner, .storage = Owner.storage, .state = Owner.state, .ownership = Owner.ownership, .sources = Owner.sources } };
        try t.expectEqual(recovery.Status.resumed, try driver.poll());
        try t.expectEqual(@as(usize, 0), try owner.session.?.poll(1));
        try t.expect((try store.receiptClock()) == null);
        clock.now = 1;
        const queries = mock.calls;
        if (recreate) {
            owner.session.?.destroy();
            owner.session = null;
            gate = health.Gate.init(.{ .context = &mono, .read = Mono.read });
            try t.expectEqual(recovery.Status.waiting, try driver.poll());
        } else {
            try t.expectError(error.ReceiptClockReversed, owner.session.?.poll(1));
            try t.expectEqual(records.Health.clock_failed, owner.session.?.source_health);
        }
        try t.expectEqual(queries, mock.calls);
        try t.expectEqual(@as(?i64, 1_000_000_010), gate.snapshot().receipt_clock_floor_us);
        mono.ms = 1000;
        try t.expectEqual(recovery.Status.waiting, try driver.poll());
        clock.now = 1_000_000_110;
        mono.ms = 3000;
        mock.expected_position = "--since=@1000.000010";
        try t.expectEqual(recovery.Status.resumed, try driver.poll());
        mock.response = "{\"__CURSOR\":\"after\",\"__REALTIME_TIMESTAMP\":\"1000000011\",\"MESSAGE\":\"ordinary later entry\"}\n";
        try t.expectEqual(@as(usize, 1), try owner.session.?.poll(1));
        try t.expectEqual(@as(i64, 1_000_000_011), (try store.nativeTime("ordinary", "system-journal", null)).?.eligible.timestamp.us);
        try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    }
}
fn processing() native.Options {
    return .{ .jail = "ordinary", .parent_generation = [_]u8{1} ** 32, .timestamp = .journal, .max_record_bytes = 8192, .max_decoded_bytes = 8192 };
}
const Mock = struct {
    response: []const u8 = "",
    failure: ?anyerror = null,
    expected_position: ?[]const u8 = null,
    calls: usize = 0,
    fn run(_: std.mem.Allocator, args: []const []const u8, output: []u8, diagnostic: *transport.Diagnostic, _: u32, context: ?*anyopaque) ![]const u8 {
        const self: *Mock = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        if (self.expected_position) |position| {
            var found = false;
            for (args) |arg| if (std.mem.eql(u8, arg, position)) {
                found = true;
            };
            try t.expect(found);
        }
        diagnostic.* = .{ .exit_code = 0 };
        if (self.failure) |failure| return failure;
        if (self.response.len > output.len) return error.JournalOutputLimit;
        @memcpy(output[0..self.response.len], self.response);
        return output[0..self.response.len];
    }
    fn executor(self: *Mock) transport.Executor {
        return .{ .run = run, .context = self };
    }
};

test "native journal: bounded argv preserves selectors and explicit positions without shell syntax" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var options = transport.Options{ .matches = &.{ "_SYSTEMD_UNIT=sshd.service", "+", "SYSLOG_IDENTIFIER=sshd" } };
    const args = try transport.argv(a, options, .{ .since_us = 1_000_000_001 }, 2);
    try t.expectEqualStrings("--since=@1000.000001", args[6]);
    try t.expectEqualStrings("--lines=+2", args[7]);
    try t.expectEqualStrings("--", args[8]);
    try t.expectEqualStrings("+", args[10]);
    options.matches = &.{"--rotate"};
    try t.expectError(error.InvalidJournalMatch, transport.validate(options));
    options.matches = &.{"+"};
    try t.expectError(error.InvalidJournalMatch, transport.validate(options));
    options.matches = &.{ "_UID=0", "+" };
    try t.expectError(error.InvalidJournalMatch, transport.validate(options));
    options.matches = &.{"MESSAGE=ordinary; $(not a shell)"};
    _ = try transport.argv(a, options, .{ .cursor = "opaque; not parsed" }, 1);
    options.target = .{ .directory = "/ordinary" };
    options.namespace = "example";
    try t.expectError(error.ConflictingJournalSelection, transport.validate(options));
    options.namespace = null;
    options.target = .{ .files = &.{"relative"} };
    try t.expectError(error.InvalidJournalPath, transport.validate(options));
}

test "native journal: canonical fields retain bytes repeats metadata and integer time" {
    const scratch = try t.allocator.alloc(u8, transport.parse_bytes);
    defer t.allocator.free(scratch);
    const first = try transport.decode(scratch, "{\"MESSAGE\":[99,97,102,195,169],\"__CURSOR\":\"opaque\",\"__REALTIME_TIMESTAMP\":\"9007199254740993\",\"__MONOTONIC_TIMESTAMP\":\"123\",\"_UID\":\"0\",\"TAG\":[\"b\",\"a\"]}", 4096);
    const hash = first.raw_hash;
    try t.expectEqualStrings("café", first.message);
    try t.expectEqual(@as(?u64, 9007199254740993), first.realtime_us);
    try t.expectEqual(@as(?u64, 123), first.monotonic_us);
    try t.expectEqual(@as(usize, 7), first.fields.len);
    const second = try transport.decode(scratch, "{\"TAG\":[\"a\",\"b\"],\"_UID\":\"0\",\"__MONOTONIC_TIMESTAMP\":\"123\",\"__REALTIME_TIMESTAMP\":\"9007199254740993\",\"__CURSOR\":\"opaque\",\"MESSAGE\":\"café\"}", 4096);
    try t.expectEqualSlices(u8, &hash, &second.raw_hash);
    for ([_][]const u8{
        "{\"MESSAGE\":null,\"__CURSOR\":\"c\"}",
        "{\"MESSAGE\":[\"a\",\"b\"],\"__CURSOR\":\"c\"}",
        "{\"MESSAGE\":\"x\",\"__CURSOR\":\"c\",\"__REALTIME_TIMESTAMP\":\"-1\"}",
        "{\"MESSAGE\":\"x\",\"__CURSOR\":\"c\",\"__REALTIME_TIMESTAMP\":\"18446744073709551616\"}",
        "{\"MESSAGE\":\"x\",\"__CURSOR\":\"c\",\"MESSAGE\":\"y\"}",
    }) |bad| {
        if (transport.decode(scratch, bad, 4096)) |_| return error.InvalidRecordAccepted else |_| {}
    }
    try t.expectError(error.JournalMessageLimit, transport.decode(scratch, row1[0 .. row1.len - 1], 1));
    var small: [8]u8 = undefined;
    try t.expectError(error.JournalParseLimit, transport.decode(&small, row1[0 .. row1.len - 1], 4096));
}

test "native journal: runner captures errors bounds output and reaps timed out children" {
    var output: [32]u8 = undefined;
    var diagnostic = transport.Diagnostic{};
    const empty = try transport.execute(t.allocator, &.{"/bin/true"}, &output, &diagnostic, 1000, null);
    try t.expectEqual(@as(usize, 0), empty.len);
    try t.expectError(error.JournalChildFailed, transport.execute(t.allocator, &.{"/bin/false"}, &output, &diagnostic, 1000, null));
    try t.expectEqual(@as(?u8, 1), diagnostic.exit_code);
    var timer = try std.time.Timer.start();
    try t.expectError(error.JournalTimeout, transport.execute(t.allocator, &.{ "/bin/sleep", "2" }, &output, &diagnostic, 20, null));
    try t.expect(timer.read() < std.time.ns_per_s);
    try t.expectError(error.JournalOutputLimit, transport.execute(t.allocator, &.{ "/usr/bin/printf", "%100s", "ordinary" }, &output, &diagnostic, 1000, null));
    try t.expectError(error.FileNotFound, transport.execute(t.allocator, &.{"/nonexistent/fail2zig-journal-test"}, &output, &diagnostic, 1000, null));
}

test "native journal: durable tail baseline exact restart pending validation and later input" {
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(database);
    var clock = Clock{};
    var mock = Mock{ .response = row1, .expected_position = "--lines=1" };
    const options = sessions.Options{ .processing = processing(), .clock = Clock.read, .clock_context = &clock, .executor = mock.executor() };
    {
        var store = try durable.Store.open(a, database);
        defer store.close();
        try store.enableReceipts(1);
        try store.enableNativeTime();
        const session = try sessions.Session.create(a, &store, options);
        defer session.destroy();
        store.fail_at = .before_commit;
        try t.expectError(error.InjectedFailure, session.poll(1));
        try t.expectEqual(@as(u64, 0), try store.revision("ordinary"));
        store.fail_at = null;
        try t.expectEqual(@as(usize, 0), try session.poll(1));
        try t.expectEqualDeep(policy.Counters{}, session.processor.timeHealth());
        mock.response = row1 ++ row2;
        mock.expected_position = "--cursor=one";
        store.fail_at = .after_receipt_delete;
        try t.expectError(error.InjectedFailure, session.poll(1));
        try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        try t.expectEqual(@as(u64, 1), try store.revision("ordinary"));
    }
    clock.now += 100;
    var store = try durable.Store.open(a, database);
    defer store.close();
    try store.enableReceipts(1);
    const session = try sessions.Session.create(a, &store, options);
    defer session.destroy();
    try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    try t.expectEqual(@as(usize, 1), try session.poll(1));
    const saved = (try store.nativeTime("ordinary", "system-journal", null)).?.eligible;
    try t.expectEqual(@as(i64, 1_000_000_010), saved.receipt.us);
    try t.expectEqual(@as(i64, 1_000_000_001), saved.original.?.us);
    mock.response = row2 ++ row3;
    mock.expected_position = "--cursor=two";
    try t.expectEqual(@as(usize, 1), try session.poll(1));
    try t.expectEqual(@as(u64, 2), session.processor.timeHealth().eligible);
    try t.expectEqual(@as(i64, 0), try store.pendingIntents());
    mock.response = row3;
    mock.expected_position = "--cursor=three";
    try t.expectEqual(@as(usize, 0), try session.poll(1));
    mock.response = row2;
    try t.expectError(error.ResumeLost, session.poll(1));
    try t.expectEqual(records.Health.resume_lost, session.source_health);
    const before = try store.revision("ordinary");
    try t.expectError(error.ResumeLost, sessions.Session.create(a, &store, options));
    try t.expectEqual(before, try store.revision("ordinary"));
}

test "native journal: empty baseline retains initial time across restart and malformed output cannot advance" {
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(database);
    var clock = Clock{};
    var mock = Mock{};
    const options = sessions.Options{ .processing = processing(), .clock = Clock.read, .clock_context = &clock, .executor = mock.executor() };
    {
        var store = try durable.Store.open(a, database);
        defer store.close();
        try store.enableReceipts(1);
        try store.enableNativeTime();
        const session = try sessions.Session.create(a, &store, options);
        defer session.destroy();
        try t.expectEqual(@as(usize, 0), try session.poll(1));
    }
    clock.now += 10_000_000;
    mock.expected_position = "--since=@1000.000010";
    var store = try durable.Store.open(a, database);
    defer store.close();
    try store.enableReceipts(1);
    const session = try sessions.Session.create(a, &store, options);
    defer session.destroy();
    const before = try store.revision("ordinary");
    mock.response = row1[0 .. row1.len - 1];
    try t.expectError(error.IncompleteJournalRecord, session.poll(1));
    try t.expectEqual(before, try store.revision("ordinary"));
    mock.response = row1 ++ row2;
    try t.expectError(error.JournalRecordLimit, session.poll(1));
    try t.expectEqual(before, try store.revision("ordinary"));
    mock.failure = error.JournalTimeout;
    try t.expectError(error.JournalTimeout, session.poll(1));
    try t.expectEqual(records.Health.child_failed, session.source_health);
    mock.failure = error.InputOutput;
    try t.expectError(error.InputOutput, session.poll(1));
    try t.expectEqual(records.Health.read_failed, session.source_health);
    mock.failure = null;
    mock.response = row1;
    try t.expectEqual(@as(usize, 1), try session.poll(1));
    try t.expectEqual(records.Health.healthy, session.source_health);
}

const Fixture = struct {
    temp: t.TmpDir,
    root: []const u8,
    executable: []const u8,
    fn init(a: std.mem.Allocator) !Fixture {
        const executable = std.process.getEnvVarOwned(a, "FAIL2ZIG_TEST_JOURNALCTL") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => try a.dupe(u8, "/usr/bin/journalctl"),
            else => return err,
        };
        errdefer a.free(executable);
        try std.fs.cwd().access(executable, .{});
        var temp = t.tmpDir(.{});
        errdefer temp.cleanup();
        const archive_path = std.process.getEnvVarOwned(a, "FAIL2ZIG_TEST_JOURNAL_FIXTURES") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => try a.dupe(u8, "tests/fixtures/native-journal/fixtures.tar.gz"),
            else => return err,
        };
        defer a.free(archive_path);
        const archive = try std.fs.cwd().openFile(archive_path, .{});
        defer archive.close();
        var gzip = std.compress.gzip.decompressor(archive.reader());
        try std.tar.pipeToFileSystem(temp.dir, gzip.reader(), .{});
        return .{ .temp = temp, .root = try temp.dir.realpathAlloc(a, "."), .executable = executable };
    }
    fn deinit(self: *Fixture, a: std.mem.Allocator) void {
        a.free(self.root);
        a.free(self.executable);
        self.temp.cleanup();
    }
};

test "native journal: real journalctl compressed fixtures batch oldest records and recover exact SQLite cursor" {
    const a = t.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit(a);
    for ([_][]const u8{ "none", "XZ", "LZ4", "ZSTD" }) |codec| {
        const selected_name = try std.fmt.allocPrint(a, "selected-{s}", .{codec});
        defer a.free(selected_name);
        try fixture.temp.dir.makeDir(selected_name);
        const selected = try std.fs.path.join(a, &.{ fixture.root, selected_name });
        defer a.free(selected);
        const database = try std.fmt.allocPrint(a, "{s}/{s}.sqlite", .{ fixture.root, codec });
        defer a.free(database);
        var clock = Clock{ .now = 1_750_000_000_000_000 };
        const options = sessions.Options{ .processing = processing(), .journal = .{ .executable = fixture.executable, .target = .{ .directory = selected }, .batch_records = 2 }, .clock = Clock.read, .clock_context = &clock };
        {
            var store = try durable.Store.open(a, database);
            defer store.close();
            try store.enableReceipts(1);
            try store.enableNativeTime();
            const session = try sessions.Session.create(a, &store, options);
            defer session.destroy();
            try t.expectEqual(@as(usize, 0), try session.poll(1));
            const original = try std.fmt.allocPrint(a, "fixtures/{s}.journal", .{codec});
            defer a.free(original);
            const destination = try std.fmt.allocPrint(a, "{s}/ordinary.journal", .{selected_name});
            defer a.free(destination);
            try fixture.temp.dir.copyFile(original, fixture.temp.dir, destination, .{});
            clock.now += 100;
            try t.expectEqual(@as(usize, 1), try session.poll(1));
            try t.expectEqual(@as(i64, 1_750_000_000_000_001), (try store.nativeTime("ordinary", "system-journal", null)).?.eligible.original.?.us);
            store.fail_at = .after_receipt_delete;
            try t.expectError(error.InjectedFailure, session.poll(1));
            try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        }
        clock.now += 100;
        var store = try durable.Store.open(a, database);
        defer store.close();
        try store.enableReceipts(1);
        const session = try sessions.Session.create(a, &store, options);
        defer session.destroy();
        try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        try t.expectEqual(@as(usize, 1), try session.poll(1));
        const second = (try store.nativeTime("ordinary", "system-journal", null)).?.eligible;
        try t.expectEqual(@as(i64, 1_750_000_000_000_002), second.original.?.us);
        try t.expectEqual(@as(i64, 1_750_000_000_000_100), second.receipt.us);
        try t.expectEqual(@as(usize, 1), try session.poll(2));
        try t.expectEqual(@as(i64, 1_750_000_000_000_003), (try store.nativeTime("ordinary", "system-journal", null)).?.eligible.original.?.us);
        try t.expectEqual(@as(usize, 0), try session.poll(2));
        try t.expectEqual(@as(u64, 3), session.processor.timeHealth().eligible);
        try t.expectEqual(@as(i64, 0), try store.pendingIntents());
    }
}

test "native journal: real journalctl tail baseline and changed selected view never imply continuity" {
    const a = t.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit(a);
    const journal = try std.fs.path.join(a, &.{ fixture.root, "fixtures", "none.journal" });
    defer a.free(journal);
    const database = try std.fs.path.join(a, &.{ fixture.root, "tail.sqlite" });
    defer a.free(database);
    var clock = Clock{ .now = 1_750_000_000_000_100 };
    const paths = [_][]const u8{journal};
    const options = sessions.Options{ .processing = processing(), .journal = .{ .executable = fixture.executable, .target = .{ .files = &paths } }, .clock = Clock.read, .clock_context = &clock };
    var store = try durable.Store.open(a, database);
    defer store.close();
    try store.enableReceipts(1);
    try store.enableNativeTime();
    const session = try sessions.Session.create(a, &store, options);
    defer session.destroy();
    try t.expectEqual(@as(usize, 0), try session.poll(1));
    try t.expectEqual(@as(usize, 0), try session.poll(1));
    try t.expectEqualDeep(policy.Counters{}, session.processor.timeHealth());
    var changed = options;
    changed.journal.matches = &.{"F2Z_KIND=allow"};
    try t.expectError(error.SourceGenerationMismatch, sessions.Session.create(a, &store, changed));
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const buffer = try a.alloc(u8, 256 * 1024);
    defer a.free(buffer);
    var diagnostic = transport.Diagnostic{};
    const tail_args = try transport.argv(arena.allocator(), options.journal, .tail, 1);
    const tail = try transport.execute(a, tail_args, buffer, &diagnostic, 5000, null);
    const scratch = try a.alloc(u8, transport.parse_bytes);
    defer a.free(scratch);
    const entry = try transport.decode(scratch, tail[0 .. tail.len - 1], 8192);
    const seek_args = try transport.argv(arena.allocator(), changed.journal, .{ .cursor = entry.cursor }, 2);
    const filtered = try transport.execute(a, seek_args, buffer, &diagnostic, 5000, null);
    try t.expectEqual(@as(usize, 0), filtered.len);
}

test "native journal: pending changes refuse activation and allocation failures preserve the committed owner" {
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(database);
    var clock = Clock{};
    var mock = Mock{ .response = row1 };
    const options = sessions.Options{ .processing = processing(), .clock = Clock.read, .clock_context = &clock, .executor = mock.executor() };
    var store = try durable.Store.open(a, database);
    defer store.close();
    try store.enableReceipts(1);
    try store.enableNativeTime();
    {
        const session = try sessions.Session.create(a, &store, options);
        defer session.destroy();
        _ = try session.poll(1);
        mock.response = row1 ++ row2;
        store.fail_at = .after_receipt_delete;
        try t.expectError(error.InjectedFailure, session.poll(1));
    }
    store.fail_at = null;
    mock.response = row1 ++ "{\"__CURSOR\":\"two\",\"__REALTIME_TIMESTAMP\":\"1000000001\",\"MESSAGE\":\"changed\",\"_UID\":\"0\"}\n";
    try t.expectError(error.PendingRecordMismatch, sessions.Session.create(a, &store, options));
    mock.response = row1;
    try t.expectError(error.PendingRecordUnavailable, sessions.Session.create(a, &store, options));
    mock.response = row1 ++ row2;
    const Check = struct {
        fn run(allocator: std.mem.Allocator, db: *durable.Store, config: sessions.Options) !void {
            const candidate = try sessions.Session.create(allocator, db, config);
            candidate.destroy();
        }
    };
    try t.checkAllAllocationFailures(a, Check.run, .{ &store, options });
    try t.expectEqual(@as(u64, 1), try store.revision("ordinary"));
    try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
}

test "native journal: shared storage failure blocks every session before another journal query" {
    const health = @import("core/storage_health.zig");
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(database);
    var store = try durable.Store.open(a, database);
    defer store.close();
    try store.enableReceipts(2);
    try store.enableNativeTime();
    const Monotonic = struct {
        fn read(_: ?*anyopaque) u64 {
            return 0;
        }
    };
    var gate = health.Gate.init(.{ .context = null, .read = Monotonic.read });
    const generation = try gate.beginRecovery();
    try gate.completed(generation, .storage);
    var clock = Clock{};
    var mock = Mock{ .response = row1 };
    var options = sessions.Options{ .processing = processing(), .gate = &gate, .clock = Clock.read, .clock_context = &clock, .executor = mock.executor() };
    const first = try sessions.Session.create(a, &store, options);
    defer first.destroy();
    options.processing.jail = "another";
    const second = try sessions.Session.create(a, &store, options);
    defer second.destroy();
    try t.expectError(error.StoragePaused, first.poll(1));
    try gate.completed(generation, .state);
    try gate.completed(generation, .ownership);
    try gate.completed(generation, .sources);
    _ = try first.poll(1);
    _ = try second.poll(1);
    mock.response = row1 ++ row2;
    store.fail_at = .before_receipt_commit;
    try t.expectError(error.InjectedFailure, first.poll(1));
    try t.expectEqual(health.Phase.intervention, gate.snapshot().phase);
    const calls = mock.calls;
    try t.expectError(error.StoragePaused, second.poll(1));
    try t.expectEqual(calls, mock.calls);
    try t.expectEqualDeep(policy.Counters{}, first.processor.timeHealth());
    try t.expectEqualDeep(policy.Counters{}, second.processor.timeHealth());
    try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
}
