// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const origin = @import("engine_test").core.native_journal_origin;
const journal = @import("engine_test").core.native_journal_detector;
const builtin = @import("engine_test").core.native_builtin_detector;
const records = @import("engine_test").core.source_record;
const stored = @import("engine_test").core.native_detection_record;
const sessions = @import("engine_test").core.native_journal_session;
const transport = @import("engine_test").core.native_journal_transport;
const durable = @import("engine_test").core.record_store;
const time = @import("engine_test").core.native_time;
const policy = @import("engine_test").core.source_time_policy;
const projection = @import("engine_test").config.native_journal_detection;
const config = @import("engine_test").config.native;
const machine = "0123456789abcdef0123456789abcdef";
const failure = "Failed password for root from 203.0.113.7 port 22 ssh2";
const valid_fields = [_]records.JournalField{
    .{ .name = "_MACHINE_ID", .value = machine },
    .{ .name = "_UID", .value = "0" },
    .{ .name = "_EXE", .value = "/usr/sbin/sshd" },
    .{ .name = "_TRANSPORT", .value = "syslog" },
};
const admitted = policy.Result{ .eligible = .{ .timestamp = .{ .us = 1_000_000_000 }, .original = .{ .us = 1_000_000_000 }, .receipt = .{ .us = 1_000_000_010 }, .origin = .event } };
fn profile() !origin.Profile {
    return origin.Profile.init(machine, &.{ "/usr/sbin/sshd", "/usr/lib/openssh/sshd-session" });
}
fn baseDetector() !builtin.Detector {
    return builtin.Detector.init(t.allocator, .{ .filter = "sshd", .body = .whole, .ignore_capacity = 1, .max_decoded_bytes = 2048 });
}

test "native detection: journal origin requires complete unambiguous trusted metadata" {
    const p = try profile();
    try t.expect(p.rejection(&valid_fields) == null);
    try t.expectEqual(stored.Kind.origin_missing, p.rejection(null).?);
    for (0..valid_fields.len) |i| {
        var fields = valid_fields;
        fields[i].name = "SYSLOG_IDENTIFIER";
        fields[i].value = "sshd";
        try t.expectEqual(stored.Kind.origin_missing, p.rejection(&fields).?);
        const duplicate = valid_fields ++ [_]records.JournalField{valid_fields[i]};
        try t.expectEqual(stored.Kind.origin_ambiguous, p.rejection(&duplicate).?);
    }
    const Case = struct { index: usize, value: []const u8, kind: stored.Kind };
    for ([_]Case{
        .{ .index = 0, .value = "1123456789abcdef0123456789abcdef", .kind = .origin_machine },
        .{ .index = 1, .value = "1000", .kind = .origin_uid },
        .{ .index = 1, .value = "+0", .kind = .origin_uid },
        .{ .index = 2, .value = "/usr/bin/logger", .kind = .origin_executable },
        .{ .index = 2, .value = "/usr/sbin/sshd (deleted)", .kind = .origin_executable },
        .{ .index = 3, .value = "stdout", .kind = .origin_transport },
        .{ .index = 3, .value = "journal", .kind = .origin_transport },
    }) |case| {
        var fields = valid_fields;
        fields[case.index].value = case.value;
        try t.expectEqual(case.kind, p.rejection(&fields).?);
    }
    var child = valid_fields;
    child[2].value = "/usr/lib/openssh/sshd-session";
    try t.expect(p.rejection(&child) == null);
    const tagged = [_]records.JournalField{ .{ .name = "SYSLOG_IDENTIFIER", .value = "anything" }, valid_fields[3], valid_fields[2], valid_fields[1], valid_fields[0] };
    try t.expect(p.rejection(&tagged) == null);
}

test "native detection: journal origin profile validates paths and binds host executable changes" {
    for ([_][]const u8{ "", "0", "00000000000000000000000000000000", "0123456789ABCDEF0123456789ABCDEF" }) |id|
        try t.expectError(error.InvalidJournalMachine, origin.Profile.init(id, &.{"/usr/sbin/sshd"}));
    for ([_][]const u8{ "sshd", "/", "/usr//sshd", "/usr/../sshd", "/usr/./sshd", "/usr/sshd/", "/usr/sshd\x00" }) |path|
        try t.expectError(error.InvalidJournalExecutable, origin.Profile.init(machine, &.{path}));
    try t.expectError(error.InvalidJournalExecutables, origin.Profile.init(machine, &.{}));
    try t.expectError(error.DuplicateJournalExecutable, origin.Profile.init(machine, &.{ "/usr/sbin/sshd", "/usr/sbin/sshd" }));
    const original = try profile();
    const moved = try origin.Profile.init(machine, &.{"/opt/ssh/sshd"});
    const other_host = try origin.Profile.init("1123456789abcdef0123456789abcdef", original.executables);
    try t.expect(!std.mem.eql(u8, &original.generation, &moved.generation));
    try t.expect(!std.mem.eql(u8, &original.generation, &other_host.generation));
}

test "native detection: journal rejection never yields a subject and age still excludes evidence" {
    var base = try baseDetector();
    defer base.deinit(t.allocator);
    const detector = try journal.Detector.init(&base, try profile());
    const consumer = detector.consumer();
    const result = try consumer.evaluate(failure, &valid_fields, admitted, consumer.context);
    try t.expectEqual(stored.Kind.candidate, result.kind);
    try t.expectEqualDeep(stored.Subject{ .v4 = .{ 203, 0, 113, 7 } }, result.subject.?);
    const rejected = try consumer.evaluate(failure, null, admitted, consumer.context);
    try t.expectEqual(stored.Kind.origin_missing, rejected.kind);
    try t.expect(rejected.subject == null and rejected.pattern == null);
    const old = try consumer.evaluate(failure, null, .{ .obsolete = admitted.eligible }, consumer.context);
    try t.expectEqual(stored.Kind.time_excluded, old.kind);
    base.body = .syslog;
    try t.expectError(error.UnsupportedJournalDetector, journal.Detector.init(&base, try profile()));
}

test "native detection: explicit SSH emitter profiles stay exact across listener session and auth layouts" {
    const executables = [_][]const u8{
        "/usr/sbin/sshd",
        "/usr/lib/openssh/sshd-session",
        "/usr/lib/openssh/sshd-auth",
        "/usr/libexec/openssh/sshd-session",
        "/usr/libexec/openssh/sshd-auth",
        "/opt/ssh/libexec/sshd-auth",
    };
    var base = try baseDetector();
    defer base.deinit(t.allocator);
    for (executables) |selected| {
        const detector = try journal.Detector.init(&base, try origin.Profile.init(machine, &.{selected}));
        const consumer = detector.consumer();
        for (executables) |emitter| {
            var fields = valid_fields ++ [_]records.JournalField{
                .{ .name = "SYSLOG_IDENTIFIER", .value = "sshd" },
                .{ .name = "_COMM", .value = "sshd" },
            };
            fields[2].value = emitter;
            const result = try consumer.evaluate(failure, &fields, admitted, consumer.context);
            if (std.mem.eql(u8, selected, emitter)) {
                try t.expectEqual(stored.Kind.candidate, result.kind);
                try t.expectEqualDeep(stored.Subject{ .v4 = .{ 203, 0, 113, 7 } }, result.subject.?);
            } else {
                try t.expectEqual(stored.Kind.origin_executable, result.kind);
                try t.expect(result.subject == null and result.pattern == null);
            }
        }
        const Case = struct { index: usize, value: []const u8, kind: stored.Kind };
        for ([_]Case{
            .{ .index = 0, .value = "1123456789abcdef0123456789abcdef", .kind = .origin_machine },
            .{ .index = 1, .value = "1000", .kind = .origin_uid },
            .{ .index = 3, .value = "stdout", .kind = .origin_transport },
        }) |case| {
            var fields = valid_fields;
            fields[2].value = selected;
            fields[case.index].value = case.value;
            const result = try consumer.evaluate(failure, &fields, admitted, consumer.context);
            try t.expectEqual(case.kind, result.kind);
            try t.expect(result.subject == null and result.pattern == null);
        }
        for (0..valid_fields.len) |index| {
            var fields = valid_fields ++ [_]records.JournalField{valid_fields[index]};
            fields[2].value = selected;
            fields[valid_fields.len] = fields[index];
            const result = try consumer.evaluate(failure, &fields, admitted, consumer.context);
            try t.expectEqual(stored.Kind.origin_ambiguous, result.kind);
            try t.expect(result.subject == null and result.pattern == null);
        }
    }
}

test "native detection: existing explicit journal generation remains stable and order sensitive" {
    const original = try profile();
    // Pin the released explicit profile identity: default discovery must not migrate it.
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "27d6bebdacd18cdb9690f62e7bccf7d8c8085b635744fff3caa3fd6027179693");
    try t.expectEqualSlices(u8, &expected, &original.generation);
    const copied_path = try t.allocator.dupe(u8, "/usr/sbin/sshd");
    defer t.allocator.free(copied_path);
    const recreated = try origin.Profile.init(machine, &.{ copied_path, "/usr/lib/openssh/sshd-session" });
    try t.expectEqualSlices(u8, &original.generation, &recreated.generation);
    const reordered = try origin.Profile.init(machine, &.{ "/usr/lib/openssh/sshd-session", "/usr/sbin/sshd" });
    const expanded = try origin.Profile.init(machine, &.{ "/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/usr/lib/openssh/sshd-auth" });
    try t.expect(!std.mem.eql(u8, &original.generation, &reordered.generation));
    try t.expect(!std.mem.eql(u8, &original.generation, &expanded.generation));
}

test "native detection: journal parser preserves repeated origin fields for exclusion" {
    const p = try profile();
    const scratch = try t.allocator.alloc(u8, transport.parse_bytes);
    defer t.allocator.free(scratch);
    const row = "{\"__CURSOR\":\"ordinary\",\"__REALTIME_TIMESTAMP\":\"1000000000\",\"MESSAGE\":\"ordinary metadata fixture\",\"_MACHINE_ID\":\"" ++ machine ++ "\",\"_UID\":[\"0\",\"0\"],\"_EXE\":\"/usr/sbin/sshd\",\"_TRANSPORT\":\"syslog\"}";
    const parsed = try transport.decode(scratch, row, 2048);
    try t.expectEqual(stored.Kind.origin_ambiguous, p.rejection(parsed.fields).?);
}

const Clock = struct {
    value: i64 = 1_000_000_010,
    fn read(context: ?*anyopaque) !time.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        return .{ .us = self.value };
    }
};
const Mock = struct {
    response: []const u8 = "",
    fn run(_: std.mem.Allocator, _: []const []const u8, output: []u8, diagnostic: *transport.Diagnostic, _: u32, context: ?*anyopaque) ![]const u8 {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        if (self.response.len > output.len) return error.JournalOutputLimit;
        @memcpy(output[0..self.response.len], self.response);
        diagnostic.* = .{ .exit_code = 0 };
        return output[0..self.response.len];
    }
};
fn jsonRow(cursor: []const u8, uid: []const u8) ![]const u8 {
    return std.fmt.allocPrint(t.allocator, "{{\"__CURSOR\":\"{s}\",\"__REALTIME_TIMESTAMP\":\"1000000020\",\"MESSAGE\":\"{s}\",\"_MACHINE_ID\":\"{s}\",\"_UID\":\"{s}\",\"_EXE\":\"/usr/sbin/sshd\",\"_TRANSPORT\":\"syslog\",\"SYSLOG_IDENTIFIER\":\"sshd\"}}\n", .{ cursor, failure, machine, uid });
}
fn admit(store: *durable.Store) !void {
    try store.enableReceipts(1);
    try store.enableNativeTime();
    try store.enableDetection();
    try store.enableClockRecovery();
    try store.enableJournalDetection();
}

test "native detection: journal session atomically excludes untrusted input and continues after reopen" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "origin.sqlite" });
    defer t.allocator.free(path);
    var store = try durable.Store.open(t.allocator, path);
    defer store.close();
    try admit(&store);
    var jails = [_]config.JailConfig{.{ .name = "ssh", .filter = "sshd", .source = .journald }};
    const cfg = config.Config{ .jails = &jails };
    const plan = try projection.Plan.create(t.allocator, &cfg, 0, [_]u8{0} ** 32, .{ .machine_id = machine, .executables = &.{"/usr/sbin/sshd"}, .ignore_capacity = 8 });
    defer plan.destroy();
    var clock = Clock{};
    var mock = Mock{};
    var opts = plan.sessionOptions();
    opts.clock = Clock.read;
    opts.clock_context = &clock;
    opts.executor = .{ .context = &mock, .run = Mock.run };
    var owner: ?*sessions.Session = try sessions.Session.create(t.allocator, &store, opts);
    defer if (owner) |session| session.destroy();
    try t.expectEqual(@as(usize, 0), try owner.?.poll(1));
    clock.value += 30;
    const rejected = try jsonRow("one", "1000");
    defer t.allocator.free(rejected);
    const accepted = try jsonRow("two", "0");
    defer t.allocator.free(accepted);
    mock.response = rejected;
    const revision = owner.?.pipe.revision;
    store.fail_at = .after_detection;
    try t.expectError(error.InjectedFailure, owner.?.poll(1));
    try t.expectEqual(revision, try store.revision("ssh"));
    try t.expect((try store.nativeDetection("ssh", "system-journal", null)) == null);
    try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    owner.?.destroy();
    owner = null;
    store.close();
    store = try durable.Store.open(t.allocator, path);
    try admit(&store);
    owner = try sessions.Session.create(t.allocator, &store, opts);
    try t.expectEqual(@as(usize, 1), try owner.?.poll(1));
    try t.expectEqual(stored.Kind.origin_uid, (try store.nativeDetection("ssh", "system-journal", null)).?.kind);
    try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    const both = try std.mem.concat(t.allocator, u8, &.{ rejected, accepted });
    defer t.allocator.free(both);
    mock.response = both;
    try t.expectEqual(@as(usize, 1), try owner.?.poll(1));
    try t.expectEqual(stored.Kind.candidate, (try store.nativeDetection("ssh", "system-journal", null)).?.kind);
    try t.expectEqual(@as(i64, 0), try store.pendingIntents());
    try t.expectEqual(clock.value, (try store.receiptClock()).?.us);
    owner.?.destroy();
    owner = null;
    mock.response = accepted;
    var changed = plan.qualified.?;
    changed.generation[0] ^= 1;
    var changed_opts = opts;
    changed_opts.detection = changed.consumer();
    try t.expectError(error.SourceGenerationMismatch, sessions.Session.create(t.allocator, &store, changed_opts));
    owner = try sessions.Session.create(t.allocator, &store, opts);
    try t.expectEqual(@as(usize, 0), try owner.?.poll(1));
}

test "native detection: journal retry window and decision share the exact durable cursor transaction" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "retry.sqlite" });
    defer t.allocator.free(path);
    var store = try durable.Store.open(t.allocator, path);
    defer store.close();
    try admit(&store);
    try store.enableRetry();
    var base = try baseDetector();
    defer base.deinit(t.allocator);
    const detector = try journal.Detector.init(&base, try profile());
    var clock = Clock{};
    var mock = Mock{};
    const opts = sessions.Options{ .processing = .{ .jail = "ssh", .parent_generation = [_]u8{0} ** 32, .timestamp = .journal }, .detection = detector.consumer(), .retry = .{ .maxretry = 2, .window_us = 600_000_000, .duration = .{ .finite_us = 60_000_000 }, .max_subjects = 8 }, .clock = Clock.read, .clock_context = &clock, .executor = .{ .context = &mock, .run = Mock.run } };
    var owner: ?*sessions.Session = try sessions.Session.create(t.allocator, &store, opts);
    defer if (owner) |session| session.destroy();
    _ = try owner.?.poll(1);
    clock.value += 30;
    const one = try jsonRow("one", "0");
    defer t.allocator.free(one);
    const two = try jsonRow("two", "0");
    defer t.allocator.free(two);
    const both = try std.mem.concat(t.allocator, u8, &.{ one, two });
    defer t.allocator.free(both);
    mock.response = one;
    try t.expectEqual(@as(usize, 1), try owner.?.poll(1));
    const subject = (try store.nativeDetection("ssh", "system-journal", null)).?.subject.?;
    try t.expectEqual(@as(u16, 1), (try store.retryState("ssh", subject)).?.count);
    mock.response = both;
    store.fail_at = .after_retry_decision;
    try t.expectError(error.InjectedFailure, owner.?.poll(1));
    try t.expectEqual(@as(u64, 2), owner.?.pipe.revision);
    try t.expectEqual(@as(u16, 1), (try store.retryState("ssh", subject)).?.count);
    owner.?.destroy();
    owner = null;
    store.close();
    store = try durable.Store.open(t.allocator, path);
    try store.enableReceipts(1);
    owner = try sessions.Session.create(t.allocator, &store, opts);
    try t.expectEqual(@as(usize, 1), try owner.?.poll(1));
    const decision = (try store.retryDecision("ssh", "system-journal", null)).?;
    try t.expectEqual(@as(u64, 1), decision.ordinal);
    try t.expectEqual(clock.value + 60_000_000, decision.lease.finite);
    try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    mock.response = two;
    try t.expectEqual(@as(usize, 0), try owner.?.poll(1));
    try t.expectEqual(@as(u64, 1), (try store.retryState("ssh", subject)).?.decisions);
    const saved_state = (try store.retryState("ssh", subject)).?;
    const saved_revision = try store.revision("ssh");
    owner.?.destroy();
    owner = null;
    store.close();
    store = try durable.Store.open(t.allocator, path);
    try store.enableReceipts(1);
    const changed_profiles = [_][]const []const u8{
        &.{ "/usr/lib/openssh/sshd-session", "/usr/sbin/sshd" },
        &.{ "/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/usr/lib/openssh/sshd-auth" },
    };
    for (changed_profiles) |executables| {
        const changed_detector = try journal.Detector.init(&base, try origin.Profile.init(machine, executables));
        var changed_opts = opts;
        changed_opts.detection = changed_detector.consumer();
        try t.expectError(error.RetryGenerationMismatch, sessions.Session.create(t.allocator, &store, changed_opts));
        try t.expectEqual(saved_revision, try store.revision("ssh"));
        try t.expectEqual(saved_state.count, (try store.retryState("ssh", subject)).?.count);
        try t.expectEqual(saved_state.decisions, (try store.retryState("ssh", subject)).?.decisions);
        try t.expectEqual(decision.lease.finite, (try store.retryDecision("ssh", "system-journal", null)).?.lease.finite);
    }
    clock.value += 1_000_000;
    owner = try sessions.Session.create(t.allocator, &store, opts);
    try t.expectEqual(@as(usize, 0), try owner.?.poll(1));
    try t.expectEqual(saved_revision, try store.revision("ssh"));
    try t.expectEqual(saved_state.count, (try store.retryState("ssh", subject)).?.count);
    try t.expectEqual(saved_state.decisions, (try store.retryState("ssh", subject)).?.decisions);
    const resumed_decision = (try store.retryDecision("ssh", "system-journal", null)).?;
    try t.expectEqual(decision.ordinal, resumed_decision.ordinal);
    try t.expectEqual(decision.lease.finite, resumed_decision.lease.finite);
    try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
}

test "native detection: journal configuration preserves ignores and rejects unresolved preparation" {
    var jails = [_]config.JailConfig{.{ .name = "ssh", .filter = "sshd" }};
    var cfg = config.Config{ .defaults = .{ .source = .journald, .findtime = 300, .ignoreip = &.{"203.0.113.0/24"} }, .jails = &jails };
    const settings = projection.Settings{ .machine_id = machine, .executables = &.{"/usr/sbin/sshd"}, .ignore_capacity = 1 };
    const first = try projection.Plan.create(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings);
    defer first.destroy();
    try t.expectEqual(@as(i64, 300_000_000), first.processing.window_us);
    const consumer = first.sessionOptions().detection.?;
    try t.expectEqual(stored.Kind.ignored, (try consumer.evaluate(failure, &valid_fields, admitted, consumer.context)).kind);
    jails[0].ignoreip = &.{};
    const second = try projection.Plan.create(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings);
    defer second.destroy();
    const changed = second.sessionOptions().detection.?;
    try t.expectEqual(stored.Kind.candidate, (try changed.evaluate(failure, &valid_fields, admitted, changed.context)).kind);
    try t.expect(!std.mem.eql(u8, &consumer.generation, &changed.generation));
    const Allocation = struct {
        fn run(a: std.mem.Allocator, input: *const config.Config, selected: projection.Settings) !void {
            const plan = try projection.Plan.create(a, input, 0, [_]u8{0} ** 32, selected);
            defer plan.destroy();
            try t.expectEqual(@as(i64, 300_000_000), plan.processing.window_us);
        }
    };
    try t.checkAllAllocationFailures(t.allocator, Allocation.run, .{ &cfg, settings });
    cfg.defaults.source = .auto;
    try t.expectError(error.SourceSelectionRequired, projection.Plan.create(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings));
    cfg.defaults.source = .journald;
    jails[0].filter = "postfix";
    try t.expectError(error.UnsupportedJournalDetector, projection.Plan.create(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings));
    jails[0].filter = "sshd";
    cfg.global.compatibility_pending = true;
    try t.expectError(error.CompatibilityNotAdmitted, projection.Plan.create(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings));
}

test "native detection: journal plan owns discovered executable storage after caller release" {
    var jails = [_]config.JailConfig{.{ .name = "ssh", .filter = "sshd", .source = .journald }};
    const cfg = config.Config{ .jails = &jails };
    var temporary = std.heap.ArenaAllocator.init(t.allocator);
    const plan = blk: {
        defer temporary.deinit();
        const paths = try temporary.allocator().alloc([]const u8, 1);
        paths[0] = try temporary.allocator().dupe(u8, "/usr/sbin/sshd");
        break :blk try projection.Plan.create(t.allocator, &cfg, 0, [_]u8{0} ** 32, .{ .machine_id = machine, .executables = paths, .ignore_capacity = 1 });
    };
    defer plan.destroy();
    try t.expectEqualStrings("/usr/sbin/sshd", plan.profile.executables[0]);
    const consumer = plan.sessionOptions().detection.?;
    try t.expectEqual(stored.Kind.candidate, (try consumer.evaluate(failure, &valid_fields, admitted, consumer.context)).kind);
}

test "native detection: journal session admission and allocation failure cannot acknowledge input" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "allocation.sqlite" });
    defer t.allocator.free(path);
    var store = try durable.Store.open(t.allocator, path);
    defer store.close();
    try store.enableReceipts(1);
    try store.enableNativeTime();
    try store.enableDetection();
    try store.enableClockRecovery();
    var base = try baseDetector();
    defer base.deinit(t.allocator);
    const detector = try journal.Detector.init(&base, try profile());
    var clock = Clock{};
    var mock = Mock{};
    var opts = sessions.Options{ .processing = .{ .jail = "ssh", .parent_generation = [_]u8{0} ** 32, .timestamp = .journal }, .detection = detector.consumer(), .clock = Clock.read, .clock_context = &clock, .executor = .{ .context = &mock, .run = Mock.run } };
    try t.expectError(error.JournalDetectionStorageRequired, sessions.Session.create(t.allocator, &store, opts));
    try store.enableJournalDetection();
    const Check = struct {
        fn run(a: std.mem.Allocator, target: *durable.Store, options: sessions.Options) !void {
            const session = try sessions.Session.create(a, target, options);
            defer session.destroy();
            try t.expectEqual(@as(u64, 0), session.pipe.revision);
        }
    };
    try t.checkAllAllocationFailures(t.allocator, Check.run, .{ &store, opts });
    opts.processing.encoding = .latin1;
    try t.expectError(error.InvalidJournalCodec, sessions.Session.create(t.allocator, &store, opts));
    try t.expectEqual(@as(u64, 0), try store.revision("ssh"));
    try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
}
