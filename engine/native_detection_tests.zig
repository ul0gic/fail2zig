// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const builtin = @import("core/native_builtin_detector.zig");
const projection = @import("config/native_file_detection.zig");
const config = @import("config/native.zig");
const registry = @import("filters/registry.zig");
const parser = @import("core/parser.zig");
const policy = @import("core/source_time_policy.zig");
const processor = @import("core/native_source_processor.zig");
const sessions = @import("core/native_file_session.zig");
const store_mod = @import("core/record_store.zig");
const text = @import("core/source_text.zig");
const time = @import("core/native_time.zig");
const t = std.testing;
comptime {
    _ = @import("native_journal_detection_tests.zig");
}
const eligible = policy.Result{ .eligible = .{
    .timestamp = .{ .us = 9_007_199_254_740_993 },
    .original = .{ .us = 9_007_199_254_740_994 },
    .receipt = .{ .us = 9_007_199_254_740_993 },
    .origin = .clock_adjusted,
} };
const failure = "Failed password for root from 203.0.113.7 port 22 ssh2";
const options = builtin.Options{ .filter = "sshd", .body = .whole, .ignore_capacity = 8, .max_decoded_bytes = 2048 };
const settings = projection.Settings{ .timestamp = .undated, .body = .whole, .start = .head, .max_sources = 2, .ignore_capacity = 8 };

test "native detection: retained external filter corpus and rule identities" {
    const Fixture = struct { filter: []const u8, ip: ?[]const u8, line: []const u8 };
    const bytes = try std.fs.cwd().readFileAlloc(t.allocator, @import("detection_test_options").corpus_path, 1 << 20);
    defer t.allocator.free(bytes);
    const corpus = try std.json.parseFromSlice([]Fixture, t.allocator, bytes, .{});
    defer corpus.deinit();
    var positive = [_]usize{0} ** registry.registered_count;
    var negative = positive;
    for (corpus.value) |fixture| {
        // Recidive is intentionally absent from the external-line consumer.
        if (std.mem.eql(u8, fixture.filter, "recidive")) continue;
        var opts = options;
        opts.filter = fixture.filter;
        var detector = try builtin.Detector.init(t.allocator, opts);
        defer detector.deinit(t.allocator);
        // Existing fixtures contain both service bodies and syslog envelopes.
        // Their historical extractor is explicit here, not a detector fallback.
        const body = parser.stripSyslogPrefix(fixture.line);
        const result = try detector.evaluate(body, eligible);
        const index = for (registry.entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, fixture.filter)) break i;
        } else unreachable;
        if (fixture.ip) |ip| {
            const expected = try shared.IpAddress.parse(ip);
            const match = if (expected.isUnenforceable()) blk: {
                try t.expect(result == .unenforceable);
                break :blk result.unenforceable;
            } else blk: {
                try t.expect(result == .candidate);
                try t.expectEqualDeep(eligible.eligible, result.candidate.time);
                break :blk result.candidate.match;
            };
            try t.expectEqual(expected, match.subject);
            try t.expectEqualStrings(fixture.filter, match.filter);
            try t.expectEqualStrings(registry.entries[index].patterns[match.pattern_index].name, match.pattern);
            positive[index] += 1;
        } else {
            try t.expect(result == .no_match);
            negative[index] += 1;
        }
    }
    for (registry.entries, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, "recidive")) continue;
        try t.expect(positive[i] > 0 and negative[i] > 0);
    }
}

test "native detection: ineligible records never become candidates" {
    var detector = try builtin.Detector.init(t.allocator, options);
    defer detector.deinit(t.allocator);
    try t.expect((try detector.evaluate(failure, .{ .obsolete = eligible.eligible })) == .time_excluded);
    inline for (@typeInfo(policy.Reason).@"enum".fields) |field| {
        try t.expect((try detector.evaluate(failure, .{ .rejected = .{ .reason = @enumFromInt(field.value) } })) == .time_excluded);
    }
    var receipt = eligible;
    receipt.eligible.origin = .receipt;
    receipt.eligible.original = null;
    try t.expectEqualDeep(receipt.eligible, (try detector.evaluate(failure, receipt)).candidate.time);
    // A later-declared pattern must retain its actual index, not ParseResult's
    // default zero matched_pattern_id.
    const result = try detector.evaluate("Invalid user guest from 203.0.113.7 port 22", eligible);
    try t.expect(result.candidate.match.pattern_index > 0);
}

test "native detection: strict syslog envelope and complete decoded records" {
    var opts = options;
    opts.body = .syslog;
    var detector = try builtin.Detector.init(t.allocator, opts);
    defer detector.deinit(t.allocator);
    for ([_][]const u8{
        "Sep 12 10:00:00 host sshd[10]: " ++ failure,
        "2026-09-12T10:00:00Z host sshd[10]: " ++ failure,
    }) |line| try t.expect((try detector.evaluate(line, eligible)) == .candidate);
    for ([_][]const u8{ failure, "bad-date host sshd[10]: " ++ failure, "Sep 12 10:00:00 host sshd[10] " ++ failure }) |line|
        try t.expect((try detector.evaluate(line, eligible)) == .malformed_body);
    for ([_][]const u8{ "\xff", failure ++ "\x00tail", failure ++ "\nsecond", failure ++ "\rsecond" }) |line|
        try t.expectError(error.InvalidDecodedRecord, detector.evaluate(line, eligible));
    const oversized = [_]u8{'x'} ** 2049;
    try t.expectError(error.RecordTooLarge, detector.evaluate(&oversized, eligible));
}

test "native detection: canonical address ignores and protected addresses" {
    var opts = options;
    opts.ignore = &.{ "203.0.113.0/24", "2001:db8:1::/48" };
    var detector = try builtin.Detector.init(t.allocator, opts);
    defer detector.deinit(t.allocator);
    for ([_][]const u8{ "203.0.113.7", "::ffff:203.0.113.7", "2001:db8:1::7" }) |ip| {
        const line = try std.fmt.allocPrint(t.allocator, "Failed password for root from {s} port 22 ssh2", .{ip});
        defer t.allocator.free(line);
        try t.expect((try detector.evaluate(line, eligible)) == .ignored);
    }
    try t.expect((try detector.evaluate("Failed password for root from 203.0.114.7 port 22 ssh2", eligible)) == .candidate);
    for ([_][]const u8{ "0.1.2.3", "127.0.0.2", "::", "::1", "::ffff:127.0.0.1" }) |ip| {
        const line = try std.fmt.allocPrint(t.allocator, "Failed password for root from {s} port 22 ssh2", .{ip});
        defer t.allocator.free(line);
        try t.expect((try detector.evaluate(line, eligible)) == .unenforceable);
    }
}

test "native detection: invalid configuration refuses instead of dropping rules" {
    var opts = options;
    opts.filter = "custom-rule";
    try t.expectError(error.UnknownFilter, builtin.Detector.init(t.allocator, opts));
    opts.filter = "recidive";
    try t.expectError(error.InternalEventsRequired, builtin.Detector.init(t.allocator, opts));
    opts = options;
    for ([_][]const u8{ "", "example.invalid", "203.0.113.1/33", "2001:db8::/129", "not-an-ip" }) |bad| {
        opts.ignore = &.{bad};
        try t.expectError(error.InvalidStaticIgnore, builtin.Detector.init(t.allocator, opts));
    }
    opts.ignore_capacity = 0;
    opts.ignore = &.{"203.0.113.7"};
    try t.expectError(error.IgnoreCapacityExceeded, builtin.Detector.init(t.allocator, opts));
}

test "native detection: immutable owned ignores and stable semantic binding" {
    var spec = "203.0.113.0/24".*;
    var opts = options;
    opts.ignore = &.{&spec};
    var first = try builtin.Detector.init(t.allocator, opts);
    defer first.deinit(t.allocator);
    @memset(&spec, 'x');
    try t.expect((try first.evaluate(failure, eligible)) == .ignored);
    opts.ignore = &.{"203.0.113.0/24"};
    var same = try builtin.Detector.init(t.allocator, opts);
    defer same.deinit(t.allocator);
    try t.expectEqual(first.generation, same.generation);
    opts.ignore = &.{};
    var changed = try builtin.Detector.init(t.allocator, opts);
    defer changed.deinit(t.allocator);
    try t.expect(!std.mem.eql(u8, &first.generation, &changed.generation));
    opts = options;
    opts.filter = "nginx-http-auth";
    var hyphen = try builtin.Detector.init(t.allocator, opts);
    defer hyphen.deinit(t.allocator);
    opts.filter = "nginx_http_auth";
    var underscore = try builtin.Detector.init(t.allocator, opts);
    defer underscore.deinit(t.allocator);
    try t.expectEqual(hyphen.generation, underscore.generation);
    opts.body = .syslog;
    var body = try builtin.Detector.init(t.allocator, opts);
    defer body.deinit(t.allocator);
    try t.expect(!std.mem.eql(u8, &body.generation, &underscore.generation));
}

fn fixtureConfig(jails: []config.JailConfig) config.Config {
    return .{ .defaults = .{ .source = .file, .findtime = 300, .ignoreip = &.{"203.0.113.0/24"} }, .jails = jails };
}
fn fixtureJail() config.JailConfig {
    return .{ .name = "ssh", .filter = "sshd", .logpath = &.{"/nonexistent/native-auth.log"} };
}

test "native detection: file projection inheritance override and processor binding" {
    var jails = [_]config.JailConfig{fixtureJail()};
    var cfg = fixtureConfig(&jails);
    var plan = try projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings);
    defer plan.deinit(t.allocator);
    try t.expectEqual(@as(i64, 300_000_000), plan.processing.window_us);
    try t.expectEqualStrings(jails[0].logpath[0], plan.specs[0].pattern);
    try t.expect((try plan.detection.evaluate(failure, eligible)) == .ignored);
    jails[0].ignoreip = &.{};
    jails[0].findtime = 600;
    var override = try projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings);
    defer override.deinit(t.allocator);
    try t.expect((try override.detection.evaluate(failure, eligible)) == .candidate);
    try t.expectEqual(@as(i64, 600_000_000), override.processing.window_us);
    var scratch: [2048]u8 = undefined;
    var before = try processor.Processor.init(t.allocator, plan.processing, &scratch, .{ .us = 0 });
    var after = try processor.Processor.init(t.allocator, override.processing, &scratch, .{ .us = 0 });
    try t.expect(!std.mem.eql(u8, &before.generation, &after.generation));
    const baseline = try before.adapter().prepare(.{ .kind = .checkpoint, .source = "fixture", .occurrence = "baseline", .cursor = "cursor", .message = "", .raw_hash = [_]u8{0} ** 32 }, &before);
    defer baseline.release(baseline.context);
    try t.expectError(error.SourceGenerationMismatch, after.adapter().prepare_restore(baseline.checkpoint, &after));
    try t.expect(!after.in_flight);
    jails[0].findtime = std.math.maxInt(u64);
    try t.expectError(error.InvalidFindtime, projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings));
}

test "native detection: native decoding and time preparation feed a staged candidate" {
    var jails = [_]config.JailConfig{fixtureJail()};
    jails[0].ignoreip = &.{};
    const cfg = fixtureConfig(&jails);
    var configured = settings;
    configured.body = .syslog;
    configured.timestamp = .{ .field = .{ .format = .syslog, .boundary = .{ .length = 15 }, .context = .{ .year = 2026, .offset_seconds = 0 } } };
    var plan = try projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, configured);
    defer plan.deinit(t.allocator);
    const now = try @import("core/native_time.zig").parse(.iso8601, "2026-09-12T10:00:01Z", .{});
    var scratch: [2048]u8 = undefined;
    var owner = try processor.Processor.init(t.allocator, plan.processing, &scratch, now);
    const line = "Sep 12 10:00:00 host sshd[10]: " ++ failure;
    const prepared = try owner.adapter().prepare(.{ .source = "fixture", .occurrence = "one", .cursor = "cursor", .message = line, .raw_hash = [_]u8{0} ** 32, .byte_start = 0, .receipt_time = now }, &owner);
    defer prepared.release(prepared.context);
    // This ASCII fixture has the same decoded length. The production consumer
    // integration must carry the decoder's actual slice for all other codecs.
    const candidate = (try plan.detection.evaluate(scratch[0..line.len], prepared.native_time.?)).candidate;
    try t.expectEqual(now.us - 1_000_000, candidate.time.timestamp.us);
    try t.expectEqual(try shared.IpAddress.parse("203.0.113.7"), candidate.match.subject);
    // Preparation and pure detection cannot acknowledge or publish anything.
    try t.expectEqual(@as(u64, 0), owner.timeHealth().eligible);
    try t.expect(prepared.intent == null);
}

test "native detection: file projection refuses unqualified sources and time contracts" {
    var jails = [_]config.JailConfig{fixtureJail()};
    var cfg = fixtureConfig(&jails);
    cfg.defaults.source = .auto;
    try t.expectError(error.SourceSelectionRequired, projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings));
    jails[0].source = .journald;
    try t.expectError(error.JournalOriginPolicyRequired, projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings));
    jails[0].source = .internal;
    try t.expectError(error.InternalEventsRequired, projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings));
    jails[0].source = .file;
    cfg.global.compatibility_pending = true;
    try t.expectError(error.CompatibilityNotAdmitted, projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, settings));
    cfg.global.compatibility_pending = false;
    var syslog = settings;
    syslog.body = .syslog;
    try t.expectError(error.SyslogTimestampRequired, projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, syslog));
    syslog.timestamp = .{ .field = .{ .format = .syslog, .boundary = .{ .length = 15 }, .infer_year = true } };
    try t.expectError(error.SourceTimeContextRequired, projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, syslog));
    syslog.timestamp.field.context.offset_seconds = 0;
    var plan = try projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, syslog);
    defer plan.deinit(t.allocator);
    syslog.timestamp.field.start = 1;
    try t.expectError(error.SyslogTimestampRequired, projection.Plan.init(t.allocator, &cfg, 0, [_]u8{0} ** 32, syslog));
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    var jails = [_]config.JailConfig{fixtureJail()};
    const cfg = fixtureConfig(&jails);
    var plan = try projection.Plan.init(allocator, &cfg, 0, [_]u8{0} ** 32, settings);
    defer plan.deinit(allocator);
    try t.expect((try plan.detection.evaluate(failure, eligible)) == .ignored);
}
test "native detection: all initialization allocation failures release ownership" {
    try t.checkAllAllocationFailures(t.allocator, allocationScenario, .{});
}

const Clock = struct {
    now: i64,
    fn read(context: ?*anyopaque) !time.Timestamp {
        const self: *Clock = @ptrCast(@alignCast(context.?));
        return .{ .us = self.now };
    }
};
fn writeAscii(file: std.fs.File, encoding: text.Encoding, message: []const u8) !void {
    for (message) |byte| {
        switch (encoding) {
            .utf8, .ascii, .latin1 => try file.writeAll(&.{byte}),
            .utf16le, .utf16be => {
                var bytes: [2]u8 = undefined;
                std.mem.writeInt(u16, &bytes, byte, if (encoding == .utf16le) .little else .big);
                try file.writeAll(&bytes);
            },
            .utf32le, .utf32be => {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, byte, if (encoding == .utf32le) .little else .big);
                try file.writeAll(&bytes);
            },
        }
    }
}

test "native detection: actual file consumers commit typed results and recover pending evidence in every codec" {
    for (std.enums.values(text.Encoding)) |encoding| {
        var temp = t.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const logfile = try std.fs.path.join(t.allocator, &.{ root, "auth.log" });
        defer t.allocator.free(logfile);
        const database = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
        defer t.allocator.free(database);
        const file = try temp.dir.createFile("auth.log", .{});
        defer file.close();
        var jails = [_]config.JailConfig{fixtureJail()};
        jails[0].logpath = &.{logfile};
        jails[0].ignoreip = &.{};
        const cfg = fixtureConfig(&jails);
        var configured = settings;
        configured.encoding = encoding;
        configured.body = .syslog;
        configured.timestamp = .{ .field = .{ .format = .iso8601, .boundary = .{ .delimiter = ' ' } } };
        var plan = try projection.Plan.init(t.allocator, &cfg, 0, [_]u8{1} ** 32, configured);
        defer plan.deinit(t.allocator);
        var clock = Clock{ .now = (try time.parse(.iso8601, "2026-09-12T10:00:01Z", .{})).us };
        var opts = plan.sessionOptions();
        opts.clock = Clock.read;
        opts.clock_context = &clock;
        const line = "2026-09-12T10:00:00Z host sshd[10]: " ++ failure ++ "\n";
        {
            var store = try store_mod.Store.open(t.allocator, database);
            defer store.close();
            try store.enableReceipts(2);
            try store.enableNativeTime();
            try t.expectError(error.DetectionStorageRequired, sessions.Session.create(t.allocator, &store, opts, plan.specs));
            try store.enableDetection();
            const session = try sessions.Session.create(t.allocator, &store, opts, plan.specs);
            defer session.destroy();
            try t.expectEqual(@as(usize, 0), try session.poll(1));
            try writeAscii(file, encoding, line);
            store.fail_at = .after_detection;
            try t.expectError(error.InjectedFailure, session.poll(1));
            try t.expectEqual(@as(u64, 0), session.processor.timeHealth().eligible);
            try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
            try t.expectEqual(@as(u64, 0), session.sources.sources.items[0].acknowledgedCheckpoint().?.offset);
        }
        clock.now += 1_000_000;
        {
            var store = try store_mod.Store.open(t.allocator, database);
            defer store.close();
            try store.enableReceipts(2);
            const session = try sessions.Session.create(t.allocator, &store, opts, plan.specs);
            defer session.destroy();
            try t.expectEqual(@as(usize, 1), try session.poll(1));
            const source = &session.sources.sources.items[0];
            const found = (try store.nativeDetection("ssh", source.source_id, null)).?;
            try t.expectEqual(@import("core/native_detection_record.zig").Kind.candidate, found.kind);
            try t.expectEqual([4]u8{ 203, 0, 113, 7 }, found.subject.?.v4);
            try t.expectEqualStrings("sshd", found.filter.slice());
            try t.expectEqual(plan.detection.generation, found.generation);
            const admitted = (try store.nativeTime("ssh", source.source_id, null)).?.eligible;
            try t.expectEqual(clock.now - 2_000_000, admitted.timestamp.us);
            try t.expectEqual(clock.now - 1_000_000, admitted.receipt.us);
            try t.expectEqual(@as(usize, 0), try session.poll(1));
            try t.expectEqual(@as(u64, 1), session.processor.timeHealth().eligible);
            // A second occurrence can age out while its failed commit waits.
            try writeAscii(file, encoding, line);
            store.fail_at = .after_detection;
            try t.expectError(error.InjectedFailure, session.poll(1));
            try t.expectEqual(@as(u64, 1), session.processor.timeHealth().eligible);
            try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        }
        clock.now += 601_000_000;
        {
            var store = try store_mod.Store.open(t.allocator, database);
            defer store.close();
            try store.enableReceipts(2);
            var altered = try projection.Plan.init(t.allocator, &cfg, 0, [_]u8{2} ** 32, configured);
            defer altered.deinit(t.allocator);
            var altered_opts = altered.sessionOptions();
            altered_opts.clock = Clock.read;
            altered_opts.clock_context = &clock;
            // Pending-receipt generation is checked before checkpoint restore.
            try t.expectError(error.ReceiptConflict, sessions.Session.create(t.allocator, &store, altered_opts, altered.specs));
            const session = try sessions.Session.create(t.allocator, &store, opts, plan.specs);
            defer session.destroy();
            try t.expectEqual(@as(usize, 1), try session.poll(1));
            const source = &session.sources.sources.items[0];
            const found = (try store.nativeDetection("ssh", source.source_id, null)).?;
            try t.expectEqual(@import("core/native_detection_record.zig").Kind.time_excluded, found.kind);
            try t.expect(found.subject == null);
            try t.expectEqual(@as(u64, 1), session.processor.timeHealth().eligible);
            try t.expectEqual(@as(u64, 1), session.processor.timeHealth().obsolete);
            try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
            try t.expectEqual(@as(i64, 0), try store.pendingIntents());
        }
    }
}

test "native detection: consumer returns detached typed exclusion and address outcomes" {
    var opts = options;
    opts.body = .syslog;
    opts.ignore = &.{"198.51.100.0/24"};
    var detector = try builtin.Detector.init(t.allocator, opts);
    defer detector.deinit(t.allocator);
    const Kind = @import("core/native_detection_record.zig").Kind;
    const cases = .{
        .{ "2026-09-12T10:00:00Z host sshd[10]: Failed password for root from 198.51.100.7 port 22", Kind.ignored },
        .{ "2026-09-12T10:00:00Z host sshd[10]: Failed password for root from ::1 port 22", Kind.unenforceable },
        .{ "2026-09-12T10:00:00Z host sshd[10]: Accepted password for root from 203.0.113.7 port 22", Kind.no_match },
        .{ failure, Kind.malformed_body },
        .{ "2026-09-12T10:00:00Z host sshd[10]: Failed password for root from 2001:db8::7 port 22", Kind.candidate },
    };
    const consumer = detector.consumer();
    inline for (cases) |case| {
        const result = try consumer.evaluate(case[0], eligible, consumer.context);
        try t.expectEqual(case[1], result.kind);
        try result.validate(eligible);
        if (result.kind == .candidate) try t.expectEqual(@as(u128, 0x20010db8000000000000000000000007), std.mem.readInt(u128, &result.subject.?.v6, .big));
    }
    var scratch: [2048]u8 = undefined;
    var processing_opts = processor.Options{ .jail = "ssh", .parent_generation = [_]u8{0} ** 32, .timestamp = .journal };
    try t.expectError(error.JournalOriginPolicyRequired, processor.Processor.initWithDetection(t.allocator, processing_opts, &scratch, .{ .us = 0 }, consumer));
    processing_opts.timestamp = .undated;
    var owner = try processor.Processor.initWithDetection(t.allocator, processing_opts, &scratch, .{ .us = 100 }, consumer);
    const prepared = try owner.adapter().prepare(.{ .source = "file", .occurrence = "one", .cursor = "cursor", .message = failure, .byte_start = 0, .receipt_time = .{ .us = 100 }, .raw_hash = [_]u8{0} ** 32 }, &owner);
    defer prepared.release(prepared.context);
    try t.expectEqual(Kind.malformed_body, prepared.native_detection.?.kind);
    try t.expect(prepared.intent == null);
}
