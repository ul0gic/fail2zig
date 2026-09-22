// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const rule_test = @import("cli/rule_test.zig");
const time = @import("core/native_time.zig");

const fixtures = "tests/fixtures/rule-test";

fn fixture(comptime name: []const u8) []const u8 {
    return fixtures ++ "/" ++ name;
}

fn iso(text: []const u8) i64 {
    return (time.parse(.iso8601, text, .{}) catch unreachable).us;
}

const now_us = iso("2026-04-21T12:00:10Z");

const portsentry_positive = "2026-09-22T14:01:59.799+0000 Scan from: [192.0.2.2] (192.0.2.2) protocol: [TCP] port: [23456] type: [Connect] IP opts: [unknown] ignored: [false] triggered: [true] noblock: [true] blocked: [false]";

fn base(input: rule_test.Input, rule: rule_test.Rule) rule_test.Options {
    return .{ .input = input, .rule = rule, .now_us = now_us, .tz_offset_minutes = 0 };
}

fn sample(report: *const rule_test.Report, line_no: u64) rule_test.Sample {
    for (report.samples.items) |s| if (s.line_no == line_no) return s;
    unreachable;
}

fn expectCounts(report: *const rule_test.Report, matched: u64, missed: u64, ignored: u64, rejected: u64) !void {
    try testing.expectEqual(matched, report.counts.matched);
    try testing.expectEqual(missed, report.counts.missed);
    try testing.expectEqual(ignored, report.counts.ignored);
    try testing.expectEqual(rejected, report.counts.rejected);
}

const RunResult = struct {
    class: rule_test.ExitClass,
    stdout: std.ArrayList(u8),
    stderr: std.ArrayList(u8),

    fn deinit(self: *RunResult) void {
        self.stdout.deinit();
        self.stderr.deinit();
    }
};

fn runCli(args: []const []const u8) RunResult {
    var out = RunResult{ .class = .success, .stdout = std.ArrayList(u8).init(testing.allocator), .stderr = std.ArrayList(u8).init(testing.allocator) };
    out.class = rule_test.run(testing.allocator, args, out.stdout.writer(), out.stderr.writer());
    return out;
}

test "native rule test: sshd fixture reports match, miss, ignore and reject with identity and event time" {
    var report = try rule_test.evaluate(testing.allocator, base(.{ .file = fixture("sshd.log") }, .{ .service = "sshd" }));
    defer report.deinit();
    try testing.expectEqual(@as(u64, 6), report.lines_read);
    try testing.expectEqualStrings("sshd", report.rule_name);
    try expectCounts(&report, 3, 1, 1, 1);

    const first = sample(&report, 1);
    try testing.expectEqual(rule_test.Outcome.match, first.outcome);
    try testing.expectEqualStrings("192.168.1.100", first.identity.?);
    try testing.expectEqual(iso("2026-04-21T12:00:00Z"), first.event_time_us.?);
    try testing.expectEqualStrings("time-eligible-event", first.time.?);
    try testing.expect(first.pattern != null);
    try testing.expect(first.line == null);

    try testing.expectEqualStrings("203.0.113.55", sample(&report, 2).identity.?);
    try testing.expectEqual(rule_test.Outcome.miss, sample(&report, 3).outcome);
    try testing.expectEqualStrings("no_match", sample(&report, 3).reason);
    try testing.expectEqual(rule_test.Outcome.ignore, sample(&report, 4).outcome);
    try testing.expectEqualStrings("unenforceable", sample(&report, 4).reason);
    try testing.expectEqualStrings("127.0.0.1", sample(&report, 4).identity.?);
    try testing.expectEqual(rule_test.Outcome.reject, sample(&report, 5).outcome);
    try testing.expectEqualStrings("time-rejected-malformed", sample(&report, 5).reason);
    try testing.expectEqualStrings("10.0.0.1", sample(&report, 6).identity.?);
}

test "native rule test: each syslog service fixture matches its expected lines" {
    const cases = [_]struct { file: []const u8, service: []const u8, matched: u64, missed: u64, identity: []const u8 }{
        .{ .file = fixture("postfix.log"), .service = "postfix", .matched = 2, .missed = 1, .identity = "203.0.113.20" },
        .{ .file = fixture("dovecot.log"), .service = "dovecot", .matched = 1, .missed = 1, .identity = "203.0.113.30" },
        .{ .file = fixture("vsftpd.log"), .service = "vsftpd", .matched = 1, .missed = 1, .identity = "203.0.113.40" },
    };
    for (cases) |c| {
        var report = try rule_test.evaluate(testing.allocator, base(.{ .file = c.file }, .{ .service = c.service }));
        defer report.deinit();
        try expectCounts(&report, c.matched, c.missed, 0, 0);
        try testing.expectEqualStrings(c.identity, sample(&report, 1).identity.?);
        try testing.expectEqual(iso("2026-04-21T12:00:00Z"), sample(&report, 1).event_time_us.?);
    }
}

test "native rule test: portsentry CLI uses ISO time and the whole authentic history record" {
    var result = runCli(&.{ "--record", portsentry_positive, "--service", "portsentry", "--now", "1790085729" });
    defer result.deinit();
    try testing.expectEqual(rule_test.ExitClass.success, result.class);
    try testing.expectEqual(@as(usize, 0), result.stderr.items.len);

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, result.stdout.items, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings("portsentry", root.get("rule").?.object.get("name").?.string);
    try testing.expectEqual(@as(i64, 1), root.get("counts").?.object.get("matched").?.integer);
    const first = root.get("samples").?.array.items[0].object;
    try testing.expectEqualStrings("match", first.get("outcome").?.string);
    try testing.expectEqualStrings("192.0.2.2", first.get("identity").?.string);
    try testing.expectEqual(@as(i64, 1_790_085_719_799_000), first.get("event_time_us").?.integer);
    try testing.expectEqualStrings("time-eligible-event", first.get("time").?.string);
}

test "native rule test: undated web services default to receipt time and whole-line matching" {
    const cases = [_]struct { file: []const u8, service: []const u8, identity: []const u8 }{
        .{ .file = fixture("apache-auth.log"), .service = "apache-auth", .identity = "203.0.113.50" },
        .{ .file = fixture("nginx-http-auth.log"), .service = "nginx-http-auth", .identity = "203.0.113.60" },
    };
    for (cases) |c| {
        var report = try rule_test.evaluate(testing.allocator, base(.{ .file = c.file }, .{ .service = c.service }));
        defer report.deinit();
        try expectCounts(&report, 2, 1, 0, 0);
        try testing.expectEqualStrings(c.identity, sample(&report, 1).identity.?);
        try testing.expectEqualStrings("time-eligible-receipt", sample(&report, 1).time.?);
        try testing.expectEqual(now_us, sample(&report, 1).event_time_us.?);
    }
}

test "native rule test: single record input and explicit ignore list" {
    var opts = base(.{ .record = "Apr 21 12:00:00 host sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2" }, .{ .service = "sshd" });
    var report = try rule_test.evaluate(testing.allocator, opts);
    defer report.deinit();
    try expectCounts(&report, 1, 0, 0, 0);
    try testing.expectEqual(@as(u64, 1), report.lines_read);

    opts.ignore = &.{"203.0.113.0/24"};
    var ignored = try rule_test.evaluate(testing.allocator, opts);
    defer ignored.deinit();
    try expectCounts(&ignored, 0, 0, 1, 0);
    try testing.expectEqualStrings("ignored", sample(&ignored, 1).reason);

    opts.ignore = &.{"not-a-cidr"};
    try testing.expectError(error.InvalidIgnore, rule_test.evaluate(testing.allocator, opts));
}

test "native rule test: unknown service, internal-event service and invalid rule file are refused" {
    try testing.expectError(error.UnknownService, rule_test.evaluate(testing.allocator, base(.{ .record = "x" }, .{ .service = "nope" })));
    try testing.expectError(error.InternalEventsRequired, rule_test.evaluate(testing.allocator, base(.{ .record = "x" }, .{ .service = "recidive" })));
    try testing.expectError(error.RuleFileInvalid, rule_test.evaluate(testing.allocator, base(.{ .record = "x" }, .{ .rule_file = fixture("custom.log") })));
    try testing.expectError(error.RuleFileNotFound, rule_test.evaluate(testing.allocator, base(.{ .record = "x" }, .{ .rule_file = fixture("absent.json") })));
}

test "native rule test: custom template rule reports the native Reason vocabulary" {
    var report = try rule_test.evaluate(testing.allocator, base(.{ .file = fixture("custom.log") }, .{ .rule_file = fixture("custom-rule.json") }));
    defer report.deinit();
    try testing.expectEqualStrings("app-denied", report.rule_name);
    try testing.expectEqualStrings("rule_file", report.rule_kind);
    try expectCounts(&report, 1, 2, 1, 1);
    try testing.expectEqualStrings("matched", sample(&report, 1).reason);
    try testing.expectEqualStrings("203.0.113.100", sample(&report, 1).identity.?);
    try testing.expectEqualStrings("condition_failed", sample(&report, 2).reason);
    try testing.expectEqualStrings("exclusion_matched", sample(&report, 3).reason);
    try testing.expectEqual(rule_test.Outcome.ignore, sample(&report, 3).outcome);
    try testing.expectEqualStrings("template_mismatch", sample(&report, 4).reason);
    try testing.expectEqual(rule_test.Outcome.reject, sample(&report, 5).outcome);
    try testing.expectEqualStrings("invalid_subject", sample(&report, 5).reason);
}

test "native rule test: hostname subject stays raw without --identity dns and resolves through the given server only" {
    var report = try rule_test.evaluate(testing.allocator, base(.{ .file = fixture("hostname.log") }, .{ .rule_file = fixture("hostname-rule.json") }));
    defer report.deinit();
    try expectCounts(&report, 1, 0, 0, 0);
    try testing.expectEqualStrings("attacker.invalid", sample(&report, 1).identity.?);

    var opts = base(.{ .file = fixture("hostname.log") }, .{ .rule_file = fixture("hostname-rule.json") });
    opts.identity = .dns;
    try testing.expectError(error.DnsServerRequired, rule_test.evaluate(testing.allocator, opts));
    opts.dns_server = "not-an-address";
    try testing.expectError(error.DnsServerInvalid, rule_test.evaluate(testing.allocator, opts));
    opts.dns_server = "127.0.0.1:0";
    try testing.expectError(error.DnsServerInvalid, rule_test.evaluate(testing.allocator, opts));

    if (builtin.os.tag != .linux) return;
    opts.dns_server = "127.0.0.1:9";
    var timer = try std.time.Timer.start();
    var resolved = try rule_test.evaluate(testing.allocator, opts);
    defer resolved.deinit();
    try testing.expect(timer.read() < 5 * std.time.ns_per_s);
    const id = sample(&resolved, 1).identity.?;
    try testing.expect(std.mem.startsWith(u8, id, "attacker.invalid (dns:"));
}

test "native rule test: --config resolves the jail's timestamp, offset and ignoreip" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var config = try tmp.dir.createFile("jail.toml", .{ .mode = 0o600 });
    defer config.close();
    try config.chmod(0o600);
    const config_text = try std.fs.cwd().readFileAlloc(testing.allocator, fixture("jail.toml"), 64 * 1024);
    defer testing.allocator.free(config_text);
    try config.writeAll(config_text);
    const config_path = try tmp.dir.realpathAlloc(testing.allocator, "jail.toml");
    defer testing.allocator.free(config_path);
    var opts: rule_test.Options = .{ .input = .{ .file = fixture("sshd.log") }, .rule = .{ .service = "sshd" }, .now_us = now_us, .config = config_path };
    var report = try rule_test.evaluate(testing.allocator, opts);
    defer report.deinit();
    try testing.expectEqual(rule_test.Outcome.ignore, sample(&report, 1).outcome);
    try testing.expectEqualStrings("ignored", sample(&report, 1).reason);
    try testing.expectEqual(iso("2026-04-21T10:00:01Z"), sample(&report, 2).event_time_us.?);

    opts.jail = "missing";
    try testing.expectError(error.JailNotFound, rule_test.evaluate(testing.allocator, opts));
    opts.jail = null;
    opts.config = fixture("absent.toml");
    try testing.expectError(error.ConfigNotFound, rule_test.evaluate(testing.allocator, opts));
    opts.config = fixture("custom.log");
    try testing.expectError(error.ConfigInvalid, rule_test.evaluate(testing.allocator, opts));
}

test "native rule test: syslog year inference and --year override" {
    var opts = base(.{ .file = fixture("syslog-year.log") }, .{ .service = "sshd" });
    opts.now_us = iso("2026-01-01T00:00:30Z");
    var inferred = try rule_test.evaluate(testing.allocator, opts);
    defer inferred.deinit();
    try testing.expectEqual(rule_test.Outcome.reject, sample(&inferred, 1).outcome);
    try testing.expectEqualStrings("time-rejected-malformed", sample(&inferred, 1).reason);
    try testing.expectEqual(iso("2025-12-31T23:59:59Z"), sample(&inferred, 2).event_time_us.?);
    try testing.expectEqualStrings("time-eligible-event", sample(&inferred, 2).time.?);

    opts.year = 2024;
    opts.now_us = iso("2024-02-29T08:15:05Z");
    var leap = try rule_test.evaluate(testing.allocator, opts);
    defer leap.deinit();
    try testing.expectEqual(iso("2024-02-29T08:15:00Z"), sample(&leap, 1).event_time_us.?);
    try testing.expectEqual(rule_test.Outcome.match, sample(&leap, 1).outcome);
    try testing.expectEqualStrings("time-rejected-future", sample(&leap, 2).time.?);
    try testing.expectEqual(rule_test.Outcome.reject, sample(&leap, 2).outcome);

    opts.now_us = iso("2025-02-01T00:00:00Z");
    var stale = try rule_test.evaluate(testing.allocator, opts);
    defer stale.deinit();
    try testing.expectEqualStrings("time-obsolete-event", stale.samples.items[1].time.?);
    try testing.expectEqual(rule_test.Outcome.match, stale.samples.items[1].outcome);

    opts.year = 2023;
    var nonleap = try rule_test.evaluate(testing.allocator, opts);
    defer nonleap.deinit();
    try testing.expectEqualStrings("time-rejected-malformed", sample(&nonleap, 1).reason);
}

test "native rule test: timestamp format override and future timestamps" {
    var opts = base(.{ .record = "1776772800 Failed password for root from 203.0.113.3 port 22 ssh2" }, .{ .service = "sshd" });
    opts.timestamp = .epoch_seconds;
    var epoch = try rule_test.evaluate(testing.allocator, opts);
    defer epoch.deinit();
    try testing.expectEqual(iso("2026-04-21T12:00:00Z"), sample(&epoch, 1).event_time_us.?);
    try testing.expectEqualStrings("time-eligible-event", sample(&epoch, 1).time.?);
    try testing.expectEqual(rule_test.Outcome.miss, sample(&epoch, 1).outcome);

    opts.input = .{ .record = "1776776400 Failed password for root from 203.0.113.3 port 22 ssh2" };
    var future = try rule_test.evaluate(testing.allocator, opts);
    defer future.deinit();
    try testing.expectEqualStrings("time-rejected-future", sample(&future, 1).reason);
    try testing.expectEqual(rule_test.Outcome.reject, sample(&future, 1).outcome);

    opts.input = .{ .record = "2026-04-21T12:00:00Z host sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2" };
    opts.timestamp = .iso8601;
    var isor = try rule_test.evaluate(testing.allocator, opts);
    defer isor.deinit();
    try testing.expectEqualStrings("203.0.113.4", sample(&isor, 1).identity.?);
    try testing.expectEqual(iso("2026-04-21T12:00:00Z"), sample(&isor, 1).event_time_us.?);
}

test "native rule test: named time zone is loaded from the zoneinfo root" {
    std.fs.cwd().access("/usr/share/zoneinfo/Europe/Berlin", .{}) catch return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try @import("timezone_test_fixture.zig").copyInstalled(&tmp, &.{"Europe/Berlin"});
    defer testing.allocator.free(root);
    var opts = base(.{ .record = "Apr 21 14:00:00 host sshd[1]: Failed password for root from 203.0.113.6 port 22 ssh2" }, .{ .service = "sshd" });
    opts.tz_offset_minutes = null;
    opts.time_zone = "Europe/Berlin";
    opts.timezone_root = root;
    var report = rule_test.evaluate(testing.allocator, opts) catch |err| {
        std.debug.print("installed Europe/Berlin rule evaluation: {s}\n", .{@errorName(err)});
        return err;
    };
    defer report.deinit();
    try testing.expectEqual(iso("2026-04-21T12:00:00Z"), sample(&report, 1).event_time_us.?);
    opts.time_zone = "Not/AZone";
    try testing.expectError(error.TimezoneUnavailable, rule_test.evaluate(testing.allocator, opts));
}

test "native rule test: encoding override decodes latin1 and rejects it as utf8" {
    var opts = base(.{ .file = fixture("latin1.log") }, .{ .service = "sshd" });
    var utf8 = try rule_test.evaluate(testing.allocator, opts);
    defer utf8.deinit();
    try expectCounts(&utf8, 0, 0, 0, 1);
    try testing.expectEqualStrings("invalid_encoding", sample(&utf8, 1).reason);

    opts.encoding = .latin1;
    var latin = try rule_test.evaluate(testing.allocator, opts);
    defer latin.deinit();
    try expectCounts(&latin, 1, 0, 0, 0);
    try testing.expectEqualStrings("203.0.113.90", sample(&latin, 1).identity.?);
}

test "native rule test: malformed bytes reject only the affected line" {
    var report = try rule_test.evaluate(testing.allocator, base(.{ .file = fixture("malformed.log") }, .{ .service = "sshd" }));
    defer report.deinit();
    try testing.expectEqual(@as(u64, 3), report.lines_read);
    try expectCounts(&report, 2, 0, 0, 1);
    try testing.expectEqualStrings("invalid_encoding", sample(&report, 2).reason);
}

test "native rule test: oversized line is rejected and streaming continues; missing and huge files are refused" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var f = try tmp.dir.createFile("big.log", .{});
        defer f.close();
        var chunk: [4096]u8 = undefined;
        @memset(&chunk, 'A');
        var written: usize = 0;
        while (written < 70_000) : (written += chunk.len) try f.writeAll(&chunk);
        try f.writeAll("\nApr 21 12:00:00 host sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2\n");
    }
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const big = try tmp.dir.realpath("big.log", &abs_buf);
    var report = try rule_test.evaluate(testing.allocator, base(.{ .file = big }, .{ .service = "sshd" }));
    defer report.deinit();
    try testing.expectEqual(@as(u64, 2), report.lines_read);
    try expectCounts(&report, 1, 0, 0, 1);
    try testing.expectEqualStrings("line_too_long", sample(&report, 1).reason);
    try testing.expectEqualStrings("203.0.113.7", sample(&report, 2).identity.?);

    try testing.expectError(error.InputNotFound, rule_test.evaluate(testing.allocator, base(.{ .file = fixture("absent.log") }, .{ .service = "sshd" })));
    try testing.expectError(error.InputNotRegular, rule_test.evaluate(testing.allocator, base(.{ .file = fixtures }, .{ .service = "sshd" })));

    {
        const f = try tmp.dir.createFile("huge.log", .{});
        defer f.close();
        try f.setEndPos(rule_test.max_file_bytes + 1);
    }
    var huge_buf: [std.fs.max_path_bytes]u8 = undefined;
    const huge = try tmp.dir.realpath("huge.log", &huge_buf);
    try testing.expectError(error.InputTooLarge, rule_test.evaluate(testing.allocator, base(.{ .file = huge }, .{ .service = "sshd" })));

    var long_record = base(.{ .record = big }, .{ .service = "sshd" });
    long_record.input = .{ .record = try testing.allocator.alloc(u8, rule_test.max_line_bytes + 1) };
    defer testing.allocator.free(long_record.input.record);
    @memset(@constCast(long_record.input.record), 'B');
    var rec = try rule_test.evaluate(testing.allocator, long_record);
    defer rec.deinit();
    try testing.expectEqualStrings("line_too_long", sample(&rec, 1).reason);
}

test "native rule test: samples are bounded by --limit while counts stay complete" {
    var opts = base(.{ .file = fixture("sshd.log") }, .{ .service = "sshd" });
    opts.limit = 2;
    var report = try rule_test.evaluate(testing.allocator, opts);
    defer report.deinit();
    try testing.expectEqual(@as(usize, 2), report.samples.items.len);
    try testing.expectEqual(@as(u64, 4), report.samples_omitted);
    try expectCounts(&report, 3, 1, 1, 1);

    opts.limit = 20;
    opts.max_lines = 2;
    var capped = try rule_test.evaluate(testing.allocator, opts);
    defer capped.deinit();
    try testing.expectEqual(@as(u64, 2), capped.lines_read);
    try expectCounts(&capped, 2, 0, 0, 0);
}

test "native rule test: raw lines appear only with --print-lines" {
    var opts = base(.{ .record = "Apr 21 12:00:00 host sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2" }, .{ .service = "sshd" });
    opts.print_lines = true;
    var report = try rule_test.evaluate(testing.allocator, opts);
    defer report.deinit();
    try testing.expectEqualStrings(opts.input.record, sample(&report, 1).line.?);

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try rule_test.writeJson(&report, buf.writer());
    try testing.expect(std.mem.indexOf(u8, buf.items, "\"line\":\"Apr 21") != null);
}

test "native rule test: json and table renderers carry the schema and counts" {
    var report = try rule_test.evaluate(testing.allocator, base(.{ .file = fixture("sshd.log") }, .{ .service = "sshd" }));
    defer report.deinit();
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try rule_test.writeJson(&report, buf.writer());
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqual(@as(i64, 1), root.get("schema_version").?.integer);
    try testing.expectEqualStrings("file", root.get("input").?.object.get("kind").?.string);
    try testing.expectEqual(@as(i64, 6), root.get("input").?.object.get("lines_read").?.integer);
    try testing.expectEqualStrings("service", root.get("rule").?.object.get("kind").?.string);
    try testing.expectEqual(@as(i64, 3), root.get("counts").?.object.get("matched").?.integer);
    try testing.expectEqual(@as(usize, 6), root.get("samples").?.array.items.len);
    const first = root.get("samples").?.array.items[0].object;
    try testing.expectEqualStrings("match", first.get("outcome").?.string);
    try testing.expect(first.get("line") == null);

    buf.clearRetainingCapacity();
    try rule_test.writeTable(&report, buf.writer());
    try testing.expect(std.mem.startsWith(u8, buf.items, "input\tfile\t"));
    try testing.expect(std.mem.indexOf(u8, buf.items, "counts\tmatched=3\tmissed=1\tignored=1\trejected=1\n") != null);
    try testing.expect(std.mem.indexOf(u8, buf.items, "\n1\tmatch\tmatched\t192.168.1.100\t") != null);
}

test "native rule test: run maps success, rejection and usage to the exit classes" {
    var ok = runCli(&.{ "--file", fixture("sshd.log"), "--service", "sshd", "--now", "1776772810", "--tz-offset", "0" });
    defer ok.deinit();
    try testing.expectEqual(rule_test.ExitClass.success, ok.class);
    try testing.expect(std.mem.indexOf(u8, ok.stdout.items, "\"matched\":3") != null);

    var none = runCli(&.{ "--record", "nothing here", "--service", "sshd", "--timestamp", "undated" });
    defer none.deinit();
    try testing.expectEqual(rule_test.ExitClass.success, none.class);
    try testing.expect(std.mem.indexOf(u8, none.stdout.items, "\"matched\":0") != null);

    var missing = runCli(&.{ "--file", fixture("absent.log"), "--service", "sshd" });
    defer missing.deinit();
    try testing.expectEqual(rule_test.ExitClass.rejected, missing.class);
    try testing.expectEqualStrings("rule-test: input not found\n", missing.stderr.items);

    var unknown_service = runCli(&.{ "--record", "x", "--service", "nope" });
    defer unknown_service.deinit();
    try testing.expectEqual(rule_test.ExitClass.rejected, unknown_service.class);

    const usage_cases = [_][]const []const u8{
        &.{},
        &.{ "--service", "sshd" },
        &.{ "--record", "x" },
        &.{ "--record", "x", "--file", "y", "--service", "sshd" },
        &.{ "--record", "x", "--service", "sshd", "--rule-file", "r" },
        &.{ "--record", "x", "--service", "sshd", "--identity", "dns" },
        &.{ "--record", "x", "--service", "sshd", "--bogus" },
        &.{ "--record", "x", "--service", "sshd", "--year", "0" },
        &.{ "--record", "x", "--service", "sshd", "--output", "xml" },
        &.{ "--record", "x", "--service", "sshd", "--time-zone", "UTC", "--tz-offset", "0" },
        &.{ "--record", "x", "--service" },
    };
    for (usage_cases) |args| {
        var r = runCli(args);
        defer r.deinit();
        try testing.expectEqual(rule_test.ExitClass.usage, r.class);
        try testing.expect(r.stderr.items.len > 0);
    }

    var table = runCli(&.{ "--record", "Apr 21 12:00:00 host sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2", "--service", "sshd", "--now", "1776772810", "--tz-offset", "0", "--output", "table", "--ignore", "203.0.113.0/24" });
    defer table.deinit();
    try testing.expectEqual(rule_test.ExitClass.success, table.class);
    try testing.expect(std.mem.indexOf(u8, table.stdout.items, "\n1\tignore\tignored\t203.0.113.5\t") != null);
}

test "native rule test: journal input uses the fixed journalctl transport and journal time" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const fake = try std.fs.cwd().realpath(fixture("fake-journalctl.sh"), &abs_buf);
    var opts = base(.{ .journal = &.{"SYSLOG_IDENTIFIER=sshd"} }, .{ .service = "sshd" });
    opts.journal_executable = fake;
    var report = try rule_test.evaluate(testing.allocator, opts);
    defer report.deinit();
    try testing.expectEqualStrings("journal", report.input_kind);
    try testing.expectEqual(@as(u64, 2), report.lines_read);
    try expectCounts(&report, 1, 1, 0, 0);
    try testing.expectEqualStrings("203.0.113.200", sample(&report, 1).identity.?);
    try testing.expectEqual(iso("2026-04-21T12:00:00Z"), sample(&report, 1).event_time_us.?);
    try testing.expectEqualStrings("time-eligible-event", sample(&report, 1).time.?);

    opts.journal_executable = "/nonexistent/journalctl";
    try testing.expectError(error.JournalUnavailable, rule_test.evaluate(testing.allocator, opts));
    opts.journal_executable = "relative/journalctl";
    try testing.expectError(error.JournalUnavailable, rule_test.evaluate(testing.allocator, opts));
}
