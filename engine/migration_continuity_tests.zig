// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const continuity = @import("migration/continuity.zig");
const plan_mod = @import("migration/plan.zig");
const fixture = @import("migration/fail2ban_fixture.zig");

comptime {
    _ = @import("shared");
}

const host_id = [_]u8{0x5c} ** 32;
const now: i64 = 1_800_000_000_000_000;
const cutover: i64 = now + 5_000_000;

const Env = struct {
    tmp: t.TmpDir,
    root: []u8,
    source: []u8,
    auth_log: []u8,
    error_log: []u8,

    fn init(with_journal: bool) !Env {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(t.allocator, ".");
        errdefer t.allocator.free(root);
        try tmp.dir.makeDir("source");
        const source = try std.fs.path.join(t.allocator, &.{ root, "source" });
        errdefer t.allocator.free(source);
        const auth_log = try std.fs.path.join(t.allocator, &.{ root, "auth.log" });
        errdefer t.allocator.free(auth_log);
        const error_log = try std.fs.path.join(t.allocator, &.{ root, "error.log" });
        errdefer t.allocator.free(error_log);
        const journal = if (with_journal) "[dovecot]\nenabled = true\nbackend = systemd\n" else "";
        const conf = try std.fmt.allocPrint(t.allocator,
            \\[DEFAULT]
            \\bantime = 10m
            \\findtime = 10m
            \\maxretry = 5
            \\backend = auto
            \\usedns = no
            \\banaction = nftables-allports
            \\action = %(banaction)s
            \\[sshd]
            \\enabled = true
            \\logpath = {s}
            \\[nginx-http-auth]
            \\enabled = true
            \\logpath = {s}
            \\{s}
        , .{ auth_log, error_log, journal });
        defer t.allocator.free(conf);
        try tmp.dir.writeFile(.{ .sub_path = "source/jail.conf", .data = conf });
        try tmp.dir.writeFile(.{ .sub_path = "auth.log", .data = auth_content });
        try tmp.dir.writeFile(.{ .sub_path = "error.log", .data = error_content });
        return .{ .tmp = tmp, .root = root, .source = source, .auth_log = auth_log, .error_log = error_log };
    }

    fn deinit(self: *Env) void {
        t.allocator.free(self.error_log);
        t.allocator.free(self.auth_log);
        t.allocator.free(self.source);
        t.allocator.free(self.root);
        self.tmp.cleanup();
    }

    fn makePlan(self: *Env, mode: plan_mod.Continuity, window: ?u32) !plan_mod.Plan {
        return plan_mod.plan(t.allocator, .{ .source_dir = self.source, .now_us = now, .host_id = host_id, .tool_version = "test", .continuity = mode, .replay_window_s = window, .runtime_socket = "/nonexistent/fail2ban.sock" });
    }

    fn rows(self: *Env, auth_pos: i64, error_pos: i64) [2]continuity.LogRow {
        return .{
            .{ .jail = "sshd", .path = self.auth_log, .firstlinemd5 = &auth_md5, .lastfilepos = auth_pos },
            .{ .jail = "nginx-http-auth", .path = self.error_log, .firstlinemd5 = &error_md5, .lastfilepos = error_pos },
        };
    }
};

const auth_first = "Sep 14 10:00:00 host sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2\n";
const auth_content = auth_first ++ "Sep 14 10:00:01 host sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2\n";
const error_first = "2026/09/14 10:00:00 [error] 1#1: user \"a\": password mismatch, client: 192.0.2.11\r\n";
const error_content = error_first ++ "2026/09/14 10:00:02 [error] 1#1: user \"b\": password mismatch, client: 192.0.2.12\r\n";
const auth_md5 = sha1Hex(auth_first);
const error_md5 = md5Hex(error_first);

fn md5Hex(comptime line: []const u8) [32]u8 {
    @setEvalBranchQuota(200_000);
    var digest: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(line, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn sha1Hex(comptime line: []const u8) [40]u8 {
    @setEvalBranchQuota(400_000);
    var digest: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(line, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn render(b: *const continuity.Boundary) ![]u8 {
    var buf = std.ArrayList(u8).init(t.allocator);
    errdefer buf.deinit();
    try continuity.writeBoundaryJson(b, buf.writer());
    return buf.toOwnedSlice();
}

fn fileFor(b: *const continuity.Boundary, group: []const u8) *const continuity.FileBoundary {
    for (b.files) |*f| if (std.mem.eql(u8, f.group, group)) return f;
    unreachable;
}

test "migration continuity: lossless resume when md5 and offsets agree, including an unread tail" {
    var env = try Env.init(false);
    defer env.deinit();
    var p = try env.makePlan(.lossless, null);
    defer p.deinit();
    const logs = env.rows(@intCast(auth_content.len), @intCast(error_first.len));
    var b = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &logs, .cutover_us = cutover });
    defer b.deinit();
    try t.expectEqual(continuity.Outcome.lossless, b.outcome);
    try t.expect(b.replay == null);
    try t.expectEqual(@as(usize, 2), b.files.len);
    try t.expectEqual(@as(usize, 0), b.journals.len);

    const sshd = fileFor(&b, "sshd");
    try t.expectEqual(continuity.Decision.resume_at_offset, sshd.decision);
    try t.expectEqualStrings("resume-at-end", sshd.reason);
    try t.expectEqual(true, sshd.observed.first_line_md5_matches.?);
    try t.expect(sshd.observed.offset_valid);
    const stat = try std.fs.cwd().statFile(env.auth_log);
    try t.expectEqual(@as(u64, @intCast(stat.inode)), sshd.checkpoint.?.inode);
    try t.expectEqual(@as(u64, auth_content.len), sshd.checkpoint.?.offset);
    try t.expectEqual(@as(u8, 64), sshd.checkpoint.?.prefix_len);
    var expected_prefix: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(auth_content[0..64], &expected_prefix, .{});
    try t.expectEqualSlices(u8, &expected_prefix, &sshd.checkpoint.?.prefix_hash);
    try t.expectEqual(@as(u8, 2), sshd.checkpoint.?.version);

    const nginx = fileFor(&b, "nginx-http-auth");
    try t.expectEqual(continuity.Decision.resume_at_offset, nginx.decision);
    try t.expectEqualStrings("resume-with-unread-tail", nginx.reason);
    try t.expectEqual(@as(u64, error_first.len), nginx.checkpoint.?.offset);
}

test "migration continuity: md5 mismatch blocks lossless and replays under reset_replay" {
    var env = try Env.init(false);
    defer env.deinit();
    var lossless = try env.makePlan(.lossless, null);
    defer lossless.deinit();
    var logs = env.rows(@intCast(auth_content.len), @intCast(error_content.len));
    logs[0].firstlinemd5 = "00000000000000000000000000000000";
    var blocked = try continuity.evaluate(t.allocator, .{ .doc = &lossless.doc, .logs = &logs, .cutover_us = cutover });
    defer blocked.deinit();
    try t.expectEqual(continuity.Outcome.blocked, blocked.outcome);
    try t.expectEqual(continuity.Decision.blocked, fileFor(&blocked, "sshd").decision);
    try t.expectEqualStrings("first-line-md5-mismatch", fileFor(&blocked, "sshd").reason);
    try t.expectEqual(false, fileFor(&blocked, "sshd").observed.first_line_md5_matches.?);
    try t.expect(fileFor(&blocked, "sshd").checkpoint == null);
    try t.expectEqual(continuity.Decision.resume_at_offset, fileFor(&blocked, "nginx-http-auth").decision);

    var reset = try env.makePlan(.reset_replay, 600);
    defer reset.deinit();
    var replayed = try continuity.evaluate(t.allocator, .{ .doc = &reset.doc, .logs = &logs, .cutover_us = cutover });
    defer replayed.deinit();
    try t.expectEqual(continuity.Outcome.non_lossless, replayed.outcome);
    try t.expectEqual(continuity.Decision.replay_window, fileFor(&replayed, "sshd").decision);
    try t.expectEqual(@as(u32, 600), replayed.replay.?.window_s);
    try t.expectEqual(cutover - 600 * std.time.us_per_s, replayed.replay.?.from_us);
    try t.expectEqual(cutover, replayed.replay.?.cutover_us);
}

test "migration continuity: rotated file has a new inode and a mismatching first line" {
    var env = try Env.init(false);
    defer env.deinit();
    var p = try env.makePlan(.reset_replay, 300);
    defer p.deinit();
    const before = try std.fs.cwd().statFile(env.auth_log);
    try env.tmp.dir.rename("auth.log", "auth.log.1");
    try env.tmp.dir.writeFile(.{ .sub_path = "auth.log", .data = "Sep 15 00:00:00 host sshd[2]: Server listening on 0.0.0.0 port 22.\n" });
    const logs = env.rows(@intCast(auth_content.len), @intCast(error_content.len));
    var b = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &logs, .cutover_us = cutover });
    defer b.deinit();
    const sshd = fileFor(&b, "sshd");
    try t.expectEqual(continuity.Decision.replay_window, sshd.decision);
    try t.expectEqualStrings("first-line-md5-mismatch", sshd.reason);
    try t.expect(sshd.observed.ino.? != @as(u64, @intCast(before.inode)));
    try t.expectEqual(continuity.Outcome.non_lossless, b.outcome);
}

test "migration continuity: truncated file with offset beyond size is not resumable" {
    var env = try Env.init(false);
    defer env.deinit();
    var p = try env.makePlan(.lossless, null);
    defer p.deinit();
    const logs = env.rows(@intCast(auth_content.len + 100), @intCast(error_content.len));
    var b = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &logs, .cutover_us = cutover });
    defer b.deinit();
    const sshd = fileFor(&b, "sshd");
    try t.expectEqual(continuity.Decision.blocked, sshd.decision);
    try t.expectEqualStrings("offset-beyond-size", sshd.reason);
    try t.expectEqual(true, sshd.observed.first_line_md5_matches.?);
    try t.expect(!sshd.observed.offset_valid);
    try t.expectEqual(continuity.Outcome.blocked, b.outcome);
}

test "migration continuity: missing file, missing row, unrecorded md5 and incomplete first line" {
    var env = try Env.init(false);
    defer env.deinit();
    var p = try env.makePlan(.reset_replay, 60);
    defer p.deinit();
    try env.tmp.dir.deleteFile("auth.log");
    const logs = env.rows(@intCast(auth_content.len), @intCast(error_content.len));
    var missing = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &logs, .cutover_us = cutover });
    defer missing.deinit();
    try t.expectEqualStrings("file-missing", fileFor(&missing, "sshd").reason);
    try t.expectEqual(continuity.Decision.replay_window, fileFor(&missing, "sshd").decision);
    try t.expect(fileFor(&missing, "sshd").observed.ino == null);

    try env.tmp.dir.writeFile(.{ .sub_path = "auth.log", .data = "no terminator yet" });
    var incomplete = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &logs, .cutover_us = cutover });
    defer incomplete.deinit();
    try t.expectEqualStrings("first-line-incomplete", fileFor(&incomplete, "sshd").reason);
    try t.expect(fileFor(&incomplete, "sshd").observed.first_line_md5_matches == null);

    var no_row = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = logs[1..], .cutover_us = cutover });
    defer no_row.deinit();
    try t.expectEqualStrings("no-logs-row", fileFor(&no_row, "sshd").reason);

    var unrecorded = logs;
    unrecorded[1].firstlinemd5 = null;
    var unrec = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &unrecorded, .cutover_us = cutover });
    defer unrec.deinit();
    try t.expectEqualStrings("first-line-md5-unrecorded", fileFor(&unrec, "nginx-http-auth").reason);

    var odd = logs;
    odd[1].firstlinemd5 = "abcdef0123456789";
    var unrecognised = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &odd, .cutover_us = cutover });
    defer unrecognised.deinit();
    try t.expectEqualStrings("first-line-digest-unrecognised", fileFor(&unrecognised, "nginx-http-auth").reason);
    try t.expect(fileFor(&unrecognised, "nginx-http-auth").observed.first_line_md5_matches == null);
}

test "migration continuity: a SHA-1 row does not match under MD5 and an MD5 row does not match under SHA-1" {
    var env = try Env.init(false);
    defer env.deinit();
    var p = try env.makePlan(.lossless, null);
    defer p.deinit();
    var swapped = env.rows(@intCast(auth_content.len), @intCast(error_content.len));
    const auth_as_md5 = md5Hex(auth_first);
    const error_as_sha1 = sha1Hex(error_first);
    swapped[0].firstlinemd5 = &auth_as_md5;
    swapped[1].firstlinemd5 = &error_as_sha1;
    var b = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &swapped, .cutover_us = cutover });
    defer b.deinit();
    try t.expectEqual(continuity.Decision.resume_at_offset, fileFor(&b, "sshd").decision);
    try t.expectEqual(continuity.Decision.resume_at_offset, fileFor(&b, "nginx-http-auth").decision);
    try t.expectEqual(continuity.Outcome.lossless, b.outcome);
    const uppercase = std.ascii.upperString(t.allocator.alloc(u8, 40) catch unreachable, &auth_md5);
    defer t.allocator.free(uppercase);
    swapped[0].firstlinemd5 = uppercase;
    var upper = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &swapped, .cutover_us = cutover });
    defer upper.deinit();
    try t.expectEqual(continuity.Decision.resume_at_offset, fileFor(&upper, "sshd").decision);
}

test "migration continuity: journal groups never get a fabricated cursor" {
    var env = try Env.init(true);
    defer env.deinit();
    const logs = env.rows(@intCast(auth_content.len), @intCast(error_content.len));

    var lossless = try env.makePlan(.lossless, null);
    defer lossless.deinit();
    var blocked = try continuity.evaluate(t.allocator, .{ .doc = &lossless.doc, .logs = &logs, .cutover_us = cutover });
    defer blocked.deinit();
    try t.expectEqual(@as(usize, 1), blocked.journals.len);
    try t.expectEqualStrings("dovecot", blocked.journals[0].group);
    try t.expectEqual(continuity.Decision.blocked, blocked.journals[0].decision);
    try t.expectEqualStrings("journal-cursor-unavailable", blocked.journals[0].reason);
    try t.expectEqual(continuity.Outcome.blocked, blocked.outcome);
    try t.expectEqual(continuity.Decision.resume_at_offset, fileFor(&blocked, "sshd").decision);

    var reset = try env.makePlan(.reset_replay, 120);
    defer reset.deinit();
    var replay = try continuity.evaluate(t.allocator, .{ .doc = &reset.doc, .logs = &logs, .cutover_us = cutover });
    defer replay.deinit();
    try t.expectEqual(continuity.Decision.replay_window, replay.journals[0].decision);
    try t.expectEqualStrings("journal-tail-with-bounded-since-replay", replay.journals[0].reason);
    try t.expectEqual(continuity.Outcome.non_lossless, replay.outcome);

    var no_window = try env.makePlan(.reset_replay, null);
    defer no_window.deinit();
    var tail = try continuity.evaluate(t.allocator, .{ .doc = &no_window.doc, .logs = &logs, .cutover_us = cutover });
    defer tail.deinit();
    try t.expect(tail.replay == null);
    try t.expectEqual(continuity.Decision.start_at_tail, tail.journals[0].decision);
    try t.expectEqual(continuity.Outcome.non_lossless, tail.outcome);
}

test "migration continuity: replay window boundary math is explicit and saturating" {
    var env = try Env.init(false);
    defer env.deinit();
    var p = try env.makePlan(.reset_replay, 3600);
    defer p.deinit();
    const logs = env.rows(0, 0);
    var b = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &logs, .cutover_us = 1_000_000 });
    defer b.deinit();
    try t.expectEqual(@as(i64, 1_000_000 - 3600 * 1_000_000), b.replay.?.from_us);
    try t.expectEqual(continuity.Outcome.lossless, b.outcome);
    const json = try render(&b);
    defer t.allocator.free(json);
    try t.expect(std.mem.indexOf(u8, json, "\"replay\":{\"window_s\":3600,\"cutover_us\":1000000,\"from_us\":-3599000000}") != null);
    try t.expect(std.mem.indexOf(u8, json, "\"not_transferable\":[\"pending_records\",\"in_window_failure_counters\",\"multiline_correlation_state\"]") != null);
}

test "migration continuity: evaluation is deterministic and never touches the files" {
    var env = try Env.init(true);
    defer env.deinit();
    var p = try env.makePlan(.reset_replay, 600);
    defer p.deinit();
    const logs = env.rows(@intCast(auth_content.len), @intCast(error_first.len));
    const before_auth = try std.fs.cwd().statFile(env.auth_log);
    const before_error = try std.fs.cwd().statFile(env.error_log);
    var b1 = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &logs, .cutover_us = cutover });
    defer b1.deinit();
    var b2 = try continuity.evaluate(t.allocator, .{ .doc = &p.doc, .logs = &logs, .cutover_us = cutover });
    defer b2.deinit();
    const j1 = try render(&b1);
    defer t.allocator.free(j1);
    const j2 = try render(&b2);
    defer t.allocator.free(j2);
    try t.expectEqualStrings(j1, j2);
    try t.expectEqualSlices(u8, &fileFor(&b1, "sshd").checkpoint.?.incarnation, &fileFor(&b2, "sshd").checkpoint.?.incarnation);
    const after_auth = try std.fs.cwd().statFile(env.auth_log);
    const after_error = try std.fs.cwd().statFile(env.error_log);
    try t.expectEqual(before_auth.mtime, after_auth.mtime);
    try t.expectEqual(before_error.mtime, after_error.mtime);
    const auth_now = try std.fs.cwd().readFileAlloc(t.allocator, env.auth_log, 1 << 16);
    defer t.allocator.free(auth_now);
    try t.expectEqualStrings(auth_content, auth_now);
    try t.expect(std.mem.startsWith(u8, j1, "{\"schema_version\":1,\"requested\":\"reset_replay\",\"outcome\":\"non_lossless\","));
}

test "migration continuity: readLogs returns the snapshot logs rows with optional md5" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "fail2ban.sqlite3" });
    defer t.allocator.free(path);
    try fixture.build(path, .{});
    const rows = try continuity.readLogs(t.allocator, path);
    defer continuity.freeLogs(t.allocator, rows);
    try t.expectEqual(@as(usize, 2), rows.len);
    try t.expectEqualStrings("sshd", rows[0].jail);
    try t.expectEqualStrings("/var/log/auth.log", rows[0].path);
    try t.expectEqualStrings("d41d8cd98f00b204e9800998ecf8427e", rows[0].firstlinemd5.?);
    try t.expectEqual(@as(i64, 12345), rows[0].lastfilepos.?);
    try t.expect(rows[1].firstlinemd5 == null);
}
