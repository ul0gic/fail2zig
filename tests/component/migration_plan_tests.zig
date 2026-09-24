// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const plan_mod = @import("engine_test").migration.plan;
const snapshot = @import("engine_test").migration.sqlite_snapshot;
const fixture = @import("engine_test").migration.fail2ban_fixture;

comptime {
    _ = @import("shared");
}

const fixture_root = "tests/fixtures/fail2ban/config";
const host_id = [_]u8{0xab} ** 32;
const now: i64 = 1_800_000_000_000_000;

const Env = struct {
    tmp: t.TmpDir,
    root: []u8,
    source: []u8,

    fn init(tree: ?[]const u8) !Env {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(t.allocator, ".");
        errdefer t.allocator.free(root);
        try tmp.dir.makeDir("source");
        const source = try std.fs.path.join(t.allocator, &.{ root, "source" });
        errdefer t.allocator.free(source);
        if (tree) |name| {
            const from = try std.fs.path.join(t.allocator, &.{ fixture_root, name });
            defer t.allocator.free(from);
            try copyTree(from, source);
        }
        return .{ .tmp = tmp, .root = root, .source = source };
    }

    fn deinit(self: *Env) void {
        t.allocator.free(self.source);
        t.allocator.free(self.root);
        self.tmp.cleanup();
    }

    fn path(self: *Env, name: []const u8) ![]u8 {
        return std.fs.path.join(t.allocator, &.{ self.root, name });
    }

    fn writeSource(self: *Env, rel: []const u8, data: []const u8) !void {
        var dir = try std.fs.cwd().openDir(self.source, .{});
        defer dir.close();
        if (std.fs.path.dirname(rel)) |parent| try dir.makePath(parent);
        try dir.writeFile(.{ .sub_path = rel, .data = data });
    }

    fn options(self: *Env) plan_mod.PlanOptions {
        return .{ .source_dir = self.source, .now_us = now, .host_id = host_id, .tool_version = "test", .continuity = .reset_replay, .replay_window_s = 600, .runtime_socket = "/nonexistent/fail2ban.sock" };
    }
};

fn copyTree(from: []const u8, to: []const u8) !void {
    var src = try std.fs.cwd().openDir(from, .{ .iterate = true });
    defer src.close();
    var dst = try std.fs.cwd().openDir(to, .{});
    defer dst.close();
    var walker = try src.walk(t.allocator);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        switch (entry.kind) {
            .directory => try dst.makePath(entry.path),
            .file => {
                if (std.fs.path.dirname(entry.path)) |parent| try dst.makePath(parent);
                try entry.dir.copyFile(entry.basename, dst, entry.path, .{});
            },
            else => {},
        }
    }
}

fn render(p: *const plan_mod.Plan) ![]u8 {
    var buf = std.ArrayList(u8).init(t.allocator);
    errdefer buf.deinit();
    try plan_mod.renderJson(p, buf.writer());
    return buf.toOwnedSlice();
}

fn hasString(items: []const []const u8, needle: []const u8) bool {
    for (items) |i| if (std.mem.eql(u8, i, needle)) return true;
    return false;
}

fn hasBlocker(p: *const plan_mod.Plan, group: []const u8, reason: []const u8) bool {
    for (p.doc.blockers) |b| if (std.mem.eql(u8, b.group, group) and std.mem.eql(u8, b.reason, reason)) return true;
    return false;
}

fn hasChange(p: *const plan_mod.Plan, group: []const u8, change: []const u8) bool {
    for (p.doc.semantic_changes) |c| if (std.mem.eql(u8, c.group, group) and std.mem.eql(u8, c.change, change)) return true;
    return false;
}

const lossless_tree =
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
    \\logpath = /var/log/auth.log
    \\[nginx-http-auth]
    \\enabled = true
    \\logpath = /var/log/nginx/error.log
    \\
;

const Captured = struct {
    snap: snapshot.Snapshot,
    fn deinit(self: *Captured) void {
        self.snap.deinit(t.allocator);
    }
};

fn captureFixtureDb(env: *Env) !Captured {
    const source_db = try env.path("fail2ban.sqlite3");
    defer t.allocator.free(source_db);
    try fixture.build(source_db, .{});
    const staging = try env.path("staging");
    defer t.allocator.free(staging);
    try std.posix.mkdir(staging, 0o700);
    return .{ .snap = try snapshot.capture(t.allocator, source_db, staging, .{}) };
}

test "migration plan: supported tree with reset_replay selects both groups and records semantic changes" {
    var env = try Env.init("supported");
    defer env.deinit();
    var p = try plan_mod.plan(t.allocator, env.options());
    defer p.deinit();
    try t.expectEqual(@as(usize, 0), p.doc.blockers.len);
    try t.expectEqual(@as(usize, 2), p.doc.selection.len);
    try t.expectEqualStrings("nginx-http-auth", p.doc.selection[0]);
    try t.expectEqualStrings("sshd", p.doc.selection[1]);
    try t.expect(hasString(p.doc.assumptions, "non_lossless:true"));
    try t.expect(hasString(p.doc.assumptions, "replay_window_s:600"));
    try t.expect(hasChange(&p, "sshd", "backend-substitution:systemd->journalctl"));
    try t.expect(hasChange(&p, "sshd", "journalmatch-replacement:native-origin-qualification"));
    try t.expect(!hasChange(&p, "nginx-http-auth", "port-scope-widened-to-host"));
    try t.expectEqual(now, p.doc.created_us);
    try t.expectEqual(now + plan_mod.validity_us, p.doc.valid_until_us);
    try t.expectEqualStrings("absent", p.doc.drift.runtime_state);
    try t.expectEqual(@as(usize, 3), p.doc.drift.files.len);
    try t.expect(p.doc.snapshot == null);
    try t.expect(p.doc.snapshot_fp == null);
    try t.expectEqualStrings("abababababababababababababababababababababababababababababababab", p.doc.host_id_hex);
    var table = std.ArrayList(u8).init(t.allocator);
    defer table.deinit();
    try plan_mod.renderTable(&p, table.writer());
    try t.expect(std.mem.indexOf(u8, table.items, "selection: nginx-http-auth sshd") != null);
}

test "migration plan: identical inputs render byte-identical JSON and only time fields change with now_us" {
    var env = try Env.init("blocker");
    defer env.deinit();
    var p1 = try plan_mod.plan(t.allocator, env.options());
    defer p1.deinit();
    var p2 = try plan_mod.plan(t.allocator, env.options());
    defer p2.deinit();
    const a = try render(&p1);
    defer t.allocator.free(a);
    const b = try render(&p2);
    defer t.allocator.free(b);
    try t.expectEqualStrings(a, b);

    var later = env.options();
    later.now_us = now + 1;
    var p3 = try plan_mod.plan(t.allocator, later);
    defer p3.deinit();
    const c = try render(&p3);
    defer t.allocator.free(c);
    try t.expect(!std.mem.eql(u8, a, c));
    const va = try std.json.parseFromSlice(std.json.Value, t.allocator, a, .{});
    defer va.deinit();
    const vc = try std.json.parseFromSlice(std.json.Value, t.allocator, c, .{});
    defer vc.deinit();
    const keys = va.value.object.keys();
    for (keys) |key| {
        if (std.mem.eql(u8, key, "created_us") or std.mem.eql(u8, key, "valid_until_us") or std.mem.eql(u8, key, "digest")) continue;
        var sa = std.ArrayList(u8).init(t.allocator);
        defer sa.deinit();
        var sc = std.ArrayList(u8).init(t.allocator);
        defer sc.deinit();
        try std.json.stringify(va.value.object.get(key).?, .{}, sa.writer());
        try std.json.stringify(vc.value.object.get(key).?, .{}, sc.writer());
        try t.expectEqualStrings(sa.items, sc.items);
    }
    try t.expect(!std.mem.eql(u8, p1.doc.digest, p3.doc.digest));
}

test "migration plan: group dispositions aggregate into blockers with their kind" {
    var env = try Env.init("blocker");
    defer env.deinit();
    var p = try plan_mod.plan(t.allocator, env.options());
    defer p.deinit();
    try t.expectEqual(@as(usize, 0), p.doc.selection.len);
    try t.expect(hasBlocker(&p, "myapp", "custom-filter:myapp"));
    try t.expect(hasBlocker(&p, "sshd", "custom-action-script:notify-admin"));
    try t.expect(hasBlocker(&p, "nginx-http-auth", "ignorecommand"));
    for (p.doc.blockers) |b| try t.expectEqualStrings("blocker", b.kind);

    var env2 = try Env.init("operator-change");
    defer env2.deinit();
    var p2 = try plan_mod.plan(t.allocator, env2.options());
    defer p2.deinit();
    try t.expect(hasBlocker(&p2, "sshd", "ignoreip-hostname:gateway.example"));
    try t.expectEqualStrings("operator_change", p2.doc.blockers[0].kind);
}

test "migration plan: reset_replay without a window and source_db without a snapshot are blockers" {
    var env = try Env.init("supported");
    defer env.deinit();
    var opts = env.options();
    opts.replay_window_s = null;
    opts.source_db = "/var/lib/fail2ban/fail2ban.sqlite3";
    var p = try plan_mod.plan(t.allocator, opts);
    defer p.deinit();
    try t.expect(hasBlocker(&p, "*", "replay-window-missing"));
    try t.expect(hasBlocker(&p, "*", "snapshot-missing"));
    try t.expect(hasString(p.doc.assumptions, "non_lossless:true"));
    try t.expectEqualStrings("/var/lib/fail2ban/fail2ban.sqlite3", p.doc.source_db.?);
}

test "migration plan: lossless continuity needs a usable logs row per file group and never a journal group" {
    var env = try Env.init("supported");
    defer env.deinit();
    var opts = env.options();
    opts.continuity = .lossless;
    opts.replay_window_s = null;
    var without = try plan_mod.plan(t.allocator, opts);
    defer without.deinit();
    try t.expect(hasBlocker(&without, "sshd", "continuity-unavailable:sshd"));
    try t.expect(hasBlocker(&without, "nginx-http-auth", "continuity-unavailable:nginx-http-auth"));
    try t.expectEqual(@as(usize, 0), without.doc.assumptions.len);

    var env2 = try Env.init(null);
    defer env2.deinit();
    try env2.writeSource("jail.conf", lossless_tree);
    var captured = try captureFixtureDb(&env2);
    defer captured.deinit();
    var opts2 = env2.options();
    opts2.continuity = .lossless;
    opts2.replay_window_s = null;
    opts2.snapshot = &captured.snap;
    opts2.source_db = captured.snap.source_path;
    var with = try plan_mod.plan(t.allocator, opts2);
    defer with.deinit();
    try t.expect(!hasBlocker(&with, "sshd", "continuity-unavailable:sshd"));
    try t.expect(hasBlocker(&with, "nginx-http-auth", "continuity-unavailable:nginx-http-auth"));
    try t.expectEqual(@as(usize, 1), with.doc.blockers.len);
    const rec = with.doc.snapshot.?;
    try t.expectEqual(@as(i64, 4), rec.version);
    try t.expectEqual(fixture.seeded_ban_count, rec.bans);
    try t.expectEqualStrings(rec.recorded_sha256, with.doc.snapshot_fp.?);
}

test "migration plan: snapshot fingerprint mismatch and version problems are blockers" {
    var env = try Env.init("supported");
    defer env.deinit();
    var captured = try captureFixtureDb(&env);
    defer captured.deinit();
    var tampered = captured.snap;
    tampered.destination_sha256[0] ^= 0xff;
    var opts = env.options();
    opts.snapshot = &tampered;
    var p = try plan_mod.plan(t.allocator, opts);
    defer p.deinit();
    try t.expect(hasBlocker(&p, "*", "snapshot-fingerprint-mismatch"));
    try t.expect(!std.mem.eql(u8, p.doc.snapshot.?.recorded_sha256, p.doc.snapshot_fp.?));

    var wrong_version = captured.snap;
    wrong_version.version = 3;
    opts.snapshot = &wrong_version;
    var p2 = try plan_mod.plan(t.allocator, opts);
    defer p2.deinit();
    try t.expect(hasBlocker(&p2, "*", "snapshot-version:3"));

    var missing = captured.snap;
    missing.destination_path = @constCast("/nonexistent/snapshot.sqlite3");
    opts.snapshot = &missing;
    var p3 = try plan_mod.plan(t.allocator, opts);
    defer p3.deinit();
    try t.expect(hasBlocker(&p3, "*", "snapshot-unreadable"));
    try t.expect(p3.doc.snapshot_fp == null);
}

test "migration plan: secret boundaries name key paths and never carry values" {
    var env = try Env.init(null);
    defer env.deinit();
    try env.writeSource("jail.conf",
        \\[DEFAULT]
        \\bantime = 10m
        \\findtime = 10m
        \\maxretry = 5
        \\backend = auto
        \\banaction = nftables-allports
        \\destemail = ops@example.invalid
        \\sender = fail2ban@example.invalid
        \\[sshd]
        \\enabled = true
        \\logpath = /var/log/auth.log
        \\action = %(banaction)s
        \\         mail-report[dest="%(destemail)s", smtpuser="reporter", api_token="HUNTER2SECRET", name="sshd"]
        \\
    );
    var p = try plan_mod.plan(t.allocator, env.options());
    defer p.deinit();
    try t.expect(hasString(p.doc.secret_boundaries, "sshd/destemail"));
    try t.expect(hasString(p.doc.secret_boundaries, "sshd/sender"));
    try t.expect(hasString(p.doc.secret_boundaries, "sshd/action/mail-report/smtpuser"));
    try t.expect(hasString(p.doc.secret_boundaries, "sshd/action/mail-report/api_token"));
    try t.expect(!hasString(p.doc.secret_boundaries, "sshd/action/mail-report/name"));
    try t.expect(hasBlocker(&p, "sshd", "unknown-action:mail-report"));
    const json = try render(&p);
    defer t.allocator.free(json);
    try t.expect(std.mem.indexOf(u8, json, "HUNTER2SECRET") == null);
    try t.expect(std.mem.indexOf(u8, json, "ops@example.invalid") == null);
}

test "migration plan: validation is stale exactly one microsecond past valid_until" {
    var env = try Env.init("supported");
    defer env.deinit();
    var p = try plan_mod.plan(t.allocator, env.options());
    defer p.deinit();
    var ok = try plan_mod.validate(t.allocator, &p, .{ .now_us = p.doc.valid_until_us, .runtime_socket = "/nonexistent/fail2ban.sock" });
    defer ok.deinit();
    try t.expectEqual(plan_mod.Outcome.valid, ok.outcome);
    try t.expectEqual(@as(usize, 0), ok.reasons.len);
    var stale = try plan_mod.validate(t.allocator, &p, .{ .now_us = p.doc.valid_until_us + 1, .runtime_socket = "/nonexistent/fail2ban.sock" });
    defer stale.deinit();
    try t.expectEqual(plan_mod.Outcome.stale, stale.outcome);
    try t.expect(hasString(stale.reasons, "stale:valid_until_exceeded"));
}

test "migration plan: blockers make an otherwise fresh plan blocked" {
    var env = try Env.init("blocker");
    defer env.deinit();
    var p = try plan_mod.plan(t.allocator, env.options());
    defer p.deinit();
    var v = try plan_mod.validate(t.allocator, &p, .{ .now_us = now });
    defer v.deinit();
    try t.expectEqual(plan_mod.Outcome.blocked, v.outcome);
    try t.expect(hasString(v.reasons, "blocked:myapp:custom-filter:myapp"));
}

test "migration plan: file edit, addition and removal are drift" {
    var env = try Env.init("supported");
    defer env.deinit();
    var p = try plan_mod.plan(t.allocator, env.options());
    defer p.deinit();

    try env.writeSource("jail.local", "[sshd]\nmaxretry = 2\n");
    var edited = try plan_mod.validate(t.allocator, &p, .{ .now_us = now });
    defer edited.deinit();
    try t.expectEqual(plan_mod.Outcome.drifted, edited.outcome);
    try t.expect(hasString(edited.reasons, "file-changed:jail.local"));

    try env.writeSource("jail.local", "[sshd]\nmaxretry = 3\n");
    try env.writeSource("jail.d/20-extra.conf", "[postfix]\nenabled = false\n");
    var added = try plan_mod.validate(t.allocator, &p, .{ .now_us = now });
    defer added.deinit();
    try t.expectEqual(plan_mod.Outcome.drifted, added.outcome);
    try t.expect(hasString(added.reasons, "file-added:jail.d/20-extra.conf"));

    var dir = try std.fs.cwd().openDir(env.source, .{});
    defer dir.close();
    try dir.deleteFile("jail.d/20-extra.conf");
    try dir.deleteFile("jail.d/10-sshd.conf");
    var removed = try plan_mod.validate(t.allocator, &p, .{ .now_us = now });
    defer removed.deinit();
    try t.expectEqual(plan_mod.Outcome.drifted, removed.outcome);
    try t.expect(hasString(removed.reasons, "file-removed:jail.d/10-sshd.conf"));
}

test "migration plan: snapshot change and a runtime socket appearing are drift" {
    var env = try Env.init("supported");
    defer env.deinit();
    var captured = try captureFixtureDb(&env);
    defer captured.deinit();
    const sock = try env.path("fail2ban.sock");
    defer t.allocator.free(sock);
    var opts = env.options();
    opts.snapshot = &captured.snap;
    opts.runtime_socket = sock;
    var p = try plan_mod.plan(t.allocator, opts);
    defer p.deinit();
    try t.expectEqualStrings("absent", p.doc.drift.runtime_state);

    var clean = try plan_mod.validate(t.allocator, &p, .{ .now_us = now });
    defer clean.deinit();
    try t.expectEqual(plan_mod.Outcome.valid, clean.outcome);

    const fd = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(fd);
    var addr = try std.net.Address.initUnix(sock);
    try std.posix.bind(fd, &addr.any, addr.getOsSockLen());
    var with_socket = try plan_mod.validate(t.allocator, &p, .{ .now_us = now });
    defer with_socket.deinit();
    try t.expectEqual(plan_mod.Outcome.drifted, with_socket.outcome);
    try t.expect(hasString(with_socket.reasons, "runtime-state-changed:absent->unknown"));
    try std.fs.cwd().deleteFile(sock);

    var file = try std.fs.cwd().openFile(captured.snap.destination_path, .{ .mode = .read_write });
    defer file.close();
    try file.seekFromEnd(0);
    try file.writeAll("x");
    var changed = try plan_mod.validate(t.allocator, &p, .{ .now_us = now });
    defer changed.deinit();
    try t.expectEqual(plan_mod.Outcome.drifted, changed.outcome);
    try t.expect(hasString(changed.reasons, "snapshot-changed"));
}

test "migration plan: plan file round trip is byte-identical, 0600, and tampering is rejected" {
    var env = try Env.init("supported");
    defer env.deinit();
    var p = try plan_mod.plan(t.allocator, env.options());
    defer p.deinit();
    const path = try env.path("plan.json");
    defer t.allocator.free(path);
    try plan_mod.writePlanFile(&p, path);
    const stat = try std.fs.cwd().statFile(path);
    try t.expectEqual(@as(u32, 0o600), @as(u32, @intCast(stat.mode & 0o777)));

    var read = try plan_mod.readPlanFile(t.allocator, path);
    defer read.deinit();
    const original = try render(&p);
    defer t.allocator.free(original);
    const reread = try render(&read);
    defer t.allocator.free(reread);
    try t.expectEqualStrings(original, reread);
    var expected_fp: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(original, &expected_fp, .{});
    try t.expectEqualSlices(u8, &expected_fp, &read.plan_fp.?);
    var v = try plan_mod.validate(t.allocator, &read, .{ .now_us = now, .runtime_socket = "/nonexistent/fail2ban.sock" });
    defer v.deinit();
    try t.expectEqual(plan_mod.Outcome.valid, v.outcome);

    const tampered = try std.mem.replaceOwned(u8, t.allocator, original, "\"selection\":[\"nginx-http-auth\",\"sshd\"]", "\"selection\":[\"sshd\"]");
    defer t.allocator.free(tampered);
    try t.expect(!std.mem.eql(u8, tampered, original));
    try env.tmp.dir.writeFile(.{ .sub_path = "tampered.json", .data = tampered });
    const tampered_path = try env.path("tampered.json");
    defer t.allocator.free(tampered_path);
    try t.expectError(error.PlanTampered, plan_mod.readPlanFile(t.allocator, tampered_path));

    try env.tmp.dir.writeFile(.{ .sub_path = "invalid.json", .data = "{\"schema_version\":1}" });
    const invalid_path = try env.path("invalid.json");
    defer t.allocator.free(invalid_path);
    try t.expectError(error.PlanInvalid, plan_mod.readPlanFile(t.allocator, invalid_path));
    try t.expectError(error.PlanUnreadable, plan_mod.readPlanFile(t.allocator, "/nonexistent/plan.json"));
}

test "migration plan: oversized plan file is a typed error" {
    var env = try Env.init(null);
    defer env.deinit();
    const big = try t.allocator.alloc(u8, plan_mod.max_plan_bytes + 1);
    defer t.allocator.free(big);
    @memset(big, ' ');
    try env.tmp.dir.writeFile(.{ .sub_path = "big.json", .data = big });
    const path = try env.path("big.json");
    defer t.allocator.free(path);
    try t.expectError(error.PlanTooLarge, plan_mod.readPlanFile(t.allocator, path));
}

test "migration plan: planning and validation never modify the source tree or snapshot" {
    var env = try Env.init("blocker");
    defer env.deinit();
    var captured = try captureFixtureDb(&env);
    defer captured.deinit();
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const before = try snapshotTree(arena.allocator(), env.root);
    var opts = env.options();
    opts.snapshot = &captured.snap;
    opts.continuity = .lossless;
    var p = try plan_mod.plan(t.allocator, opts);
    defer p.deinit();
    var v = try plan_mod.validate(t.allocator, &p, .{ .now_us = now });
    defer v.deinit();
    const after = try snapshotTree(arena.allocator(), env.root);
    try t.expectEqual(before.len, after.len);
    for (before, after) |x, y| {
        try t.expectEqualStrings(x.path, y.path);
        try t.expectEqual(x.mtime, y.mtime);
        try t.expectEqualSlices(u8, &x.sha256, &y.sha256);
    }
}

const Entry = struct { path: []const u8, mtime: i128, sha256: [32]u8 };

fn snapshotTree(a: std.mem.Allocator, dir_path: []const u8) ![]Entry {
    var list = std.ArrayList(Entry).init(a);
    var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();
    var walker = try dir.walk(a);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const stat = try entry.dir.statFile(entry.basename);
        const bytes = try entry.dir.readFileAlloc(a, entry.basename, 1 << 24);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        try list.append(.{ .path = try a.dupe(u8, entry.path), .mtime = stat.mtime, .sha256 = digest });
    }
    const slice = try list.toOwnedSlice();
    std.mem.sort(Entry, slice, {}, struct {
        fn lt(_: void, x: Entry, y: Entry) bool {
            return std.mem.order(u8, x.path, y.path) == .lt;
        }
    }.lt);
    return slice;
}
