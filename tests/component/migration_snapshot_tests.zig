// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const snapshot = @import("engine_test").migration.sqlite_snapshot;
const db = @import("engine_test").migration.fail2ban_db;
const fixture = @import("engine_test").migration.fail2ban_fixture;

comptime {
    _ = @import("shared");
}

const t = std.testing;

test "migration snapshot: transient text binding copies caller bytes before stepping" {
    var conn = try db.Connection.open(":memory:", db.open_flags.readwrite | db.open_flags.create);
    defer conn.close();
    var stmt = try conn.prepare("SELECT ?1, ?2");
    defer stmt.finalize();

    var text = [_]u8{ 's', 's', 'h', 'd', 0, 'x' };
    try stmt.bindText(1, &text);
    try stmt.bindText(2, "");
    @memset(&text, '!');

    try t.expect(try stmt.step());
    try t.expectEqualStrings("sshd\x00x", stmt.columnBytes(0).?);
    try t.expectEqualStrings("", stmt.columnBytes(1).?);
    try t.expect(!try stmt.step());
}

const Env = struct {
    tmp: t.TmpDir,
    root: []u8,
    source: []u8,
    staging: []u8,

    fn init(a: std.mem.Allocator) !Env {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(a, ".");
        errdefer a.free(root);
        const source = try std.fs.path.join(a, &.{ root, "fail2ban.sqlite3" });
        errdefer a.free(source);
        const staging = try std.fs.path.join(a, &.{ root, "staging" });
        errdefer a.free(staging);
        try std.posix.mkdir(staging, 0o700);
        return .{ .tmp = tmp, .root = root, .source = source, .staging = staging };
    }

    fn deinit(self: *Env, a: std.mem.Allocator) void {
        a.free(self.staging);
        a.free(self.source);
        a.free(self.root);
        self.tmp.cleanup();
    }

    fn stagingEntries(self: Env) !usize {
        var dir = try std.fs.cwd().openDir(self.staging, .{ .iterate = true });
        defer dir.close();
        var it = dir.iterate();
        var count: usize = 0;
        while (try it.next()) |_| count += 1;
        return count;
    }
};

const SourceFingerprint = struct {
    main_sha: [32]u8,
    main_mtime_ns: i128,
    wal_sha: ?[32]u8,

    fn take(a: std.mem.Allocator, source: []const u8) !SourceFingerprint {
        const stat = try std.fs.cwd().statFile(source);
        const wal = try std.fmt.allocPrint(a, "{s}-wal", .{source});
        defer a.free(wal);
        const wal_sha: ?[32]u8 = snapshot.sha256File(wal) catch null;
        return .{ .main_sha = try snapshot.sha256File(source), .main_mtime_ns = stat.mtime, .wal_sha = wal_sha };
    }

    fn expectUnchanged(self: SourceFingerprint, a: std.mem.Allocator, source: []const u8) !void {
        const now = try take(a, source);
        try t.expectEqualSlices(u8, &self.main_sha, &now.main_sha);
        try t.expectEqual(self.main_mtime_ns, now.main_mtime_ns);
        if (self.wal_sha) |before| {
            try t.expectEqualSlices(u8, &before, &now.wal_sha.?);
        } else if (now.wal_sha != null) {
            const wal = try std.fmt.allocPrint(a, "{s}-wal", .{source});
            defer a.free(wal);
            try t.expectEqual(@as(u64, 0), (try std.fs.cwd().statFile(wal)).size);
        }
    }
};

fn expectSeededSnapshot(a: std.mem.Allocator, env: Env, snap: snapshot.Snapshot) !void {
    try t.expectEqual(db.expected_version, snap.version);
    try t.expectEqual(fixture.seeded_jail_count, snap.row_counts.jails);
    try t.expectEqual(fixture.seeded_log_count, snap.row_counts.logs);
    try t.expectEqual(fixture.seeded_ban_count, snap.row_counts.bans);
    try t.expectEqual(fixture.seeded_ban_count, snap.row_counts.bips);
    try t.expectEqualStrings(env.source, snap.source_path);
    const stat = try std.posix.fstatat(std.posix.AT.FDCWD, env.source, std.posix.AT.SYMLINK_NOFOLLOW);
    try t.expectEqual(@as(u64, @intCast(stat.ino)), snap.source_ino);
    try t.expectEqual(@as(u64, @intCast(stat.size)), snap.source_size);
    try t.expect(std.mem.startsWith(u8, snap.destination_path, env.staging));
    const dest_stat = try std.fs.cwd().statFile(snap.destination_path);
    try t.expectEqual(@as(u32, 0o600), @as(u32, @intCast(dest_stat.mode & 0o777)));
    try t.expectEqualSlices(u8, &snap.destination_sha256, &(try snapshot.sha256File(snap.destination_path)));
    try t.expect(snap.backup_steps >= 1);
    try t.expect(snap.pages_copied >= 1);

    var reader = try db.Reader.open(a, snap.destination_path);
    defer reader.close();
    var jails = try reader.jails();
    defer jails.deinit();
    var jail_a = (try jails.next()).?;
    defer jail_a.deinit(a);
    try t.expectEqualStrings("sshd", jail_a.name);
    try t.expectEqual(db.Optional(i64){ .present = 1 }, jail_a.enabled);
    var jail_b = (try jails.next()).?;
    defer jail_b.deinit(a);
    try t.expectEqualStrings("nginx-http-auth", jail_b.name);
    try t.expectEqual(db.Optional(i64){ .present = 0 }, jail_b.enabled);
    try t.expectEqual(@as(?db.Jail, null), try jails.next());

    var logs = try reader.logs();
    defer logs.deinit();
    var log_a = (try logs.next()).?;
    defer log_a.deinit(a);
    try t.expectEqualStrings("/var/log/auth.log", log_a.path.present);
    try t.expectEqualStrings("d41d8cd98f00b204e9800998ecf8427e", log_a.firstlinemd5.present);
    try t.expectEqual(db.Optional(i64){ .present = 12345 }, log_a.lastfilepos);
    var log_b = (try logs.next()).?;
    defer log_b.deinit(a);
    try t.expect(log_b.firstlinemd5 == .absent);

    const expected = fixture.seededBans(1_700_000_000);
    inline for (.{ "bans", "bips" }) |table| {
        var rows = if (comptime std.mem.eql(u8, table, "bans")) try reader.bans() else try reader.bips();
        defer rows.deinit();
        var seen: usize = 0;
        while (try rows.next()) |row_const| {
            var row = row_const;
            defer row.deinit(a);
            var matched = false;
            for (expected) |want| {
                if (!std.mem.eql(u8, want.ip.?, row.ip.present)) continue;
                matched = true;
                try t.expectEqualStrings(want.jail, row.jail);
                try t.expectEqual(want.timeofban, row.timeofban);
                try t.expectEqual(want.bantime, row.bantime);
                try t.expectEqual(want.bancount, row.bancount);
                if (want.data) |data| try t.expectEqualStrings(data, row.data.present) else try t.expect(row.data == .absent);
            }
            try t.expect(matched);
            seen += 1;
        }
        try t.expectEqual(expected.len, seen);
    }
}

fn captureProfile(profile: fixture.JournalProfile) !void {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = profile });
    const before = try SourceFingerprint.take(a, env.source);
    var snap = try snapshot.capture(a, env.source, env.staging, .{});
    defer snap.deinit(a);
    try before.expectUnchanged(a, env.source);
    try expectSeededSnapshot(a, env, snap);
    try t.expectEqual(@as(usize, 1), try env.stagingEntries());
}

test "migration snapshot: checkpointed WAL source captures every seeded row" {
    try captureProfile(.wal);
}

test "migration snapshot: DELETE journal source captures every seeded row" {
    try captureProfile(.delete);
}

test "migration snapshot: MEMORY journal source captures every seeded row" {
    try captureProfile(.memory);
}

test "migration snapshot: uncheckpointed WAL frames are visible and the source WAL is untouched" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .wal_pending });
    const wal_path = try std.fmt.allocPrint(a, "{s}-wal", .{env.source});
    defer a.free(wal_path);
    const wal_stat = try std.fs.cwd().statFile(wal_path);
    try t.expect(wal_stat.size > 0);
    const before = try SourceFingerprint.take(a, env.source);
    try t.expect(before.wal_sha != null);

    var snap = try snapshot.capture(a, env.source, env.staging, .{});
    defer snap.deinit(a);
    try t.expectEqualStrings("wal", snap.journal_mode_observed);
    try before.expectUnchanged(a, env.source);
    try expectSeededSnapshot(a, env, snap);
    try t.expectEqual(@as(usize, 1), try env.stagingEntries());
}

const Writer = struct {
    conn: db.Connection,
    writes: u32 = 0,
    stop_after: ?u32,

    fn hook(context: *anyopaque, step: u32) void {
        const self: *Writer = @ptrCast(@alignCast(context));
        if (self.stop_after) |limit| {
            if (self.writes >= limit) return;
        }
        var ip_buffer: [32]u8 = undefined;
        const ip = std.fmt.bufPrint(&ip_buffer, "203.0.113.{d}", .{(step % 200) + 1}) catch unreachable;
        fixture.insertBan(self.conn, "bans", .{ .jail = "sshd", .ip = ip, .timeofban = 1_700_000_000, .bantime = 60, .data = null }) catch |err| {
            std.debug.print("writer failed: {s}\n", .{@errorName(err)});
            return;
        };
        self.writes += 1;
    }
};

test "migration snapshot: concurrent writer restarts the backup and the final copy is consistent" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete });
    var writer = Writer{ .conn = try fixture.openWriter(env.source), .stop_after = 3 };
    defer writer.conn.close();

    var snap = try snapshot.capture(a, env.source, env.staging, .{
        .pages_per_step = 1,
        .between_steps = .{ .context = &writer, .func = Writer.hook },
    });
    defer snap.deinit(a);
    try t.expectEqual(@as(u32, 3), writer.writes);
    try t.expect(snap.restarts >= 1);
    try t.expectEqual(fixture.seeded_ban_count + 3, snap.row_counts.bans);
    try t.expectEqualSlices(u8, &snap.destination_sha256, &(try snapshot.sha256File(snap.destination_path)));

    var source_reader = try db.Reader.open(a, env.source);
    defer source_reader.close();
    var reader = try db.Reader.open(a, snap.destination_path);
    defer reader.close();
    var expected = try source_reader.bans();
    defer expected.deinit();
    var actual = try reader.bans();
    defer actual.deinit();
    while (try expected.next()) |want_const| {
        var want = want_const;
        defer want.deinit(a);
        var got = (try actual.next()).?;
        defer got.deinit(a);
        try t.expectEqualStrings(want.ip.present, got.ip.present);
        try t.expectEqual(want.timeofban, got.timeofban);
    }
    try t.expectEqual(@as(?db.Ban, null), try actual.next());
}

const SourceSwap = struct {
    source: []const u8,
    original: []const u8,
    replacement: []const u8,

    fn hook(context: *anyopaque, stage: snapshot.IdentityHookStage) void {
        const self: *SourceSwap = @ptrCast(@alignCast(context));
        switch (stage) {
            .before_open => {
                std.fs.cwd().rename(self.source, self.original) catch unreachable;
                std.fs.cwd().rename(self.replacement, self.source) catch unreachable;
            },
            .after_open => {
                std.fs.cwd().rename(self.source, self.replacement) catch unreachable;
                std.fs.cwd().rename(self.original, self.source) catch unreachable;
            },
        }
    }
};

test "migration snapshot: swap-back around source open is refused" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete });
    const original = try std.fs.path.join(a, &.{ env.root, "original.sqlite3" });
    defer a.free(original);
    const replacement = try std.fs.path.join(a, &.{ env.root, "replacement.sqlite3" });
    defer a.free(replacement);
    try fixture.build(replacement, .{ .profile = .delete, .now = 1_800_000_000 });
    const original_sha = try snapshot.sha256File(env.source);
    const replacement_sha = try snapshot.sha256File(replacement);
    try t.expect(!std.mem.eql(u8, &original_sha, &replacement_sha));

    var swap = SourceSwap{ .source = env.source, .original = original, .replacement = replacement };
    try t.expectError(error.NotRegularFile, snapshot.capture(a, env.source, env.staging, .{
        .identity_hook = .{ .context = &swap, .func = SourceSwap.hook },
    }));
    try t.expectEqualSlices(u8, &original_sha, &(try snapshot.sha256File(env.source)));
    try t.expectEqualSlices(u8, &replacement_sha, &(try snapshot.sha256File(replacement)));
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
}

test "migration snapshot: unbounded concurrent writer aborts after the restart budget with no destination" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete });
    var writer = Writer{ .conn = try fixture.openWriter(env.source), .stop_after = null };
    defer writer.conn.close();
    try t.expectError(error.ConcurrentWriter, snapshot.capture(a, env.source, env.staging, .{
        .pages_per_step = 1,
        .between_steps = .{ .context = &writer, .func = Writer.hook },
    }));
    try t.expect(writer.writes > snapshot.Limits.max_restarts);
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
}

test "migration snapshot: unsupported schema versions 3 and 5 are refused without touching the source" {
    const a = t.allocator;
    for ([_]i64{ 3, 5 }) |version| {
        var env = try Env.init(a);
        defer env.deinit(a);
        try fixture.build(env.source, .{ .profile = .wal, .version = version });
        const before = try SourceFingerprint.take(a, env.source);
        try t.expectError(error.UnsupportedVersion, snapshot.capture(a, env.source, env.staging, .{}));
        try before.expectUnchanged(a, env.source);
        try t.expectEqual(@as(usize, 0), try env.stagingEntries());
    }
}

test "migration snapshot: a version table with zero or two rows is unsupported" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete });
    var writer = try fixture.openWriter(env.source);
    defer writer.close();
    try writer.exec("INSERT INTO fail2banDb(version) VALUES(4)");
    try t.expectError(error.UnsupportedVersion, snapshot.capture(a, env.source, env.staging, .{}));
    try writer.exec("DELETE FROM fail2banDb");
    try t.expectError(error.UnsupportedVersion, snapshot.capture(a, env.source, env.staging, .{}));
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
}

test "migration snapshot: a missing required table is an unsupported schema" {
    const a = t.allocator;
    for ([_][]const u8{ "fail2banDb", "jails", "logs", "bans", "bips" }) |table| {
        var env = try Env.init(a);
        defer env.deinit(a);
        try fixture.build(env.source, .{ .profile = .delete, .omit_table = table });
        const before = try SourceFingerprint.take(a, env.source);
        const result = snapshot.capture(a, env.source, env.staging, .{});
        try t.expectError(error.UnsupportedSchema, result);
        try before.expectUnchanged(a, env.source);
        try t.expectEqual(@as(usize, 0), try env.stagingEntries());
    }
}

test "migration snapshot: an extra column or a view under a required name is unsupported" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete });
    var writer = try fixture.openWriter(env.source);
    defer writer.close();
    try writer.exec("ALTER TABLE bans ADD COLUMN extra TEXT");
    try t.expectError(error.UnsupportedSchema, snapshot.capture(a, env.source, env.staging, .{}));
    try writer.exec("DROP TABLE bips; CREATE VIEW bips AS SELECT * FROM bans");
    try t.expectError(error.UnsupportedSchema, snapshot.capture(a, env.source, env.staging, .{}));
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
}

test "migration snapshot: corrupted page content fails integrity and is refused" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete });
    {
        const file = try std.fs.cwd().openFile(env.source, .{ .mode = .read_write });
        defer file.close();
        var garbage: [4096]u8 = undefined;
        @memset(&garbage, 0xA5);
        try file.pwriteAll(&garbage, 4096);
    }
    const before = try SourceFingerprint.take(a, env.source);
    const result = snapshot.capture(a, env.source, env.staging, .{});
    if (result) |_| return error.TestUnexpectedResult else |err| switch (err) {
        error.IntegrityCheckFailed, error.CorruptDatabase => {},
        else => return err,
    }
    try before.expectUnchanged(a, env.source);
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
}

test "migration snapshot: truncated file and non-database bytes are refused" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete });
    {
        const file = try std.fs.cwd().openFile(env.source, .{ .mode = .read_write });
        defer file.close();
        try file.setEndPos(4096 + 100);
    }
    const truncated = snapshot.capture(a, env.source, env.staging, .{});
    if (truncated) |_| return error.TestUnexpectedResult else |err| switch (err) {
        error.IntegrityCheckFailed, error.CorruptDatabase => {},
        else => return err,
    }
    try std.fs.cwd().writeFile(.{ .sub_path = env.source, .data = "this is not a database\n" });
    try t.expectError(error.CorruptDatabase, snapshot.capture(a, env.source, env.staging, .{}));
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
}

test "migration snapshot: missing file, unreadable file and symlink are refused" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try t.expectError(error.OpenFailed, snapshot.capture(a, env.source, env.staging, .{}));

    try fixture.build(env.source, .{ .profile = .delete });
    const link = try std.fs.path.join(a, &.{ env.root, "link.sqlite3" });
    defer a.free(link);
    try std.fs.cwd().symLink(env.source, link, .{});
    const before = try SourceFingerprint.take(a, env.source);
    try t.expectError(error.NotRegularFile, snapshot.capture(a, link, env.staging, .{}));
    try t.expectError(error.NotRegularFile, snapshot.capture(a, env.root, env.staging, .{}));

    if (std.os.linux.geteuid() == 0) return error.SkipZigTest;
    try std.posix.fchmodat(std.posix.AT.FDCWD, env.source, 0o000, 0);
    defer std.posix.fchmodat(std.posix.AT.FDCWD, env.source, 0o600, 0) catch {};
    try t.expectError(error.AccessDenied, snapshot.capture(a, env.source, env.staging, .{}));
    try std.posix.fchmodat(std.posix.AT.FDCWD, env.source, 0o600, 0);
    try before.expectUnchanged(a, env.source);
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
}

test "migration snapshot: interruption after N backup steps removes the destination and leaves the source unchanged" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .wal_pending });
    const before = try SourceFingerprint.take(a, env.source);
    try t.expectError(error.InjectedFailure, snapshot.capture(a, env.source, env.staging, .{ .pages_per_step = 1, .fail_after_steps = 2 }));
    try before.expectUnchanged(a, env.source);
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
    var snap = try snapshot.capture(a, env.source, env.staging, .{ .pages_per_step = 1 });
    defer snap.deinit(a);
    try before.expectUnchanged(a, env.source);
    try expectSeededSnapshot(a, env, snap);
}

test "migration snapshot: a source larger than 1 GiB is refused before any open" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    {
        const file = try std.fs.cwd().createFile(env.source, .{});
        defer file.close();
        try file.setEndPos(snapshot.Limits.max_source_bytes + 1);
    }
    try t.expectError(error.SourceTooLarge, snapshot.capture(a, env.source, env.staging, .{}));
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
}

test "migration snapshot: row ceilings for logs and bans+bips remove the destination" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete });
    var writer = try fixture.openWriter(env.source);
    defer writer.close();
    try writer.exec("BEGIN");
    {
        var stmt = try writer.prepare("INSERT INTO logs(jail, path) VALUES('sshd', ?1)");
        defer stmt.finalize();
        var i: u64 = 0;
        while (i < snapshot.Limits.max_log_rows - fixture.seeded_log_count + 1) : (i += 1) {
            var buffer: [64]u8 = undefined;
            try stmt.bindText(1, try std.fmt.bufPrint(&buffer, "/var/log/extra/{d}.log", .{i}));
            _ = try stmt.step();
            _ = db.api.reset(stmt.stmt);
        }
    }
    try writer.exec("COMMIT");
    try t.expectError(error.RowLimitExceeded, snapshot.capture(a, env.source, env.staging, .{}));
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
    try writer.exec("DELETE FROM logs WHERE path LIKE '/var/log/extra/%'");

    try writer.exec("BEGIN");
    {
        var stmt = try writer.prepare("INSERT INTO bans(jail, ip, timeofban, bantime) VALUES('sshd', ?1, 1, 1)");
        defer stmt.finalize();
        var i: u64 = 0;
        while (i < snapshot.Limits.max_ban_rows - 2 * fixture.seeded_ban_count + 1) : (i += 1) {
            var buffer: [64]u8 = undefined;
            try stmt.bindText(1, try std.fmt.bufPrint(&buffer, "192.0.2.{d}", .{i}));
            _ = try stmt.step();
            _ = db.api.reset(stmt.stmt);
        }
    }
    try writer.exec("COMMIT");
    try t.expectError(error.RowLimitExceeded, snapshot.capture(a, env.source, env.staging, .{}));
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
}

test "migration snapshot: reader reports NULL fields explicitly and rejects wrong types and oversized values" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete, .seed_rows = false });
    {
        var writer = try fixture.openWriter(env.source);
        defer writer.close();
        try writer.exec("INSERT INTO jails(name, enabled) VALUES('sshd', 1)");
        try writer.exec("INSERT INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES('sshd', NULL, NULL, NULL)");
        try writer.exec("INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES('sshd', NULL, 1, 2, 3, NULL)");
        try writer.exec("INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES('sshd', '192.0.2.1', 1, 2, 3, 42)");
        try writer.exec("INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES('sshd', '" ++ ("a" ** 65) ++ "', 1, 2, 3, NULL)");
        try writer.exec("INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES('sshd', '192.0.2.2', 'soon', 2, 3, NULL)");
        var stmt = try writer.prepare("INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES('sshd', '192.0.2.3', 1, 2, 3, ?1)");
        defer stmt.finalize();
        const big = try a.alloc(u8, db.max_data_bytes + 1);
        defer a.free(big);
        @memset(big, 'x');
        try stmt.bindText(1, big);
        _ = try stmt.step();
    }
    var snap = try snapshot.capture(a, env.source, env.staging, .{});
    defer snap.deinit(a);
    try t.expectEqual(@as(u64, 5), snap.row_counts.bans);

    var reader = try db.Reader.open(a, snap.destination_path);
    defer reader.close();
    var logs = try reader.logs();
    defer logs.deinit();
    var log = (try logs.next()).?;
    defer log.deinit(a);
    try t.expect(log.path == .absent);
    try t.expect(log.firstlinemd5 == .absent);
    try t.expect(log.lastfilepos == .absent);

    var bans = try reader.bans();
    defer bans.deinit();
    var first = (try bans.next()).?;
    defer first.deinit(a);
    try t.expect(first.ip == .absent);
    try t.expect(first.data == .absent);
    try t.expectEqual(@as(i64, 2), first.bantime);
    try t.expectError(error.InvalidRow, bans.next());
    try t.expectError(error.InvalidRow, bans.next());
    try t.expectError(error.InvalidRow, bans.next());
    try t.expectError(error.InvalidRow, bans.next());
    try t.expectEqual(@as(?db.Ban, null), try bans.next());
}

test "migration snapshot: reader refuses a database that is not schema 4" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete, .version = 5 });
    try t.expectError(error.UnsupportedVersion, db.Reader.open(a, env.source));
    try std.fs.cwd().deleteFile(env.source);
    try fixture.build(env.source, .{ .profile = .delete, .omit_table = "logs" });
    try t.expectError(error.UnsupportedSchema, db.Reader.open(a, env.source));
}

test "migration snapshot: staging directory must be a private 0700 directory owned by the caller" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete });
    try snapshot.verifyStagingDir(env.staging);

    const link = try std.fs.path.join(a, &.{ env.root, "staging-link" });
    defer a.free(link);
    try std.fs.cwd().symLink(env.staging, link, .{ .is_directory = true });
    try t.expectError(error.SymlinkRefused, snapshot.verifyStagingDir(link));
    try t.expectError(error.StagingUnsafe, snapshot.capture(a, env.source, link, .{}));

    try t.expectError(error.NotDirectory, snapshot.verifyStagingDir(env.source));
    try t.expectError(error.StagingUnsafe, snapshot.capture(a, env.source, env.source, .{}));

    const missing = try std.fs.path.join(a, &.{ env.root, "absent" });
    defer a.free(missing);
    try t.expectError(error.NotFound, snapshot.verifyStagingDir(missing));

    for ([_]std.posix.mode_t{ 0o750, 0o705, 0o770, 0o777 }) |mode| {
        try std.posix.fchmodat(std.posix.AT.FDCWD, env.staging, mode, 0);
        try t.expectError(error.PermissiveMode, snapshot.verifyStagingDir(env.staging));
        try t.expectError(error.StagingUnsafe, snapshot.capture(a, env.source, env.staging, .{}));
    }
    try std.posix.fchmodat(std.posix.AT.FDCWD, env.staging, 0o700, 0);
    try t.expectEqual(@as(usize, 0), try env.stagingEntries());
    var snap = try snapshot.capture(a, env.source, env.staging, .{});
    defer snap.deinit(a);
}

test "migration snapshot: a staging directory owned by another uid is refused" {
    if (std.os.linux.geteuid() != 0) return error.SkipZigTest;
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    const foreign = try std.fs.path.join(a, &.{ env.root, "foreign" });
    defer a.free(foreign);
    try std.posix.mkdir(foreign, 0o700);
    var foreign_dir = try std.fs.cwd().openDir(foreign, .{});
    defer foreign_dir.close();
    try std.posix.fchown(foreign_dir.fd, 65534, 65534);
    try t.expectError(error.ForeignOwner, snapshot.verifyStagingDir(foreign));
}

test "migration snapshot: staging refuses when the directory is missing" {
    const a = t.allocator;
    var env = try Env.init(a);
    defer env.deinit(a);
    try fixture.build(env.source, .{ .profile = .delete });
    const missing = try std.fs.path.join(a, &.{ env.root, "absent" });
    defer a.free(missing);
    try t.expectError(error.StagingUnavailable, snapshot.capture(a, env.source, missing, .{}));
}
