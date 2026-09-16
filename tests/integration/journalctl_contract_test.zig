// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const command = @import("engine").firewall.iptables.command;
const t = std.testing;

const Fixture = struct {
    tmp: t.TmpDir,
    root: []const u8,
    executable: []const u8,

    fn init(a: std.mem.Allocator) !Fixture {
        const selected = std.process.getEnvVarOwned(a, "FAIL2ZIG_TEST_JOURNALCTL") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        const executable = selected orelse "/usr/bin/journalctl";
        if (!std.fs.path.isAbsolute(executable)) return error.InvalidTestExecutable;
        std.fs.cwd().access(executable, .{}) catch |err| {
            if (selected != null) return err;
            return error.SkipZigTest;
        };
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const archive_path = std.process.getEnvVarOwned(a, "FAIL2ZIG_TEST_JOURNAL_FIXTURES") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => "tests/fixtures/native-journal/fixtures.tar.gz",
            else => return err,
        };
        const archive = try std.fs.cwd().openFile(archive_path, .{});
        defer archive.close();
        var gzip = std.compress.gzip.decompressor(archive.reader());
        try std.tar.pipeToFileSystem(tmp.dir, gzip.reader(), .{});
        return .{ .tmp = tmp, .root = try tmp.dir.realpathAlloc(a, "fixtures"), .executable = executable };
    }

    fn query(self: *Fixture, a: std.mem.Allocator, codec: []const u8, extra: []const []const u8) ![]std.json.Value {
        var argv = std.ArrayList([]const u8).init(a);
        try argv.appendSlice(&.{ self.executable, "-o", "json", "--no-pager", "-q" });
        try argv.append(try std.fmt.allocPrint(a, "--file={s}/{s}.journal", .{ self.root, codec }));
        try argv.appendSlice(extra);
        const result = try command.run(a, argv.items, 5000);
        if (result.code != 0) std.debug.print("fixture journalctl exited {d}: {s}\n", .{ result.code, result.stderr });
        try t.expectEqual(@as(u8, 0), result.code);
        var rows = std.ArrayList(std.json.Value).init(a);
        var lines = std.mem.tokenizeScalar(u8, result.stdout, '\n');
        while (lines.next()) |line| try rows.append(try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{}));
        return rows.toOwnedSlice();
    }
};

fn field(row: std.json.Value, name: []const u8) ![]const u8 {
    if (row != .object) return error.BadFixtureOutput;
    const value = row.object.get(name) orelse return error.MissingField;
    if (value != .string) return error.InvalidFieldType;
    return value.string;
}

test "journalctl contract: all four codecs preserve complete messages and microseconds" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init(a);
    defer f.tmp.cleanup();
    for ([_][]const u8{ "none", "XZ", "LZ4", "ZSTD" }) |codec| {
        const rows = try f.query(a, codec, &.{"--all"});
        try t.expectEqual(@as(usize, 3), rows.len);
        for (rows, 1..) |row, sequence| {
            const prefix = try std.fmt.allocPrint(a, "fixture-{d}-", .{sequence});
            const message = try field(row, "MESSAGE");
            try t.expect(std.mem.startsWith(u8, message, prefix));
            try t.expectEqual(prefix.len + 4096, message.len);
            try t.expectEqual(@as(usize, 4096), std.mem.count(u8, message[prefix.len..], "X"));
            try t.expectEqual(1750000000000000 + sequence, try std.fmt.parseInt(u64, try field(row, "__REALTIME_TIMESTAMP"), 10));
            try t.expect((try field(row, "__CURSOR")).len > 0);
        }
    }
}

test "journalctl contract: exact cursor reopen includes anchor while after-cursor excludes it" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init(a);
    defer f.tmp.cleanup();
    const rows = try f.query(a, "none", &.{"--all"});
    const cursor = try field(rows[1], "__CURSOR");
    const inclusive = try f.query(a, "none", &.{ "--all", try std.fmt.allocPrint(a, "--cursor={s}", .{cursor}) });
    try t.expectEqual(@as(usize, 2), inclusive.len);
    try t.expectEqualStrings(cursor, try field(inclusive[0], "__CURSOR"));
    const after = try f.query(a, "none", &.{ "--all", try std.fmt.allocPrint(a, "--after-cursor={s}", .{cursor}) });
    try t.expectEqual(@as(usize, 1), after.len);
    try t.expectEqualStrings("3", try field(after[0], "F2Z_SEQUENCE"));
    const tail = try f.query(a, "none", &.{ "--all", try std.fmt.allocPrint(a, "--after-cursor={s}", .{try field(rows[2], "__CURSOR")}) });
    try t.expectEqual(@as(usize, 0), tail.len);
}

test "journalctl contract: successful seek does not prove the saved anchor is in the selected view" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init(a);
    defer f.tmp.cleanup();
    const all = try f.query(a, "none", &.{"--all"});
    const cursor = try field(all[0], "__CURSOR");
    const selected = try f.query(a, "none", &.{ "--all", "F2Z_KIND=allow", try std.fmt.allocPrint(a, "--cursor={s}", .{cursor}) });
    try t.expectEqual(@as(usize, 1), selected.len);
    try t.expectEqualStrings("2", try field(selected[0], "F2Z_SEQUENCE"));
    try t.expect(!std.mem.eql(u8, cursor, try field(selected[0], "__CURSOR")));
}

test "journalctl contract: selector grouping preserves alternatives and conjunctions" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init(a);
    defer f.tmp.cleanup();
    try t.expectEqual(@as(usize, 2), (try f.query(a, "ZSTD", &.{ "--all", "F2Z_KIND=deny" })).len);
    try t.expectEqual(@as(usize, 3), (try f.query(a, "ZSTD", &.{ "--all", "F2Z_KIND=deny", "F2Z_KIND=allow" })).len);
    try t.expectEqual(@as(usize, 1), (try f.query(a, "ZSTD", &.{ "--all", "F2Z_KIND=deny", "F2Z_SEQUENCE=3" })).len);
    try t.expectEqual(@as(usize, 3), (try f.query(a, "ZSTD", &.{ "--all", "F2Z_KIND=deny", "+", "F2Z_SEQUENCE=2" })).len);
}

test "journalctl contract: default JSON elides large fields and all restores them" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init(a);
    defer f.tmp.cleanup();
    const rows = try f.query(a, "none", &.{});
    try t.expectEqual(@as(usize, 3), rows.len);
    try t.expect(rows[0].object.get("MESSAGE").? == .null);
    const full = try f.query(a, "none", &.{"--all"});
    try t.expect((try field(full[0], "MESSAGE")).len > 4096);
}
