// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const shared = @import("shared");
const engine = @import("engine_test");
const source = engine.core.journald_source;
const config_mod = engine.config.native;
const EventLoop = engine.core.event_loop.EventLoop;
const JailId = shared.JailId;
const JournalJail = source.JournalJail;
const JournaldSource = source.JournaldSource;
const ResolvedSource = source.ResolvedSource;
const sshd_selectors = source.sshd_selectors;
const max_line_len = source.max_line_len;
const max_cursor_len = source.max_cursor_len;
const max_jails = source.max_jails;
const max_entries_per_tick = source.max_entries_per_tick;
const CursorEntry = source.CursorEntry;
const resolveSource = source.resolveSource;
const selectorsForFilter = source.selectorsForFilter;
const buildPollArgv = source.buildPollArgv;
const buildBaselineArgv = source.buildBaselineArgv;
const decodeEntry = source.decodeEntry;
const extractCursor = source.extractCursor;
const cursorPath = source.cursorPath;
const saveCursors = source.saveCursors;
const loadCursors = source.loadCursors;

const testing = std.testing;

test "journald: resolveSource explicit .file always picks file" {
    try testing.expectEqual(ResolvedSource.file, resolveSource(.file, false, true, true));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.file, false, false, false));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.file, true, false, true));
}

test "journald: resolveSource explicit .journald needs journalctl, else fails closed" {
    try testing.expectEqual(ResolvedSource.journald, resolveSource(.journald, false, true, true));
    try testing.expectEqual(ResolvedSource.fail, resolveSource(.journald, false, false, true));
    try testing.expectEqual(ResolvedSource.journald, resolveSource(.journald, false, true, false));
}

test "journald: resolveSource auto with an EXISTING logpath picks file (SYS-015)" {
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, true, true, true));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, true, false, true));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, true, true, false));
}

test "journald: resolveSource auto with ABSENT log + sshd + journalctl picks journald (SYS-015)" {
    try testing.expectEqual(ResolvedSource.journald, resolveSource(.auto, false, true, true));
}

test "journald: resolveSource auto with ABSENT log + NON-sshd filter stays file (no fail-closed)" {
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, false, true, false));
}

test "journald: resolveSource auto with ABSENT log + sshd but NO journalctl stays file" {
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, false, false, true));
    try testing.expectEqual(ResolvedSource.file, resolveSource(.auto, false, false, false));
}

test "journald: selectorsForFilter returns the set for sshd, null otherwise" {
    const sshd = selectorsForFilter("sshd");
    try testing.expect(sshd != null);
    try testing.expectEqual(@as(usize, sshd_selectors.len), sshd.?.len);
    try testing.expect(selectorsForFilter("nginx-http-auth") == null);
    try testing.expect(selectorsForFilter("apache-auth") == null);
    try testing.expect(selectorsForFilter("") == null);
    try testing.expect(selectorsForFilter("sshd-ddos") == null);
}

test "journald: config_mod.filterSupportsJournald stays in sync with selectorsForFilter" {
    const candidates = [_][]const u8{ "sshd", "nginx-http-auth", "apache-auth", "postfix", "dovecot", "", "sshd-ddos" };
    for (candidates) |f| {
        try testing.expectEqual(selectorsForFilter(f) != null, config_mod.filterSupportsJournald(f));
    }
}

test "journald: addJail fails closed on an unsupported filter and does not register" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();

    const jail = try JailId.fromSlice("nginx-http-auth");
    try testing.expectError(
        error.UnsupportedJournaldFilter,
        src.addJail(jail, "nginx-http-auth", CallRecorder.onLine, null),
    );
    try testing.expectEqual(@as(usize, 0), src.jailCount());
    try testing.expect(!src.hasJails());

    const sshd = try JailId.fromSlice("sshd");
    try src.addJail(sshd, "sshd", CallRecorder.onLine, null);
    try testing.expectEqual(@as(usize, 1), src.jailCount());
}

test "journald: selector argv ORs across fields with a standalone +" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const argv = try buildPollArgv(arena.allocator(), config_mod.journalctl_path, &sshd_selectors, "--after-cursor=s=abc");
    const expect = [_][]const u8{
        config_mod.journalctl_path,
        "SYSLOG_IDENTIFIER=sshd",
        "SYSLOG_IDENTIFIER=sshd-session",
        "+",
        "_COMM=sshd",
        "_COMM=sshd-session",
        "-o",
        "json",
        "--no-pager",
        "-q",
        "--after-cursor=s=abc",
    };
    try testing.expectEqual(expect.len, argv.len);
    for (expect, argv) |e, got| {
        try testing.expectEqualStrings(e, got);
    }
    try testing.expectEqualStrings("+", argv[3]);
}

test "journald: baseline argv uses -n 1, no --after-cursor" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const argv = try buildBaselineArgv(arena.allocator(), config_mod.journalctl_path, &sshd_selectors);
    var saw_n = false;
    var saw_one = false;
    for (argv, 0..) |tok, i| {
        if (std.mem.eql(u8, tok, "-n")) {
            saw_n = true;
            if (i + 1 < argv.len and std.mem.eql(u8, argv[i + 1], "1")) saw_one = true;
        }
        try testing.expect(!std.mem.startsWith(u8, tok, "--after-cursor"));
    }
    try testing.expect(saw_n and saw_one);
}

test "journald: decodeEntry string MESSAGE passes through verbatim" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    const line =
        \\{"MESSAGE":"Invalid user bob from 1.2.3.4 port 22","__CURSOR":"s=abc;i=1"}
    ;
    const e = try decodeEntry(arena.allocator(), line, &msg_buf, &cur_buf);
    try testing.expectEqualStrings("Invalid user bob from 1.2.3.4 port 22", e.message);
    try testing.expect(e.cursor != null);
    try testing.expectEqualStrings("s=abc;i=1", e.cursor.?);
}

test "journald: decodeEntry byte-array MESSAGE decodes to raw bytes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    const line =
        \\{"MESSAGE":[72,105,255],"__CURSOR":"s=x"}
    ;
    const e = try decodeEntry(arena.allocator(), line, &msg_buf, &cur_buf);
    try testing.expectEqual(@as(usize, 3), e.message.len);
    try testing.expectEqual(@as(u8, 72), e.message[0]);
    try testing.expectEqual(@as(u8, 105), e.message[1]);
    try testing.expectEqual(@as(u8, 255), e.message[2]);
}

test "journald: decodeEntry rejects out-of-range byte-array element" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    const line =
        \\{"MESSAGE":[72,300]}
    ;
    try testing.expectError(error.MalformedMessage, decodeEntry(arena.allocator(), line, &msg_buf, &cur_buf));
}

test "journald: decodeEntry skips missing MESSAGE" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    const line =
        \\{"__CURSOR":"s=x","PRIORITY":"6"}
    ;
    try testing.expectError(error.NoMessage, decodeEntry(arena.allocator(), line, &msg_buf, &cur_buf));
}

test "journald: decodeEntry malformed json is not fatal" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    try testing.expectError(error.MalformedMessage, decodeEntry(arena.allocator(), "{not json", &msg_buf, &cur_buf));
}

test "journald: decodeEntry without __CURSOR yields a null cursor (line still decoded)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg_buf: [max_line_len]u8 = undefined;
    var cur_buf: [max_cursor_len]u8 = undefined;
    const line =
        \\{"MESSAGE":"Invalid user x from 9.9.9.9 port 1"}
    ;
    const e = try decodeEntry(arena.allocator(), line, &msg_buf, &cur_buf);
    try testing.expectEqualStrings("Invalid user x from 9.9.9.9 port 1", e.message);
    try testing.expect(e.cursor == null);
}

const CallRecorder = struct {
    lines: std.ArrayList([]const u8),
    first_line_ms: i64 = 0,
    fn init(a: Allocator) CallRecorder {
        return .{ .lines = std.ArrayList([]const u8).init(a) };
    }
    fn deinit(self: *CallRecorder) void {
        for (self.lines.items) |l| self.lines.allocator.free(l);
        self.lines.deinit();
    }
    fn onLine(line: []const u8, jail: JailId, truncated: bool, ud: ?*anyopaque) void {
        _ = jail;
        _ = truncated;
        const self: *CallRecorder = @ptrCast(@alignCast(ud.?));
        if (self.first_line_ms == 0) self.first_line_ms = std.time.milliTimestamp();
        const dup = self.lines.allocator.dupe(u8, line) catch return;
        self.lines.append(dup) catch self.lines.allocator.free(dup);
    }
};

test "journald: processBatch feeds callback then advances cursor only from entries with __CURSOR" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();

    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();

    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    const batch =
        "{\"MESSAGE\":\"Invalid user a from 1.1.1.1 port 1\",\"__CURSOR\":\"s=first;i=1\"}\n" ++
        "{\"MESSAGE\":\"Invalid user b from 2.2.2.2 port 2\"}\n";
    JournaldSource.TestAccess.processBatch(&src, jj, batch);

    try testing.expectEqual(@as(usize, 2), rec.lines.items.len);
    try testing.expectEqualStrings("Invalid user a from 1.1.1.1 port 1", rec.lines.items[0]);
    try testing.expectEqualStrings("Invalid user b from 2.2.2.2 port 2", rec.lines.items[1]);
    try testing.expectEqualStrings("s=first;i=1", JournalJail.TestAccess.cursorSlice(jj));
    try testing.expect(src.dirty);
}

test "journald: processBatch keeps the latest cursor across multiple cursored entries" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    const batch =
        "{\"MESSAGE\":\"m1 1.1.1.1\",\"__CURSOR\":\"s=one\"}\n" ++
        "{\"MESSAGE\":\"m2 2.2.2.2\",\"__CURSOR\":\"s=two\"}\n" ++
        "{\"MESSAGE\":\"m3 3.3.3.3\",\"__CURSOR\":\"s=three\"}\n";
    JournaldSource.TestAccess.processBatch(&src, jj, batch);
    try testing.expectEqualStrings("s=three", JournalJail.TestAccess.cursorSlice(jj));
}

test "journald: cursorPath derives the sidecar next to the state file" {
    var buf: [4096]u8 = undefined;
    const p = try cursorPath("/var/lib/fail2zig/state.bin", &buf);
    try testing.expectEqualStrings("/var/lib/fail2zig/journald-cursors.bin", p);
}

test "journald: cursor sidecar roundtrips" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dbuf);
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&pbuf, "{s}/journald-cursors.bin", .{dir});

    const entries = [_]CursorEntry{
        .{ .name = "sshd", .cursor = "s=abc;i=1;b=2" },
        .{ .name = "nginx", .cursor = "s=def;i=9" },
    };
    try saveCursors(&entries, path);

    const loaded = try loadCursors(testing.allocator, path);
    defer {
        for (loaded) |e| {
            testing.allocator.free(e.name);
            testing.allocator.free(e.cursor);
        }
        testing.allocator.free(loaded);
    }
    try testing.expectEqual(@as(usize, 2), loaded.len);
    try testing.expectEqualStrings("sshd", loaded[0].name);
    try testing.expectEqualStrings("s=abc;i=1;b=2", loaded[0].cursor);
    try testing.expectEqualStrings("nginx", loaded[1].name);
    try testing.expectEqualStrings("s=def;i=9", loaded[1].cursor);
}

test "journald: cursor sidecar corruption re-seeds (empty)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dbuf);
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&pbuf, "{s}/journald-cursors.bin", .{dir});

    const entries = [_]CursorEntry{.{ .name = "sshd", .cursor = "s=abc" }};
    try saveCursors(&entries, path);

    {
        const f = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
        defer f.close();
        try f.seekTo(12);
        try f.writeAll(&[_]u8{0xFF});
    }

    const loaded = try loadCursors(testing.allocator, path);
    defer testing.allocator.free(loaded);
    try testing.expectEqual(@as(usize, 0), loaded.len);
}

test "journald: cursor sidecar missing file returns empty without error" {
    const loaded = try loadCursors(testing.allocator, "/definitely/not/here/journald-cursors.bin");
    defer testing.allocator.free(loaded);
    try testing.expectEqual(@as(usize, 0), loaded.len);
}

test "journald: collectCursors only includes jails with a cursor" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();

    const sshd = try JailId.fromSlice("sshd");
    const nginx = try JailId.fromSlice("nginx");
    try src.addJail(sshd, "sshd", CallRecorder.onLine, null);
    try src.addJail(nginx, "sshd", CallRecorder.onLine, null);

    src.seedCursor("sshd", "s=seeded");

    var buf: [max_jails]CursorEntry = undefined;
    const got = src.collectCursors(&buf);
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("sshd", got[0].name);
    try testing.expectEqualStrings("s=seeded", got[0].cursor);
}

const FlushSpy = struct {
    calls: u32 = 0,
    succeeds: bool = true,
    fn hook(ud: ?*anyopaque) bool {
        const self: *FlushSpy = @ptrCast(@alignCast(ud.?));
        self.calls += 1;
        return self.succeeds;
    }
};

test "journald: failed flush retries without new records and clears dirty only on success" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var spy = FlushSpy{ .succeeds = false };
    src.setFlushHook(FlushSpy.hook, &spy);
    src.dirty = true;
    src.maybeFlush();
    try testing.expect(src.dirty);
    try testing.expectEqual(@as(u32, 1), spy.calls);
    spy.succeeds = true;
    src.maybeFlush();
    try testing.expect(!src.dirty);
    try testing.expectEqual(@as(u32, 2), spy.calls);
    src.maybeFlush();
    try testing.expectEqual(@as(u32, 2), spy.calls);
}

test "journald: maybeFlush fires the hook once on a dirty source and clears dirty" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();

    var spy = FlushSpy{};
    src.setFlushHook(FlushSpy.hook, &spy);

    src.dirty = true;
    src.maybeFlush();
    try testing.expectEqual(@as(u32, 1), spy.calls);
    try testing.expect(!src.dirty);

    src.maybeFlush();
    try testing.expectEqual(@as(u32, 1), spy.calls);
}

test "journald: maybeFlush does nothing on a clean source" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();

    var spy = FlushSpy{};
    src.setFlushHook(FlushSpy.hook, &spy);

    src.maybeFlush();
    try testing.expectEqual(@as(u32, 0), spy.calls);
    try testing.expect(!src.dirty);
}

test "journald: processBatch marks dirty so maybeFlush will fire" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    var spy = FlushSpy{};
    src.setFlushHook(FlushSpy.hook, &spy);

    try testing.expect(!src.dirty);
    JournaldSource.TestAccess.processBatch(&src, jj, "{\"MESSAGE\":\"m 1.2.3.4\",\"__CURSOR\":\"s=c1\"}\n");
    try testing.expect(src.dirty);

    src.maybeFlush();
    try testing.expectEqual(@as(u32, 1), spy.calls);
    try testing.expect(!src.dirty);
}

test "journald: extractCursor returns the cursor even when MESSAGE is missing/malformed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var cur_buf: [max_cursor_len]u8 = undefined;

    const no_msg =
        \\{"__CURSOR":"s=base;i=42","PRIORITY":"6"}
    ;
    const c1 = extractCursor(arena.allocator(), no_msg, &cur_buf);
    try testing.expect(c1 != null);
    try testing.expectEqualStrings("s=base;i=42", c1.?);

    const bad_msg =
        \\{"MESSAGE":[999],"__CURSOR":"s=base2"}
    ;
    const c2 = extractCursor(arena.allocator(), bad_msg, &cur_buf);
    try testing.expect(c2 != null);
    try testing.expectEqualStrings("s=base2", c2.?);

    const no_cursor =
        \\{"MESSAGE":"Invalid user x from 1.2.3.4 port 22"}
    ;
    try testing.expect(extractCursor(arena.allocator(), no_cursor, &cur_buf) == null);

    try testing.expect(extractCursor(arena.allocator(), "{not json", &cur_buf) == null);
}

test "journald: seedBaseline sets cursor + dirty but does NOT invoke the callback" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    try testing.expect(jj.cursor_len == 0);
    const baseline =
        "{\"MESSAGE\":\"some recent journal line\",\"__CURSOR\":\"s=tail;i=7\"}\n";
    JournaldSource.TestAccess.seedBaseline(&src, jj, baseline);

    try testing.expectEqualStrings("s=tail;i=7", JournalJail.TestAccess.cursorSlice(jj));
    try testing.expect(src.dirty);
    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
}

test "journald: first-run baseline of a FAILURE entry does not ban (no callback)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    const baseline =
        "{\"MESSAGE\":\"Invalid user attacker from 203.0.113.9 port 22\",\"__CURSOR\":\"s=preexisting\"}\n";
    JournaldSource.TestAccess.seedBaseline(&src, jj, baseline);

    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
    try testing.expectEqualStrings("s=preexisting", JournalJail.TestAccess.cursorSlice(jj));
}

test "journald: seedBaseline with empty output leaves the jail un-baselined" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    JournaldSource.TestAccess.seedBaseline(&src, jj, "");
    try testing.expectEqual(@as(usize, 0), jj.cursor_len);
    try testing.expect(!src.dirty);
    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
}

test "journald: steady-state processBatch STILL invokes the callback (contrast with baseline)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    const jail = try JailId.fromSlice("sshd");
    try src.addJail(jail, "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    JournalJail.TestAccess.setCursor(jj, "s=already-baselined");
    const batch =
        "{\"MESSAGE\":\"Invalid user x from 5.5.5.5 port 1\",\"__CURSOR\":\"s=new1\"}\n";
    JournaldSource.TestAccess.processBatch(&src, jj, batch);

    try testing.expectEqual(@as(usize, 1), rec.lines.items.len);
    try testing.expectEqualStrings("Invalid user x from 5.5.5.5 port 1", rec.lines.items[0]);
    try testing.expectEqualStrings("s=new1", JournalJail.TestAccess.cursorSlice(jj));
    try testing.expectEqual(@as(u64, 1), jj.lines_seen);
}

test "journald: healthForJail unhealthy until a clean poll completes (SYS-017)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];

    const h0 = src.healthForJail("sshd").?;
    try testing.expect(!h0.healthy);
    try testing.expectEqual(@as(u64, 0), h0.lines_seen);

    jj.last_read_ok_ts = 1234;
    jj.lines_seen = 7;
    const h1 = src.healthForJail("sshd").?;
    try testing.expect(h1.healthy);
    try testing.expectEqual(@as(u64, 7), h1.lines_seen);
    try testing.expectEqual(@as(i64, 1234), h1.last_read_ok_ts);
}

test "journald: healthForJail returns null for an unknown jail (SYS-017)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    try testing.expect(src.healthForJail("nope") == null);
}

fn feedChunk(src: *JournaldSource, jj: *JournalJail, bytes: []const u8) bool {
    @memcpy(jj.pending[jj.pending_len..][0..bytes.len], bytes);
    jj.pending_len += bytes.len;
    return JournaldSource.TestAccess.consumeLines(src, jj);
}

test "journald: line buffer reassembles entries split across chunks (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    JournalJail.TestAccess.setCursor(jj, "s=seed");

    try testing.expect(feedChunk(&src, jj, "{\"MESSAGE\":\"m1 1.1.1.1\",\"__CUR"));
    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
    try testing.expect(feedChunk(&src, jj, "SOR\":\"s=1\"}\n{\"MESS"));
    try testing.expectEqual(@as(usize, 1), rec.lines.items.len);
    try testing.expectEqualStrings("s=1", JournalJail.TestAccess.cursorSlice(jj));
    try testing.expect(feedChunk(&src, jj, "AGE\":\"m2 2.2.2.2\",\"__CURSOR\":\"s=2\"}\n"));
    try testing.expectEqual(@as(usize, 2), rec.lines.items.len);
    try testing.expectEqualStrings("m2 2.2.2.2", rec.lines.items[1]);
    try testing.expectEqualStrings("s=2", JournalJail.TestAccess.cursorSlice(jj));
    try testing.expectEqual(@as(usize, 0), jj.pending_len);
}

test "journald: line buffer drops an over-long entry and resyncs on the next newline (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    JournalJail.TestAccess.setCursor(jj, "s=seed");

    @memset(jj.pending, 'x');
    jj.pending_len = jj.pending.len;
    try testing.expect(JournaldSource.TestAccess.consumeLines(&src, jj));
    try testing.expect(jj.discarding);
    try testing.expectEqual(@as(usize, 0), jj.pending_len);
    try testing.expectEqual(@as(usize, 1), jj.entries);

    try testing.expect(feedChunk(&src, jj, "yyy\n{\"MESSAGE\":\"ok 3.3.3.3\",\"__CURSOR\":\"s=3\"}\n"));
    try testing.expect(!jj.discarding);
    try testing.expectEqual(@as(usize, 1), rec.lines.items.len);
    try testing.expectEqualStrings("ok 3.3.3.3", rec.lines.items[0]);
    try testing.expectEqualStrings("s=3", JournalJail.TestAccess.cursorSlice(jj));
}

test "journald: entry cap stops the stream and reports it (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    JournalJail.TestAccess.setCursor(jj, "s=seed");
    jj.entries = max_entries_per_tick;

    try testing.expect(!feedChunk(&src, jj, "{\"MESSAGE\":\"late 4.4.4.4\",\"__CURSOR\":\"s=late\"}\n"));
    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
    try testing.expectEqualStrings("s=seed", JournalJail.TestAccess.cursorSlice(jj));
}

const FakeJournalctl = struct {
    tmp: testing.TmpDir,
    path_buf: [std.fs.max_path_bytes]u8 = undefined,
    path_len: usize = 0,

    fn create(body: []const u8) !FakeJournalctl {
        var self = FakeJournalctl{ .tmp = testing.tmpDir(.{}) };
        errdefer self.tmp.cleanup();
        try self.tmp.dir.writeFile(.{
            .sub_path = "journalctl",
            .data = body,
            .flags = .{ .mode = 0o755 },
        });
        const p = try self.tmp.dir.realpath("journalctl", &self.path_buf);
        self.path_len = p.len;
        return self;
    }

    fn path(self: *const FakeJournalctl) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    fn cleanup(self: *FakeJournalctl) void {
        self.tmp.cleanup();
    }

    fn createJournalBacked() !FakeJournalctl {
        var self = FakeJournalctl{ .tmp = testing.tmpDir(.{}) };
        errdefer self.tmp.cleanup();
        var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
        const dir = try self.tmp.dir.realpath(".", &dir_buf);
        var body_buf: [2048]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buf,
            \\#!/bin/sh
            \\J="{s}/journal"
            \\cur=""
            \\for a in "$@"; do case "$a" in --after-cursor=*) cur="${{a#--after-cursor=}}";; esac; done
            \\if [ -z "$cur" ]; then tail -n 1 "$J"; else awk -v c="$cur" 'f{{print}} index($0,"\"__CURSOR\":\"" c "\"")>0{{f=1}}' "$J"; fi
            \\
        , .{dir});
        try self.tmp.dir.writeFile(.{ .sub_path = "journal", .data = "" });
        try self.tmp.dir.writeFile(.{
            .sub_path = "journalctl",
            .data = body,
            .flags = .{ .mode = 0o755 },
        });
        const p = try self.tmp.dir.realpath("journalctl", &self.path_buf);
        self.path_len = p.len;
        return self;
    }

    fn appendJournal(self: *FakeJournalctl, line: []const u8) !void {
        const f = try self.tmp.dir.openFile("journal", .{ .mode = .write_only });
        defer f.close();
        try f.seekFromEnd(0);
        try f.writeAll(line);
    }
};

const poll_timer_fds: usize = 1;

fn openFdCount() !usize {
    var dir = try std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true });
    defer dir.close();
    var n: usize = 0;
    var it = dir.iterate();
    while (try it.next()) |_| n += 1;
    return n - 1;
}

const LoopDriver = struct {
    loop: *EventLoop,
    rec: *CallRecorder,
    jj: *JournalJail,
    src: ?*JournaldSource = null,
    start_ms: i64,
    want_lines: usize,
    want_reaped: bool,
    timer_fired_ms: i64 = 0,
    fd_fired_ms: i64 = 0,

    const deadline_ms: i64 = 8000;

    fn onCheck(_: u64, ud: ?*anyopaque) void {
        const d: *LoopDriver = @ptrCast(@alignCast(ud.?));
        const now = std.time.milliTimestamp();
        if (d.src) |src| {
            if (d.jj.child) |c| {
                if (c.eof) JournaldSource.TestAccess.finishChild(src, d.jj, .eof);
            }
        }
        const lines_ok = d.rec.lines.items.len >= d.want_lines;
        const reaped_ok = !d.want_reaped or d.jj.child == null;
        if ((lines_ok and reaped_ok) or now - d.start_ms > deadline_ms) d.loop.stop();
    }

    fn onProbeTimer(_: u64, ud: ?*anyopaque) void {
        const d: *LoopDriver = @ptrCast(@alignCast(ud.?));
        d.timer_fired_ms = std.time.milliTimestamp();
    }

    fn onProbeFd(fd: posix.fd_t, _: u32, ud: ?*anyopaque) void {
        const d: *LoopDriver = @ptrCast(@alignCast(ud.?));
        d.fd_fired_ms = std.time.milliTimestamp();
        var buf: [8]u8 = undefined;
        _ = posix.read(fd, &buf) catch {};
    }
};

fn waitpidErrno(pid: posix.pid_t) linux.E {
    var status: u32 = 0;
    const rc = linux.waitpid(pid, &status, linux.W.NOHANG);
    return linux.E.init(rc);
}

test "journald: slow journalctl does not stall the loop — timer and fd serviced mid-poll (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.create(
        \\#!/bin/sh
        \\sleep 2
        \\printf '{"MESSAGE":"Invalid user a from 1.1.1.1 port 1","__CURSOR":"s=a1"}\n'
        \\printf '{"MESSAGE":"Invalid user b from 2.2.2.2 port 2","__CURSOR":"s=a2"}\n'
        \\printf '{"MESSAGE":"Invalid user c from 3.3.3.3 port 3","__CURSOR":"s=a3"}\n'
        \\
    );
    defer fake.cleanup();

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
    });
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    JournalJail.TestAccess.setCursor(jj, "s=seed");

    var drv = LoopDriver{
        .loop = &loop,
        .rec = &rec,
        .jj = jj,
        .start_ms = std.time.milliTimestamp(),
        .want_lines = 3,
        .want_reaped = false,
    };

    const efd = try posix.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    defer posix.close(efd);
    try loop.addFd(efd, linux.EPOLL.IN, LoopDriver.onProbeFd, &drv);
    const one: u64 = 1;
    _ = try posix.write(efd, std.mem.asBytes(&one));

    _ = try loop.addTimer(200, LoopDriver.onProbeTimer, &drv, true);
    _ = try loop.addTimer(25, LoopDriver.onCheck, &drv, false);
    const fds_before = try openFdCount();
    try JournaldSource.TestAccess.pollJail(&src, jj);
    const pid = jj.child.?.pid;
    try src.attach();

    try loop.run();
    try loop.removeFd(efd);

    try testing.expectEqual(@as(usize, 3), rec.lines.items.len);
    try testing.expectEqualStrings("Invalid user c from 3.3.3.3 port 3", rec.lines.items[2]);
    try testing.expectEqualStrings("s=a3", JournalJail.TestAccess.cursorSlice(jj));
    try testing.expect(rec.first_line_ms - drv.start_ms >= 1900);
    try testing.expect(drv.timer_fired_ms > 0);
    try testing.expect(drv.timer_fired_ms < rec.first_line_ms);
    try testing.expect(drv.fd_fired_ms > 0);
    try testing.expect(drv.fd_fired_ms < rec.first_line_ms);

    src.deinit();
    const fds_after = try openFdCount();
    src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    try testing.expectEqual(fds_before, fds_after);
    try testing.expectEqual(linux.E.CHILD, waitpidErrno(pid));
}

test "journald: hung journalctl is killed at the timeout, reaped, cursor unchanged (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.create(
        \\#!/bin/sh
        \\exec sleep 1000
        \\
    );
    defer fake.cleanup();

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
        .child_timeout_ms = 1500,
    });
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    JournalJail.TestAccess.setCursor(jj, "s=seed");

    var drv = LoopDriver{
        .loop = &loop,
        .rec = &rec,
        .jj = jj,
        .start_ms = std.time.milliTimestamp(),
        .want_lines = 0,
        .want_reaped = true,
    };

    _ = try loop.addTimer(25, LoopDriver.onCheck, &drv, false);
    try src.attach();
    const fds_before = try openFdCount();
    try JournaldSource.TestAccess.pollJail(&src, jj);
    const pid = jj.child.?.pid;
    try loop.run();
    try testing.expect(jj.child == null);
    try testing.expectEqual(fds_before, try openFdCount());

    const elapsed = std.time.milliTimestamp() - drv.start_ms;
    try testing.expect(elapsed >= 1500);
    try testing.expect(elapsed < LoopDriver.deadline_ms);
    try testing.expect(jj.child == null);
    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
    try testing.expectEqualStrings("s=seed", JournalJail.TestAccess.cursorSlice(jj));
    try testing.expectEqual(@as(i64, 0), jj.last_read_ok_ts);
    try testing.expectEqual(linux.E.CHILD, waitpidErrno(pid));
}

test "journald: EOF mid-line drops the partial entry and the next poll starts clean (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.create(
        \\#!/bin/sh
        \\printf '{"MESSAGE":"complete 1.1.1.1","__CURSOR":"s=c1"}\n{"MESSAGE":"partial'
        \\
    );
    defer fake.cleanup();

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
    });
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    JournalJail.TestAccess.setCursor(jj, "s=seed");

    var drv = LoopDriver{
        .loop = &loop,
        .rec = &rec,
        .jj = jj,
        .start_ms = std.time.milliTimestamp(),
        .want_lines = 2,
        .want_reaped = true,
    };

    try JournaldSource.TestAccess.pollJail(&src, jj);
    try src.attach();
    _ = try loop.addTimer(25, LoopDriver.onCheck, &drv, false);
    try loop.run();

    try testing.expectEqual(@as(usize, 2), rec.lines.items.len);
    try testing.expectEqualStrings("complete 1.1.1.1", rec.lines.items[0]);
    try testing.expectEqualStrings("complete 1.1.1.1", rec.lines.items[1]);
    try testing.expectEqualStrings("s=c1", JournalJail.TestAccess.cursorSlice(jj));
    try testing.expectEqual(@as(usize, 0), jj.pending_len);
    try testing.expect(!jj.discarding);
    try testing.expect(jj.last_read_ok_ts > 0);
}

test "journald: a tick while a child is in flight does not spawn a second one (PRF-001)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.create(
        \\#!/bin/sh
        \\exec sleep 1000
        \\
    );
    defer fake.cleanup();

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
    });
    defer src.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, null);
    const jj = &src.jails.items[0];
    JournalJail.TestAccess.setCursor(jj, "s=seed");

    try JournaldSource.TestAccess.pollJail(&src, jj);
    const pid = jj.child.?.pid;
    const fd = jj.child.?.stdout_fd;
    try JournaldSource.TestAccess.pollJail(&src, jj);
    try testing.expectEqual(pid, jj.child.?.pid);
    try testing.expectEqual(fd, jj.child.?.stdout_fd);
    try testing.expectEqual(@as(usize, 2), loop.registrations.count());

    src.deinit();
    src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{});
    try testing.expectEqual(linux.E.CHILD, waitpidErrno(pid));
    try testing.expectEqual(@as(usize, 1), loop.registrations.count());
}

test "journald: twenty EOF-path polls leave the open fd count flat (SYS-023)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.create(
        \\#!/bin/sh
        \\printf '{"MESSAGE":"Invalid user a from 1.1.1.1 port 1","__CURSOR":"s=eof"}\n'
        \\
    );
    defer fake.cleanup();

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
    });
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    JournalJail.TestAccess.setCursor(jj, "s=seed");

    var drv = LoopDriver{
        .loop = &loop,
        .rec = &rec,
        .jj = jj,
        .src = &src,
        .start_ms = 0,
        .want_lines = 0,
        .want_reaped = true,
    };
    _ = try loop.addTimer(5, LoopDriver.onCheck, &drv, false);

    const fds_before = try openFdCount();
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        drv.start_ms = std.time.milliTimestamp();
        drv.want_lines = i + 1;
        try JournaldSource.TestAccess.pollJail(&src, jj);
        try loop.run();
        try testing.expect(jj.child == null);
        try testing.expectEqual(i + 1, rec.lines.items.len);
    }
    try testing.expectEqual(fds_before, try openFdCount());
    try testing.expect(jj.last_read_ok_ts > 0);
}

test "journald: twenty kill-path polls leave the open fd count flat (SYS-023)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.create(
        \\#!/bin/sh
        \\exec sleep 1000
        \\
    );
    defer fake.cleanup();

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
    });
    defer src.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, null);
    const jj = &src.jails.items[0];
    JournalJail.TestAccess.setCursor(jj, "s=seed");

    const fds_before = try openFdCount();
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        try JournaldSource.TestAccess.pollJail(&src, jj);
        const pid = jj.child.?.pid;
        JournaldSource.TestAccess.finishChild(&src, jj, .kill);
        try testing.expect(jj.child == null);
        try testing.expectEqual(linux.E.CHILD, waitpidErrno(pid));
    }
    try testing.expectEqual(fds_before, try openFdCount());
    try testing.expectEqual(@as(usize, 1), loop.registrations.count());
}

test "journald: attach baselines synchronously; entries logged before the first tick are delivered (SYS-024)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.createJournalBacked();
    defer fake.cleanup();
    try fake.appendJournal("{\"MESSAGE\":\"Invalid user old from 9.9.9.9 port 9\",\"__CURSOR\":\"s=0\"}\n");

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
    });
    defer src.deinit();
    var rec = CallRecorder.init(testing.allocator);
    defer rec.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, &rec);
    const jj = &src.jails.items[0];
    try testing.expectEqual(@as(usize, 0), jj.cursor_len);

    const fds_before = try openFdCount();
    try src.attach();
    try testing.expectEqualStrings("s=0", JournalJail.TestAccess.cursorSlice(jj));
    try testing.expect(jj.child == null);
    try testing.expect(jj.last_read_ok_ts > 0);
    try testing.expectEqual(@as(usize, 0), rec.lines.items.len);
    try testing.expectEqual(fds_before + poll_timer_fds, try openFdCount());

    try fake.appendJournal("{\"MESSAGE\":\"Invalid user a from 1.1.1.1 port 1\",\"__CURSOR\":\"s=1\"}\n");
    try fake.appendJournal("{\"MESSAGE\":\"Invalid user b from 2.2.2.2 port 2\",\"__CURSOR\":\"s=2\"}\n");

    var drv = LoopDriver{
        .loop = &loop,
        .rec = &rec,
        .jj = jj,
        .start_ms = std.time.milliTimestamp(),
        .want_lines = 2,
        .want_reaped = false,
    };
    _ = try loop.addTimer(25, LoopDriver.onCheck, &drv, false);
    try loop.run();

    try testing.expectEqual(@as(usize, 2), rec.lines.items.len);
    try testing.expectEqualStrings("Invalid user a from 1.1.1.1 port 1", rec.lines.items[0]);
    try testing.expectEqualStrings("Invalid user b from 2.2.2.2 port 2", rec.lines.items[1]);
    try testing.expectEqualStrings("s=2", JournalJail.TestAccess.cursorSlice(jj));
}

test "journald: attach skips the baseline for a jail with a sidecar cursor (SYS-024)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.createJournalBacked();
    defer fake.cleanup();
    try fake.appendJournal("{\"MESSAGE\":\"Invalid user old from 9.9.9.9 port 9\",\"__CURSOR\":\"s=0\"}\n");

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
    });
    defer src.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, null);
    const jj = &src.jails.items[0];
    src.seedCursor("sshd", "s=restored");

    try src.attach();
    try testing.expectEqualStrings("s=restored", JournalJail.TestAccess.cursorSlice(jj));
    try testing.expectEqual(@as(i64, 0), jj.last_read_ok_ts);
}

test "journald: a hung baseline is killed at the baseline timeout and attach still succeeds (SYS-024)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fake = try FakeJournalctl.create(
        \\#!/bin/sh
        \\exec sleep 1000
        \\
    );
    defer fake.cleanup();

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    var src = try JournaldSource.init(testing.allocator, &loop, "/tmp/fail2zig-test/state.bin", .{
        .journalctl_path = fake.path(),
        .baseline_timeout_ms = 300,
    });
    defer src.deinit();
    try src.addJail(try JailId.fromSlice("sshd"), "sshd", CallRecorder.onLine, null);
    const jj = &src.jails.items[0];

    const fds_before = try openFdCount();
    const t0 = std.time.milliTimestamp();
    try src.attach();
    const elapsed = std.time.milliTimestamp() - t0;
    try testing.expect(elapsed >= 300);
    try testing.expect(elapsed < 3000);
    try testing.expect(jj.child == null);
    try testing.expectEqual(@as(usize, 0), jj.cursor_len);
    try testing.expectEqual(fds_before + poll_timer_fds, try openFdCount());
    try testing.expect(src.poll_handle != null);
}
