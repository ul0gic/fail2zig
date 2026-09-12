// SPDX-License-Identifier: AGPL-3.0-or-later
// Offline N1 link experiment. This is not the production journal adapter.
const std = @import("std");
const Journal = opaque {};
extern "c" fn sd_journal_open_files(*?*Journal, [*:null]const ?[*:0]const u8, c_int) c_int;
extern "c" fn sd_journal_close(*Journal) void;
extern "c" fn sd_journal_next(*Journal) c_int;
extern "c" fn sd_journal_get_data(*Journal, [*:0]const u8, *?*const anyopaque, *usize) c_int;
extern "c" fn sd_journal_set_data_threshold(*Journal, usize) c_int;
extern "c" fn sd_journal_get_cursor(*Journal, *?[*:0]u8) c_int;
extern "c" fn sd_journal_seek_cursor(*Journal, [*:0]const u8) c_int;
extern "c" fn sd_journal_test_cursor(*Journal, [*:0]const u8) c_int;
extern "c" fn sd_journal_add_match(*Journal, *const anyopaque, usize) c_int;
extern "c" fn free(?*anyopaque) void;
extern "c" fn puts([*:0]const u8) c_int;

fn open(path: [*:0]const u8) !*Journal {
    const paths = [_:null]?[*:0]const u8{path};
    var journal: ?*Journal = null;
    if (sd_journal_open_files(&journal, &paths, 0) < 0) return error.OpenFailed;
    const j = journal orelse return error.OpenFailed;
    errdefer sd_journal_close(j);
    if (sd_journal_set_data_threshold(j, 0) < 0) return error.ThresholdFailed;
    return j;
}

fn field(j: *Journal, name: [*:0]const u8) ![]const u8 {
    var data: ?*const anyopaque = null;
    var len: usize = 0;
    if (sd_journal_get_data(j, name, &data, &len) < 0) return error.FieldFailed;
    if (len > 8192) return error.FieldTooLarge;
    const ptr: [*]const u8 = @ptrCast(data orelse return error.FieldFailed);
    return ptr[0..len];
}

fn record(j: *Journal, seq: u8) !void {
    var expected = "F2Z_SEQUENCE=0".*;
    expected[expected.len - 1] = '0' + seq;
    if (!std.mem.eql(u8, try field(j, "F2Z_SEQUENCE"), &expected)) return error.SequenceMismatch;
    const message = try field(j, "MESSAGE");
    var prefix = "MESSAGE=fixture-0-".*;
    prefix[prefix.len - 2] = '0' + seq;
    if (message.len != prefix.len + 4096 or !std.mem.startsWith(u8, message, &prefix)) return error.MessageMismatch;
    for (message[prefix.len..]) |byte| if (byte != 'X') return error.MessageMismatch;
}

fn run(path: [*:0]const u8) !void {
    var cursor: ?[*:0]u8 = null;
    defer if (cursor) |c| free(c);
    {
        const j = try open(path);
        defer sd_journal_close(j);
        for (1..4) |seq| {
            if (sd_journal_next(j) != 1) return error.MissingRecord;
            try record(j, @intCast(seq));
            if (seq == 1 and sd_journal_get_cursor(j, &cursor) < 0) return error.CursorFailed;
        }
        if (sd_journal_next(j) != 0) return error.UnexpectedRecord;
    }
    {
        const j = try open(path);
        defer sd_journal_close(j);
        const saved = cursor orelse return error.CursorFailed;
        if (sd_journal_seek_cursor(j, saved) < 0 or sd_journal_next(j) != 1 or
            sd_journal_test_cursor(j, saved) != 1) return error.ResumeFailed;
        try record(j, 1);
        for (2..4) |seq| {
            if (sd_journal_next(j) != 1) return error.ResumeFailed;
            try record(j, @intCast(seq));
        }
        if (sd_journal_next(j) != 0) return error.UnexpectedRecord;
    }
    {
        const j = try open(path);
        defer sd_journal_close(j);
        const match = "F2Z_KIND=deny";
        if (sd_journal_add_match(j, match, match.len) < 0) return error.MatchFailed;
        for ([_]u8{ 1, 3 }) |seq| {
            if (sd_journal_next(j) != 1) return error.MatchFailed;
            try record(j, seq);
        }
        if (sd_journal_next(j) != 0) return error.MatchFailed;
    }
}

export fn main(argc: c_int, argv: [*][*:0]u8) c_int {
    if (argc != 2) {
        _ = puts("usage: journal-probe FIXTURE.journal");
        return 2;
    }
    run(argv[1]) catch |err| {
        _ = puts(@errorName(err));
        return 1;
    };
    _ = puts("PASS: 3 exact records; cursor close/reopen; 2 selected records");
    return 0;
}
