// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const files = @import("engine_probe").core.durable_file_source;
const source_record = @import("engine_probe").core.source_record;
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len > 1 and std.mem.eql(u8, args[1], "--file")) {
        if (args.len != 5) return error.UsageFilePathFramingStart;
        const framing = std.meta.stringToEnum(files.Framing, args[3]) orelse return error.InvalidFraming;
        const start = std.meta.stringToEnum(files.Start, args[4]) orelse return error.InvalidStart;
        var source = try files.FileSource.init(allocator, args[2], "file-fixture", start, null);
        defer source.deinit();
        source.framing = framing;
        while (try source.poll(onFile, null)) {}
        return;
    }
    return error.JournalReaderRetired;
}

fn onFile(record: source_record.Record, _: ?*anyopaque) !void {
    if (record.kind == .checkpoint) return;
    const writer = std.io.getStdOut().writer();
    try writer.print("{{\"message_hex\":\"{s}\",\"byte_start\":{d},\"byte_end\":{d}}}\n", .{ std.fmt.fmtSliceHexLower(record.message), record.byte_start.?, record.byte_end.? });
}
