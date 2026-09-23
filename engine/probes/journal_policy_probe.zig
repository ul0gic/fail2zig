// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const policy = @import("engine_probe").core.journal_policy;
const Request = struct {
    options: policy.Options = .{},
    files_words: ?[]const u8 = null,
    state_logs: []const u8,
    runtime_logs: []const u8,
    effective_uid: u32 = 0,
    default_flags: ?[]const u8 = null,
    unreadable: []const []const u8 = &.{},
    private_root: []const u8 = "",
};
const Response = struct {
    arguments: ?policy.Prepared = null,
    preparation_error: ?[]const u8 = null,
    selection_flags: ?u32 = null,
    selection_error: ?[]const u8 = null,
    selection_diagnostic: ?[]const u8 = null,
    reader_checked: bool = false,
    reader_error: ?[]const u8 = null,
    reader_admission: []const u8 = "retired",
};
fn readable(path: []const u8, context: ?*anyopaque) !bool {
    const request: *const Request = @ptrCast(@alignCast(context.?));
    for (request.unreadable) |denied| if (std.mem.eql(u8, denied, path)) return false;
    return true;
}
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len != 2) return error.InvalidArguments;
    const input = try std.fs.cwd().readFileAlloc(allocator, args[1], 8 * 1024 * 1024);
    const requests = try std.json.parseFromSliceLeaky([]Request, allocator, input, .{});
    var responses = std.ArrayList(Response).init(allocator);
    for (requests) |*request| {
        var options = request.options;
        if (request.files_words) |words| options.files = try policy.splitFiles(allocator, words);
        const prepared = policy.prepare(allocator, options, .{ .state_logs = request.state_logs, .runtime_logs = request.runtime_logs, .effective_uid = request.effective_uid, .default_flags = request.default_flags, .readable = readable, .context = request }) catch |err| {
            try responses.append(.{ .preparation_error = @errorName(err) });
            continue;
        };
        var response = Response{ .arguments = prepared, .selection_diagnostic = prepared.selectionDiagnostic() };
        if (prepared.selection(&.{})) |selection| {
            response.selection_flags = selection.flags;
        } else |err| {
            response.selection_error = @errorName(err);
        }
        try responses.append(response);
    }
    try std.json.stringify(responses.items, .{}, std.io.getStdOut().writer());
}

test {
    std.testing.refAllDecls(policy);
}
