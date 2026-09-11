// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Original fixture preparation only; this probe never opens a journal.
const std = @import("std");
const policy = @import("core/journal_policy.zig");
const reader = @import("core/systemd_reader.zig");
const Request = struct {
    options: policy.Options = .{},
    files_words: ?[]const u8 = null,
    state_logs: []const u8,
    runtime_logs: []const u8,
    effective_uid: u32 = 0,
    default_flags: ?[]const u8 = null,
    unreadable: []const []const u8 = &.{},
    private_root: []const u8,
};
const Response = struct {
    arguments: ?policy.Prepared = null,
    preparation_error: ?[]const u8 = null,
    selection_flags: ?u32 = null,
    selection_error: ?[]const u8 = null,
    selection_diagnostic: ?[]const u8 = null,
    reader_checked: bool = false,
    reader_error: ?[]const u8 = null,
};
fn readable(path: []const u8, context: ?*anyopaque) !bool {
    const request: *const Request = @ptrCast(@alignCast(context.?));
    for (request.unreadable) |denied| if (std.mem.eql(u8, denied, path)) return false;
    return true;
}
fn privateSelection(prepared: policy.Prepared, root: []const u8) bool {
    if (root.len < 10 or !std.fs.path.isAbsolute(root)) return false;
    if (prepared.path == null and prepared.files == null) return false;
    if (prepared.path) |path| if (path.len != 0 and !(std.mem.startsWith(u8, path, root) and path.len > root.len and path[root.len] == '/')) return false;
    if (prepared.files) |paths| for (paths) |path| {
        if (!(std.mem.startsWith(u8, path, root) and path.len > root.len and path[root.len] == '/')) return false;
    };
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
        const private = privateSelection(prepared, request.private_root);
        response.reader_checked = private;
        if (prepared.selection(&.{})) |selection| {
            response.selection_flags = selection.flags;
            if (private) {
                if (reader.Reader.init(allocator, "private-policy-probe", selection, null)) |value| {
                    var journal = value;
                    journal.deinit();
                } else |err| response.reader_error = @errorName(err);
            }
        } else |err| {
            response.selection_error = @errorName(err);
            if (private) response.reader_error = if (err == error.ConflictingJournalSelection) "InvalidJournalSelection" else @errorName(err);
        }
        try responses.append(response);
    }
    try std.json.stringify(responses.items, .{}, std.io.getStdOut().writer());
}

test {
    std.testing.refAllDecls(policy);
}
