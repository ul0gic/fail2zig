// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Renders client and daemon version information as JSON, plain lines or a table.
// Holds: Table output escapes every version string with renderDiagnostic; plain output prints daemon_version, git_commit, build_date raw.

const std = @import("std");
const OutputFormat = @import("shared.zig").OutputFormat;
const Color = @import("shared.zig").Color;
const diagnostic_max_bytes = @import("shared.zig").diagnostic_max_bytes;
const renderDiagnostic = @import("shared.zig").renderDiagnostic;

pub const VersionPayload = struct {
    daemon_version: ?[]const u8 = null,
    git_commit: ?[]const u8 = null,
    build_date: ?[]const u8 = null,
};

pub fn formatVersion(
    allocator: std.mem.Allocator,
    writer: anytype,
    client_version: []const u8,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    _ = color;
    switch (fmt) {
        .json => {
            try writer.print(
                \\{{"client_version":"{s}","daemon":
            , .{client_version});
            if (payload_json.len == 0) {
                try writer.writeAll("null");
            } else {
                try writer.writeAll(payload_json);
            }
            try writer.writeAll("}\n");
        },
        .plain => {
            try writer.print("client\t{s}\n", .{client_version});
            if (payload_json.len > 0) {
                const parsed = std.json.parseFromSlice(
                    VersionPayload,
                    allocator,
                    payload_json,
                    .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
                ) catch return;
                defer parsed.deinit();
                if (parsed.value.daemon_version) |v| try writer.print("daemon\t{s}\n", .{v});
                if (parsed.value.git_commit) |c| try writer.print("git\t{s}\n", .{c});
                if (parsed.value.build_date) |d| try writer.print("built\t{s}\n", .{d});
            }
        },
        .table => {
            const parsed = try std.json.parseFromSlice(
                VersionPayload,
                allocator,
                if (payload_json.len == 0) "{}" else payload_json,
                .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
            );
            defer parsed.deinit();
            var diagnostic: [diagnostic_max_bytes]u8 = undefined;
            if (parsed.value.daemon_version) |v| {
                if (std.mem.eql(u8, client_version, v)) {
                    try writer.print("fail2zig {s} (client and daemon)\n", .{renderDiagnostic(&diagnostic, client_version)});
                } else {
                    try writer.print("Client: fail2zig {s}\n", .{renderDiagnostic(&diagnostic, client_version)});
                    try writer.print("Daemon: fail2zig {s}\n", .{renderDiagnostic(&diagnostic, v)});
                }
            } else {
                try writer.print("Client: fail2zig {s}\nDaemon: version unavailable\n", .{renderDiagnostic(&diagnostic, client_version)});
            }
            if (parsed.value.git_commit) |c| try writer.print("  commit: {s}\n", .{renderDiagnostic(&diagnostic, c)});
            if (parsed.value.build_date) |d| try writer.print("  built:  {s}\n", .{renderDiagnostic(&diagnostic, d)});
        },
    }
}
