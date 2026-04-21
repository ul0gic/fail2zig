const std = @import("std");
const shared = @import("shared");

// Wire all engine modules into the build graph so their tests are discovered.
const allocator_mod = @import("core/allocator.zig");
const memory_mod = @import("core/memory.zig");
const event_loop = @import("core/event_loop.zig");
const log_watcher = @import("core/log_watcher.zig");
const line_buffer_mod = @import("core/line_buffer.zig");
const logger_mod = @import("core/logger.zig");
const parser = @import("core/parser.zig");
const state = @import("core/state.zig");
const firewall = @import("firewall/backend.zig");
const config = @import("config/native.zig");
const http = @import("net/http.zig");
const ws = @import("net/ws.zig");

pub const version = "0.1.0";

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("fail2zig v{s}\n", .{version});
}

test "engine starts" {
    try std.testing.expectEqualStrings("0.1.0", version);
}

test {
    _ = allocator_mod;
    _ = memory_mod;
    _ = event_loop;
    _ = log_watcher;
    _ = line_buffer_mod;
    _ = logger_mod;
    _ = parser;
    _ = state;
    _ = firewall;
    _ = config;
    _ = http;
    _ = ws;
    _ = shared;
}
