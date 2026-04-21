//! WebSocket server skeleton (real-time event stream for dashboard). Real
//! implementation arrives in Phase 5. This stub exists so the module graph
//! compiles.

const std = @import("std");

pub const WsServer = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) WsServer {
        return .{ .allocator = allocator };
    }
};

test "ws: instantiates" {
    const server = WsServer.init(std.testing.allocator);
    try std.testing.expect(@TypeOf(server.allocator) == std.mem.Allocator);
}
