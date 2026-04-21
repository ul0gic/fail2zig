//! HTTP server skeleton (metrics endpoint + JSON status API). Real
//! implementation arrives in Phase 5. This stub exists so the module graph
//! compiles.

const std = @import("std");

pub const Error = error{NotImplemented};

pub const HttpServer = struct {
    allocator: std.mem.Allocator,
    port: u16,

    pub fn init(allocator: std.mem.Allocator, port: u16) HttpServer {
        return .{ .allocator = allocator, .port = port };
    }

    pub fn deinit(self: *HttpServer) void {
        _ = self;
    }

    pub fn start(self: *HttpServer) Error!void {
        _ = self;
        return error.NotImplemented;
    }
};

test "http: instantiates and start returns NotImplemented" {
    var server = HttpServer.init(std.testing.allocator, 9090);
    defer server.deinit();
    try std.testing.expectEqual(@as(u16, 9090), server.port);
    try std.testing.expectError(error.NotImplemented, server.start());
}
