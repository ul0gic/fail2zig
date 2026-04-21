//! Parser engine skeleton. Real implementation arrives in Phase 3 (comptime
//! pattern DSL + SIMD-friendly extraction). This stub exists so the module
//! graph compiles.

const std = @import("std");
const shared = @import("shared");

pub const Error = error{NotImplemented};

pub const ParseResult = struct {
    ip: shared.IpAddress,
    timestamp: ?shared.Timestamp = null,
    matched_pattern_id: u16 = 0,
};

pub const Parser = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Parser {
        return .{ .allocator = allocator };
    }

    pub fn parseLine(self: *const Parser, line: []const u8) Error!?ParseResult {
        _ = self;
        _ = line;
        return error.NotImplemented;
    }
};

test "parser: instantiates and parseLine returns NotImplemented" {
    const p = Parser.init(std.testing.allocator);
    try std.testing.expectError(
        error.NotImplemented,
        p.parseLine("Failed password from 1.2.3.4"),
    );
}
