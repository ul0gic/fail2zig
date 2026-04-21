const std = @import("std");
const shared = @import("shared");

pub const version = "0.1.0";

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("fail2zig-client v{s}\n", .{version});
}

test "client starts" {
    try std.testing.expectEqualStrings("0.1.0", version);
    _ = shared;
}
