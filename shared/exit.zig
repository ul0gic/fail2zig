// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

pub const ExitClass = enum(u8) {
    success = 0,
    rejected = 1,
    usage = 2,
    unavailable = 3,
    partial = 4,
    uncertain = 5,

    pub fn code(self: ExitClass) u8 {
        return @intFromEnum(self);
    }
};

test "exit: classes keep the frozen 0-5 numbering" {
    const std = @import("std");
    try std.testing.expectEqual(@as(u8, 0), ExitClass.success.code());
    try std.testing.expectEqual(@as(u8, 1), ExitClass.rejected.code());
    try std.testing.expectEqual(@as(u8, 2), ExitClass.usage.code());
    try std.testing.expectEqual(@as(u8, 3), ExitClass.unavailable.code());
    try std.testing.expectEqual(@as(u8, 4), ExitClass.partial.code());
    try std.testing.expectEqual(@as(u8, 5), ExitClass.uncertain.code());
}
