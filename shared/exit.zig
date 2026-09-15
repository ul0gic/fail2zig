// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

//! Native exit classification shared by every `fail2zig` entry point.
//! Classes 4 and 5 are reserved for typed administration/migration outcomes that
//! observe a durable effect; entry points that cannot observe one never emit them.

pub const ExitClass = enum(u8) {
    /// Operation completed and every claimed effect was observed.
    success = 0,
    /// Valid request refused by the daemon or the local operation.
    rejected = 1,
    /// Usage, argument parsing, output formatting or local validation failure.
    usage = 2,
    /// Service or transport unavailable (no socket, refused, timeout).
    unavailable = 3,
    /// A durable effect was applied but verified incomplete.
    partial = 4,
    /// A durable effect may have been applied and could not be established.
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
