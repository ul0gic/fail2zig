// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Defines the process exit classes and their numeric codes.
// Holds: Each class's enum value is the process exit status itself, 0 through 5; code returns it unmapped.

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
