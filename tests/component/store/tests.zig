// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
pub const sqlite = @import("sqlite_tests.zig");
pub const transactions = @import("transaction_tests.zig");
pub const recovery = @import("recovery_tests.zig");
pub const detection = @import("detection_tests.zig");
pub const retry_consumer = @import("retry_consumer_tests.zig");
test {
    std.testing.refAllDecls(@This());
}
