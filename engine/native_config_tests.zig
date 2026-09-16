// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
test "native: configuration registration" {
    _ = @import("config/native.zig");
    _ = @import("config/native_paths.zig");
}

test "native: default authority and explicit legacy opt-out" {
    const std = @import("std");
    const config = @import("config/native.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cfg = try config.Config.parse(arena.allocator(), "[global]\nmetrics_enabled = false\n");
    try std.testing.expect(cfg.global.native_ingestion);
    try config.validate(&cfg);
    cfg = try config.Config.parse(arena.allocator(), "[global]\nnative_ingestion = false\n");
    try std.testing.expectError(error.NativeIngestionRequired, config.validate(&cfg));
}
