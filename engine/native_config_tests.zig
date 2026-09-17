// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
test "native: configuration registration" {
    _ = @import("config/native.zig");
    _ = @import("config/native_paths.zig");
    _ = @import("config/native_journal_profile.zig");
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

test "native: journal executable omission remains distinct from explicit empty and exact override" {
    const std = @import("std");
    const config = @import("config/native.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const header = "[jails.sshd]\nfilter = \"sshd\"\n";
    const omitted = try config.Config.parse(a, header);
    try std.testing.expect(!omitted.jails[0].journal_executables_explicit);
    const empty = try config.Config.parse(a, header ++ "journal_executables = []\n");
    try std.testing.expect(empty.jails[0].journal_executables_explicit);
    try std.testing.expectEqual(@as(usize, 0), empty.jails[0].journal_executables.len);
    const custom = try config.Config.parse(a, header ++ "journal_executables = [\"/opt/ssh/session\", \"/opt/ssh/listener\"]\n");
    try std.testing.expect(custom.jails[0].journal_executables_explicit);
    try std.testing.expectEqual(@as(usize, 2), custom.jails[0].journal_executables.len);
    try std.testing.expectEqualStrings("/opt/ssh/session", custom.jails[0].journal_executables[0]);
    try std.testing.expectEqualStrings("/opt/ssh/listener", custom.jails[0].journal_executables[1]);
}
