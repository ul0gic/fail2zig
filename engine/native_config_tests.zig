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

test "native: validation diagnostics distinguish resource fields without changing the error" {
    const std = @import("std");
    const config = @import("config/native.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cfg = try config.Config.parse(arena.allocator(), "[global]\nmetrics_enabled = false\n");

    cfg.global.native_memory_ceiling_mb = 0;
    cfg.global.native_fd_ceiling = 0;
    var diag: config.ValidationDiagnostic = .{};
    try std.testing.expectError(error.InvalidNativeResources, config.validate(&cfg));
    try std.testing.expectError(error.InvalidNativeResources, config.validateDiag(&cfg, &diag));
    try std.testing.expectEqual(config.ValidationSection.global, diag.section);
    try std.testing.expectEqual(config.ValidationKey.native_memory_ceiling_mb, diag.key);
    var rendered: [96]u8 = undefined;
    try std.testing.expectEqualStrings("[global].native_memory_ceiling_mb: must be greater than 0", diag.render(&rendered));

    cfg.global.native_memory_ceiling_mb = 256;
    try std.testing.expectError(error.InvalidNativeResources, config.validateDiag(&cfg, &diag));
    try std.testing.expectEqual(config.ValidationKey.native_fd_ceiling, diag.key);
    try std.testing.expectEqualStrings("[global].native_fd_ceiling: must be greater than 0", diag.render(&rendered));
}

test "native: validation diagnostics preserve first jail and identify later jail failures" {
    const std = @import("std");
    const config = @import("config/native.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cfg = try config.Config.parse(
        arena.allocator(),
        "[global]\nmetrics_enabled = false\n[jails.first]\nfilter = \"sshd\"\njournal_executables = [\"relative\"]\n[jails.second]\nfilter = \"sshd\"\njournal_executables = [\"also-relative\"]\n",
    );
    var diag: config.ValidationDiagnostic = .{};
    try std.testing.expectError(error.InvalidNativePath, config.validateDiag(&cfg, &diag));
    try std.testing.expectEqualStrings("first", diag.jail());
    try std.testing.expectEqual(config.ValidationKey.journal_executables, diag.key);

    cfg.jails[0].journal_executables = &.{"/usr/bin/sshd"};
    try std.testing.expectError(error.InvalidNativePath, config.validate(&cfg));
    try std.testing.expectError(error.InvalidNativePath, config.validateDiag(&cfg, &diag));
    try std.testing.expectEqualStrings("second", diag.jail());
    var rendered: [96]u8 = undefined;
    try std.testing.expectEqualStrings(
        "journal_executables: entries must be absolute, bounded, and contain no NUL; jail 'second'",
        diag.render(&rendered),
    );
}

test "native: validation diagnostics distinguish defaults from jail policy" {
    const std = @import("std");
    const config = @import("config/native.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cfg = try config.Config.parse(arena.allocator(), "[global]\nmetrics_enabled = false\n[jails.web]\nfilter = \"sshd\"\n");
    cfg.defaults.maxretry = 0;
    cfg.jails[0].maxretry = 0;
    var diag: config.ValidationDiagnostic = .{};
    try std.testing.expectError(error.InvalidMaxretry, config.validateDiag(&cfg, &diag));
    try std.testing.expectEqual(config.ValidationSection.defaults, diag.section);
    try std.testing.expectEqual(@as(u8, 0), diag.jail_len);

    cfg.defaults.maxretry = 5;
    try std.testing.expectError(error.InvalidMaxretry, config.validate(&cfg));
    try std.testing.expectError(error.InvalidMaxretry, config.validateDiag(&cfg, &diag));
    try std.testing.expectEqual(config.ValidationSection.jail, diag.section);
    try std.testing.expectEqualStrings("web", diag.jail());
    var rendered: [96]u8 = undefined;
    try std.testing.expectEqualStrings("maxretry: must be between 1 and 128; jail 'web'", diag.render(&rendered));
}

test "native: validation diagnostics own escaped bounded jail context and clear on reuse" {
    const std = @import("std");
    const config = @import("config/native.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cfg = try config.Config.parse(arena.allocator(), "[global]\nmetrics_enabled = false\n[jails.safe]\nfilter = \"sshd\"\n");
    const hostile_name = "bad\x01'\\name-" ++ ("x" ** 80);
    cfg.jails[0].name = hostile_name;
    var diag: config.ValidationDiagnostic = .{};
    try std.testing.expectError(error.InvalidJailName, config.validateDiag(&cfg, &diag));
    try std.testing.expectEqual(config.ValidationDiagnostic.max_jail_bytes, diag.jail().len);
    try std.testing.expect(diag.jail_truncated);

    var full: [160]u8 = undefined;
    const full_text = diag.render(&full);
    try std.testing.expect(std.mem.startsWith(u8, full_text, "name: must be a valid jail identifier; jail 'bad\\x01\\'\\\\name-"));
    try std.testing.expect(std.mem.endsWith(u8, full_text, "...'"));
    try std.testing.expect(std.mem.indexOfScalar(u8, full_text, 0x01) == null);

    var short: [64]u8 = undefined;
    const short_text = diag.render(&short);
    try std.testing.expect(std.mem.startsWith(u8, short_text, "name: must be a valid jail identifier"));
    try std.testing.expect(std.mem.endsWith(u8, short_text, "..."));
    try std.testing.expect(!std.mem.endsWith(u8, short_text, "\\x."));

    cfg.jails[0].name = "safe";
    try config.validateDiag(&cfg, &diag);
    try std.testing.expectEqual(config.ValidationSection.none, diag.section);
    try std.testing.expectEqual(config.ValidationKey.none, diag.key);
    try std.testing.expectEqual(@as(u8, 0), diag.jail_len);
    try std.testing.expect(!diag.jail_truncated);
}
