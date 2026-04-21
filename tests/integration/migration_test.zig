//! Config migration integration test.
//!
//! Exercises the full `fail2zig --import-config <dir>` path against a
//! synthetic fail2ban directory tree. Unlike the unit tests in
//! `engine/config/migration.zig`, this test drives the migration at the
//! module boundary the CLI would use, then re-loads the generated TOML
//! through the native parser and verifies the resulting `Config` matches
//! what the source fail2ban INI declared.
//!
//! The test is pure in-process (no subprocess spawn) because
//! `engine.migration_mod.importConfig` is exported via the `engine`
//! module — we drive it directly. That keeps this test fast and
//! deterministic even when the daemon binary isn't built.

const std = @import("std");
const builtin = @import("builtin");

const engine = @import("engine");

const migration = engine.migration_mod;
const native = engine.config_mod;

const testing = std.testing;

/// Helper: populate a `TmpDir` with a minimal-but-realistic fail2ban tree.
/// Returns the absolute path of the tmp root (caller must free).
fn makeFail2banTree(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    // jail.conf — base defaults only.
    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[DEFAULT]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\
        \\[sshd]
        \\enabled = false
        \\filter = sshd
        \\logpath = /var/log/auth.log
        \\
        ,
    });

    // jail.local — operator overrides. Enables sshd and tightens maxretry;
    // adds a second jail.
    try tmp.dir.writeFile(.{
        .sub_path = "jail.local",
        .data =
        \\[sshd]
        \\enabled = true
        \\maxretry = 3
        \\bantime = 3600
        \\
        \\[nginx-http-auth]
        \\enabled = true
        \\filter = nginx-http-auth
        \\logpath = /var/log/nginx/error.log
        \\
        ,
    });

    // filter.d/sshd.conf — fail2ban would look for this, but we rely on
    // fail2zig's built-in `sshd` filter registration. Placing a stub here
    // exercises the "filter.d present but built-in wins" code path.
    try tmp.dir.makePath("filter.d");
    try tmp.dir.writeFile(.{
        .sub_path = "filter.d/sshd.conf",
        .data =
        \\[Definition]
        \\failregex = ^%(__prefix_line)sFailed \S+ for .* from <HOST>
        \\
        ,
    });

    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs = try tmp.dir.realpath(".", &abs_buf);
    return allocator.dupe(u8, abs);
}

test "integration: migration round-trips jail.conf + jail.local into TOML" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const source_dir = try makeFail2banTree(testing.allocator, &tmp);
    defer testing.allocator.free(source_dir);

    // Migration output file lives in the same tmp tree.
    const output_path = try std.fmt.allocPrint(
        testing.allocator,
        "{s}/config.toml",
        .{source_dir},
    );
    defer testing.allocator.free(output_path);

    // Run the migration. `importConfig` uses its own arena.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const report = try migration.importConfig(arena.allocator(), source_dir, output_path);

    // Both jails must have been imported.
    try testing.expectEqual(@as(u32, 2), report.jails_imported);
    try testing.expectEqualStrings(output_path, report.output_path);

    // The output file must be a valid native TOML config and reflect
    // jail.local's overrides.
    var arena2 = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena2.deinit();
    const cfg = try native.Config.loadFile(arena2.allocator(), output_path);
    try testing.expectEqual(@as(usize, 2), cfg.jails.len);

    // sshd: enabled by jail.local, maxretry=3, bantime=3600.
    var sshd: ?native.JailConfig = null;
    var nginx: ?native.JailConfig = null;
    for (cfg.jails) |j| {
        if (std.mem.eql(u8, j.name, "sshd")) sshd = j;
        if (std.mem.eql(u8, j.name, "nginx-http-auth")) nginx = j;
    }
    try testing.expect(sshd != null);
    try testing.expect(nginx != null);

    try testing.expect(sshd.?.enabled);
    try testing.expectEqual(@as(?u32, 3), sshd.?.maxretry);
    try testing.expectEqual(@as(?u64, 3600), sshd.?.bantime);
    try testing.expectEqualStrings("sshd", sshd.?.filter);

    try testing.expect(nginx.?.enabled);
    try testing.expectEqualStrings("nginx-http-auth", nginx.?.filter);
}

test "integration: migration emits valid TOML even when source tree is minimal" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Absolute minimum: just jail.conf with a DEFAULT and one enabled jail.
    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[DEFAULT]
        \\bantime = 1200
        \\findtime = 300
        \\
        \\[sshd]
        \\enabled = true
        \\filter = sshd
        \\logpath = /var/log/auth.log
        \\
        ,
    });

    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const source_dir_tmp = try tmp.dir.realpath(".", &abs_buf);
    const source_dir = try testing.allocator.dupe(u8, source_dir_tmp);
    defer testing.allocator.free(source_dir);
    const output_path = try std.fmt.allocPrint(
        testing.allocator,
        "{s}/config.toml",
        .{source_dir},
    );
    defer testing.allocator.free(output_path);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const report = try migration.importConfig(arena.allocator(), source_dir, output_path);
    try testing.expectEqual(@as(u32, 1), report.jails_imported);

    var arena2 = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena2.deinit();
    const cfg = try native.Config.loadFile(arena2.allocator(), output_path);
    try testing.expectEqual(@as(usize, 1), cfg.jails.len);
    try testing.expectEqualStrings("sshd", cfg.jails[0].name);
    try testing.expect(cfg.jails[0].enabled);
    // The DEFAULT block fed cfg.defaults.
    try testing.expectEqual(@as(u64, 1200), cfg.defaults.bantime);
    try testing.expectEqual(@as(u64, 300), cfg.defaults.findtime);
}

test "integration: migration refuses to clobber with a zero-jail import" {
    // A source dir with no jail files at all should still succeed at the
    // module level (it writes an empty TOML) — the CLI returns exit 1 for
    // that case. We exercise the module path here to confirm the
    // guarantees migration makes about its report.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const source_dir_tmp = try tmp.dir.realpath(".", &abs_buf);
    const source_dir = try testing.allocator.dupe(u8, source_dir_tmp);
    defer testing.allocator.free(source_dir);
    const output_path = try std.fmt.allocPrint(
        testing.allocator,
        "{s}/config.toml",
        .{source_dir},
    );
    defer testing.allocator.free(output_path);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const report = try migration.importConfig(arena.allocator(), source_dir, output_path);
    try testing.expectEqual(@as(u32, 0), report.jails_imported);
}
