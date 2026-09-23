// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const effective = @import("engine_test").config.native_effective;
const native = @import("engine_test").config.native;
const Fixture = struct {
    tmp: t.TmpDir,
    root: []u8,
    fn init() !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        return .{ .tmp = tmp, .root = try tmp.dir.realpathAlloc(t.allocator, ".") };
    }
    fn deinit(self: *Fixture) void {
        t.allocator.free(self.root);
        self.tmp.cleanup();
    }
    fn write(self: *Fixture, path: []const u8, data: []const u8) !void {
        if (std.fs.path.dirname(path)) |dir| try self.tmp.dir.makePath(dir);
        try self.tmp.dir.writeFile(.{ .sub_path = path, .data = data, .flags = .{ .mode = 0o600 } });
    }
    fn base(self: *Fixture) !void {
        try self.write("jail.conf", "[DEFAULT]\nfindtime=2m 3s\nbantime=10m\nmaxretry=4\n[probe]\nenabled=true\nbackend=polling\nlogpath=/original/input.log tail\nfilter=original\nignoreip=192.0.2.0/24\nignoreself=false\nusedns=no\n");
        try self.write("filter.d/original.conf", "[Definition]\nfailregex=original hostile input fixture\ndatepattern=EPOCH\n");
    }
};
fn binding(jail: effective.Jail, proofs: []const effective.AssetBinding) effective.Binding {
    return .{ .jail = jail.name, .prepared_generation = jail.generation, .rule_generation = [_]u8{3} ** 32, .native_filter = "qualified-original", .assets = proofs, .source_kind = .file, .timestamp = .{ .field = .{ .format = .epoch_seconds, .boundary = .{ .delimiter = ' ' } } }, .family = .v4, .effect_scope_generation = [_]u8{4} ** 32 };
}
test "native effective: layers includes local order and raw provenance remain intact" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    try f.write("jail.conf", "[INCLUDES]\nbefore=before.conf\nafter=after.conf\n[probe]\nenabled=true\nbackend=polling\nfilter=original\nlogpath=/original/input.log\nmaxretry=2\n");
    try f.write("before.conf", "[DEFAULT]\nmaxretry=1\nfindtime=60\n");
    try f.write("after.conf", "[probe]\nmaxretry=3\n");
    try f.write("jail.d/10-first.conf", "[probe]\nmaxretry=4\n");
    try f.write("jail.local", "[probe]\nmaxretry=5\n");
    try f.write("jail.d/99-last.local", "[probe]\nmaxretry=6\n");
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    try t.expectEqual(@as(usize, 1), p.jails.len);
    const graph = p.document.source;
    try t.expectEqual(@as(usize, 6), graph.sources.items.len);
    try t.expectEqualStrings("6", graph.section("probe").?.get("maxretry").?);
    try t.expectEqualStrings("5", graph.section("probe").?.previous.get("maxretry").?);
    try t.expectEqual(.before, graph.sources.items[0].edge);
    try t.expectEqual(.after, graph.sources.items[2].edge);
    try t.expect(std.mem.endsWith(u8, graph.sources.items[5].path, "99-last.local"));
    var found = false;
    for (p.jails[0].options) |option| if (std.mem.eql(u8, option.name, "maxretry")) {
        try t.expectEqualStrings("6", option.value.?);
        try t.expectEqualStrings("6", option.origin.?.raw);
        try t.expect(std.mem.endsWith(u8, option.origin.?.source, "99-last.local"));
        found = true;
    };
    try t.expect(found);
}
test "native effective: parameterized initial known and final jail filter context are distinct" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("jail.conf", "[probe]\nenabled=true\nbackend=systemd\nfilter=original[mode=focused]\ndatepattern=%(known/datepattern)s EPOCH\n");
    try f.write("filter.d/original.conf", "[Definition]\ndatepattern=TAI64N\nfailregex=mode=<mode>\njournalmatch=TYPE=<logtype> FORMAT=%(datepattern)s\n[Init]\nmode=default\n");
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    const asset = p.jails[0].assets[0];
    try t.expectEqualStrings("mode=focused", asset.combined.get("failregex").?);
    try t.expectEqualStrings("TYPE=journal FORMAT=TAI64N EPOCH", asset.combined.get("journalmatch").?);
    try t.expectEqualStrings("TAI64N EPOCH", p.jails[0].source.processing.date_patterns[0]);
    try t.expect(p.document.source.section("probe").?.get("known/datepattern") == null);
}
test "native effective: admission creates separate typed projection and retains original pending manifest" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    var original = native.Config{};
    original.global.compatibility_pending = true;
    original.global.compatibility_manifest = "original immutable evidence";
    var diag: effective.Diagnostic = .{};
    try t.expectError(error.MissingEffectiveBinding, effective.Projection.create(t.allocator, p, &original, &.{}, &diag));
    try t.expectEqualStrings("probe", diag.jail);
    const proofs = [_]effective.AssetBinding{.{ .generation = p.jails[0].assets[0].generation }};
    const bindings = [_]effective.Binding{binding(p.jails[0], &proofs)};
    const projected = try effective.Projection.create(t.allocator, p, &original, &bindings, &diag);
    defer projected.destroy();
    try t.expect(original.global.compatibility_pending);
    try t.expect(!projected.config.global.compatibility_pending);
    try t.expectEqualStrings(original.global.compatibility_manifest, projected.config.global.compatibility_manifest);
    try t.expect(projected.config.jails[0].enabled);
    try t.expectEqual(@as(u64, 123), projected.config.jails[0].findtime.?);
    try t.expectEqual(@as(u64, 600), projected.config.jails[0].bantime.?);
    try t.expectEqual(@as(u32, 4), projected.config.jails[0].maxretry.?);
    try t.expectEqual(.tail, projected.consumers[0].source.paths[0].start.?);
    try t.expectEqual(@as(i64, 123_000_000), projected.consumers[0].processing.window_us);
    try t.expectEqual(false, projected.consumers[0].ignore.self_required);
}
test "native effective: builtin named custom assets and unknown settings never inherit admission" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    try f.write("jail.local", "[probe]\nfilter=sshd\nignorecommand=never-execute-original-fixture\n");
    try f.write("filter.d/sshd.conf", "[Definition]\nfailregex=custom different from builtin\n");
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    const original = native.Config{};
    const proofs = [_]effective.AssetBinding{.{ .generation = p.jails[0].assets[0].generation }};
    var bindings = [_]effective.Binding{binding(p.jails[0], &proofs)};
    var diag: effective.Diagnostic = .{};
    try t.expectError(error.UnsupportedEffectiveOption, effective.Projection.create(t.allocator, p, &original, &bindings, &diag));
    try t.expectEqualStrings("ignorecommand", diag.key);
    try f.write("jail.local", "[probe]\nfilter=sshd\n");
    const clean = try effective.Prepared.create(t.allocator, f.root, .{});
    defer clean.destroy();
    bindings[0] = binding(clean.jails[0], &.{});
    bindings[0].native_filter = "sshd";
    try t.expectError(error.UnqualifiedEffectiveAsset, effective.Projection.create(t.allocator, clean, &original, &bindings, &diag));
}
test "native effective: source and asset generation changes invalidate consumer proof" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    const old = try effective.Prepared.create(t.allocator, f.root, .{});
    defer old.destroy();
    const proofs = [_]effective.AssetBinding{.{ .generation = old.jails[0].assets[0].generation }};
    var bindings = [_]effective.Binding{binding(old.jails[0], &proofs)};
    try f.write("jail.local", "[probe]\nmaxretry=7\n");
    const current = try effective.Prepared.create(t.allocator, f.root, .{});
    defer current.destroy();
    const original = native.Config{};
    var diag: effective.Diagnostic = .{};
    try t.expectError(error.EffectiveGenerationMismatch, effective.Projection.create(t.allocator, current, &original, &bindings, &diag));
    bindings[0].prepared_generation = current.jails[0].generation;
    var wrong = proofs;
    wrong[0].generation[0] ^= 1;
    bindings[0].assets = &wrong;
    try t.expectError(error.UnqualifiedEffectiveAsset, effective.Projection.create(t.allocator, current, &original, &bindings, &diag));
}
test "native effective: directory admission charges all nonmatches and bounds bytes arena" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    for ([_][]const u8{ "jail.d/a.txt", "jail.d/b.txt", "jail.d/c.txt" }) |path| try f.write(path, "unrelated original fixture\n");
    try t.expectError(error.ConfigDirectoryLimit, effective.Prepared.create(t.allocator, f.root, .{ .visited_entries = 2 }));
    try t.expectError(error.ConfigSourceByteLimit, effective.Prepared.create(t.allocator, f.root, .{ .source_bytes = 4 }));
    try t.expectError(error.OutOfMemory, effective.Prepared.create(t.allocator, f.root, .{ .arena_bytes = 4096 }));
}
test "native effective: recursive includes local companions cycles and depth retain evidence" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("jail.conf", "[INCLUDES]\nbefore=a.conf\n[probe]\nenabled=false\n");
    try f.write("a.conf", "[INCLUDES]\nbefore=b.conf\n[DEFAULT]\nfindtime=10\n");
    try f.write("b.conf", "[INCLUDES]\nbefore=a.conf\n[DEFAULT]\nfindtime=9\n");
    try f.write("a.local", "[DEFAULT]\nfindtime=11\n");
    try t.expectError(error.IncludeDepthExceeded, effective.Prepared.create(t.allocator, f.root, .{ .include_depth = 2 }));
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    try t.expectEqual(@as(usize, 1), p.document.source.warnings.items.len);
    try t.expectEqualStrings("include cycle skipped", p.document.source.warnings.items[0].message);
    try t.expectEqualStrings("11", p.document.source.section("DEFAULT").?.get("findtime").?);
}
fn allocation(a: std.mem.Allocator, root: []const u8) !void {
    const p = try effective.Prepared.create(a, root, .{});
    defer p.destroy();
    const original = native.Config{};
    var diag: effective.Diagnostic = .{};
    const proofs = [_]effective.AssetBinding{.{ .generation = p.jails[0].assets[0].generation }};
    const bindings = [_]effective.Binding{binding(p.jails[0], &proofs)};
    const projection = try effective.Projection.create(a, p, &original, &bindings, &diag);
    defer projection.destroy();
}
test "native effective: allocator failures reclaim preparation and projection owners" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    try t.checkAllAllocationFailures(t.allocator, allocation, .{f.root});
}

test "native effective: typed global logging state target and retention require explicit admission" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    try f.write("source.sqlite", "original source fixture must never be mutated");
    try f.write("fail2ban.conf", "[Definition]\nloglevel=WARNING\nlogtarget=stderr\nallowipv6=no\ndbfile=source.sqlite\ndbpurgeage=1d\ndbmaxmatches=10\n");
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    const target = try std.fs.path.join(t.allocator, &.{ f.root, "native.sqlite" });
    defer t.allocator.free(target);
    var original = native.Config{};
    original.global.state_file = target;
    original.global.compatibility_pending = true;
    const proofs = [_]effective.AssetBinding{.{ .generation = p.jails[0].assets[0].generation }};
    const bindings = [_]effective.Binding{binding(p.jails[0], &proofs)};
    var diag: effective.Diagnostic = .{};
    try t.expectError(error.RequiredEffectiveState, effective.Projection.create(t.allocator, p, &original, &bindings, &diag));
    var global = effective.GlobalBinding{ .prepared_generation = p.globals.config_generation, .state_file = target };
    try t.expectError(error.RequiredEffectiveState, effective.Projection.createWithGlobal(t.allocator, p, &original, global, &bindings, &diag));
    global.retention_generation = [_]u8{11} ** 32;
    const projected = try effective.Projection.createWithGlobal(t.allocator, p, &original, global, &bindings, &diag);
    defer projected.destroy();
    try t.expectEqual(native.LogLevel.warn, projected.config.global.log_level);
    try t.expectEqualStrings(target, projected.config.global.state_file);
    try t.expectEqualStrings("source.sqlite", projected.globals.source_dbfile.?);
    try t.expectEqual(@as(u64, 86400), projected.globals.retention.?.purge_age_seconds.?);
    try t.expectEqual(@as(u32, 10), projected.globals.retention.?.max_matches.?);
    try t.expect(original.global.compatibility_pending);
    const retained = try f.tmp.dir.readFileAlloc(t.allocator, "source.sqlite", 128);
    defer t.allocator.free(retained);
    try t.expectEqualStrings("original source fixture must never be mutated", retained);
    try t.expectError(error.FileNotFound, f.tmp.dir.access("native.sqlite", .{}));
}
test "native effective: source database aliases and disabled persistence cannot become native targets" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    try f.write("source.sqlite", "source fixture");
    try f.write("fail2ban.conf", "[Definition]\ndbfile=source.sqlite\n");
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    try f.tmp.dir.symLink("source.sqlite", "alias.sqlite", .{});
    const target = try std.fs.path.join(t.allocator, &.{ f.root, "alias.sqlite" });
    defer t.allocator.free(target);
    var original = native.Config{};
    original.global.state_file = target;
    const proofs = [_]effective.AssetBinding{.{ .generation = p.jails[0].assets[0].generation }};
    var bindings = [_]effective.Binding{binding(p.jails[0], &proofs)};
    var diag: effective.Diagnostic = .{};
    const global = effective.GlobalBinding{ .prepared_generation = p.globals.config_generation, .state_file = target };
    try t.expectError(error.UnsafeStateProjection, effective.Projection.createWithGlobal(t.allocator, p, &original, global, &bindings, &diag));
    try f.write("fail2ban.conf", "[Definition]\ndbfile=None\n");
    const disabled = try effective.Prepared.create(t.allocator, f.root, .{});
    defer disabled.destroy();
    bindings[0] = binding(disabled.jails[0], &proofs);
    try t.expectError(error.RequiredEffectiveState, effective.Projection.create(t.allocator, disabled, &original, &bindings, &diag));
}
test "native effective: unsupported global sinks levels pid semantics and duration overflow refuse" {
    const cases = [_]struct { line: []const u8, key: []const u8 }{
        .{ .line = "logtarget=SYSLOG", .key = "logtarget" },
        .{ .line = "loglevel=TRACE", .key = "loglevel" },
        .{ .line = "pidfile=/original/pid", .key = "pidfile" },
    };
    for (cases) |case| {
        var f = try Fixture.init();
        defer f.deinit();
        try f.base();
        const global = try std.fmt.allocPrint(t.allocator, "[Definition]\n{s}\n", .{case.line});
        defer t.allocator.free(global);
        try f.write("fail2ban.conf", global);
        const p = try effective.Prepared.create(t.allocator, f.root, .{});
        defer p.destroy();
        var diag: effective.Diagnostic = .{};
        const original = native.Config{};
        try t.expectError(error.UnsupportedEffectiveGlobal, effective.Projection.create(t.allocator, p, &original, &.{}, &diag));
        try t.expectEqualStrings(case.key, diag.key);
    }
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    try f.write("jail.local", "[probe]\nfindtime=18446744073709551615w\n");
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    const proofs = [_]effective.AssetBinding{.{ .generation = p.jails[0].assets[0].generation }};
    const bindings = [_]effective.Binding{binding(p.jails[0], &proofs)};
    var diag: effective.Diagnostic = .{};
    const original = native.Config{};
    try t.expectError(error.InvalidEffectiveDuration, effective.Projection.create(t.allocator, p, &original, &bindings, &diag));
}
test "native effective: unsafe config file refuses before any consumer projection" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    var file = try f.tmp.dir.openFile("jail.conf", .{ .mode = .read_write });
    try file.chmod(0o666);
    file.close();
    try t.expectError(error.UntrustedConfigFile, effective.Prepared.create(t.allocator, f.root, .{}));
}

test "native effective: projection generation binds concrete consumer time resolver and native global state" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    const proofs = [_]effective.AssetBinding{.{ .generation = p.jails[0].assets[0].generation }};
    var bindings = [_]effective.Binding{binding(p.jails[0], &proofs)};
    var original = native.Config{};
    var diag: effective.Diagnostic = .{};
    const first = try effective.Projection.create(t.allocator, p, &original, &bindings, &diag);
    defer first.destroy();
    bindings[0].rule_generation[0] ^= 1;
    const next = try effective.Projection.create(t.allocator, p, &original, &bindings, &diag);
    defer next.destroy();
    try t.expect(!std.mem.eql(u8, &first.generation, &next.generation));
    try t.expect(!std.mem.eql(u8, &first.consumers[0].processing.parent_generation, &next.consumers[0].processing.parent_generation));
    original.global.state_file = "/original/separate-native-state";
    const changed = try effective.Projection.create(t.allocator, p, &original, &bindings, &diag);
    defer changed.destroy();
    try t.expect(!std.mem.eql(u8, &next.generation, &changed.generation));
    bindings[0].timestamp = .{ .field = .{ .format = .syslog, .boundary = .{ .length = 15 } } };
    try t.expectError(error.SourceTimeContextRequired, effective.Projection.create(t.allocator, p, &original, &bindings, &diag));
}
test "native effective: enabled original protection cannot disappear from projection" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    var originals = [_]native.JailConfig{.{ .name = "not-in-import", .enabled = true }};
    const original = native.Config{ .jails = &originals };
    var diag: effective.Diagnostic = .{};
    try t.expectError(error.UnprojectedOriginalJail, effective.Projection.create(t.allocator, p, &original, &.{}, &diag));
    try t.expectEqualStrings("not-in-import", diag.jail);
}

test "native effective: NUL include and database source paths return typed errors before filesystem calls" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("jail.conf", "[INCLUDES]\nbefore=original\x00.conf\n[probe]\nenabled=false\n");
    try t.expectError(error.InvalidConfigPath, effective.Prepared.create(t.allocator, f.root, .{}));
    try f.base();
    try f.write("fail2ban.conf", "[Definition]\ndbfile=original\x00.sqlite\n");
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    const original = native.Config{};
    var diag: effective.Diagnostic = .{};
    try t.expectError(error.InvalidEffectiveValue, effective.Projection.create(t.allocator, p, &original, &.{}, &diag));
    try t.expectEqualStrings("dbfile", diag.key);
    try t.expectEqualStrings("invalid database source path", diag.detail);
}
test "native effective: disabled same-name jail needs explicit retirement and error diagnostics own bytes" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    try f.write("jail.local", "[probe]\nenabled=false\n");
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    var originals = [_]native.JailConfig{.{ .name = "probe", .enabled = true }};
    const original = native.Config{ .jails = &originals };
    var diag: effective.Diagnostic = .{};
    try t.expectError(error.OriginalJailRetirementRequired, effective.Projection.create(t.allocator, p, &original, &.{}, &diag));
    try t.expectEqualStrings("probe", diag.jail);
    try f.write("fail2ban.conf", "[Definition]\nloglevel=UNSUPPORTED_ORIGINAL_LEVEL\n");
    const invalid = try effective.Prepared.create(t.allocator, f.root, .{});
    defer invalid.destroy();
    const empty = native.Config{};
    try t.expectError(error.UnsupportedEffectiveGlobal, effective.Projection.create(t.allocator, invalid, &empty, &.{}, &diag));
    const reuse = try t.allocator.alloc(u8, 4 * 1024 * 1024);
    defer t.allocator.free(reuse);
    @memset(reuse, 0xa5);
    try t.expectEqualStrings("UNSUPPORTED_ORIGINAL_LEVEL", diag.detail);
    try t.expectEqual(@intFromPtr(&diag.detail_bytes), @intFromPtr(diag.detail.ptr));
    try t.expect(!diag.truncated);
}
test "native effective: socket runtime length and state alias refuse before unlink-capable IPC" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.base();
    const target = try std.fs.path.join(t.allocator, &.{ f.root, "native.sqlite" });
    defer t.allocator.free(target);
    var original = native.Config{};
    original.global.state_file = target;
    var diag: effective.Diagnostic = .{};
    const alias = try std.fmt.allocPrint(t.allocator, "[Definition]\nsocket={s}\n", .{target});
    defer t.allocator.free(alias);
    try f.write("fail2ban.conf", alias);
    const p = try effective.Prepared.create(t.allocator, f.root, .{});
    defer p.destroy();
    try t.expectError(error.UnsafeStateProjection, effective.Projection.create(t.allocator, p, &original, &.{}, &diag));
    var long = [_]u8{'x'} ** 108;
    long[0] = '/';
    const config = try std.fmt.allocPrint(t.allocator, "[Definition]\nsocket={s}\n", .{long});
    defer t.allocator.free(config);
    try f.write("fail2ban.conf", config);
    const invalid = try effective.Prepared.create(t.allocator, f.root, .{});
    defer invalid.destroy();
    try t.expectError(error.InvalidEffectiveValue, effective.Projection.create(t.allocator, invalid, &original, &.{}, &diag));
}
