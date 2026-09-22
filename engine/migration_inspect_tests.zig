// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const inspect = @import("migration/inspect.zig");

const fixture_root = "tests/fixtures/fail2ban/config";

fn fixture(name: []const u8) inspect.Options {
    return .{ .source_dir = std.fs.path.join(t.allocator, &.{ fixture_root, name }) catch unreachable, .tool_version = "test" };
}

fn render(manifest: *const inspect.Manifest) ![]u8 {
    var buf = std.ArrayList(u8).init(t.allocator);
    errdefer buf.deinit();
    try inspect.renderJson(manifest, buf.writer());
    return buf.toOwnedSlice();
}

fn group(manifest: *const inspect.Manifest, name: []const u8) *const inspect.Group {
    for (manifest.groups) |*g| if (std.mem.eql(u8, g.name, name)) return g;
    unreachable;
}

fn hasReason(d: inspect.Disposition, reason: []const u8) bool {
    for (d.reasons) |r| if (std.mem.eql(u8, r, reason)) return true;
    return false;
}

const Snapshot = struct { path: []const u8, mtime: i128, sha256: [32]u8 };

fn snapshotTree(a: std.mem.Allocator, dir_path: []const u8) ![]Snapshot {
    var list = std.ArrayList(Snapshot).init(a);
    var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();
    var walker = try dir.walk(a);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const stat = try entry.dir.statFile(entry.basename);
        const bytes = try entry.dir.readFileAlloc(a, entry.basename, 1 << 20);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        try list.append(.{ .path = try a.dupe(u8, entry.path), .mtime = stat.mtime, .sha256 = digest });
    }
    const slice = try list.toOwnedSlice();
    std.mem.sort(Snapshot, slice, {}, struct {
        fn lt(_: void, x: Snapshot, y: Snapshot) bool {
            return std.mem.order(u8, x.path, y.path) == .lt;
        }
    }.lt);
    return slice;
}

test "migration inspect: supported tree maps every enabled group and exits success" {
    const opts = fixture("supported");
    defer t.allocator.free(opts.source_dir);
    var m = try inspect.inspect(t.allocator, opts);
    defer m.deinit();
    try t.expectEqual(inspect.ExitClass.success, inspect.exitClass(&m));
    try t.expectEqual(@as(usize, 3), m.groups.len);
    try t.expectEqual(@as(usize, 0), m.assets.len);
    try t.expectEqual(@as(usize, 0), m.unknown_values.len);

    const sshd = group(&m, "sshd");
    try t.expect(sshd.enabled);
    try t.expectEqual(inspect.DispositionKind.supported, sshd.disposition.kind);
    try t.expectEqualStrings("sshd", sshd.mapping.builtin_filter.?);
    try t.expectEqualStrings("systemd", sshd.backend);
    try t.expectEqualStrings("host", sshd.mapping.scope);
    try t.expectEqualStrings("600s", sshd.mapping.duration);
    try t.expectEqualStrings("_SYSTEMD_UNIT=sshd.service + _COMM=sshd", sshd.journalmatch.?);
    try t.expectEqual(@as(usize, 2), sshd.ignoreip.len);

    const nginx = group(&m, "nginx-http-auth");
    try t.expectEqual(inspect.DispositionKind.supported, nginx.disposition.kind);
    try t.expectEqual(@as(usize, 1), nginx.logpaths.len);
    try t.expectEqualStrings("/var/log/nginx/error.log", nginx.logpaths[0]);

    const postfix = group(&m, "postfix");
    try t.expect(!postfix.enabled);
    try t.expectEqual(inspect.DispositionKind.not_enabled, postfix.disposition.kind);
}

test "migration inspect: jail.local overrides jail.d which overrides jail.conf with provenance" {
    const opts = fixture("supported");
    defer t.allocator.free(opts.source_dir);
    var m = try inspect.inspect(t.allocator, opts);
    defer m.deinit();
    try t.expectEqualStrings("3", group(&m, "sshd").maxretry.?);
    try t.expectEqualStrings("3600s", group(&m, "nginx-http-auth").mapping.duration);
    try t.expectEqual(@as(usize, 3), m.files.len);
    try t.expectEqualStrings("jail.conf", m.files[0].path);
    try t.expectEqualStrings("jail.d/10-sshd.conf", m.files[1].path);
    try t.expectEqualStrings("jail.local", m.files[2].path);
    for (m.files) |f| try t.expectEqual(inspect.SourceFile, @TypeOf(f));
    for (m.files) |f| try t.expectEqual(.layer, f.edge);
}

test "migration inspect: sha256 of each source file matches the bytes on disk" {
    const opts = fixture("supported");
    defer t.allocator.free(opts.source_dir);
    var m = try inspect.inspect(t.allocator, opts);
    defer m.deinit();
    for (m.files) |f| {
        const full = try std.fs.path.join(t.allocator, &.{ opts.source_dir, f.path });
        defer t.allocator.free(full);
        const bytes = try std.fs.cwd().readFileAlloc(t.allocator, full, 1 << 20);
        defer t.allocator.free(bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        try t.expectEqualSlices(u8, &digest, &f.sha256);
    }
}

test "migration inspect: repeated inspection renders byte-identical JSON" {
    const opts = fixture("blocker");
    defer t.allocator.free(opts.source_dir);
    var first = try inspect.inspect(t.allocator, opts);
    defer first.deinit();
    const a = try render(&first);
    defer t.allocator.free(a);
    var second = try inspect.inspect(t.allocator, opts);
    defer second.deinit();
    const b = try render(&second);
    defer t.allocator.free(b);
    try t.expectEqualStrings(a, b);
    try t.expect(std.mem.startsWith(u8, a, "{\"schema_version\":1,\"tool_version\":\"test\",\"reference_profile\":\"fail2ban-1.1.1\",\"source\":{\"dir\":"));
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, a, .{});
    defer parsed.deinit();
    const keys = parsed.value.object.keys();
    const expected = [_][]const u8{ "schema_version", "tool_version", "reference_profile", "source", "groups", "assets", "unknown_values" };
    try t.expectEqual(expected.len, keys.len);
    for (expected, keys) |e, k| try t.expectEqualStrings(e, k);
}

test "migration inspect: operator-change tree reports hostname, increment and modified stock filter" {
    const opts = fixture("operator-change");
    defer t.allocator.free(opts.source_dir);
    var m = try inspect.inspect(t.allocator, opts);
    defer m.deinit();
    try t.expectEqual(inspect.ExitClass.rejected, inspect.exitClass(&m));
    const sshd = group(&m, "sshd");
    try t.expectEqual(inspect.DispositionKind.operator_change, sshd.disposition.kind);
    try t.expect(hasReason(sshd.disposition, "ignoreip-hostname:gateway.example"));
    try t.expect(hasReason(sshd.disposition, "bantime-increment"));
    try t.expect(hasReason(sshd.disposition, "stock-filter-modified"));
    try t.expectEqualStrings("sshd", sshd.mapping.builtin_filter.?);
    try t.expectEqual(@as(usize, 1), m.assets.len);
    try t.expectEqualStrings("sshd", m.assets[0].name);
    try t.expectEqual(inspect.AssetKind.filter, m.assets[0].kind);
    try t.expectEqual(inspect.StockState.modified, m.assets[0].modified_vs_stock);
    try t.expectEqual(inspect.DispositionKind.operator_change, m.assets[0].disposition.kind);
}

test "migration inspect: blocker tree reports custom filter, custom action, ignorecommand and cycle" {
    const opts = fixture("blocker");
    defer t.allocator.free(opts.source_dir);
    var m = try inspect.inspect(t.allocator, opts);
    defer m.deinit();
    try t.expectEqual(inspect.ExitClass.rejected, inspect.exitClass(&m));

    const myapp = group(&m, "myapp");
    try t.expectEqual(inspect.DispositionKind.blocker, myapp.disposition.kind);
    try t.expect(hasReason(myapp.disposition, "custom-filter:myapp"));
    try t.expect(myapp.mapping.builtin_filter == null);

    const sshd = group(&m, "sshd");
    try t.expectEqual(inspect.DispositionKind.blocker, sshd.disposition.kind);
    try t.expect(hasReason(sshd.disposition, "custom-action-script:notify-admin"));

    const nginx = group(&m, "nginx-http-auth");
    try t.expectEqual(inspect.DispositionKind.blocker, nginx.disposition.kind);
    try t.expect(hasReason(nginx.disposition, "ignorecommand"));
    try t.expect(hasReason(nginx.disposition, "interpolation-error:bantime:InterpolationCycle"));
    try t.expect(hasReason(nginx.disposition, "interpolation-error:findtime:InterpolationCycle"));

    try t.expectEqual(@as(usize, 2), m.assets.len);
    try t.expectEqual(inspect.AssetKind.filter, m.assets[0].kind);
    try t.expectEqualStrings("myapp", m.assets[0].name);
    try t.expectEqual(inspect.DispositionKind.blocker, m.assets[0].disposition.kind);
    try t.expectEqual(inspect.AssetKind.action, m.assets[1].kind);
    try t.expectEqualStrings("notify-admin", m.assets[1].name);
}

test "migration inspect: portsentry Fail2ban history format is a blocker" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const config =
        \\[portsentry]
        \\enabled = true
        \\filter = portsentry
        \\backend = polling
        \\logpath = /var/lib/portsentry/portsentry.history
        \\banaction = nftables-allports
        \\
    ;
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = config });
    const path = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(path);
    var m = try inspect.inspect(t.allocator, .{ .source_dir = path });
    defer m.deinit();

    try t.expectEqual(inspect.ExitClass.rejected, inspect.exitClass(&m));
    const portsentry = group(&m, "portsentry");
    try t.expect(portsentry.enabled);
    try t.expectEqual(inspect.DispositionKind.blocker, portsentry.disposition.kind);
    try t.expect(hasReason(portsentry.disposition, "portsentry-history-format-unverified"));
    try t.expectEqualStrings("portsentry", portsentry.mapping.builtin_filter.?);
}

test "migration inspect: disabled tree keeps groups visible and retains unknown keys" {
    const opts = fixture("disabled");
    defer t.allocator.free(opts.source_dir);
    var m = try inspect.inspect(t.allocator, opts);
    defer m.deinit();
    try t.expectEqual(inspect.ExitClass.success, inspect.exitClass(&m));
    try t.expectEqual(@as(usize, 2), m.groups.len);
    for (m.groups) |g| {
        try t.expect(!g.enabled);
        try t.expectEqual(inspect.DispositionKind.not_enabled, g.disposition.kind);
        try t.expectEqual(@as(usize, 0), g.disposition.reasons.len);
    }
    try t.expectEqual(@as(usize, 1), m.unknown_values.len);
    try t.expectEqualStrings("sshd", m.unknown_values[0].section);
    try t.expectEqualStrings("operator_note", m.unknown_values[0].key);
    try t.expectEqualStrings("jail.conf:12", m.unknown_values[0].provenance);
    var table = std.ArrayList(u8).init(t.allocator);
    defer table.deinit();
    try inspect.renderTable(&m, table.writer());
    try t.expect(std.mem.indexOf(u8, table.items, "operator_note") != null);
    try t.expect(std.mem.endsWith(u8, table.items, "exit: success\n"));
}

test "migration inspect: inspection never modifies the source tree" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{ "supported", "operator-change", "blocker", "disabled" }) |name| {
        const dir = try std.fs.path.join(a, &.{ fixture_root, name });
        const before = try snapshotTree(a, dir);
        var m = try inspect.inspect(t.allocator, .{ .source_dir = dir });
        m.deinit();
        const after = try snapshotTree(a, dir);
        try t.expectEqual(before.len, after.len);
        for (before, after) |x, y| {
            try t.expectEqualStrings(x.path, y.path);
            try t.expectEqual(x.mtime, y.mtime);
            try t.expectEqualSlices(u8, &x.sha256, &y.sha256);
        }
    }
}

test "migration inspect: unreadable or empty source directory is a typed error" {
    try t.expectError(error.SourceUnreadable, inspect.inspect(t.allocator, .{ .source_dir = "tests/fixtures/fail2ban/config/does-not-exist" }));
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(path);
    try t.expectError(error.NoJailConfiguration, inspect.inspect(t.allocator, .{ .source_dir = path }));
}

test "migration inspect: symlinked source directory resolves and reports relative paths" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const target = try std.fs.cwd().realpathAlloc(t.allocator, fixture_root ++ "/supported");
    defer t.allocator.free(target);
    try tmp.dir.symLink(target, "linked", .{ .is_directory = true });
    const link = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(link);
    const source_dir = try std.fs.path.join(t.allocator, &.{ link, "linked" });
    defer t.allocator.free(source_dir);
    var m = try inspect.inspect(t.allocator, .{ .source_dir = source_dir });
    defer m.deinit();
    try t.expectEqual(inspect.ExitClass.success, inspect.exitClass(&m));
    try t.expectEqualStrings("jail.conf", m.files[0].path);
    try t.expectEqualStrings("jail.local", m.files[2].path);
}

test "migration inspect: oversized file is a typed error" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const big = try t.allocator.alloc(u8, 1024 * 1024 + 1);
    defer t.allocator.free(big);
    @memset(big, '#');
    big[0] = '\n';
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = big });
    const path = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(path);
    try t.expectError(error.FileTooLarge, inspect.inspect(t.allocator, .{ .source_dir = path }));
}

test "migration inspect: too many drop-in files is a typed error" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = "[DEFAULT]\nbantime = 1h\n" });
    try tmp.dir.makeDir("jail.d");
    var i: usize = 0;
    var name_buf: [32]u8 = undefined;
    while (i < 1025) : (i += 1) {
        const name = try std.fmt.bufPrint(&name_buf, "jail.d/{d:0>5}.conf", .{i});
        try tmp.dir.writeFile(.{ .sub_path = name, .data = "[x]\n" });
    }
    const path = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(path);
    try t.expectError(error.TooManyFiles, inspect.inspect(t.allocator, .{ .source_dir = path }));
}

test "migration inspect: group limit and manifest byte limit are typed errors" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var text = std.ArrayList(u8).init(t.allocator);
    defer text.deinit();
    try text.appendSlice("[DEFAULT]\nbantime = 1h\n");
    var i: usize = 0;
    while (i < 3) : (i += 1) try text.writer().print("[jail{d}]\nenabled = false\n", .{i});
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = text.items });
    const path = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(path);
    try t.expectError(error.TooManyGroups, inspect.inspect(t.allocator, .{ .source_dir = path, .limits = .{ .max_groups = 2 } }));
    try t.expectError(error.ManifestTooLarge, inspect.inspect(t.allocator, .{ .source_dir = path, .limits = .{ .max_manifest_bytes = 64 } }));
    var m = try inspect.inspect(t.allocator, .{ .source_dir = path, .limits = .{ .max_groups = 3 } });
    defer m.deinit();
    try t.expectEqual(@as(usize, 3), m.groups.len);
}

test "migration inspect: port-scoped, glob and duration edge cases are classified" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = 
        \\[DEFAULT]
        \\banaction = iptables-multiport
        \\action = %(banaction)s[port="%(port)s"]
        \\[sshd]
        \\enabled = yes
        \\port = ssh
        \\logpath = /var/log/auth.log*
        \\bantime = -1
        \\maxretry = 200
        \\[postfix]
        \\enabled = on
        \\backend = weird
        \\bantime = 0
        \\findtime = -1
        \\action = nftables[type=allports]
        \\[dovecot]
        \\enabled = true
        \\backend = systemd
        \\action = ipset-allports
        \\protocol = icmp
        \\chain = FORWARD
        \\
    });
    const path = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(path);
    var m = try inspect.inspect(t.allocator, .{ .source_dir = path });
    defer m.deinit();

    const sshd = group(&m, "sshd");
    try t.expectEqual(inspect.DispositionKind.operator_change, sshd.disposition.kind);
    try t.expect(!hasReason(sshd.disposition, "port-scope-widened-to-host"));
    try t.expect(hasReason(sshd.disposition, "logpath-glob"));
    try t.expect(hasReason(sshd.disposition, "maxretry-out-of-range:200"));
    try t.expectEqualStrings("permanent", sshd.mapping.duration);
    try t.expectEqualStrings("port", sshd.mapping.scope);

    const postfix = group(&m, "postfix");
    try t.expectEqual(inspect.DispositionKind.blocker, postfix.disposition.kind);
    try t.expect(hasReason(postfix.disposition, "unsupported-backend:weird"));
    try t.expect(hasReason(postfix.disposition, "zero-bantime"));
    try t.expect(hasReason(postfix.disposition, "invalid-findtime:-1"));
    try t.expectEqualStrings("host", postfix.mapping.scope);

    const dovecot = group(&m, "dovecot");
    try t.expectEqual(inspect.DispositionKind.blocker, dovecot.disposition.kind);
    try t.expect(hasReason(dovecot.disposition, "unsupported-protocol:icmp"));
    try t.expect(hasReason(dovecot.disposition, "unsupported-chain:FORWARD"));
}

fn asset(manifest: *const inspect.Manifest, kind: inspect.AssetKind, name: []const u8) *const inspect.Asset {
    for (manifest.assets) |*a| if (a.kind == kind and std.mem.eql(u8, a.name, name)) return a;
    unreachable;
}

test "migration inspect: an untouched 1.1.1 stock tree with the lab override inspects as supported" {
    const opts = fixture("stock-1.1.1");
    defer t.allocator.free(opts.source_dir);
    var m = try inspect.inspect(t.allocator, opts);
    defer m.deinit();
    const sshd = group(&m, "sshd");
    if (sshd.disposition.kind != .supported) {
        std.debug.print("stock sshd reasons: {s}\n", .{sshd.disposition.reasons});
    }
    try t.expectEqual(inspect.DispositionKind.supported, sshd.disposition.kind);
    try t.expectEqual(inspect.ExitClass.success, inspect.exitClass(&m));
    try t.expectEqualStrings("sshd[mode=normal]", sshd.filter);
    try t.expectEqualStrings("sshd", sshd.mapping.builtin_filter.?);
    try t.expectEqualStrings("polling", sshd.backend);
    try t.expectEqualStrings("/var/log/auth.log", sshd.logpaths[0]);
    try t.expectEqualStrings("port", sshd.mapping.scope);
    try t.expectEqualStrings("3600s", sshd.mapping.duration);
    try t.expectEqualStrings("<known/chain>", sshd.chain.?);
    try t.expectEqual(inspect.StockState.stock, asset(&m, .filter, "sshd").modified_vs_stock);
    try t.expectEqual(inspect.DispositionKind.supported, asset(&m, .filter, "sshd").disposition.kind);
    try t.expectEqual(inspect.StockState.stock, asset(&m, .action, "nftables").modified_vs_stock);
    for (m.groups) |g| if (!g.enabled) try t.expectEqual(inspect.DispositionKind.not_enabled, g.disposition.kind);
    const json = try render(&m);
    defer t.allocator.free(json);
    try t.expect(std.mem.indexOf(u8, json, "\"modified_vs_stock\":false") != null);
    try t.expect(std.mem.indexOf(u8, json, "interpolation-error") == null);
}

test "migration inspect: a one-byte edit or a .local overlay on a stock filter is reported as modified" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    var src = try std.fs.cwd().openDir(fixture_root ++ "/stock-1.1.1", .{ .iterate = true });
    defer src.close();
    var walker = try src.walk(t.allocator);
    defer walker.deinit();
    while (try walker.next()) |entry| switch (entry.kind) {
        .directory => try tmp.dir.makePath(entry.path),
        .file => {
            if (std.fs.path.dirname(entry.path)) |parent| try tmp.dir.makePath(parent);
            try entry.dir.copyFile(entry.basename, tmp.dir, entry.path, .{});
        },
        else => {},
    };
    {
        const file = try tmp.dir.openFile("filter.d/sshd.conf", .{ .mode = .read_write });
        defer file.close();
        try file.seekFromEnd(0);
        try file.writeAll("\n");
    }
    var edited = try inspect.inspect(t.allocator, .{ .source_dir = root });
    defer edited.deinit();
    try t.expectEqual(inspect.DispositionKind.operator_change, group(&edited, "sshd").disposition.kind);
    try t.expect(hasReason(group(&edited, "sshd").disposition, "stock-filter-modified"));
    try t.expectEqual(inspect.StockState.modified, asset(&edited, .filter, "sshd").modified_vs_stock);
    try t.expectEqual(inspect.StockState.stock, asset(&edited, .action, "nftables").modified_vs_stock);

    try tmp.dir.copyFile("filter.d/sshd.conf", tmp.dir, "filter.d/sshd.conf.tmp", .{});
    try src.copyFile("filter.d/sshd.conf", tmp.dir, "filter.d/sshd.conf", .{});
    try tmp.dir.deleteFile("filter.d/sshd.conf.tmp");
    try tmp.dir.writeFile(.{ .sub_path = "filter.d/sshd.local", .data = "[Definition]\nignoreregex = ^.*10\\.0\\.0\\.1.*$\n" });
    var overlay = try inspect.inspect(t.allocator, .{ .source_dir = root });
    defer overlay.deinit();
    try t.expect(hasReason(group(&overlay, "sshd").disposition, "stock-filter-modified"));
    try t.expectEqual(inspect.StockState.modified, asset(&overlay, .filter, "sshd").modified_vs_stock);

    try tmp.dir.deleteFile("filter.d/sshd.local");
    try tmp.dir.writeFile(.{ .sub_path = "jail.d/zz.conf", .data = "[sshd]\nfilter = sshd[mode=aggressive]\nusedns = yes\n" });
    var params = try inspect.inspect(t.allocator, .{ .source_dir = root });
    defer params.deinit();
    try t.expect(hasReason(group(&params, "sshd").disposition, "filter-parameters-unverified"));
    try t.expect(hasReason(group(&params, "sshd").disposition, "usedns"));
    try t.expectEqual(inspect.StockState.stock, asset(&params, .filter, "sshd").modified_vs_stock);
}
