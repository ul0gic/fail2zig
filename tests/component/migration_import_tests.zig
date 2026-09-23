// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const import = @import("engine_test").migration.import;
const db = @import("engine_test").migration.fail2ban_db;
const fixture = @import("engine_test").migration.fail2ban_fixture;
const snapshot = @import("engine_test").migration.sqlite_snapshot;
const plan = @import("engine_test").migration.plan;
const scope = @import("engine_test").firewall.scope;
const durable = @import("engine_test").core.record_store;
const effects = @import("engine_test").core.native_effect;

comptime {
    _ = @import("shared");
}

const t = std.testing;
const a = t.allocator;
const now_s: i64 = 1_700_000_000;
const now_us: i64 = now_s * std.time.us_per_s;

const Source = struct {
    tmp: t.TmpDir,
    root: []u8,
    path: []u8,

    fn init() !Source {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(a, ".");
        errdefer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "fail2ban.sqlite3" });
        errdefer a.free(path);
        return .{ .tmp = tmp, .root = root, .path = path };
    }

    fn deinit(self: *Source) void {
        a.free(self.path);
        a.free(self.root);
        self.tmp.cleanup();
    }

    fn empty(self: *Source, jails: []const []const u8) !void {
        try fixture.build(self.path, .{ .profile = .delete, .seed_rows = false });
        var writer = try fixture.openWriter(self.path);
        defer writer.close();
        for (jails) |jail| {
            var stmt = try writer.prepare("INSERT INTO jails(name, enabled) VALUES(?1, 1)");
            defer stmt.finalize();
            try stmt.bindText(1, jail);
            _ = try stmt.step();
        }
    }

    fn ban(self: *Source, row: fixture.BanRow) !void {
        var writer = try fixture.openWriter(self.path);
        defer writer.close();
        try fixture.insertBan(writer, "bans", row);
    }

    fn bip(self: *Source, row: fixture.BanRow) !void {
        var writer = try fixture.openWriter(self.path);
        defer writer.close();
        try fixture.insertBan(writer, "bips", row);
    }

    fn exec(self: *Source, sql: [*:0]const u8) !void {
        var writer = try fixture.openWriter(self.path);
        defer writer.close();
        try writer.exec(sql);
    }
};

const GroupSpec = struct { name: []const u8, enabled: bool = true, kind: []const u8 = "supported", scope: []const u8 = "host" };

const Doc = struct {
    arena: std.heap.ArenaAllocator,
    doc: plan.Document,

    fn init(groups: []const GroupSpec, selection: []const []const u8, blockers: []const plan.Blocker) !Doc {
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const al = arena.allocator();
        var json = std.ArrayList(u8).init(al);
        try json.appendSlice("{\"groups\":[");
        for (groups, 0..) |g, i| {
            if (i != 0) try json.append(',');
            try json.writer().print("{{\"name\":\"{s}\",\"enabled\":{},\"disposition\":{{\"kind\":\"{s}\",\"reasons\":[]}},\"mapping\":{{\"service\":\"{s}\",\"builtin_filter\":null,\"scope\":\"{s}\",\"duration\":\"finite\"}}}}", .{ g.name, g.enabled, g.kind, g.name, g.scope });
        }
        try json.appendSlice("]}");
        const manifest = try std.json.parseFromSliceLeaky(std.json.Value, al, json.items, .{});
        return .{ .arena = arena, .doc = .{
            .tool_version = "test",
            .host_id_hex = "00",
            .created_us = now_us,
            .valid_until_us = now_us + 1,
            .continuity = "reset_replay",
            .replay_window_s = 600,
            .source_dir = "/etc/fail2ban",
            .source_db = null,
            .snapshot = null,
            .snapshot_fp = null,
            .manifest = manifest,
            .assumptions = &.{},
            .semantic_changes = &.{},
            .blockers = blockers,
            .secret_boundaries = &.{},
            .selection = selection,
            .drift = .{ .files = &.{}, .runtime_socket = "/run/none", .runtime_state = "absent" },
            .digest = "",
        } };
    }

    fn deinit(self: *Doc) void {
        self.arena.deinit();
    }
};

fn run(source: *Source, doc: *const Doc, backend: import.Backend) !import.Staging {
    return import.import(a, .{ .snapshot_path = source.path, .document = &doc.doc, .backend = backend, .now_us = now_us });
}

fn hasBlocker(report: import.Report, group: []const u8, prefix: []const u8) bool {
    for (report.blockers) |b| if (std.mem.eql(u8, b.group, group) and std.mem.startsWith(u8, b.reason, prefix)) return true;
    return false;
}

fn hostRow(jail: []const u8, ip: []const u8, timeofban: i64, bantime: i64) fixture.BanRow {
    return .{ .jail = jail, .ip = ip, .timeofban = timeofban, .bantime = bantime, .bancount = 1, .data = "{}" };
}

const sshd_only = [_][]const u8{"sshd"};
const sshd_group = [_]GroupSpec{.{ .name = "sshd" }};

test "migration import: active, expired, permanent and IPv6 bans become owners with original deadlines" {
    var source = try Source.init();
    defer source.deinit();
    try source.empty(&.{"sshd"});
    try source.ban(hostRow("sshd", "192.0.2.10", now_s - 600, 3600));
    try source.ban(hostRow("sshd", "192.0.2.11", now_s - 7200, 3600));
    try source.ban(hostRow("sshd", "198.51.100.7", now_s - 86400, -1));
    try source.ban(hostRow("sshd", "2001:db8::1", now_s - 60, 600));
    try source.ban(hostRow("sshd", "192.0.2.12", now_s - 3600, 3600));
    var doc = try Doc.init(&sshd_group, &sshd_only, &.{});
    defer doc.deinit();
    var staging = try run(&source, &doc, .nftables);
    defer staging.deinit();

    try t.expect(!staging.report.blocked());
    try t.expectEqual(@as(u64, 3), staging.report.imported_owners);
    try t.expectEqual(@as(u64, 2), staging.report.skipped_expired);
    try t.expectEqual(@as(u64, 0), staging.report.double_count_avoided);
    try t.expectEqualStrings("unknown", staging.report.kernel_state);
    try t.expectEqual(@as(usize, 3), staging.owners.len);

    const active = staging.owners[0];
    try t.expectEqualStrings("sshd", active.jail);
    try t.expectEqual(import.LeaseKind.finite, active.lease_kind);
    try t.expectEqual((now_s - 600 + 3600) * std.time.us_per_s, active.deadline_us.?);
    try t.expectEqual((now_s - 600) * std.time.us_per_s, active.source_event_us);
    try t.expectEqual(@as(u64, 1), active.source_row);
    try t.expectEqual(scope.Family.v4, active.scope.subject.family);
    try t.expectEqual(scope.SubjectKind.host, active.scope.subject.kind);
    try t.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 10 }, active.scope.subject.address[0..4]);
    const decoded = try scope.Scope.decode(&active.encoded);
    try t.expectEqual(scope.Verdict.drop, decoded.verdict);
    try t.expect(decoded.protocols.isAll());
    try t.expect(decoded.ports.isAll());

    const permanent = staging.owners[1];
    try t.expectEqual(import.LeaseKind.permanent, permanent.lease_kind);
    try t.expect(permanent.deadline_us == null);
    try t.expectEqual(@as(u64, 3), permanent.source_row);

    const v6 = staging.owners[2];
    try t.expectEqual(scope.Family.v6, v6.scope.subject.family);
    try t.expectEqual(@as(u8, 128), v6.scope.subject.prefix);
    try t.expectEqual((now_s - 60 + 600) * std.time.us_per_s, v6.deadline_us.?);
}

test "migration import: unknown sentinel, zero, future and absent-ip rows are blockers with the row named" {
    var source = try Source.init();
    defer source.deinit();
    try source.empty(&.{"sshd"});
    try source.ban(hostRow("sshd", "198.51.100.8", now_s - 300, -2));
    try source.ban(hostRow("sshd", "198.51.100.9", now_s - 300, 0));
    try source.ban(hostRow("sshd", "198.51.100.10", now_s + 5, 600));
    try source.ban(.{ .jail = "sshd", .ip = null, .timeofban = now_s - 1, .bantime = 600, .data = null });
    try source.ban(hostRow("sshd", "not-an-ip", now_s - 1, 600));
    try source.ban(hostRow("sshd", "::ffff:192.0.2.5", now_s - 1, 600));
    try source.ban(hostRow("sshd", "192.0.2.20", now_s - 1, 600));
    var doc = try Doc.init(&sshd_group, &sshd_only, &.{});
    defer doc.deinit();
    var staging = try run(&source, &doc, .nftables);
    defer staging.deinit();

    try t.expect(staging.report.blocked());
    try t.expect(hasBlocker(staging.report, "sshd", "bantime-unknown-sentinel:row:1"));
    try t.expect(hasBlocker(staging.report, "sshd", "bantime-invalid:0:row:2"));
    try t.expect(hasBlocker(staging.report, "sshd", "timeofban-in-future:row:3"));
    try t.expect(hasBlocker(staging.report, "sshd", "ip-absent:row:4"));
    try t.expect(hasBlocker(staging.report, "sshd", "ip-invalid:row:5"));
    try t.expect(hasBlocker(staging.report, "sshd", "ip-invalid:row:6"));
    try t.expectEqual(@as(usize, 6), staging.report.blockers.len);
    try t.expectEqual(@as(u64, 1), staging.report.imported_owners);
    try t.expectEqual(@as(u64, 7), staging.owners[0].source_row);
}

test "migration import: network subjects need nftables or ipset and a canonical prefix" {
    var source = try Source.init();
    defer source.deinit();
    try source.empty(&.{"sshd"});
    try source.ban(hostRow("sshd", "192.0.2.0/24", now_s - 1, 3600));
    try source.ban(hostRow("sshd", "2001:db8:1::/48", now_s - 1, -1));
    var doc = try Doc.init(&sshd_group, &sshd_only, &.{});
    defer doc.deinit();

    inline for (.{ import.Backend.nftables, import.Backend.ipset }) |backend| {
        var staging = try run(&source, &doc, backend);
        defer staging.deinit();
        try t.expect(!staging.report.blocked());
        try t.expectEqual(@as(usize, 2), staging.owners.len);
        try t.expectEqual(scope.SubjectKind.network, staging.owners[0].scope.subject.kind);
        try t.expectEqual(@as(u8, 24), staging.owners[0].scope.subject.prefix);
        try t.expectEqual(scope.SubjectKind.network, staging.owners[1].scope.subject.kind);
        try t.expectEqual(@as(u8, 48), staging.owners[1].scope.subject.prefix);
        try t.expectEqual(import.LeaseKind.permanent, staging.owners[1].lease_kind);
    }
    var blocked = try run(&source, &doc, .iptables);
    defer blocked.deinit();
    try t.expect(hasBlocker(blocked.report, "sshd", "network-scope-unsupported-by-backend:iptables:row:1"));
    try t.expect(hasBlocker(blocked.report, "sshd", "network-scope-unsupported-by-backend:iptables:row:2"));
    try t.expectEqual(@as(usize, 0), blocked.owners.len);

    try source.ban(hostRow("sshd", "192.0.2.1/24", now_s - 1, 3600));
    var noncanonical = try run(&source, &doc, .nftables);
    defer noncanonical.deinit();
    try t.expect(hasBlocker(noncanonical.report, "sshd", "network-invalid:row:3"));
}

test "migration import: repeated live rows collapse to one owner and bips history never double counts" {
    var source = try Source.init();
    defer source.deinit();
    try source.empty(&.{"sshd"});
    try source.ban(hostRow("sshd", "192.0.2.10", now_s - 3000, 3600));
    try source.ban(.{ .jail = "sshd", .ip = "192.0.2.10", .timeofban = now_s - 600, .bantime = 3600, .bancount = 2, .data = null });
    try source.ban(hostRow("sshd", "192.0.2.10", now_s - 2000, -1));
    try source.ban(hostRow("sshd", "192.0.2.10", now_s - 100, 600));
    try source.bip(.{ .jail = "sshd", .ip = "192.0.2.10", .timeofban = now_s - 100, .bantime = 600, .bancount = 4, .data = null });
    try source.bip(.{ .jail = "sshd", .ip = "192.0.2.11", .timeofban = now_s - 90000, .bantime = 3600, .bancount = 3, .data = null });
    try source.bip(.{ .jail = "sshd", .ip = "198.51.100.8", .timeofban = now_s - 50, .bantime = -2, .bancount = 1, .data = null });
    var doc = try Doc.init(&sshd_group, &sshd_only, &.{});
    defer doc.deinit();
    var staging = try run(&source, &doc, .nftables);
    defer staging.deinit();

    try t.expect(!staging.report.blocked());
    try t.expectEqual(@as(usize, 1), staging.owners.len);
    try t.expectEqual(import.LeaseKind.permanent, staging.owners[0].lease_kind);
    try t.expectEqual((now_s - 100) * std.time.us_per_s, staging.owners[0].source_event_us);
    try t.expectEqual(@as(i64, 2), staging.owners[0].bancount);
    try t.expectEqual(@as(u64, 3 + 1), staging.report.double_count_avoided);
    try t.expectEqual(@as(usize, 2), staging.history.len);
    try t.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 11 }, staging.history[0].scope.subject.address[0..4]);
    try t.expectEqual((now_s - 90000) * std.time.us_per_s, staging.history[0].event_us);
    try t.expectEqual(@as(i64, 3), staging.history[0].bancount);
    try t.expectEqual(@as(u64, 2), staging.history[0].source_row);
    try t.expectEqual(import.EventKind.restored_ban, staging.history[0].event_kind);
    try t.expectEqualSlices(u8, &[_]u8{ 198, 51, 100, 8 }, staging.history[1].scope.subject.address[0..4]);
    try t.expectEqual(@as(u64, 2), staging.report.imported_history);
}

test "migration import: enabled snapshot jails without a supported selected plan group block, others are skipped" {
    var source = try Source.init();
    defer source.deinit();
    try source.empty(&.{ "sshd", "postfix", "nginx", "dovecot", "apache" });
    try source.exec("INSERT INTO jails(name, enabled) VALUES('recidive', 0)");
    try source.ban(hostRow("sshd", "192.0.2.10", now_s - 1, 600));
    try source.ban(hostRow("postfix", "192.0.2.11", now_s - 1, 600));
    try source.ban(hostRow("nginx", "192.0.2.12", now_s - 1, 600));
    try source.ban(hostRow("recidive", "192.0.2.13", now_s - 1, 600));
    try source.ban(hostRow("dovecot", "192.0.2.14", now_s - 1, 600));
    try source.ban(hostRow("apache", "192.0.2.15", now_s - 1, 600));
    const groups = [_]GroupSpec{
        .{ .name = "sshd" },
        .{ .name = "nginx", .kind = "blocker" },
        .{ .name = "dovecot" },
        .{ .name = "apache", .enabled = false, .kind = "not_enabled" },
    };
    var doc = try Doc.init(&groups, &.{ "sshd", "apache" }, &.{});
    defer doc.deinit();
    var staging = try run(&source, &doc, .nftables);
    defer staging.deinit();

    try t.expect(hasBlocker(staging.report, "postfix", "group-not-in-plan"));
    try t.expect(hasBlocker(staging.report, "nginx", "group-unsupported-in-plan"));
    try t.expect(hasBlocker(staging.report, "apache", "group-unsupported-in-plan"));
    try t.expectEqual(@as(usize, 3), staging.report.blockers.len);
    try t.expectEqual(@as(usize, 2), staging.report.skipped_unsupported.len);
    try t.expectEqualStrings("dovecot", staging.report.skipped_unsupported[0].group);
    try t.expectEqualStrings("group-not-selected", staging.report.skipped_unsupported[0].reason);
    try t.expectEqualStrings("recidive", staging.report.skipped_unsupported[1].group);
    try t.expectEqualStrings("jail-disabled-in-snapshot", staging.report.skipped_unsupported[1].reason);
    try t.expectEqual(@as(usize, 1), staging.owners.len);
    try t.expectEqualStrings("sshd", staging.owners[0].jail);
}

test "migration import: the snapshot enabled flag never gates import; the plan selection does" {
    var source = try Source.init();
    defer source.deinit();
    try source.empty(&.{});
    try source.exec("INSERT INTO jails(name, enabled) VALUES('sshd', 0), ('nginx-http-auth', 0), ('postfix', 0)");
    try source.ban(hostRow("sshd", "192.0.2.10", now_s - 600, 3600));
    try source.ban(hostRow("sshd", "192.0.2.11", now_s - 7200, 3600));
    try source.ban(hostRow("sshd", "198.51.100.7", now_s - 86400, -1));
    try source.ban(hostRow("nginx-http-auth", "203.0.113.9", now_s - 100, 600));
    try source.bip(hostRow("nginx-http-auth", "203.0.113.9", now_s - 100, 600));
    try source.ban(hostRow("postfix", "203.0.113.10", now_s - 100, 600));
    try source.ban(hostRow("ghost", "203.0.113.11", now_s - 100, 600));
    const groups = [_]GroupSpec{ .{ .name = "sshd" }, .{ .name = "nginx-http-auth" }, .{ .name = "postfix" } };
    var doc = try Doc.init(&groups, &.{ "sshd", "nginx-http-auth" }, &.{});
    defer doc.deinit();
    var staging = try run(&source, &doc, .nftables);
    defer staging.deinit();

    try t.expect(!staging.report.blocked());
    try t.expectEqual(@as(usize, 3), staging.owners.len);
    try t.expectEqualStrings("sshd", staging.owners[0].jail);
    try t.expectEqualStrings("sshd", staging.owners[1].jail);
    try t.expectEqualStrings("nginx-http-auth", staging.owners[2].jail);
    try t.expectEqual(@as(usize, 0), staging.history.len);
    try t.expectEqual(@as(u64, 1), staging.report.skipped_expired);
    try t.expectEqual(@as(u64, 1), staging.report.double_count_avoided);
    try t.expectEqual(@as(usize, 1), staging.report.skipped_unsupported.len);
    try t.expectEqualStrings("postfix", staging.report.skipped_unsupported[0].group);
    try t.expectEqualStrings("jail-disabled-in-snapshot", staging.report.skipped_unsupported[0].reason);
}

test "migration import: a plan carrying blockers or a malformed manifest is refused" {
    var source = try Source.init();
    defer source.deinit();
    try source.empty(&.{"sshd"});
    const blockers = [_]plan.Blocker{.{ .group = "*", .kind = "continuity", .reason = "replay-window-missing" }};
    var blocked = try Doc.init(&sshd_group, &sshd_only, &blockers);
    defer blocked.deinit();
    try t.expectError(error.PlanInvalid, run(&source, &blocked, .nftables));

    var malformed = try Doc.init(&sshd_group, &sshd_only, &.{});
    defer malformed.deinit();
    malformed.doc.manifest = .{ .string = "nope" };
    try t.expectError(error.PlanInvalid, run(&source, &malformed, .nftables));

    var unknown_scope = try Doc.init(&[_]GroupSpec{.{ .name = "sshd", .scope = "interface" }}, &sshd_only, &.{});
    defer unknown_scope.deinit();
    try source.ban(hostRow("sshd", "192.0.2.10", now_s - 1, 600));
    var staging = try run(&source, &unknown_scope, .nftables);
    defer staging.deinit();
    try t.expect(hasBlocker(staging.report, "sshd", "scope-mapping-unknown:interface"));
}

test "migration import: a captured snapshot of the seeded fixture imports through the real capture path" {
    var source = try Source.init();
    defer source.deinit();
    try fixture.build(source.path, .{ .profile = .wal_pending });
    const staging_dir = try std.fs.path.join(a, &.{ source.root, "staging" });
    defer a.free(staging_dir);
    try std.posix.mkdir(staging_dir, 0o700);
    var snap = try snapshot.capture(a, source.path, staging_dir, .{});
    defer snap.deinit(a);

    const groups = [_]GroupSpec{ .{ .name = "sshd" }, .{ .name = "nginx-http-auth", .enabled = false, .kind = "not_enabled" } };
    var doc = try Doc.init(&groups, &sshd_only, &.{});
    defer doc.deinit();
    var staging = try import.import(a, .{ .snapshot_path = snap.destination_path, .document = &doc.doc, .backend = .nftables, .now_us = now_us });
    defer staging.deinit();
    try t.expect(hasBlocker(staging.report, "sshd", "bantime-unknown-sentinel:row:4"));
    try t.expectEqual(@as(usize, 1), staging.report.blockers.len);
    try t.expectEqual(@as(u64, 3), staging.report.imported_owners);
    try t.expectEqual(@as(u64, 1), staging.report.skipped_expired);
    try t.expectEqualStrings("nginx-http-auth", staging.report.skipped_unsupported[0].group);
    try t.expectEqual(@as(u64, 2), staging.report.imported_history);
    try t.expectEqual(@as(u64, 3), staging.report.double_count_avoided);
    const digest = try snapshot.sha256File(snap.destination_path);
    try t.expectEqualSlices(u8, &snap.destination_sha256, &digest);
}

test "migration import: two hundred thousand generated bans rows import within the supported bound" {
    var source = try Source.init();
    defer source.deinit();
    try source.empty(&.{"sshd"});
    const total: u32 = @intCast(snapshot.Limits.max_ban_rows);
    {
        var writer = try fixture.openWriter(source.path);
        defer writer.close();
        try writer.exec("BEGIN");
        var stmt = try writer.prepare("INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES('sshd', ?1, ?2, 3600, 1, NULL)");
        defer stmt.finalize();
        var i: u32 = 0;
        while (i < total) : (i += 1) {
            const n = if (i % 10 == 9) i - 1 else i;
            var ip: [40]u8 = undefined;
            try stmt.bindText(1, try std.fmt.bufPrint(&ip, "2001:db8:{x}:{x}::1", .{ n >> 16, n & 0xffff }));
            try stmt.bindInt64(2, now_s - 60 - @as(i64, i % 50));
            _ = try stmt.step();
            _ = db.api.reset(stmt.stmt);
        }
        try writer.exec("COMMIT");
    }
    var doc = try Doc.init(&sshd_group, &sshd_only, &.{});
    defer doc.deinit();
    var timer = try std.time.Timer.start();
    var staging = try run(&source, &doc, .nftables);
    defer staging.deinit();
    const elapsed_ns = timer.read();
    try t.expect(!staging.report.blocked());
    try t.expectEqual(@as(u64, total - total / 10), staging.report.imported_owners);
    try t.expectEqual(@as(u64, total / 10), staging.report.double_count_avoided);
    try t.expectEqual(@as(u64, 0), staging.report.skipped_expired);
    try t.expect(elapsed_ns < 30 * std.time.ns_per_s);
}

const StoreFixture = struct {
    tmp: t.TmpDir,
    path: []u8,
    store: durable.Store,

    fn init() !StoreFixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
        errdefer a.free(path);
        var store = try durable.Store.open(a, path);
        errdefer store.close();
        try store.enableReceipts(8);
        try store.enableNativeTime();
        try store.enableYearInference();
        try store.enableDetection();
        try store.enableClockRecovery();
        try store.enableJournalDetection();
        try store.enableRetry();
        try store.enableConsumers();
        try store.enableEffects();
        try store.admitInstallation(try effects.Installation.init([_]u8{7} ** 16, .nftables, "host-default"), .{ .selector = "host-default", .disposition = .verified_absent });
        try store.enableTimeProvenance();
        try store.enableConsumerManifests();
        try store.enableConfirmedHistory();
        try store.enableMaintenance();
        try store.enableCleanup();
        try store.enableRetryLeases();
        try store.enableApplicationHistory();
        try store.enableEscalation();
        try store.enableCanonicalEffects();
        try store.enableHistoryResets();
        try store.enableActionTargets();
        try store.enableAdminState();
        try store.enableMigrationState();
        return .{ .tmp = tmp, .path = path, .store = store };
    }

    fn deinit(self: *StoreFixture) void {
        self.store.close();
        a.free(self.path);
        self.tmp.cleanup();
    }

    fn addRun(self: *StoreFixture, run_id: [32]u8) !void {
        var sql: [512]u8 = undefined;
        const text = try std.fmt.bufPrintZ(&sql, "INSERT INTO migration_runs VALUES(X'{s}',zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),'/var/lib/fail2zig/recovery',zeroblob(32),1,{d},{d});", .{ std.fmt.bytesToHex(run_id, .lower), now_us, now_us });
        try self.store.inspectExec(text);
    }

    fn count(self: *StoreFixture, comptime table: []const u8, run_id: [32]u8) !i64 {
        var sql: [256]u8 = undefined;
        const text = try std.fmt.bufPrintZ(&sql, "SELECT count(*) FROM " ++ table ++ " WHERE run_id=X'{s}';", .{std.fmt.bytesToHex(run_id, .lower)});
        return self.store.inspectInteger(text);
    }

    fn scalar(self: *StoreFixture, comptime sql: [:0]const u8) !i64 {
        return self.store.inspectInteger(sql);
    }

    fn handle(self: *StoreFixture) *db.Db {
        return @ptrCast(self.store.db);
    }

    fn stageRows(self: *StoreFixture, run_id: [32]u8, owners: []const import.StagedOwnerRow, history: []const import.StagedHistoryRow) !void {
        const conn = db.Connection{ .db = self.handle() };
        try self.store.inspectExec("BEGIN IMMEDIATE;");
        errdefer self.store.inspectExec("ROLLBACK;") catch {};
        inline for (.{ import.staging_sql.delete_owners, import.staging_sql.delete_history }) |sql| {
            var del = try conn.prepare(sql);
            defer del.finalize();
            try bindBlob(del, 1, &run_id);
            try t.expect(!try del.step());
        }
        for (owners, 1..) |row, seq| {
            var ins = try conn.prepare(import.staging_sql.insert_owner);
            defer ins.finalize();
            try bindBlob(ins, 1, &run_id);
            try ins.bindInt64(2, @intCast(seq));
            try ins.bindText(3, row.jail);
            try bindBlob(ins, 4, &row.scope);
            try ins.bindInt64(5, row.lease_kind);
            if (row.deadline_us) |deadline| try ins.bindInt64(6, deadline) else try ins.bindNull(6);
            try ins.bindInt64(7, row.source_event_us);
            try ins.bindInt64(8, @intCast(row.source_row));
            try t.expect(!try ins.step());
        }
        for (history, 1..) |row, seq| {
            var ins = try conn.prepare(import.staging_sql.insert_history);
            defer ins.finalize();
            try bindBlob(ins, 1, &run_id);
            try ins.bindInt64(2, @intCast(seq));
            try ins.bindText(3, row.jail);
            try bindBlob(ins, 4, &row.scope);
            try ins.bindInt64(5, row.event_kind);
            try ins.bindInt64(6, row.event_us);
            try ins.bindInt64(7, row.bancount);
            try ins.bindInt64(8, @intCast(row.source_row));
            try t.expect(!try ins.step());
        }
        try self.store.inspectExec("COMMIT;");
    }
};

const bind_blob = @extern(*const fn (*db.Statement, c_int, ?*const anyopaque, c_int, ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int, .{ .name = "sqlite3_bind_blob" });

fn bindBlob(stmt: db.Stmt, index: c_int, bytes: []const u8) !void {
    const transient: ?*const fn (?*anyopaque) callconv(.c) void = @ptrFromInt(std.math.maxInt(usize));
    if (bind_blob(stmt.stmt, index, bytes.ptr, @intCast(bytes.len), transient) != db.rc.ok) return error.BindFailed;
}

fn stagedFixture(source: *Source) !void {
    try source.empty(&.{"sshd"});
    try source.ban(hostRow("sshd", "192.0.2.10", now_s - 600, 3600));
    try source.ban(hostRow("sshd", "198.51.100.7", now_s - 86400, -1));
    try source.ban(hostRow("sshd", "2001:db8::1", now_s - 60, 600));
    try source.bip(.{ .jail = "sshd", .ip = "192.0.2.11", .timeofban = now_s - 90000, .bantime = 3600, .bancount = 3, .data = null });
    try source.bip(.{ .jail = "sshd", .ip = "192.0.2.10", .timeofban = now_s - 600, .bantime = 3600, .bancount = 1, .data = null });
}

test "migration import: staged rows persist into schema 23 and a repeat run is idempotent" {
    var source = try Source.init();
    defer source.deinit();
    try stagedFixture(&source);
    var doc = try Doc.init(&sshd_group, &sshd_only, &.{});
    defer doc.deinit();
    var staging = try run(&source, &doc, .nftables);
    defer staging.deinit();
    try t.expect(!staging.report.blocked());

    var f = try StoreFixture.init();
    defer f.deinit();
    const run_id = [_]u8{0x11} ** 32;
    const other = [_]u8{0x22} ** 32;
    try f.addRun(run_id);
    try f.addRun(other);

    const owners = try import.ownerRows(a, &staging);
    defer a.free(owners);
    const history = try import.historyRows(a, &staging);
    defer a.free(history);
    try t.expectEqual(@as(usize, 3), owners.len);
    try t.expectEqual(@as(usize, 1), history.len);

    try f.stageRows(run_id, owners, history);
    try t.expectEqual(@as(i64, 3), try f.count("migration_staged_owners", run_id));
    try t.expectEqual(@as(i64, 1), try f.count("migration_staged_history", run_id));
    try t.expectEqual(@as(i64, 1), try f.scalar("SELECT count(*) FROM migration_staged_owners WHERE lease_kind=2 AND deadline_us IS NULL;"));
    try t.expectEqual(@as(i64, 2), try f.scalar("SELECT count(*) FROM migration_staged_owners WHERE lease_kind=1 AND deadline_us IS NOT NULL;"));
    try t.expectEqual((now_s - 600 + 3600) * std.time.us_per_s, try f.scalar("SELECT deadline_us FROM migration_staged_owners WHERE seq=1;"));
    try t.expectEqual(@as(i64, 92), try f.scalar("SELECT length(scope) FROM migration_staged_owners WHERE seq=1;"));
    try t.expectEqual(@as(i64, 3), try f.scalar("SELECT bancount FROM migration_staged_history WHERE seq=1;"));
    try t.expectEqual(@as(i64, 1), try f.scalar("SELECT event_kind FROM migration_staged_history WHERE seq=1;"));

    try f.store.inspectExec("INSERT INTO migration_staged_owners VALUES(X'1111111111111111111111111111111111111111111111111111111111111111',9,'stale',zeroblob(92),2,NULL,0,0);");
    try f.store.inspectExec("INSERT INTO migration_staged_owners VALUES(X'2222222222222222222222222222222222222222222222222222222222222222',1,'other',zeroblob(92),2,NULL,0,0);");
    try t.expectEqual(@as(i64, 4), try f.count("migration_staged_owners", run_id));
    try f.stageRows(run_id, owners, history);
    try t.expectEqual(@as(i64, 3), try f.count("migration_staged_owners", run_id));
    try t.expectEqual(@as(i64, 1), try f.count("migration_staged_history", run_id));
    try t.expectEqual(@as(i64, 0), try f.scalar("SELECT count(*) FROM migration_staged_owners WHERE jail='stale';"));
    try t.expectEqual(@as(i64, 1), try f.count("migration_staged_owners", other));

    try t.expectEqual(@as(i64, 0), try f.scalar("SELECT count(*) FROM retry_states;"));
}

test "migration import: staging refuses a blocked report and a run id without a run row" {
    var source = try Source.init();
    defer source.deinit();
    try source.empty(&.{"sshd"});
    try source.ban(hostRow("sshd", "198.51.100.8", now_s - 300, -2));
    try source.ban(hostRow("sshd", "192.0.2.10", now_s - 300, 600));
    var doc = try Doc.init(&sshd_group, &sshd_only, &.{});
    defer doc.deinit();
    var blocked = try run(&source, &doc, .nftables);
    defer blocked.deinit();
    try t.expect(blocked.report.blocked());
    const Refusing = struct {
        pub fn stageMigrationRows(_: *@This(), _: [32]u8, _: []const import.StagedOwnerRow, _: []const import.StagedHistoryRow) !void {
            return error.TestUnexpectedResult;
        }
    };
    var refusing = Refusing{};
    try t.expectError(error.MigrationBlocked, import.stage(&refusing, [_]u8{1} ** 32, &blocked));

    var f = try StoreFixture.init();
    defer f.deinit();
    const owners = try import.ownerRows(a, &blocked);
    defer a.free(owners);
    try t.expectError(error.DatabaseFailure, f.stageRows([_]u8{3} ** 32, owners, &.{}));
    try t.expectEqual(@as(i64, 0), try f.scalar("SELECT count(*) FROM migration_staged_owners;"));
}

test "migration import: stage forwards typed rows to the store method" {
    var source = try Source.init();
    defer source.deinit();
    try stagedFixture(&source);
    var doc = try Doc.init(&sshd_group, &sshd_only, &.{});
    defer doc.deinit();
    var staging = try run(&source, &doc, .nftables);
    defer staging.deinit();
    const Recording = struct {
        run_id: [32]u8 = undefined,
        owners: usize = 0,
        history: usize = 0,
        permanent: usize = 0,
        pub fn stageMigrationRows(self: *@This(), run_id: [32]u8, owners: []const import.StagedOwnerRow, history: []const import.StagedHistoryRow) !void {
            self.run_id = run_id;
            self.owners = owners.len;
            self.history = history.len;
            for (owners) |row| if (row.lease_kind == 2) {
                self.permanent += 1;
            };
        }
    };
    var recording = Recording{};
    try import.stage(&recording, [_]u8{9} ** 32, &staging);
    try t.expectEqualSlices(u8, &([_]u8{9} ** 32), &recording.run_id);
    try t.expectEqual(@as(usize, 3), recording.owners);
    try t.expectEqual(@as(usize, 1), recording.history);
    try t.expectEqual(@as(usize, 1), recording.permanent);
}
