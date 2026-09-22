// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const durable = @import("core/record_store.zig");
const effect = @import("core/native_effect.zig");
const action_outcome = @import("core/native_action_outcome.zig");
const runtime = @import("native_effect_runtime.zig");
const inspection = @import("firewall/inspection.zig");
const command = @import("firewall/command.zig");
const linux = std.os.linux;
const t = std.testing;
const bindings = [_]runtime.Binding{ .{ .jail = "fixture", .generation = [_]u8{3} ** 32 }, .{ .jail = "shared", .generation = [_]u8{3} ** 32 } };
const subject = @import("core/native_detection_record.zig").Subject{ .v4 = .{ 192, 0, 2, 91 } };
const Fixture = struct {
    tmp: t.TmpDir,
    path: []u8,
    store: durable.Store,
    installation: effect.Installation,
    fn init(backend: effect.Backend) !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const base = try tmp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(base);
        const path = try std.fs.path.join(t.allocator, &.{ base, "manager.sqlite" });
        errdefer t.allocator.free(path);
        var store = try durable.Store.open(t.allocator, path);
        errdefer store.close();
        try store.enableReceipts(8);
        try store.enableNativeTime();
        try store.enableDetection();
        try store.enableClockRecovery();
        try store.enableJournalDetection();
        try store.enableRetry();
        try store.enableConsumers();
        try store.enableEffects();
        const installation = try effect.Installation.init([_]u8{0x83} ** 16, backend, "isolated-fixture");
        try store.admitInstallation(installation, .{ .selector = "isolated-fixture", .disposition = .verified_absent });
        return .{ .tmp = tmp, .path = path, .store = store, .installation = installation };
    }
    fn deinit(self: *Fixture) void {
        self.store.close();
        t.allocator.free(self.path);
        self.tmp.cleanup();
    }
    fn manager(self: *Fixture) !*runtime.Manager {
        const result = try runtime.Manager.create(t.allocator, &self.store, self.installation);
        if (std.posix.getenv("F2Z_NATIVE_IPSET_PATH")) |path| result.inspector.ipset_path = path;
        return result;
    }
    fn enableSchema19(self: *Fixture) !void {
        try self.store.enableConsumerManifests();
        try self.store.enableConfirmedHistory();
        try self.store.enableMaintenance();
        try self.store.enableCleanup();
        try self.store.enableRetryLeases();
        try self.store.enableApplicationHistory();
        try self.store.enableEscalation();
        try self.store.enableCanonicalEffects();
    }
    fn enableSchema21(self: *Fixture) !void {
        try self.enableSchema19();
        try self.store.enableHistoryResets();
        try self.store.enableActionTargets();
    }
    fn owner(self: *Fixture, jail: []const u8, decision: u8, lease: effect.Lease) !effect.Entry {
        const now = std.time.microTimestamp();
        return self.store.setOwner(.{ .scope = try effect.Scope.host(subject), .jail = jail, .generation = [_]u8{3} ** 32, .decision_id = [_]u8{decision} ** 32, .expected_revision = 0, .lease = lease, .decided_us = now }, .{ .prepared_us = now });
    }
};
fn allocateManager(a: std.mem.Allocator, fixture: *Fixture) !void {
    const manager = try runtime.Manager.create(a, &fixture.store, fixture.installation);
    defer manager.destroy();
    try t.expect(!manager.status.ready);
    try t.expectEqual(effect.max_effects, manager.live.len);
    try t.expectEqual(effect.max_effects, manager.staged.len);
}
test "native effect runtime: every manager allocation failure releases reserved buffers" {
    var fixture = try Fixture.init(.nftables);
    defer fixture.deinit();
    try t.checkAllAllocationFailures(t.allocator, allocateManager, .{&fixture});
}
test "native effect runtime: clock and persistence failures clear previously published confirmation" {
    var fixture = try Fixture.init(.nftables);
    defer fixture.deinit();
    var entry = try fixture.owner("fixture", 1, .permanent);
    const manager = try fixture.manager();
    defer manager.destroy();
    entry.status = .applied;
    manager.live[0] = entry;
    manager.count = 1;
    manager.cached_epoch = fixture.store.effect_publication_epoch;
    manager.status.ready = true;
    try t.expect(manager.confirmedSubject(subject, std.time.microTimestamp()));
    manager.last_wall_us = std.math.maxInt(i64);
    try t.expectError(error.EffectClockReversed, manager.turn(&bindings));
    try t.expect(!manager.status.ready);
    try t.expect(!manager.confirmedSubject(subject, std.time.microTimestamp()));
    manager.status.ready = true;
    try t.expectError(error.EffectClockReversed, manager.expireDuringOutage());
    try t.expect(!manager.status.ready);
    manager.status.ready = true;
    fixture.store.reopen_required = true;
    defer fixture.store.reopen_required = false;
    try t.expectError(error.ReopenRequired, manager.admit());
    try t.expect(!manager.status.ready);
}
test "native effect runtime: admission diagnostic is bounded by value and retained until reconciliation" {
    var fixture = try Fixture.init(.iptables);
    defer fixture.deinit();
    const manager = try fixture.manager();
    defer manager.destroy();
    var cache = runtime.observation.Cache.init(manager.inspector.installation, [_]u8{0x61} ** 16);
    manager.attachObservationCache(&cache);
    manager.inspector.iptables_path = "/nonexistent/fail2zig-fixture-iptables";
    try t.expectError(error.ToolUnavailable, manager.admit());
    try t.expect(!manager.status.ready);
    try t.expect(manager.status.uncertain);
    const diagnostic = manager.status.diagnostic.?;
    try t.expectEqual(inspection.Transport.iptables, diagnostic.backend);
    try t.expectEqual(inspection.OperationStage.admission_probe, diagnostic.stage);
    try t.expectEqual(error.ToolUnavailable, diagnostic.cause);
    try t.expectEqual(inspection.MutationDisposition.not_started, diagnostic.mutation);
    var observation_page: runtime.observation.Page = undefined;
    try cache.readPage(.{ .now_ms = runtime.observation.monotonicMs() }, &observation_page);
    try t.expectEqual(.unavailable, observation_page.metadata.state);
    try t.expectEqual(error.ToolUnavailable, observation_page.metadata.attempt_failure.?);
    try t.expectEqual(inspection.OperationStage.admission_probe, observation_page.metadata.attempt_stage.?);
    const epoch = manager.repairEpoch();
    _ = try manager.beginRepair(epoch);
    try t.expectEqualDeep(diagnostic, manager.status.diagnostic.?);
    manager.storageReopened();
    try t.expectEqualDeep(diagnostic, manager.status.diagnostic.?);
}
test "native effect runtime: transient readback stays uncertain and retries with bounded backoff" {
    var fixture = try Fixture.init(.nftables);
    defer fixture.deinit();
    var entry = try fixture.owner("fixture", 1, .permanent);
    const manager = try fixture.manager();
    defer manager.destroy();
    entry.status = .applied;
    manager.live[0] = entry;
    manager.count = 1;
    manager.cached_epoch = fixture.store.effect_publication_epoch;
    manager.inspector.test_fault_readback = error.Changed;
    for ([_]usize{ 1, 0 }) |cursor| {
        manager.admitted = true;
        manager.status = .{ .ready = true };
        manager.readback_failures = 0;
        manager.cursor = cursor;
        try t.expect(!try manager.turn(&bindings));
        try t.expect(!manager.status.ready);
        try t.expect(manager.status.uncertain);
        try t.expect(!manager.confirmedSubject(subject, std.time.microTimestamp()));
        const diagnostic = manager.status.diagnostic.?;
        try t.expectEqual(inspection.OperationStage.readback, diagnostic.stage);
        try t.expectEqual(error.Changed, diagnostic.cause);
        try t.expectEqual(inspection.MutationDisposition.not_started, diagnostic.mutation);
        try t.expectEqual(@as(u16, 0), manager.readback_wait);
    }
    manager.readback_failures = 0;
    var attempts: usize = 0;
    for (0..64) |_| {
        const before = manager.readback_failures;
        try t.expect(!try manager.turn(&bindings));
        if (manager.readback_failures != before) attempts += 1;
    }
    try t.expectEqual(@as(usize, 7), attempts);
    manager.readback_wait = 0;
    manager.readback_failures = std.math.maxInt(u8);
    try t.expect(!try manager.turn(&bindings));
    try t.expectEqual(@as(u16, 255), manager.readback_wait);
    manager.readback_wait = 0;
    manager.readback_failures = 0;
    manager.admitted = false;
    try t.expect(!try manager.turn(&bindings));
    try t.expect(!manager.admitted);
    try t.expectEqual(inspection.OperationStage.admission_probe, manager.status.diagnostic.?.stage);
    manager.readback_wait = 0;
    manager.admitted = true;
    manager.inspector.test_fault_readback = error.LimitExceeded;
    try t.expectError(error.LimitExceeded, manager.turn(&bindings));
    try t.expectEqual(error.LimitExceeded, manager.status.diagnostic.?.cause);
}
fn isolatedBackend() !effect.Backend {
    const name = std.posix.getenv("F2Z_NATIVE_FIREWALL_TRANSPORT") orelse return error.SkipZigTest;
    const prior = std.posix.getenv("F2Z_NATIVE_PARENT_NETNS") orelse return error.MissingIsolationCookie;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const current = try std.fs.readLinkAbsolute("/proc/self/ns/net", &buffer);
    try t.expect(!std.mem.eql(u8, prior, current));
    if (linux.E.init(linux.unshare(linux.CLONE.NEWNET)) != .SUCCESS) return error.IsolationFailed;
    return std.meta.stringToEnum(effect.Backend, name) orelse error.InvalidFixture;
}
fn ready(manager: *runtime.Manager) !void {
    for (0..32) |_| if (try manager.turn(&bindings)) {
        try t.expect(manager.status.ready);
        return;
    };
    return error.RecoveryDidNotFinish;
}
fn driftRemove(manager: *runtime.Manager) !void {
    var name_buf: [28]u8 = undefined;
    const name = manager.inspector.installation.name(&name_buf);
    var set_buf: [31]u8 = undefined;
    const set = try std.fmt.bufPrint(&set_buf, "{s}_4", .{name});
    const args: []const []const u8 = switch (manager.installation.backend) {
        .nftables => &.{ "/usr/sbin/nft", "delete", "element", "inet", name, "banned_ipv4", "{", "192.0.2.91", "}" },
        .iptables => &.{ manager.inspector.iptables_path, "-D", name, "-s", "192.0.2.91", "-j", "DROP" },
        .ipset => &.{ manager.inspector.ipset_path, "del", set, "192.0.2.91" },
    };
    const result = try command.run(t.allocator, args, 2000);
    defer result.deinit(t.allocator);
    if (result.code != 0) {
        std.debug.print("drift fixture: {s}\n", .{result.stderr});
        return error.FixtureCommandFailed;
    }
}
fn waitUntil(deadline: i64) void {
    const delta = deadline - std.time.microTimestamp();
    if (delta > 0) std.Thread.sleep(@as(u64, @intCast(delta)) * std.time.ns_per_us);
}
test "native effect runtime: isolated final inventory catches missing scope then recovers without duplicate confirmation" {
    var fixture = try Fixture.init(try isolatedBackend());
    defer fixture.deinit();
    _ = try fixture.owner("fixture", 1, .permanent);
    const manager = try fixture.manager();
    defer manager.destroy();
    try ready(manager);
    try t.expect(manager.confirmedSubject(subject, std.time.microTimestamp()));
    try t.expectEqual(@as(u64, 1), try fixture.store.confirmedEffectEvents());
    manager.cursor = manager.count;
    try driftRemove(manager);
    try t.expect(!try manager.turn(&bindings));
    try t.expect(!manager.status.ready);
    try t.expect(!manager.confirmedSubject(subject, std.time.microTimestamp()));
    try ready(manager);
    try t.expectEqual(@as(u64, 1), try fixture.store.confirmedEffectEvents());
    manager.inspector.limits.max_bytes = 1;
    try t.expectError(error.LimitExceeded, manager.turn(&bindings));
    try t.expect(!manager.confirmedSubject(subject, std.time.microTimestamp()));
    const diagnostic = manager.status.diagnostic.?;
    try t.expectEqual(manager.inspector.installation.transport, diagnostic.backend);
    try t.expectEqual(inspection.OperationStage.readback, diagnostic.stage);
    try t.expectEqual(error.LimitExceeded, diagnostic.cause);
    try t.expectEqual(inspection.MutationDisposition.not_started, diagnostic.mutation);
    manager.inspector.limits.max_bytes = (inspection.Limits{}).max_bytes;
    try ready(manager);
    try t.expect(manager.status.diagnostic == null);
}

test "native effect runtime: isolated transient readback recovers at the next complete readback" {
    var fixture = try Fixture.init(try isolatedBackend());
    defer fixture.deinit();
    _ = try fixture.owner("fixture", 1, .{ .finite = std.time.microTimestamp() + 30_000_000 });
    const manager = try fixture.manager();
    defer manager.destroy();
    try ready(manager);
    try t.expectEqual(@as(u64, 1), try fixture.store.confirmedEffectEvents());
    manager.inspector.test_fault_readback = error.Changed;
    manager.cursor = manager.count;
    try t.expect(!try manager.turn(&bindings));
    try t.expect(manager.status.uncertain);
    try t.expect(!manager.confirmedSubject(subject, std.time.microTimestamp()));
    manager.inspector.test_fault_readback = null;
    try ready(manager);
    try t.expect(manager.status.diagnostic == null);
    try t.expect(manager.confirmedSubject(subject, std.time.microTimestamp()));
    try t.expectEqual(@as(u64, 1), try fixture.store.confirmedEffectEvents());
}

fn hostOwner(fixture: *Fixture, index: u8, deadline: i64) !void {
    const now = std.time.microTimestamp();
    const host = @import("core/native_detection_record.zig").Subject{ .v4 = .{ 198, 51, 100, index } };
    _ = try fixture.store.setOwner(.{ .scope = try effect.Scope.host(host), .jail = "fixture", .generation = [_]u8{3} ** 32, .decision_id = [_]u8{index} ** 32, .expected_revision = 0, .lease = .{ .finite = deadline }, .decided_us = now }, .{ .prepared_us = now });
}

test "native effect runtime: isolated new ban confirms in a few turns regardless of existing effects" {
    var fixture = try Fixture.init(try isolatedBackend());
    defer fixture.deinit();
    const deadline = std.time.microTimestamp() + 120_000_000;
    for (1..49) |index| try hostOwner(&fixture, @intCast(index), deadline);
    const manager = try fixture.manager();
    defer manager.destroy();
    for (0..1024) |_| {
        if (try manager.turn(&bindings)) break;
    } else return error.RecoveryDidNotFinish;
    try t.expectEqual(@as(usize, 48), manager.count);
    try hostOwner(&fixture, 49, deadline);
    var turns: usize = 0;
    while (!try manager.turn(&bindings)) : (turns += 1) try t.expect(turns < 12);
    try t.expectEqual(@as(usize, 49), manager.count);
    try t.expect(manager.confirmedSubject(.{ .v4 = .{ 198, 51, 100, 49 } }, std.time.microTimestamp()));
}

test "native effect runtime: isolated new ban is enforced before pending expiry bookkeeping" {
    const backend = try isolatedBackend();
    var fixture = try Fixture.init(backend);
    defer fixture.deinit();
    // Fixed-argv backends reconcile each entry through subprocesses.
    const bans: usize = if (backend == .nftables) 30 else 8;
    const expiring = std.time.microTimestamp() + 12_000_000;
    for (1..bans + 1) |index| try hostOwner(&fixture, @intCast(index), expiring);
    const manager = try fixture.manager();
    defer manager.destroy();
    for (0..1024) |_| {
        if (try manager.turn(&bindings)) break;
    } else return error.RecoveryDidNotFinish;
    try t.expect(std.time.microTimestamp() < expiring);
    for (manager.live[0..manager.count]) |entry| try t.expect(entry.status == .applied and entry.desired.finite == expiring);
    waitUntil(expiring + 1_100_000);
    try hostOwner(&fixture, 99, expiring + 60_000_000);
    const newcomer = try effect.Scope.host(.{ .v4 = .{ 198, 51, 100, 99 } });
    for (0..16) |_| {
        _ = try manager.turn(&bindings);
        var enforced = false;
        var expired_handled: usize = 0;
        for (manager.live[0..manager.count]) |entry| {
            if (std.meta.eql(entry.scope, newcomer)) enforced = entry.status == .applied;
            if (entry.desired != .finite or entry.desired.finite != expiring) expired_handled += @intFromBool(!std.meta.eql(entry.scope, newcomer));
        }
        if (enforced) {
            try t.expectEqual(@as(usize, 0), expired_handled);
            return;
        }
    }
    return error.NewBanNotEnforced;
}

test "native effect runtime: isolated pruning a spent scope keeps confirmation without another readback" {
    var fixture = try Fixture.init(try isolatedBackend());
    defer fixture.deinit();
    try fixture.enableSchema19();
    _ = try fixture.owner("fixture", 1, .permanent);
    const deadline = std.time.microTimestamp() + 1_000_000;
    try hostOwner(&fixture, 7, deadline);
    const manager = try fixture.manager();
    defer manager.destroy();
    try ready(manager);
    waitUntil(deadline + 50_000);
    for (0..64) |_| {
        if (!try manager.turn(&bindings)) continue;
        var absent: usize = 0;
        for (manager.live[0..manager.count]) |entry| absent += @intFromBool(entry.status == .absent);
        if (absent == 1) break;
    } else return error.RecoveryDidNotFinish;
    const exec = @extern(*const fn (*anyopaque, [*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) callconv(.c) c_int, .{ .name = "sqlite3_exec" });
    try t.expectEqual(@as(c_int, 0), exec(@ptrCast(fixture.store.db), "DELETE FROM confirmed_event_details; DELETE FROM confirmed_history_sequence; DELETE FROM confirmed_effect_events;", null, null, null));
    try t.expect(try manager.turn(&bindings));
    var pruned = false;
    while (try fixture.store.pruneSpentEffectOne()) pruned = true;
    try t.expect(pruned);
    try t.expect(try manager.turn(&bindings));
    try t.expect(manager.status.ready);
    try t.expectEqual(@as(usize, 1), manager.count);
    try t.expect(manager.confirmedSubject(subject, std.time.microTimestamp()));
}

test "native effect runtime: isolated dispatch uncertainty retains durable identity and clears at full readback" {
    var fixture = try Fixture.init(try isolatedBackend());
    defer fixture.deinit();
    const deadline = std.time.microTimestamp() + 30_000_000;
    const expected = try fixture.owner("fixture", 1, .{ .finite = deadline });
    const manager = try fixture.manager();
    defer manager.destroy();
    try manager.admit();
    manager.inspector.test_fault_after_mutations = 1;
    for (0..8) |_| {
        _ = manager.turn(&bindings) catch |failure| {
            try t.expectEqual(error.EffectBackendUncertain, failure);
            break;
        };
    } else return error.ExpectedDispatchUncertainty;
    try t.expect(!manager.status.ready);
    try t.expect(manager.status.uncertain);
    const diagnostic = manager.status.diagnostic.?;
    try t.expectEqual(manager.inspector.installation.transport, diagnostic.backend);
    try t.expectEqual(inspection.OperationStage.effect_dispatch, diagnostic.stage);
    try t.expectEqual(error.Timeout, diagnostic.cause);
    try t.expectEqual(inspection.MutationDisposition.outcome_uncertain, diagnostic.mutation);
    var rows: [1]effect.Entry = undefined;
    const page = try fixture.store.effectPage(null, null, &rows);
    try t.expectEqual(@as(usize, 1), page.count);
    try t.expectEqual(effect.Status.dispatched, rows[0].status);
    try t.expectEqualSlices(u8, &expected.scope_key, &rows[0].scope_key);
    try t.expectEqual(deadline, rows[0].desired.finite);
    manager.inspector.test_fault_after_mutations = null;
    try ready(manager);
    try t.expect(manager.status.diagnostic == null);
}

test "native effect runtime: isolated canonical network survives manager restart and expires exactly" {
    var fixture = try Fixture.init(try isolatedBackend());
    defer fixture.deinit();
    try fixture.enableSchema19();
    const canonical = inspection.canonical_scope;
    const scope = canonical.Scope{
        .subject = try canonical.Subject.parseNetwork("192.0.2.0/24"),
        .protocols = try canonical.Protocols.one(.udp),
        .ports = try canonical.Ports.list(&.{ canonical.PortRange.one(35271), .{ .first = 35280, .last = 35282 } }),
    };
    const deadline = std.time.microTimestamp() + 2_500_000;
    const entry = try fixture.store.setOwnerFromCanonical(.{
        .scope = scope,
        .jail = "fixture",
        .generation = [_]u8{3} ** 32,
        .decision_id = [_]u8{0x92} ** 32,
        .expected_revision = 0,
        .lease = .{ .finite = deadline },
        .decided_us = std.time.microTimestamp(),
    }, .{ .prepared_us = std.time.microTimestamp() });
    {
        const manager = try fixture.manager();
        defer manager.destroy();
        var cache = runtime.observation.Cache.init(manager.inspector.installation, [_]u8{0x62} ** 16);
        manager.attachObservationCache(&cache);
        try ready(manager);
        var page: runtime.observation.Page = undefined;
        try cache.readPage(.{ .now_ms = runtime.observation.monotonicMs() }, &page);
        try t.expectEqual(.owned, page.metadata.state);
        try t.expectEqual(runtime.observation.Inventory.known_entries, page.metadata.inventory);
        try t.expectEqual(@as(usize, 1), page.count);
        try t.expectEqualDeep(scope, page.entries[0].scope.?);
        try t.expectEqualSlices(u8, &entry.scope_key, &page.entries[0].effect_id.?);
        try t.expectEqual(deadline, page.entries[0].deadline_us.?);
        var snapshot = try manager.inspector.inspect();
        defer snapshot.deinit();
        try t.expectEqual(@as(usize, 1), snapshot.entries.len);
        try t.expectEqualDeep(scope, snapshot.entries[0].scope.?);
        try t.expectEqualSlices(u8, &entry.scope_key, &snapshot.entries[0].effect_id.?);
        try t.expectEqual(deadline, snapshot.entries[0].deadline_us.?);
    }
    const restarted = try fixture.manager();
    defer restarted.destroy();
    try ready(restarted);
    try t.expect(restarted.status.ready);
    waitUntil(deadline + 100_000);
    try ready(restarted);
    var expired = try restarted.inspector.inspect();
    defer expired.deinit();
    try t.expectEqual(@as(usize, 0), expired.entries.len);
}

test "native effect runtime: isolated stop restores durable intent and repair epoch rejects stale work" {
    var fixture = try Fixture.init(try isolatedBackend());
    defer fixture.deinit();
    try fixture.enableSchema21();
    const deadline = std.time.microTimestamp() + 30_000_000;
    const entry = try fixture.owner("fixture", 1, .{ .finite = deadline });
    try fixture.store.prepareActionTargets(.{ .action_id = [_]u8{1} ** 32, .scope_key = entry.scope_key, .jail = "fixture" }, .{ .prepared_us = std.time.microTimestamp() });
    try fixture.store.markActionTargetDispatched([_]u8{1} ** 32, .notification, .{ .prepared_us = std.time.microTimestamp() });
    try fixture.store.settleActionTarget([_]u8{1} ** 32, .notification, .failed, .{ .prepared_us = std.time.microTimestamp() });
    {
        const manager = try fixture.manager();
        defer manager.destroy();
        try ready(manager);
        try t.expect(manager.status.ready);
        var outcomes: [action_outcome.max_targets_per_action]action_outcome.Target = undefined;
        try t.expectEqual(@as(usize, 2), try fixture.store.actionTargets([_]u8{1} ** 32, &outcomes));
        try t.expectEqual(action_outcome.Status.confirmed, outcomes[0].status);
        try t.expectEqual(action_outcome.Status.failed, outcomes[1].status);
        const epoch = manager.repairEpoch();
        manager.inspector.test_fault_after_mutations = 1;
        try t.expectError(error.EffectBackendUncertain, manager.stopTurn(epoch));
        const diagnostic = manager.status.diagnostic.?;
        try t.expectEqual(manager.inspector.installation.transport, diagnostic.backend);
        try t.expectEqual(inspection.OperationStage.effect_dispatch, diagnostic.stage);
        try t.expectEqual(error.Timeout, diagnostic.cause);
        try t.expectEqual(inspection.MutationDisposition.outcome_uncertain, diagnostic.mutation);
        var retained: [1]effect.Entry = undefined;
        const retained_page = try fixture.store.effectPage(null, null, &retained);
        try t.expectEqual(@as(usize, 1), retained_page.count);
        try t.expectEqual(deadline, retained[0].desired.finite);
        manager.inspector.test_fault_after_mutations = null;
        while (!try manager.stopTurn(epoch)) {}
        try t.expect(manager.status.diagnostic == null);
        var stopped = try manager.inspector.inspect();
        defer stopped.deinit();
        try t.expectEqual(@as(usize, 0), stopped.entries.len);
        try t.expectEqual(@as(u64, 1), try fixture.store.confirmedEffectEvents());
    }
    const restarted = try fixture.manager();
    defer restarted.destroy();
    try ready(restarted);
    try t.expectEqual(@as(u64, 1), try fixture.store.confirmedEffectEvents());
    try t.expect(restarted.confirmedSubject(subject, std.time.microTimestamp()));
    var restored_rows: [1]effect.Entry = undefined;
    const restored_page = try fixture.store.effectPage(null, null, &restored_rows);
    try t.expectEqual(@as(usize, 1), restored_page.count);
    try t.expectEqual(deadline, restored_rows[0].desired.finite);

    try driftRemove(restarted);
    const prior_epoch = restarted.repairEpoch();
    const repair_epoch = try restarted.beginRepair(prior_epoch);
    try t.expectEqual(prior_epoch + 1, repair_epoch);
    try t.expectError(error.StaleRepairEpoch, restarted.beginRepair(prior_epoch));
    try ready(restarted);
    try t.expectEqual(@as(u64, 1), try fixture.store.confirmedEffectEvents());
    try t.expect(restarted.confirmedSubject(subject, std.time.microTimestamp()));
}
const Db = std.meta.Child(@FieldType(durable.Store, "db"));
const Exec = @FieldType(@FieldType(durable.Store, "api"), "exec");
const ForbiddenSql = struct {
    var calls: usize = 0;
    fn exec(_: *Db, _: [*:0]const u8, _: ?*anyopaque, _: ?*anyopaque, _: ?*?[*:0]u8) callconv(.c) c_int {
        calls += 1;
        return 5;
    }
};
const BlockedWriter = struct {
    blocker: durable.Store,
    selected: *durable.Store,
    actual: Exec,
    fn init(fixture: *Fixture) !BlockedWriter {
        var blocker = try durable.Store.open(t.allocator, fixture.path);
        errdefer blocker.close();
        try t.expectEqual(@as(c_int, 0), blocker.api.exec(blocker.db, "BEGIN IMMEDIATE;", null, null, null));
        errdefer _ = blocker.api.exec(blocker.db, "ROLLBACK;", null, null, null);
        try t.expectError(error.Busy, fixture.store.enableEffects());
        try t.expect(!fixture.store.reopen_required);
        const actual = fixture.store.api.exec;
        ForbiddenSql.calls = 0;
        fixture.store.api.exec = ForbiddenSql.exec;
        return .{ .blocker = blocker, .selected = &fixture.store, .actual = actual };
    }
    fn deinit(self: *BlockedWriter) void {
        self.selected.api.exec = self.actual;
        _ = self.blocker.api.exec(self.blocker.db, "ROLLBACK;", null, null, null);
        self.blocker.close();
    }
};
test "native effect runtime: isolated committed finite expiry proceeds while SQLite is unavailable" {
    var fixture = try Fixture.init(try isolatedBackend());
    defer fixture.deinit();
    const deadline = std.time.microTimestamp() + 2_000_000;
    _ = try fixture.owner("fixture", 1, .{ .finite = deadline });
    const manager = try fixture.manager();
    defer manager.destroy();
    try ready(manager);
    {
        var blocked = try BlockedWriter.init(&fixture);
        defer blocked.deinit();
        waitUntil(deadline + 20_000);
        try manager.expireDuringOutage();
        try t.expectEqual(@as(usize, 0), ForbiddenSql.calls);
        try t.expect(manager.outage_attempted[0]);
        try t.expect(!manager.status.ready);
        try t.expect(manager.status.uncertain);
    }
    var retained: [1]effect.Entry = undefined;
    const retained_page = try fixture.store.effectPage(null, null, &retained);
    try t.expectEqual(@as(usize, 1), retained_page.count);
    try t.expectEqual(deadline, retained[0].desired.finite);
    var snapshot = try manager.inspector.inspect();
    defer snapshot.deinit();
    try t.expectEqual(@as(usize, 0), snapshot.entries.len);
}
test "native effect runtime: isolated outage readback failure preserves diagnostic and durable expiry" {
    var fixture = try Fixture.init(try isolatedBackend());
    defer fixture.deinit();
    const deadline = std.time.microTimestamp() + 1_000_000;
    _ = try fixture.owner("fixture", 1, .{ .finite = deadline });
    const manager = try fixture.manager();
    defer manager.destroy();
    try ready(manager);
    {
        var blocked = try BlockedWriter.init(&fixture);
        defer blocked.deinit();
        waitUntil(deadline + 20_000);
        manager.inspector.limits.max_bytes = 1;
        try t.expectError(error.LimitExceeded, manager.expireDuringOutage());
        try t.expectEqual(@as(usize, 0), ForbiddenSql.calls);
        try t.expect(manager.outage_attempted[0]);
        try t.expect(!manager.status.ready);
        try t.expect(manager.status.uncertain);
        const diagnostic = manager.status.diagnostic.?;
        try t.expectEqual(manager.inspector.installation.transport, diagnostic.backend);
        try t.expectEqual(inspection.OperationStage.effect_dispatch, diagnostic.stage);
        try t.expectEqual(error.LimitExceeded, diagnostic.cause);
        try t.expectEqual(inspection.MutationDisposition.not_started, diagnostic.mutation);
    }
    manager.inspector.limits.max_bytes = (inspection.Limits{}).max_bytes;
    var retained: [1]effect.Entry = undefined;
    const retained_page = try fixture.store.effectPage(null, null, &retained);
    try t.expectEqual(@as(usize, 1), retained_page.count);
    try t.expectEqual(deadline, retained[0].desired.finite);
}
test "native effect runtime: isolated permanent co-owner prevents finite-owner outage expiry" {
    var fixture = try Fixture.init(try isolatedBackend());
    defer fixture.deinit();
    const deadline = std.time.microTimestamp() + 1_000_000;
    _ = try fixture.owner("fixture", 1, .{ .finite = deadline });
    _ = try fixture.owner("shared", 2, .permanent);
    const manager = try fixture.manager();
    defer manager.destroy();
    try ready(manager);
    {
        var blocked = try BlockedWriter.init(&fixture);
        defer blocked.deinit();
        waitUntil(deadline + 20_000);
        try manager.expireDuringOutage();
        try t.expectEqual(@as(usize, 0), ForbiddenSql.calls);
        try t.expect(!manager.outage_attempted[0]);
        var snapshot = try manager.inspector.inspect();
        defer snapshot.deinit();
        try t.expectEqual(@as(usize, 1), snapshot.entries.len);
        try t.expect(snapshot.entries[0].remaining_ms == null);
    }
    try ready(manager);
    var entries: [1]effect.Entry = undefined;
    const page = try fixture.store.effectPage(null, null, &entries);
    try t.expectEqual(@as(usize, 1), page.count);
    try t.expect(entries[0].desired == .permanent);
    var owners: [effect.max_page]effect.Owner = undefined;
    try t.expectEqual(@as(usize, 2), try fixture.store.effectOwners(entries[0].scope_key, entries[0].revision, &owners));
    try t.expectEqualStrings("fixture", owners[0].jail.slice());
    try t.expect(owners[0].lease == .absent);
    try t.expectEqualStrings("shared", owners[1].jail.slice());
    try t.expect(owners[1].lease == .permanent);
    try t.expectEqual(@as(u64, 2), try fixture.store.confirmedEffectEvents());
    var recovered = try manager.inspector.inspect();
    defer recovered.deinit();
    try t.expectEqual(@as(usize, 1), recovered.entries.len);
    try t.expect(recovered.entries[0].remaining_ms == null);
}
test "native effect runtime: isolated newer publication saturation and reopen fence stale expiry authority" {
    var fixture = try Fixture.init(try isolatedBackend());
    defer fixture.deinit();
    const deadline = std.time.microTimestamp() + 1_000_000;
    _ = try fixture.owner("fixture", 1, .{ .finite = deadline });
    const manager = try fixture.manager();
    defer manager.destroy();
    try ready(manager);
    _ = try fixture.owner("shared", 2, .permanent);
    waitUntil(deadline + 20_000);
    var blocked = try BlockedWriter.init(&fixture);
    defer blocked.deinit();
    try manager.expireDuringOutage();
    try t.expectEqual(@as(usize, 0), ForbiddenSql.calls);
    try t.expect(!manager.outage_attempted[0]);
    fixture.store.effect_publication_epoch = std.math.maxInt(u64);
    manager.cached_epoch = std.math.maxInt(u64);
    try manager.expireDuringOutage();
    try t.expectEqual(@as(usize, 0), ForbiddenSql.calls);
    try t.expect(!manager.outage_attempted[0]);
    manager.storageReopened();
    try t.expect(manager.cached_epoch == null);
    try t.expect(!manager.admitted);
    try manager.expireDuringOutage();
    try t.expectEqual(@as(usize, 0), ForbiddenSql.calls);
    try t.expect(!manager.outage_attempted[0]);
}

test "native effect runtime: isolated committed extension with ambiguous result poisons stale expiry authority" {
    const backend = try isolatedBackend();
    var fixture = try Fixture.init(backend);
    defer fixture.deinit();
    const original_deadline = std.time.microTimestamp() + 2_000_000;
    _ = try fixture.owner("fixture", 1, .{ .finite = original_deadline });
    const manager = try fixture.manager();
    defer manager.destroy();
    try ready(manager);
    const old_epoch = fixture.store.effect_publication_epoch;
    try t.expectEqual(@as(?u64, old_epoch), manager.cached_epoch);
    const extended_deadline = original_deadline + 30_000_000;
    const AmbiguousCommit = struct {
        var actual: Exec = undefined;
        var committed: bool = false;
        fn exec(db: *Db, statement: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
            const result = actual(db, statement, callback, context, message);
            if (result == 0 and std.mem.eql(u8, std.mem.span(statement), "COMMIT;")) {
                committed = true;
                return 10;
            }
            return result;
        }
    };
    AmbiguousCommit.actual = fixture.store.api.exec;
    AmbiguousCommit.committed = false;
    fixture.store.api.exec = AmbiguousCommit.exec;
    defer fixture.store.api.exec = AmbiguousCommit.actual;
    try t.expectError(error.StorageIo, fixture.owner("shared", 2, .{ .finite = extended_deadline }));
    fixture.store.api.exec = AmbiguousCommit.actual;
    try t.expect(AmbiguousCommit.committed);
    try t.expect(fixture.store.reopen_required);
    try t.expectEqual(old_epoch, fixture.store.effect_publication_epoch);
    try t.expectEqual(@as(?u64, old_epoch), manager.cached_epoch);
    waitUntil(original_deadline + 20_000);
    try manager.expireDuringOutage();
    try t.expect(!manager.outage_attempted[0]);
    try t.expect(!manager.status.ready);
    try t.expectEqual(@as(usize, 1), manager.status.overdue);
    if (backend == .iptables) {
        var snapshot = try manager.inspector.inspect();
        defer snapshot.deinit();
        try t.expectEqual(@as(usize, 1), snapshot.entries.len);
    }
    var reopened = try durable.Store.open(t.allocator, fixture.path);
    defer reopened.close();
    var entries: [1]effect.Entry = undefined;
    const page = try reopened.effectPage(null, null, &entries);
    try t.expectEqual(@as(usize, 1), page.count);
    try t.expectEqual(extended_deadline, entries[0].desired.finite);
    var owners: [effect.max_page]effect.Owner = undefined;
    try t.expectEqual(@as(usize, 2), try reopened.effectOwners(entries[0].scope_key, entries[0].revision, &owners));
}
