// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const effects = @import("core/native_effect.zig");
const action_outcome = @import("core/native_action_outcome.zig");
const action_context = @import("core/native_action_context.zig");
const lease_policy = @import("core/native_lease.zig");
const durable = @import("core/record_store.zig");
const canonical = @import("firewall/scope.zig");
const runtime = @import("native_effect_runtime.zig");
const time_policy = @import("core/source_time_policy.zig");
const retry = @import("core/native_retry.zig");
const detection = @import("core/native_detection_record.zig");
const t = std.testing;

fn contextInput(subject: ?canonical.Subject) action_context.Input {
    return .{
        .jail = "sshd",
        .filter = "sshd",
        .pattern = "invalid-user",
        .source = "system-journal",
        .occurrence = "cursor:7",
        .enforcement = subject,
        .event_us = 100,
        .decision_us = 120,
        .ordinal = 2,
        .event_count = 3,
        .confirmed_history_count = 1,
    };
}

test "native effects: typed action context preserves host network and missing metadata" {
    const v4_host = canonical.Subject.host(try @import("shared").IpAddress.parse("192.0.2.7"));
    const v6_host = canonical.Subject.host(try @import("shared").IpAddress.parse("2001:db8::7"));
    for ([_]canonical.Subject{ v4_host, v6_host }) |subject| {
        const context = try action_context.Context.init(contextInput(subject));
        const encoded_first = try context.encode();
        const encoded_second = try context.encode();
        try t.expectEqualSlices(u8, &encoded_first, &encoded_second);
        try t.expectEqualDeep(context, try action_context.Context.decode(&encoded_first));
        const realized = try context.legacyEffectScope();
        try t.expectEqual(subject, (try realized.toCanonical()).subject);
        try t.expect(context.correlation == null and context.user == null and context.port == null);
    }

    const networks = [_]canonical.Subject{
        try canonical.Subject.parseNetwork("198.51.100.0/24"),
        try canonical.Subject.parseNetwork("2001:db8:1::/64"),
    };
    for (networks) |subject| {
        const context = try action_context.Context.init(contextInput(subject));
        try t.expectEqual(subject, context.enforcement.?);
        try t.expectError(error.EffectScopeNotRealized, context.legacyEffectScope());
        try t.expectEqualDeep(context, try action_context.Context.decode(&try context.encode()));
    }
}

test "native effects: typed action context separates non-IP identity and keeps metacharacters inert" {
    var input = contextInput(null);
    input.source = "journal:${not-expanded}";
    input.occurrence = "event;$(false)|`false`";
    input.correlation = "account:[ops] ${literal}";
    input.user = "Jos\xc3\xa9;$(literal)";
    input.port = 65535;
    const context = try action_context.Context.init(input);
    try t.expect(context.enforcement == null);
    try t.expectEqualStrings(input.correlation.?, context.correlation.?.slice());
    try t.expectEqualStrings(input.user.?, context.user.?.slice());
    try t.expectEqualStrings(input.source, context.source.slice());
    try t.expectEqualStrings(input.occurrence, context.occurrence.slice());
    try t.expectError(error.InvalidActionContext, context.legacyEffectScope());
    try t.expectEqualDeep(context, try action_context.Context.decode(&try context.encode()));
}

test "native effects: typed action context rejects malformed and over-bound values" {
    const subject = canonical.Subject.host(try @import("shared").IpAddress.parse("192.0.2.7"));
    var input = contextInput(subject);
    var name_over = [_]u8{'n'} ** 65;
    input.source = &name_over;
    try t.expectError(error.InvalidActionContext, action_context.Context.init(input));

    input = contextInput(subject);
    var value_over = [_]u8{'v'} ** 257;
    input.occurrence = &value_over;
    try t.expectError(error.InvalidActionContext, action_context.Context.init(input));
    input = contextInput(subject);
    input.user = "nul\x00user";
    try t.expectError(error.InvalidActionContext, action_context.Context.init(input));
    input.user = "\xff";
    try t.expectError(error.InvalidActionContext, action_context.Context.init(input));
    input.user = null;
    input.port = 0;
    try t.expectError(error.InvalidActionContext, action_context.Context.init(input));
    input.port = null;
    input.event_count = 0;
    try t.expectError(error.InvalidActionContext, action_context.Context.init(input));
    input.event_count = action_context.max_event_count + 1;
    try t.expectError(error.InvalidActionContext, action_context.Context.init(input));
    input.event_count = 1;
    input.ordinal = 0;
    try t.expectError(error.InvalidActionContext, action_context.Context.init(input));
    input.ordinal = 1;
    input.event_us = 121;
    try t.expectError(error.InvalidActionContext, action_context.Context.init(input));
    try t.expectError(error.NonCanonicalNetwork, canonical.Subject.network(try @import("shared").IpAddress.parse("192.0.2.7"), 24));

    const valid = try action_context.Context.init(contextInput(subject));
    var bytes = try valid.encode();
    bytes[6] = 9;
    try t.expectError(error.InvalidActionContext, action_context.Context.decode(&bytes));
    bytes = try valid.encode();
    bytes[8] = 24;
    try t.expectError(error.InvalidActionContext, action_context.Context.decode(&bytes));
    bytes = try valid.encode();
    bytes[5] |= 1 << 3;
    try t.expectError(error.InvalidActionContext, action_context.Context.decode(&bytes));
}

test "native effects: builtin retry projection uses canonical host and bounded source identities" {
    const subject = detection.Subject{ .v4 = .{ 203, 0, 113, 7 } };
    const outcome = detection.Outcome{
        .kind = .candidate,
        .generation = [_]u8{3} ** 32,
        .filter = try detection.Name.init("sshd"),
        .pattern = try detection.Name.init("invalid-user"),
        .pattern_index = 2,
        .subject = subject,
    };
    const decision = retry.Decision{ .subject = subject, .decided_us = 120, .lease = .permanent, .ordinal = 4, .enforce = true };
    var long_source = [_]u8{'s'} ** 65;
    var long_occurrence = [_]u8{'o'} ** 257;
    const context = try action_context.fromRetry("sshd", &long_source, &long_occurrence, outcome, 100, decision, 3, 2);
    try t.expect(context.source_digest and context.occurrence_digest);
    try t.expectEqual(@as(usize, 64), context.source.slice().len);
    try t.expectEqual(@as(usize, 71), context.occurrence.slice().len);
    try t.expectEqual(canonical.SubjectKind.host, context.enforcement.?.kind);
    try t.expectEqual(@as(u64, 2), context.confirmed_history_count.?);
    _ = try context.legacyEffectScope();

    var mismatch = decision;
    mismatch.subject = .{ .v4 = .{ 203, 0, 113, 8 } };
    try t.expectError(error.InvalidActionContext, action_context.fromRetry("sshd", "file", "one", outcome, 100, mismatch, 3, null));
}
const Fixture = struct {
    tmp: t.TmpDir,
    path: []u8,
    store: durable.Store,
    fn init() !Fixture {
        return initSchema(true);
    }
    fn initSchema(with_effects: bool) !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "effects.sqlite" });
        errdefer t.allocator.free(path);
        var store = try durable.Store.open(t.allocator, path);
        errdefer store.close();
        try enable(&store, with_effects);
        return .{ .tmp = tmp, .path = path, .store = store };
    }
    fn deinit(self: *Fixture) void {
        self.store.close();
        t.allocator.free(self.path);
        self.tmp.cleanup();
    }
    fn reopen(self: *Fixture) !void {
        self.store.close();
        self.store = try durable.Store.open(t.allocator, self.path);
        try self.store.enableReceipts(8);
    }
};
fn enable(store: *durable.Store, with_effects: bool) !void {
    try store.enableReceipts(8);
    try store.enableNativeTime();
    try store.enableYearInference();
    try store.enableDetection();
    try store.enableClockRecovery();
    try store.enableJournalDetection();
    try store.enableRetry();
    try store.enableConsumers();
    if (with_effects) try store.enableEffects();
}
const TestClock = struct {
    now: i64 = 100,
    advance: i64 = 0,
    fn read(ctx: ?*anyopaque) i64 {
        const self: *TestClock = @ptrCast(@alignCast(ctx.?));
        const now = self.now;
        self.now += self.advance;
        return now;
    }
    fn value(self: *TestClock) effects.Clock {
        return .{ .prepared_us = 100, .context = self, .read = read };
    }
};
fn installation() !effects.Installation {
    return effects.Installation.init([_]u8{7} ** 16, .nftables, "host-default");
}
fn admit(store: *durable.Store) !void {
    try store.admitInstallation(try installation(), .{ .selector = "host-default", .disposition = .verified_absent });
}
fn enableSchema19(store: *durable.Store) !void {
    try store.enableConsumerManifests();
    try store.enableConfirmedHistory();
    try store.enableMaintenance();
    try store.enableCleanup();
    try store.enableRetryLeases();
    try store.enableApplicationHistory();
    try store.enableEscalation();
    try store.enableCanonicalEffects();
}
fn change(jail: []const u8, identity: u8, lease: effects.Lease) !effects.OwnerChange {
    return .{ .scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, 51 } }), .jail = jail, .generation = [_]u8{3} ** 32, .decision_id = [_]u8{identity} ** 32, .expected_revision = 0, .lease = lease, .decided_us = 100 };
}
fn observation(entry: effects.Entry, now: i64, state: effects.Lease) effects.Observation {
    return .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = [_]u8{9} ** 32, .observed_us = now, .qualification = .complete_owned, .state = state };
}
fn first(store: *durable.Store) !effects.Entry {
    var rows: [1]effects.Entry = undefined;
    const page = try store.effectPage(null, null, &rows);
    try t.expectEqual(@as(usize, 1), page.count);
    return rows[0];
}
fn sql(store: *durable.Store, statement: [:0]const u8) !void {
    const run = @extern(*const fn (*anyopaque, [*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) callconv(.c) c_int, .{ .name = "sqlite3_exec" });
    if (run(@ptrCast(store.db), statement, null, null, null) != 0) return error.TestSqlFailed;
}

test "native effects: schema 19 atomically migrates v1 identity and persists canonical scopes" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const host_entry = try f.store.setOwner(try change("legacy", 1, .permanent), clock.value());
    const host_key = host_entry.scope_key;
    try f.store.enableConsumerManifests();
    try f.store.enableConfirmedHistory();
    try f.store.enableMaintenance();
    try f.store.enableCleanup();
    try f.store.enableRetryLeases();
    try f.store.enableApplicationHistory();
    try f.store.enableEscalation();
    try t.expectEqual(@as(i64, 18), f.store.schema_version);

    f.store.fail_at = .before_canonical_effect_schema_commit;
    try t.expectError(error.InjectedFailure, f.store.enableCanonicalEffects());
    f.store.fail_at = null;
    try t.expectEqual(@as(i64, 18), f.store.schema_version);
    var rows: [4]effects.Entry = undefined;
    var page = try f.store.effectPage(null, null, &rows);
    try t.expectEqual(@as(usize, 1), page.count);
    try t.expectEqualSlices(u8, &host_key, &rows[0].scope_key);

    try f.store.enableCanonicalEffects();
    try t.expectEqual(@as(i64, 19), f.store.schema_version);
    page = try f.store.effectPage(null, null, &rows);
    try t.expectEqual(@as(usize, 1), page.count);
    try t.expectEqualSlices(u8, &host_key, &rows[0].scope_key);
    try t.expectEqualDeep(host_entry.scope.canonical, rows[0].scope.canonical);

    const network = canonical.Scope{
        .subject = try canonical.Subject.parseNetwork("2001:db8:1::/64"),
        .protocols = try canonical.Protocols.one(.tcp),
        .ports = try canonical.Ports.list(&.{canonical.PortRange.one(443)}),
    };
    const network_entry = try f.store.setOwnerFromCanonical(.{
        .scope = network,
        .jail = "network",
        .generation = [_]u8{4} ** 32,
        .decision_id = [_]u8{5} ** 32,
        .expected_revision = 0,
        .lease = .permanent,
        .decided_us = 100,
    }, clock.value());
    try t.expect(!std.mem.eql(u8, &host_key, &network_entry.scope_key));
    try t.expectEqualDeep(network, network_entry.scope.canonical);
    const shared_network_entry = try f.store.setOwnerFromCanonical(.{
        .scope = network,
        .jail = "network-shared",
        .generation = [_]u8{4} ** 32,
        .decision_id = [_]u8{6} ** 32,
        .expected_revision = 0,
        .lease = .permanent,
        .decided_us = 100,
    }, clock.value());
    try t.expectEqualSlices(u8, &network_entry.scope_key, &shared_network_entry.scope_key);
    var network_owners: [effects.max_page]effects.Owner = undefined;
    try t.expectEqual(@as(usize, 2), try f.store.effectOwners(shared_network_entry.scope_key, shared_network_entry.revision, &network_owners));

    const neighbor = canonical.Scope{
        .subject = network.subject,
        .protocols = network.protocols,
        .ports = try canonical.Ports.list(&.{canonical.PortRange.one(444)}),
    };
    const neighbor_entry = try f.store.setOwnerFromCanonical(.{
        .scope = neighbor,
        .jail = "network-neighbor",
        .generation = [_]u8{4} ** 32,
        .decision_id = [_]u8{7} ** 32,
        .expected_revision = 0,
        .lease = .permanent,
        .decided_us = 100,
    }, clock.value());
    try t.expect(!std.mem.eql(u8, &network_entry.scope_key, &neighbor_entry.scope_key));

    try f.reopen();
    page = try f.store.effectPage(null, null, &rows);
    try t.expectEqual(@as(usize, 3), page.count);
    var saw_host = false;
    var saw_network = false;
    var saw_neighbor = false;
    for (rows[0..page.count]) |entry| {
        if (std.mem.eql(u8, &entry.scope_key, &host_key)) saw_host = std.meta.eql(entry.scope.canonical, host_entry.scope.canonical);
        if (std.mem.eql(u8, &entry.scope_key, &network_entry.scope_key)) saw_network = std.meta.eql(entry.scope.canonical, network);
        if (std.mem.eql(u8, &entry.scope_key, &neighbor_entry.scope_key)) saw_neighbor = std.meta.eql(entry.scope.canonical, neighbor);
    }
    try t.expect(saw_host and saw_network and saw_neighbor);
}

test "native effects: tagged duration import deadline prolong and schedule boundaries" {
    const one = try lease_policy.Duration.finiteSeconds(1);
    try t.expectEqual(@as(i64, 1_000_000), one.finite_us);
    try t.expectEqualDeep(one, try (try lease_policy.ImportedDuration.fromSeconds(1)).activate());
    try t.expect((try lease_policy.ImportedDuration.fromSeconds(-1)) == .permanent);
    try t.expect((try (try lease_policy.ImportedDuration.fromSeconds(-1)).activate()) == .permanent);
    try t.expect((try lease_policy.ImportedDuration.fromSeconds(-2)) == .imported_unknown);
    try t.expectError(error.ImportedDurationUnknown, (try lease_policy.ImportedDuration.fromSeconds(-2)).activate());
    try t.expectError(error.InvalidDuration, lease_policy.ImportedDuration.fromSeconds(0));
    try t.expectError(error.InvalidDuration, lease_policy.ImportedDuration.fromSeconds(-3));
    try t.expectError(error.InvalidDuration, lease_policy.Duration.finiteSeconds(lease_policy.max_finite_seconds + 1));
    try t.expectError(error.InvalidDuration, (lease_policy.Duration{ .finite_us = 0 }).validate());
    try t.expectError(error.TimeOverflow, one.lease(std.math.maxInt(i64)));

    const finite = try one.lease(100);
    try t.expect(finite.live(1_000_099));
    try t.expect(!finite.live(1_000_100));
    const shorter = try finite.prolonged(.{ .finite = 900_000 }, 200);
    try t.expect(!shorter.changed);
    try t.expectEqualDeep(finite, shorter.lease);
    const longer = try finite.prolonged(.{ .finite = 2_000_000 }, 200);
    try t.expect(longer.changed);
    try t.expectEqual(@as(i64, 2_000_000), longer.lease.finite);
    try t.expect((try longer.lease.prolonged(.permanent, 200)).lease == .permanent);
    try t.expect(!(try @as(lease_policy.Lease, .permanent).prolonged(.{ .finite = 3_000_000 }, 200)).changed);
    try t.expectError(error.LeaseExpired, finite.prolonged(.permanent, 1_000_100));

    const schedule = try lease_policy.Schedule.fromLease(.{ .finite = 1_100 }, .{ .wall_us = 100, .monotonic_us = 5_000 });
    try t.expect(!schedule.due(5_999));
    try t.expect(schedule.due(6_000));
    // A running process schedules elapsed time monotonically; a forward wall
    // step alone cannot shorten the admitted lifetime.
    try t.expect(!schedule.due(5_500));
    try t.expect(!(try lease_policy.Schedule.fromLease(.permanent, .{ .wall_us = 100, .monotonic_us = 5_000 })).due(std.math.maxInt(u64)));
    try t.expect((try lease_policy.Schedule.fromLease(.{ .finite = 100 }, .{ .wall_us = 100, .monotonic_us = 5_000 })).due(5_000));
    const before_restart_boundary = try lease_policy.Schedule.fromLease(.{ .finite = 1_100 }, .{ .wall_us = 1_099, .monotonic_us = 100 });
    try t.expect(!before_restart_boundary.due(100));
    try t.expect(before_restart_boundary.due(101));
    try t.expect((try lease_policy.Schedule.fromLease(.{ .finite = 1_100 }, .{ .wall_us = 1_100, .monotonic_us = 100 })).due(100));
    try t.expectError(error.TimeOverflow, lease_policy.Schedule.fromLease(.{ .finite = std.math.maxInt(i64) }, .{ .wall_us = 0, .monotonic_us = std.math.maxInt(u64) }));
    var fence = lease_policy.ClockFence{ .wall_us = 100, .monotonic_us = 5_000 };
    try t.expectError(error.ClockReversed, fence.advance(.{ .wall_us = 99, .monotonic_us = 5_001 }));
    try t.expectError(error.ClockReversed, fence.advance(.{ .wall_us = 101, .monotonic_us = 4_999 }));
    try fence.advance(.{ .wall_us = 10_000, .monotonic_us = 5_500 });
    try fence.advance(.{ .wall_us = 10_000, .monotonic_us = 6_000 });
}

test "native effects: canonical host scope refuses aliases and unsupported wire fields" {
    const scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, 1 } });
    const wire = try scope.encode();
    try t.expectEqualDeep(scope, try effects.Scope.decode(&wire));
    for ([_]usize{ 0, 2, 3, 4, 5, 6, 7, 23 }) |index| {
        var changed = wire;
        changed[index] +%= 1;
        try t.expectError(error.InvalidEffect, effects.Scope.decode(&changed));
    }
    try t.expectError(error.InvalidEffect, effects.Scope.host(.{ .v6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 1 } }));
    try t.expectError(error.InvalidEffect, effects.Scope.host(.{ .v6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1 } }));
    var other = try installation();
    other.backend = .iptables;
    try t.expect(!std.mem.eql(u8, &try scope.key(try installation()), &try scope.key(other)));
}

test "native effects: canonical admission preserves v1 identity and refuses unrealized scope before mutation" {
    const canonical_host = canonical.Scope{ .subject = try canonical.Subject.parseHost("192.0.2.51") };
    const legacy = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, 51 } });
    try t.expectEqualDeep(legacy, try effects.Scope.fromCanonical(canonical_host));
    try t.expectEqualDeep(canonical_host, try legacy.toCanonical());
    const admitted = try effects.Scope.fromCanonical(canonical_host);
    try t.expectEqualSlices(u8, &try legacy.encode(), &try admitted.encode());
    try t.expectEqualSlices(u8, &try legacy.key(try installation()), &try admitted.key(try installation()));

    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const first_entry = try f.store.setOwner(try change("one", 1, .permanent), clock.value());
    try f.reopen();
    const second_entry = try f.store.setOwnerFromCanonical(.{
        .scope = canonical_host,
        .jail = "two",
        .generation = [_]u8{3} ** 32,
        .decision_id = [_]u8{2} ** 32,
        .expected_revision = 0,
        .lease = .permanent,
        .decided_us = 100,
    }, clock.value());
    try t.expectEqualSlices(u8, &first_entry.scope_key, &second_entry.scope_key);
    var rows: [1]effects.Entry = undefined;
    try t.expectEqual(@as(usize, 1), (try f.store.effectPage(null, null, &rows)).count);
    var owners: [effects.max_page]effects.Owner = undefined;
    try t.expectEqual(@as(usize, 2), try f.store.effectOwners(second_entry.scope_key, second_entry.revision, &owners));

    var empty = try Fixture.init();
    defer empty.deinit();
    try admit(&empty.store);
    const initial_epoch = empty.store.effect_publication_epoch;
    const network = canonical.Scope{ .subject = try canonical.Subject.parseNetwork("192.0.2.0/24") };
    const tcp_port = canonical.Scope{
        .subject = canonical_host.subject,
        .protocols = try canonical.Protocols.one(.tcp),
        .ports = try canonical.Ports.list(&.{canonical.PortRange.one(22)}),
    };
    const icmp = canonical.Scope{ .subject = canonical_host.subject, .protocols = try canonical.Protocols.one(.icmp_v4) };
    const tcp_udp = canonical.Scope{
        .subject = canonical_host.subject,
        .protocols = try canonical.Protocols.list(&.{ .tcp, .udp }),
        .ports = try canonical.Ports.list(&.{ canonical.PortRange.one(53), .{ .first = 8000, .last = 8010 } }),
    };
    for ([_]canonical.Scope{ network, tcp_port, icmp, tcp_udp }) |scope| {
        try t.expectError(error.EffectScopeNotRealized, empty.store.setOwnerFromCanonical(.{
            .scope = scope,
            .jail = "refused",
            .generation = [_]u8{3} ** 32,
            .decision_id = [_]u8{9} ** 32,
            .expected_revision = 0,
            .lease = .permanent,
            .decided_us = 100,
        }, clock.value()));
        try t.expectEqual(initial_epoch, empty.store.effect_publication_epoch);
        try t.expectEqual(@as(usize, 0), (try empty.store.effectPage(null, null, &rows)).count);
    }
}

test "native effects: migration alone authorizes nothing and installation remains stable on reopen" {
    var f = try Fixture.init();
    defer f.deinit();
    try t.expectEqual(@as(i64, 11), f.store.schema_version);
    try t.expectEqual(@as(?effects.Installation, null), try f.store.readInstallation());
    var clock = TestClock{};
    try t.expectError(error.InstallationRequired, f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value()));
    try t.expectError(error.NamespaceAdmissionRequired, f.store.admitInstallation(try installation(), .{ .selector = "host-default", .disposition = .verified_owned }));
    try admit(&f.store);
    try f.reopen();
    try t.expectEqualDeep(try installation(), (try f.store.readInstallation()).?);
    var other = try installation();
    other.id[0] = 8;
    try t.expectError(error.InstallationMismatch, f.store.admitInstallation(other, .{ .selector = "host-default", .disposition = .verified_absent }));
}

test "native effects: shared finite and permanent owners preserve maximum original protection" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const one = try f.store.setOwner(try change("one", 1, .{ .finite = 300 }), clock.value());
    const two = try f.store.setOwner(try change("two", 2, .{ .finite = 700 }), clock.value());
    try t.expectEqual(@as(i64, 700), two.desired.finite);
    try t.expectEqual(one.revision + 1, two.revision);
    const permanent = try f.store.setOwner(try change("three", 3, .permanent), clock.value());
    try t.expect(permanent.desired == .permanent);
    clock.now = 400;
    const partial = try f.store.prepareExpiry(permanent.scope_key, permanent.revision, clock.value());
    try t.expect(partial.desired == .permanent);
    var release = try change("three", 4, .absent);
    release.expected_revision = 1;
    release.decided_us = 400;
    const finite = try f.store.setOwner(release, clock.value());
    try t.expectEqual(@as(i64, 700), finite.desired.finite);
    clock.now = 700;
    const absent = try f.store.prepareExpiry(finite.scope_key, finite.revision, clock.value());
    try t.expect(absent.desired == .absent);
    var owners: [effects.max_page]effects.Owner = undefined;
    try t.expectEqual(@as(usize, 3), try f.store.effectOwners(absent.scope_key, absent.revision, &owners));
    for (owners[0..3]) |owner| try t.expect(owner.lease == .absent);
    try t.expectEqual(@as(i64, 300), (try f.store.ownerRevision(absent.scope_key, "one", 1)).?.lease.finite);
    try t.expectEqual(@as(i64, 700), (try f.store.ownerRevision(absent.scope_key, "two", 1)).?.lease.finite);
}

test "native effects: typed generation release flush and post-expiry reban preserve history and other owners" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    try enableSchema19(&f.store);
    var clock = TestClock{};
    const first_owner = try f.store.setOwner(try change("one", 1, .permanent), clock.value());
    const shared = try f.store.setOwner(try change("two", 2, .permanent), clock.value());
    try f.store.markDispatched(shared.token(), clock.value());
    _ = try f.store.settleVerified(shared.token(), observation(shared, clock.now, .permanent), clock.value());
    try t.expectEqual(@as(u64, 2), try f.store.confirmedEffectEvents());

    const next_generation = [_]u8{4} ** 32;
    const transition = effects.OwnerTransition{
        .scope = first_owner.scope.canonical,
        .jail = "one",
        .current_generation = [_]u8{3} ** 32,
        .next_generation = next_generation,
        .expected_owner_revision = 1,
        .transition_id = [_]u8{0xa1} ** 32,
        .mode = .retain,
        .occurred_us = clock.now,
    };
    for ([_]durable.CommitStage{ .after_effect_owner, .after_effect_intent }) |stage| {
        f.store.fail_at = stage;
        try t.expectError(error.InjectedFailure, f.store.transitionOwner(transition, clock.value()));
        var unchanged: [effects.max_page]effects.Owner = undefined;
        try t.expectEqual(@as(usize, 2), try f.store.effectOwners(first_owner.scope_key, shared.revision, &unchanged));
        try t.expectEqualSlices(u8, &[_]u8{3} ** 32, &unchanged[0].generation);
    }
    f.store.fail_at = null;
    const retained = try f.store.transitionOwner(transition, clock.value());
    try t.expect(retained.desired == .permanent);
    try f.store.markDispatched(retained.token(), clock.value());
    _ = try f.store.settleVerified(retained.token(), observation(retained, clock.now, .permanent), clock.value());
    try t.expectEqual(@as(u64, 2), try f.store.confirmedEffectEvents());
    const replay_epoch = f.store.effect_publication_epoch;
    const replayed = try f.store.transitionOwner(transition, clock.value());
    try t.expectEqual(retained.revision, replayed.revision);
    try t.expectEqualSlices(u8, &retained.intent_id, &replayed.intent_id);
    try t.expectEqual(replay_epoch, f.store.effect_publication_epoch);
    var owners: [effects.max_page]effects.Owner = undefined;
    try t.expectEqual(@as(usize, 2), try f.store.effectOwners(retained.scope_key, retained.revision, &owners));
    try t.expectEqualSlices(u8, &next_generation, &owners[0].generation);
    try t.expectEqualSlices(u8, &[_]u8{1} ** 32, &owners[0].decision_id);
    try t.expectEqual(@as(i64, 100), owners[0].decided_us);
    try t.expectError(error.EffectGenerationMismatch, f.store.transitionOwner(.{
        .scope = first_owner.scope.canonical,
        .jail = "one",
        .current_generation = [_]u8{3} ** 32,
        .next_generation = [_]u8{5} ** 32,
        .expected_owner_revision = owners[0].revision,
        .transition_id = [_]u8{0xa2} ** 32,
        .mode = .retain,
        .occurred_us = clock.now,
    }, clock.value()));

    const released = try f.store.transitionOwner(.{
        .scope = first_owner.scope.canonical,
        .jail = "one",
        .current_generation = next_generation,
        .next_generation = [_]u8{5} ** 32,
        .expected_owner_revision = owners[0].revision,
        .transition_id = [_]u8{0xb1} ** 32,
        .mode = .release,
        .occurred_us = clock.now,
    }, clock.value());
    try t.expect(released.desired == .permanent); // The shared owner stays live.
    try f.store.markDispatched(released.token(), clock.value());
    _ = try f.store.settleVerified(released.token(), observation(released, clock.now, .permanent), clock.value());
    try t.expectEqual(@as(u64, 2), try f.store.confirmedEffectEvents());
    const flushed = (try f.store.flushJailOwner("two", [_]u8{3} ** 32, [_]u8{0xc1} ** 32, clock.value())).?;
    try t.expect(flushed.desired == .absent);
    try t.expect((try f.store.flushJailOwner("two", [_]u8{3} ** 32, [_]u8{0xc1} ** 32, clock.value())) == null);
    try f.store.markDispatched(flushed.token(), clock.value());
    _ = try f.store.settleVerified(flushed.token(), observation(flushed, clock.now, .absent), clock.value());
    try t.expectEqual(@as(u64, 2), try f.store.confirmedEffectEvents());

    var reban_change = try change("reban", 3, .{ .finite = 200 });
    const finite = try f.store.setOwner(reban_change, clock.value());
    try f.store.markDispatched(finite.token(), clock.value());
    _ = try f.store.settleVerified(finite.token(), observation(finite, clock.now, finite.desired), clock.value());
    clock.now = 200;
    const expired = try f.store.prepareExpiry(finite.scope_key, finite.revision, clock.value());
    try f.store.markDispatched(expired.token(), clock.value());
    _ = try f.store.settleVerified(expired.token(), observation(expired, clock.now, .absent), clock.value());
    reban_change.decision_id = [_]u8{4} ** 32;
    reban_change.expected_revision = 2;
    reban_change.lease = .permanent;
    reban_change.decided_us = clock.now;
    const reban = try f.store.setOwner(reban_change, clock.value());
    try f.store.markDispatched(reban.token(), clock.value());
    _ = try f.store.settleVerified(reban.token(), observation(reban, clock.now, .permanent), clock.value());
    try t.expectEqual(@as(u64, 4), try f.store.confirmedEffectEvents());
}

test "native effects: independent target outcomes require enforcement proof and isolate optional failure" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    try enableSchema19(&f.store);
    try f.store.enableHistoryResets();
    f.store.fail_at = .before_action_target_schema_commit;
    try t.expectError(error.InjectedFailure, f.store.enableActionTargets());
    try t.expectEqual(@as(i64, 20), f.store.schema_version);
    f.store.fail_at = null;
    try f.store.enableActionTargets();
    try t.expectEqual(@as(i64, 21), f.store.schema_version);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 9, .permanent), clock.value());
    const intent = action_outcome.Intent{ .action_id = [_]u8{9} ** 32, .scope_key = entry.scope_key, .jail = "one", .metadata = "bounded fixture" };
    f.store.fail_at = .after_action_target_intent;
    try t.expectError(error.InjectedFailure, f.store.prepareActionTargets(intent, clock.value()));
    f.store.fail_at = null;
    var targets: [action_outcome.max_targets_per_action]action_outcome.Target = undefined;
    try t.expectEqual(@as(usize, 0), try f.store.actionTargets(intent.action_id, &targets));
    try f.store.prepareActionTargets(intent, clock.value());
    try f.store.prepareActionTargets(intent, clock.value());
    try t.expectEqual(@as(usize, 2), try f.store.actionTargets(intent.action_id, &targets));
    try t.expectEqual(action_outcome.Status.pending, targets[0].status);
    try t.expectEqual(action_outcome.Status.pending, targets[1].status);
    try t.expectEqualStrings("bounded fixture", targets[1].metadata());

    try f.store.markActionTargetDispatched(intent.action_id, .notification, clock.value());
    try f.store.settleActionTarget(intent.action_id, .notification, .uncertain, clock.value());
    try f.store.markActionTargetDispatched(intent.action_id, .notification, clock.value());
    f.store.fail_at = .before_action_target_settlement_commit;
    try t.expectError(error.InjectedFailure, f.store.settleActionTarget(intent.action_id, .notification, .failed, clock.value()));
    f.store.fail_at = null;
    try f.store.settleActionTarget(intent.action_id, .notification, .failed, clock.value());
    try f.store.markActionTargetDispatched(intent.action_id, .enforcement, clock.value());
    try t.expectError(error.ActionTargetProofRequired, f.store.settleActionTarget(intent.action_id, .enforcement, .confirmed, clock.value()));
    try t.expectEqual(@as(usize, 2), try f.store.actionTargets(intent.action_id, &targets));
    try t.expectEqual(action_outcome.Status.dispatched, targets[0].status);
    try t.expectEqual(action_outcome.Status.failed, targets[1].status);

    try f.store.markDispatched(entry.token(), clock.value());
    _ = try f.store.settleVerified(entry.token(), observation(entry, clock.now, .permanent), clock.value());
    try f.store.settleActionTarget(intent.action_id, .enforcement, .confirmed, clock.value());
    try f.reopen();
    try t.expectEqual(@as(usize, 2), try f.store.actionTargets(intent.action_id, &targets));
    try t.expectEqual(action_outcome.Status.confirmed, targets[0].status);
    try t.expectEqual(action_outcome.Status.failed, targets[1].status);

    const restored = action_outcome.Intent{ .action_id = [_]u8{10} ** 32, .scope_key = entry.scope_key, .jail = "one", .restored = true };
    try f.store.prepareActionTargets(restored, clock.value());
    try t.expectEqual(@as(usize, 2), try f.store.actionTargets(restored.action_id, &targets));
    try t.expectEqual(action_outcome.Status.pending, targets[0].status);
    try t.expectEqual(action_outcome.Status.suppressed_restored, targets[1].status);
    try t.expectError(error.StaleActionTarget, f.store.markActionTargetDispatched(restored.action_id, .notification, clock.value()));
    try t.expectError(error.InvalidActionTarget, f.store.prepareActionTargets(.{ .action_id = [_]u8{11} ** 32, .scope_key = entry.scope_key, .jail = "one", .metadata = &([_]u8{'x'} ** 513) }, clock.value()));
}

test "native effects: optional target saturation refuses without evicting existing rows" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    try enableSchema19(&f.store);
    try f.store.enableHistoryResets();
    try f.store.enableActionTargets();
    try sql(&f.store,
        \\WITH RECURSIVE c(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM c WHERE x<65536)
        \\INSERT INTO action_targets SELECT CAST(printf('%032x',x) AS BLOB),CASE WHEN x%2=0 THEN 1 ELSE 2 END,zeroblob(32),'capacity',CASE WHEN x%2=0 THEN 1 ELSE 0 END,0,1,100,NULL,NULL,NULL FROM c;
    );
    var clock = TestClock{};
    try t.expectError(error.ActionTargetCapacity, f.store.prepareActionTargets(.{ .action_id = [_]u8{0xee} ** 32, .scope_key = [_]u8{0xdd} ** 32, .jail = "capacity" }, clock.value()));
}

test "native effects: dispatch fences replacement and complete reconciliation retains intent identity" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value());
    try f.store.markDispatched(entry.token(), clock.value());
    try t.expectError(error.EffectReconciliationRequired, f.store.setOwner(try change("two", 2, .permanent), clock.value()));
    var incomplete = observation(entry, 100, .absent);
    incomplete.qualification = .incomplete;
    try t.expectError(error.IncompleteEffectObservation, f.store.settleVerified(entry.token(), incomplete, clock.value()));
    try t.expectEqual(effects.Settlement.retry_same_intent, try f.store.settleVerified(entry.token(), observation(entry, 100, .absent), clock.value()));
    try t.expectEqualDeep(entry.intent_id, (try first(&f.store)).intent_id);
    try f.store.markDispatched(entry.token(), clock.value());
    try t.expectEqual(effects.Settlement.verified, try f.store.settleVerified(entry.token(), observation(entry, 100, entry.desired), clock.value()));
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
    _ = try f.store.settleVerified(entry.token(), observation(entry, 100, entry.desired), clock.value());
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
    clock.now = 101;
    var drift = observation(entry, 101, .absent);
    drift.state = null;
    try t.expectEqual(effects.Settlement.retry_same_intent, try f.store.settleVerified(entry.token(), drift, clock.value()));
    try f.store.markDispatched(entry.token(), clock.value());
    _ = try f.store.settleVerified(entry.token(), observation(entry, 101, entry.desired), clock.value());
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
}

test "native effects: expired uncertain add reconciles before exact removal without a new ban" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .{ .finite = 200 }), clock.value());
    try f.store.markDispatched(entry.token(), clock.value());
    try f.reopen();
    clock.now = 250;
    try t.expectError(error.EffectReconciliationRequired, f.store.prepareExpiry(entry.scope_key, entry.revision, clock.value()));
    try t.expectEqual(effects.Settlement.expired, try f.store.settleVerified(entry.token(), observation(entry, 250, entry.desired), clock.value()));
    const remove = try f.store.prepareExpiry(entry.scope_key, entry.revision, clock.value());
    try t.expect(remove.desired == .absent);
    try f.store.markDispatched(remove.token(), clock.value());
    _ = try f.store.settleVerified(remove.token(), observation(remove, 250, .absent), clock.value());
    try t.expectEqual(@as(u64, 0), try f.store.confirmedEffectEvents());
}

test "native effects: rollback preserves owner intent publication epoch and final clock expiry" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value());
    const epoch = f.store.effect_publication_epoch;
    for ([_]durable.CommitStage{ .after_effect_owner, .after_effect_intent }) |stage| {
        f.store.fail_at = stage;
        try t.expectError(error.InjectedFailure, f.store.setOwner(try change("two", 2, .permanent), clock.value()));
        try t.expectEqual(epoch, f.store.effect_publication_epoch);
        try t.expectEqualDeep(entry, try first(&f.store));
    }
    f.store.fail_at = .before_effect_dispatch_commit;
    try t.expectError(error.InjectedFailure, f.store.markDispatched(entry.token(), clock.value()));
    try t.expectEqualDeep(entry, try first(&f.store));
    f.store.fail_at = null;
    clock.now = 499;
    clock.advance = 1;
    try t.expectError(error.EffectExpired, f.store.markDispatched(entry.token(), clock.value()));
    try t.expectEqualDeep(entry, try first(&f.store));
    clock.now = 200;
    clock.advance = 0;
    try f.store.markDispatched(entry.token(), clock.value());
    f.store.fail_at = .before_effect_receipt_commit;
    try t.expectError(error.InjectedFailure, f.store.settleVerified(entry.token(), observation(entry, 200, entry.desired), clock.value()));
    try t.expectEqual(@as(u64, 0), try f.store.confirmedEffectEvents());
    try f.reopen();
    clock.now = 199;
    try t.expectError(error.EffectClockReversed, f.store.settleVerified(entry.token(), observation(entry, 199, entry.desired), clock.value()));
}

test "native effects: detached pages detect changed snapshot and malformed canonical persisted values" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    _ = try f.store.setOwner(try change("one", 1, .permanent), clock.value());
    var rows: [1]effects.Entry = undefined;
    const page = try f.store.effectPage(null, null, &rows);
    _ = try f.store.setOwner(try change("two", 2, .permanent), clock.value());
    try t.expectError(error.StaleEffect, f.store.effectPage(rows[0].scope_key, page.revision, &rows));
    try sql(&f.store, "PRAGMA ignore_check_constraints=ON; UPDATE native_effects SET scope=zeroblob(24);");
    try t.expectError(error.InvalidEffect, f.store.effectPage(null, null, &rows));
}

const record_identity = durable.ReceiptIdentity{ .jail = "one", .source = "file", .occurrence = "1", .cursor = "cursor-1", .raw_hash = [_]u8{1} ** 32, .generation = [_]u8{3} ** 32 };
const enforcing_policy = retry.Policy{ .maxretry = 1, .window_us = 1000, .duration = .{ .finite_us = 400 }, .max_subjects = 8, .enforce = true };
fn record(clock: *TestClock) !durable.Record {
    const detected = @import("core/native_detection_record.zig");
    const outcome = try time_policy.evaluate(.timestamped, .{ .parsed = .{ .us = 100 } }, .{ .us = 100 }, .{ .us = 100 }, 1000);
    return .{ .jail = record_identity.jail, .source = record_identity.source, .occurrence = record_identity.occurrence, .cursor = record_identity.cursor, .raw_hash = record_identity.raw_hash, .receipt = .{ .time = .{ .us = 100 }, .generation = record_identity.generation }, .native_time_outcome = outcome, .native_detection = .{ .kind = .candidate, .generation = record_identity.generation, .filter = try detected.Name.init("fixture"), .pattern = try detected.Name.init("failure"), .pattern_index = 0, .subject = .{ .v4 = .{ 192, 0, 2, 51 } } }, .native_retry = .{ .generation = record_identity.generation, .policy = enforcing_policy, .processing_us = 100 }, .effects_clock = clock.value(), .disposition = outcome.disposition(), .checkpoint = "checkpoint", .zone_provenance = .{ .zone_digest = [_]u8{4} ** 32, .offset_seconds = -18000, .ambiguity = .later, .fold_selected = true } };
}
fn admitRecord(store: *durable.Store) !void {
    try store.admitRetry(record_identity.jail, record_identity.generation, enforcing_policy);
    _ = try store.beginReceipt(record_identity, .{ .us = 100 }, 0);
}

test "native effects: composed schema 14 to 21 upgrade preserves source owner expiry history and suppresses restored notification" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    try f.store.enableConsumerManifests();
    try f.store.enableConfirmedHistory();
    try f.store.enableMaintenance();
    try t.expectEqual(@as(i64, 14), f.store.schema_version);
    try admitRecord(&f.store);
    var clock = TestClock{};
    try t.expectEqual(durable.CommitResult.committed, try f.store.commitRecord(try record(&clock)));
    const entry = try first(&f.store);
    try f.store.markDispatched(entry.token(), clock.value());
    _ = try f.store.settleVerified(entry.token(), observation(entry, clock.now, entry.desired), clock.value());
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());

    try f.reopen();
    try t.expectEqual(@as(i64, 14), f.store.schema_version);
    try f.store.enableCleanup();
    try f.store.enableRetryLeases();
    try f.store.enableApplicationHistory();
    try f.store.enableEscalation();
    try f.store.enableCanonicalEffects();
    try f.store.enableHistoryResets();
    try f.store.enableActionTargets();
    try t.expectEqual(@as(i64, 21), f.store.schema_version);

    const cursor = (try f.store.sourceCursor(t.allocator, record_identity.jail, record_identity.source)).?;
    defer t.allocator.free(cursor);
    try t.expectEqualStrings(record_identity.cursor, cursor);
    try t.expectEqualDeep(retry.Lease{ .finite = 500 }, (try f.store.retryDecision(record_identity.jail, record_identity.source, record_identity.occurrence)).?.lease);
    const restored = try first(&f.store);
    try t.expectEqual(effects.Status.applied, restored.status);
    try t.expectEqual(effects.Lease{ .finite = 500 }, restored.desired);
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
    var owners: [effects.max_page]effects.Owner = undefined;
    try t.expectEqual(@as(usize, 1), try f.store.effectOwners(restored.scope_key, restored.revision, &owners));
    var targets: [action_outcome.max_targets_per_action]action_outcome.Target = undefined;
    try t.expectEqual(@as(usize, 2), try f.store.actionTargets(owners[0].decision_id, &targets));
    try t.expect(targets[0].restored and targets[1].restored);
    try t.expectEqual(action_outcome.Status.pending, targets[0].status);
    try t.expectEqual(action_outcome.Status.suppressed_restored, targets[1].status);
}

test "native effects: enforcing record cursor receipt retry owner intent and zone commit atomically" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    try enableSchema19(&f.store);
    try f.store.enableHistoryResets();
    try f.store.enableActionTargets();
    try admitRecord(&f.store);
    var clock = TestClock{};
    const value = try record(&clock);
    const scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, 51 } });
    const scope_key = try scope.key(try installation());
    const action_id = effects.hashParts("fail2zig-native-effect-decision-v2", &.{ record_identity.jail, record_identity.source, record_identity.occurrence, &record_identity.generation, &scope_key });
    var targets: [action_outcome.max_targets_per_action]action_outcome.Target = undefined;
    for ([_]durable.CommitStage{ .after_effect_owner, .after_effect_intent, .after_action_target_intent, .after_receipt_delete, .before_commit }) |stage| {
        f.store.fail_at = stage;
        try t.expectError(error.InjectedFailure, f.store.commitRecord(value));
        try t.expectEqual(@as(u64, 0), try f.store.revision("one"));
        try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
        try t.expectEqual(@as(u64, 0), f.store.effect_publication_epoch);
        var rows: [1]effects.Entry = undefined;
        try t.expectEqual(@as(usize, 0), (try f.store.effectPage(null, null, &rows)).count);
        try t.expectEqual(@as(usize, 0), try f.store.actionTargets(action_id, &targets));
    }
    f.store.fail_at = null;
    try t.expectEqual(durable.CommitResult.committed, try f.store.commitRecord(value));
    try t.expectEqual(@as(u64, 1), f.store.effect_publication_epoch);
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    try t.expectEqual(@as(i64, 500), (try first(&f.store)).desired.finite);
    try t.expectEqual(@as(usize, 2), try f.store.actionTargets(action_id, &targets));
    try t.expectEqual(action_outcome.Status.pending, targets[0].status);
    try t.expectEqual(action_outcome.Status.pending, targets[1].status);
    try t.expectEqualDeep(value.zone_provenance, try f.store.nativeTimeProvenance("one", "file", "1"));
    try t.expectEqual(durable.CommitResult.already_committed, try f.store.commitRecord(value));
    try t.expectEqual(@as(u64, 1), f.store.effect_publication_epoch);
    var changed = value;
    changed.zone_provenance.?.offset_seconds = 0;
    try t.expectError(error.OccurrenceConflict, f.store.commitRecord(changed));
    try f.reopen();
    try t.expectEqualDeep(value.zone_provenance, try f.store.nativeTimeProvenance("one", "file", null));
    try t.expectEqual(@as(i64, 500), (try first(&f.store)).desired.finite);
}

test "native effects: retry prolong commits state owner intent and stable history identity atomically" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    try f.store.enableConfirmedHistory();
    try f.store.enableMaintenance();
    try f.store.enableCleanup();
    try f.store.enableRetryLeases();
    try admit(&f.store);
    try admitRecord(&f.store);
    var clock = TestClock{};
    try t.expectEqual(durable.CommitResult.committed, try f.store.commitRecord(try record(&clock)));
    const initial = try first(&f.store);
    try f.store.markDispatched(initial.token(), clock.value());
    try t.expectEqual(effects.Settlement.verified, try f.store.settleVerified(initial.token(), observation(initial, 100, initial.desired), clock.value()));
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
    var owners: [effects.max_page]effects.Owner = undefined;
    try t.expectEqual(@as(usize, 1), try f.store.effectOwners(initial.scope_key, initial.revision, &owners));
    const original_owner = owners[0];
    const subject = @import("core/native_detection_record.zig").Subject{ .v4 = .{ 192, 0, 2, 51 } };
    const request = durable.Store.RetryProlongation{
        .jail = record_identity.jail,
        .generation = record_identity.generation,
        .subject = subject,
        .ordinal = 1,
        .expected_owner_revision = original_owner.revision,
        .requested = .{ .finite = 800 },
    };
    f.store.fail_at = .after_retry_decision;
    try t.expectError(error.InjectedFailure, f.store.prolongRetryDecision(request, clock.value()));
    f.store.fail_at = null;
    try t.expectEqualDeep(retry.Lease{ .finite = 500 }, (try f.store.retryState("one", subject)).?.lease);
    try t.expectEqualDeep(retry.Lease{ .finite = 500 }, (try f.store.retryDecision("one", "file", "1")).?.lease);
    try t.expectEqual(effects.Status.applied, (try first(&f.store)).status);
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());

    const manager = try runtime.Manager.create(t.allocator, &f.store, try installation());
    defer manager.destroy();
    manager.wall_context = &clock;
    manager.wall = TestClock.read;
    manager.last_wall_us = clock.now;
    manager.live[0] = try first(&f.store);
    manager.count = 1;
    manager.cached_epoch = f.store.effect_publication_epoch;
    manager.status.ready = true;
    try t.expect(manager.confirmedSubject(subject, clock.now));
    const longer = try manager.prolongRetry(request);
    try t.expect(longer.changed);
    try t.expect(!manager.status.ready);
    try t.expect(!manager.confirmedSubject(subject, clock.now));
    try t.expectEqualDeep(retry.Lease{ .finite = 800 }, longer.lease);
    try t.expectEqualDeep(longer.lease, longer.effect.desired);
    try f.store.markDispatched(longer.effect.token(), clock.value());
    try t.expectEqual(effects.Settlement.verified, try f.store.settleVerified(longer.effect.token(), observation(longer.effect, 100, longer.effect.desired), clock.value()));
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
    try t.expectEqual(@as(usize, 1), try f.store.effectOwners(longer.effect.scope_key, longer.effect.revision, &owners));
    try t.expectEqual(original_owner.revision + 1, owners[0].revision);
    try t.expectEqualSlices(u8, &original_owner.decision_id, &owners[0].decision_id);
    try t.expectEqual(original_owner.decided_us, owners[0].decided_us);

    var shorter = request;
    shorter.expected_owner_revision = owners[0].revision;
    shorter.requested = .{ .finite = 700 };
    const unchanged = try f.store.prolongRetryDecision(shorter, clock.value());
    try t.expect(!unchanged.changed);
    try t.expectEqual(longer.effect.revision, unchanged.effect.revision);
    var forever = shorter;
    forever.requested = .permanent;
    const permanent = try f.store.prolongRetryDecision(forever, clock.value());
    try t.expect(permanent.changed);
    try t.expectEqualDeep(retry.Lease.permanent, permanent.lease);
    try t.expectEqualDeep(retry.Lease.permanent, (try f.store.retryState("one", subject)).?.lease);
    try t.expectEqualDeep(retry.Lease.permanent, (try f.store.retryDecision("one", "file", "1")).?.lease);
    try f.store.markDispatched(permanent.effect.token(), clock.value());
    try t.expectEqual(effects.Settlement.verified, try f.store.settleVerified(permanent.effect.token(), observation(permanent.effect, 100, .permanent), clock.value()));
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
    try f.reopen();
    manager.storageReopened();
    try t.expect(!manager.confirmedSubject(subject, clock.now));
    try t.expectEqualDeep(retry.Lease.permanent, (try f.store.retryState("one", subject)).?.lease);
    try t.expectEqualDeep(retry.Lease.permanent, (try f.store.retryDecision("one", "file", "1")).?.lease);
    const restored = try first(&f.store);
    try t.expectEqualDeep(retry.Lease.permanent, restored.desired);
    try t.expectEqual(@as(usize, 1), try f.store.effectOwners(restored.scope_key, restored.revision, &owners));
    try t.expectEqualSlices(u8, &original_owner.decision_id, &owners[0].decision_id);
    try t.expectEqual(original_owner.decided_us, owners[0].decided_us);
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
}

test "native effects: actual killed migration record dispatch and receipt commits reopen before or after" {
    const Stage = enum { migration, record, dispatch, receipt };
    for ([_]Stage{ .migration, .record, .dispatch, .receipt }) |stage| for ([_]bool{ false, true }) |after| {
        var f = try Fixture.initSchema(stage != .migration);
        defer f.deinit();
        var clock = TestClock{};
        var entry: effects.Entry = undefined;
        if (stage != .migration) try admit(&f.store);
        if (stage == .record) try admitRecord(&f.store);
        if (stage == .dispatch or stage == .receipt) entry = try f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value());
        if (stage == .receipt) try f.store.markDispatched(entry.token(), clock.value());
        f.store.close();
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = durable.Store.open(std.heap.page_allocator, f.path) catch std.process.exit(2);
            child.enableReceipts(8) catch std.process.exit(3);
            const Kill = struct {
                const Db = std.meta.Child(@FieldType(durable.Store, "db"));
                const Exec = @FieldType(@FieldType(durable.Store, "api"), "exec");
                var actual: Exec = undefined;
                var after_commit: bool = false;
                fn exec(db: *Db, statement: [*:0]const u8, callback: ?*anyopaque, ctx: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (!std.mem.eql(u8, std.mem.span(statement), "COMMIT;")) return actual(db, statement, callback, ctx, message);
                    if (after_commit and actual(db, statement, callback, ctx, message) != 0) std.process.exit(4);
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(5);
                    unreachable;
                }
            };
            Kill.actual = child.api.exec;
            Kill.after_commit = after;
            child.api.exec = Kill.exec;
            switch (stage) {
                .migration => child.enableEffects() catch std.process.exit(6),
                .record => {
                    const value = record(&clock) catch std.process.exit(7);
                    _ = child.commitRecord(value) catch std.process.exit(8);
                },
                .dispatch => child.markDispatched(entry.token(), clock.value()) catch std.process.exit(9),
                .receipt => {
                    _ = child.settleVerified(entry.token(), observation(entry, 100, entry.desired), clock.value()) catch std.process.exit(10);
                },
            }
            std.process.exit(11);
        }
        const ended = std.posix.waitpid(pid, 0);
        f.store = try durable.Store.open(t.allocator, f.path);
        try f.store.enableReceipts(8);
        try t.expect(std.posix.W.IFSIGNALED(ended.status));
        try t.expectEqual(@as(u32, std.posix.SIG.KILL), std.posix.W.TERMSIG(ended.status));
        switch (stage) {
            .migration => try t.expectEqual(@as(i64, if (after) 11 else 10), f.store.schema_version),
            .record => {
                try t.expectEqual(@as(u64, @intFromBool(after)), try f.store.revision("one"));
                try t.expectEqual(@as(usize, @intFromBool(!after)), try f.store.pendingReceiptCount());
                var rows: [1]effects.Entry = undefined;
                try t.expectEqual(@as(usize, @intFromBool(after)), (try f.store.effectPage(null, null, &rows)).count);
                if (after) try t.expectEqual(@as(i64, 500), rows[0].desired.finite);
            },
            .dispatch => try t.expectEqual(if (after) effects.Status.dispatched else effects.Status.pending, (try first(&f.store)).status),
            .receipt => {
                try t.expectEqual(if (after) effects.Status.applied else effects.Status.dispatched, (try first(&f.store)).status);
                try t.expectEqual(@as(u64, @intFromBool(after)), try f.store.confirmedEffectEvents());
            },
        }
    };
}

fn allocationRead(allocator: std.mem.Allocator, path: []const u8) !void {
    var store = try durable.Store.open(allocator, path);
    defer store.close();
    var rows: [1]effects.Entry = undefined;
    try t.expectEqual(@as(usize, 1), (try store.effectPage(null, null, &rows)).count);
    try t.expectEqual(@as(i64, 500), rows[0].desired.finite);
}
test "native effects: allocator failure and SQLite OOM rollback retain committed protection" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value());
    try t.checkAllAllocationFailures(t.allocator, allocationRead, .{f.path});
    const Fail = struct {
        const Db = std.meta.Child(@FieldType(durable.Store, "db"));
        const Api = @FieldType(durable.Store, "api");
        const Prepare = @FieldType(Api, "prepare");
        var actual: Prepare = undefined;
        fn prepare(db: *Db, statement: [*:0]const u8, length: c_int, output: *?*anyopaque, tail: ?*?[*:0]const u8) callconv(.c) c_int {
            if (std.mem.startsWith(u8, std.mem.span(statement), "INSERT INTO effect_intents")) return 7;
            return actual(db, statement, length, @ptrCast(output), tail);
        }
    };
    const epoch = f.store.effect_publication_epoch;
    Fail.actual = f.store.api.prepare;
    f.store.api.prepare = @ptrCast(&Fail.prepare);
    try t.expectError(error.OutOfMemory, f.store.setOwner(try change("two", 2, .permanent), clock.value()));
    f.store.api.prepare = Fail.actual;
    try t.expectEqual(epoch, f.store.effect_publication_epoch);
    try t.expectEqualDeep(entry, try first(&f.store));
    try t.expectEqual(@as(?c_int, 7), f.store.last_error_code);
}

test "native effects: exact owner limit refuses without evicting prior authorization" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    var last: effects.Entry = undefined;
    for (0..effects.max_page) |i| {
        var name: [16]u8 = undefined;
        const jail = try std.fmt.bufPrint(&name, "owner-{d}", .{i});
        last = try f.store.setOwner(try change(jail, @intCast(i + 1), .permanent), clock.value());
    }
    const epoch = f.store.effect_publication_epoch;
    try t.expectError(error.EffectCapacity, f.store.setOwner(try change("overflow", 100, .permanent), clock.value()));
    try t.expectEqual(epoch, f.store.effect_publication_epoch);
    try t.expectEqualDeep(last, try first(&f.store));
    var rows: [effects.max_page]effects.Owner = undefined;
    try t.expectEqual(@as(usize, effects.max_page), try f.store.effectOwners(last.scope_key, last.revision, &rows));
    var stale = try change("owner-0", 101, .absent);
    try t.expectError(error.StaleEffect, f.store.setOwner(stale, clock.value()));
    stale.expected_revision = 1;
    stale.generation[0] = 99;
    try t.expectError(error.EffectGenerationMismatch, f.store.setOwner(stale, clock.value()));
}

test "native effects: advancing same-intent retry reopens with original observation history" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value());
    try f.store.markDispatched(entry.token(), clock.value());
    clock.now = 110;
    _ = try f.store.settleVerified(entry.token(), observation(entry, 110, .absent), clock.value());
    clock.now = 120;
    try f.store.markDispatched(entry.token(), clock.value());
    try f.reopen();
    try t.expectEqual(effects.Status.dispatched, (try first(&f.store)).status);
    clock.now = 130;
    _ = try f.store.settleVerified(entry.token(), observation(entry, 130, entry.desired), clock.value());
    try sql(&f.store, "CREATE TEMP TABLE receipt_count(n INTEGER CHECK(n=2)); INSERT INTO receipt_count SELECT count(*) FROM effect_observations;");
    clock.now = 140;
    try t.expectError(error.StaleEffect, f.store.settleVerified(entry.token(), observation(entry, 125, .absent), clock.value()));
    var conflict = observation(entry, 130, .absent);
    conflict.fingerprint[0] = 8;
    try t.expectError(error.StaleEffect, f.store.settleVerified(entry.token(), conflict, clock.value()));
    try t.expectEqual(effects.Status.applied, (try first(&f.store)).status);
    try t.expectEqual(@as(i64, 500), (try first(&f.store)).desired.finite);
}

test "native effects: full confirmation ledger permits existing dedup but refuses new event atomically" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .permanent), clock.value());
    try f.store.markDispatched(entry.token(), clock.value());
    _ = try f.store.settleVerified(entry.token(), observation(entry, 100, .permanent), clock.value());
    try sql(&f.store, "WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n<65535) INSERT INTO confirmed_effect_events SELECT CAST(printf('%032d',n) AS BLOB),(SELECT scope_key FROM native_effects LIMIT 1),'filler-'||n,zeroblob(32),100 FROM numbers;");
    try t.expectEqual(@as(u64, effects.max_confirmed_events), try f.store.confirmedEffectEvents());
    _ = try f.store.settleVerified(entry.token(), observation(entry, 100, .permanent), clock.value());
    clock.now = 110;
    _ = try f.store.settleVerified(entry.token(), observation(entry, 110, .absent), clock.value());
    clock.now = 120;
    try f.store.markDispatched(entry.token(), clock.value());
    _ = try f.store.settleVerified(entry.token(), observation(entry, 120, .permanent), clock.value());
    const second = try f.store.setOwner(try change("two", 2, .permanent), clock.value());
    try f.store.markDispatched(second.token(), clock.value());
    const epoch = f.store.effect_publication_epoch;
    try t.expectError(error.EffectCapacity, f.store.settleVerified(second.token(), observation(second, 120, .permanent), clock.value()));
    try t.expectEqual(epoch, f.store.effect_publication_epoch);
    try t.expectEqual(effects.Status.dispatched, (try first(&f.store)).status);
    try t.expectEqual(@as(u64, effects.max_confirmed_events), try f.store.confirmedEffectEvents());
}
