// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

//! Schema 22 (admin state) and schema 23 (migration state): upgrade order, refusal of
//! out-of-order upgrades, injected commit failure with rollback and reopen, storage failure,
//! constraint enforcement and isolation of staged migration rows from runtime admission.

const std = @import("std");
const durable = @import("core/record_store.zig");
const effects = @import("core/native_effect.zig");

const t = std.testing;

const Fixture = struct {
    tmp: t.TmpDir,
    path: []u8,
    store: durable.Store,
    open: bool = true,

    fn init() !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "admin.sqlite" });
        errdefer t.allocator.free(path);
        var store = try durable.Store.open(t.allocator, path);
        errdefer store.close();
        try enableThrough21(&store);
        return .{ .tmp = tmp, .path = path, .store = store };
    }
    fn deinit(self: *Fixture) void {
        if (self.open) self.store.close();
        t.allocator.free(self.path);
        self.tmp.cleanup();
    }
    fn reopen(self: *Fixture) !void {
        self.store.close();
        self.store = try durable.Store.open(t.allocator, self.path);
    }
    fn userVersion(self: *Fixture) !i64 {
        return self.store.inspectInteger("PRAGMA user_version;");
    }
};

/// Mirrors the daemon's `admitStore` chain up to the accepted N3 schema.
fn enableThrough21(store: *durable.Store) !void {
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
}

test "native admin store: schema 22 then 23 upgrade from the accepted N3 schema and survive reopen" {
    var f = try Fixture.init();
    defer f.deinit();
    try t.expectEqual(@as(i64, 21), f.store.schema_version);
    try t.expectError(error.AdminStorageRequired, f.store.adminRevision());
    try t.expectError(error.UnsupportedSchema, f.store.enableMigrationState());
    try t.expectEqual(@as(i64, 21), try f.userVersion());

    try f.store.enableAdminState();
    try t.expectEqual(@as(i64, 22), f.store.schema_version);
    try t.expectEqual(@as(u64, 0), try f.store.adminRevision());
    try f.store.enableMigrationState();
    try t.expectEqual(@as(i64, 23), f.store.schema_version);

    // Idempotent re-enable and reopen keep the version and the single revision row.
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try f.reopen();
    try t.expectEqual(@as(i64, 23), try f.userVersion());
    try enableThrough21(&f.store);
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try t.expectEqual(@as(u64, 0), try f.store.adminRevision());
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM admin_revision;"));
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM migration_runs;"));
}

test "native admin store: injected commit failure rolls both upgrades back and a reopen sees schema 21" {
    var f = try Fixture.init();
    defer f.deinit();
    f.store.fail_at = .before_admin_schema_commit;
    try t.expectError(error.InjectedFailure, f.store.enableAdminState());
    try t.expectEqual(@as(i64, 21), f.store.schema_version);
    try t.expectEqual(@as(i64, 21), try f.userVersion());
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM sqlite_master WHERE name IN('admin_revision','config_generations','jail_admin_states','admin_requests');"));
    f.store.fail_at = null;
    try f.store.enableAdminState();
    f.store.fail_at = .before_migration_schema_commit;
    try t.expectError(error.InjectedFailure, f.store.enableMigrationState());
    try t.expectEqual(@as(i64, 22), f.store.schema_version);
    try f.reopen();
    try t.expectEqual(@as(i64, 22), try f.userVersion());
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM sqlite_master WHERE name LIKE 'migration_%';"));
    try enableThrough21(&f.store);
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try t.expectEqual(@as(i64, 23), try f.userVersion());
}

test "native admin store: constraints reject malformed ids, enums, booleans and timestamps" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try f.store.inspectExec("INSERT INTO config_generations VALUES(zeroblob(32),zeroblob(32),'/etc/fail2zig/config.toml',10,1,0);");
    const rejected = [_][:0]const u8{
        "INSERT INTO config_generations VALUES(zeroblob(31),zeroblob(32),'/p',10,1,0);",
        "INSERT INTO config_generations VALUES(randomblob(32),zeroblob(32),'/p',-1,1,0);",
        "INSERT INTO config_generations VALUES(randomblob(32),zeroblob(32),'/p',10,2,0);",
        "INSERT INTO config_generation_jails VALUES(randomblob(32),'sshd',zeroblob(32),zeroblob(1));",
        "INSERT INTO config_generation_jails VALUES(zeroblob(32),'',zeroblob(32),zeroblob(1));",
        "INSERT INTO config_generation_jails VALUES(zeroblob(32),'sshd',zeroblob(32),zeroblob(65537));",
        "INSERT INTO jail_admin_states VALUES('sshd',1,0,zeroblob(31),5,zeroblob(32));",
        "INSERT INTO jail_admin_states VALUES('sshd',2,0,zeroblob(32),5,zeroblob(32));",
        "INSERT INTO jail_admin_states VALUES('sshd',1,0,randomblob(32),5,zeroblob(32));",
        "INSERT INTO admin_requests VALUES(zeroblob(32),11,zeroblob(1),1,zeroblob(32),1,1,zeroblob(0));",
        "INSERT INTO admin_requests VALUES(zeroblob(32),1,zeroblob(4097),1,zeroblob(32),1,1,zeroblob(0));",
        "INSERT INTO admin_requests VALUES(zeroblob(32),1,zeroblob(1),6,zeroblob(32),1,1,zeroblob(0));",
        "INSERT INTO admin_requests VALUES(zeroblob(32),1,zeroblob(1),1,zeroblob(32),-1,1,zeroblob(0));",
        "INSERT INTO admin_requests VALUES(zeroblob(32),1,zeroblob(1),1,zeroblob(32),1,1,zeroblob(4097));",
        "INSERT INTO admin_revision VALUES(2,0);",
        "UPDATE admin_revision SET mutation_revision=-1 WHERE id=1;",
        "INSERT INTO migration_runs VALUES(zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),'',zeroblob(32),10,1,1);",
        "INSERT INTO migration_runs VALUES(zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),'',zeroblob(32),1,5,4);",
        "INSERT INTO migration_steps VALUES(zeroblob(32),1,1,zeroblob(0),0,zeroblob(0),1,NULL);",
    };
    for (rejected) |sql| {
        const result = f.store.inspectExec(sql);
        try t.expect(std.meta.isError(result));
    }
    try f.store.inspectExec("INSERT INTO migration_runs VALUES(zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),'',zeroblob(32),1,5,5);");
    try f.store.inspectExec("INSERT INTO migration_steps VALUES(zeroblob(32),1,1,zeroblob(0),0,zeroblob(0),1,NULL);");
    try t.expect(std.meta.isError(f.store.inspectExec("INSERT INTO migration_steps VALUES(zeroblob(32),2,1,zeroblob(0),1,zeroblob(0),5,4);")));
    try t.expect(std.meta.isError(f.store.inspectExec("INSERT INTO migration_steps VALUES(zeroblob(32),2,1,zeroblob(0),1,zeroblob(0),5,NULL);")));
    try t.expect(std.meta.isError(f.store.inspectExec("INSERT INTO migration_staged_owners VALUES(zeroblob(32),1,'sshd',zeroblob(91),1,10,1,0);")));
    try t.expect(std.meta.isError(f.store.inspectExec("INSERT INTO migration_staged_owners VALUES(zeroblob(32),1,'sshd',zeroblob(92),2,10,1,0);")));
    try t.expect(std.meta.isError(f.store.inspectExec("INSERT INTO migration_staged_owners VALUES(zeroblob(32),1,'sshd',zeroblob(92),1,NULL,1,0);")));
    try f.store.inspectExec("INSERT INTO migration_staged_owners VALUES(zeroblob(32),1,'sshd',zeroblob(92),1,10,1,0);");
    try t.expect(std.meta.isError(f.store.inspectExec("INSERT INTO migration_deltas VALUES(randomblob(32),1,1,zeroblob(92),'sshd',1,10,1,0,1);")));
    try t.expect(std.meta.isError(f.store.inspectExec("INSERT INTO migration_deltas VALUES(zeroblob(32),1,1,zeroblob(92),'sshd',2,10,1,0,1);")));
    try f.store.inspectExec("INSERT INTO migration_deltas VALUES(zeroblob(32),1,1,zeroblob(92),'sshd',2,NULL,1,0,1);");
    // Foreign keys are asserted on by Store.open; a parent row cannot vanish beneath its steps.
    try t.expect(std.meta.isError(f.store.inspectExec("DELETE FROM migration_runs WHERE run_id=zeroblob(32);")));
}

test "native admin store: staged migration rows are invisible to owner, retry and history authority" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try f.store.inspectExec("INSERT INTO migration_runs VALUES(zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),'',zeroblob(32),5,5,5);");
    try f.store.inspectExec("INSERT INTO migration_staged_owners VALUES(zeroblob(32),1,'sshd',zeroblob(92),1,10,1,0);");
    try f.store.inspectExec("INSERT INTO migration_staged_history VALUES(zeroblob(32),1,'sshd',zeroblob(92),1,1,1,0);");
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM effect_owners;"));
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM native_effects;"));
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM confirmed_effect_events;"));
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM action_targets;"));
    try f.reopen();
    try enableThrough21(&f.store);
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM migration_staged_owners;"));
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM effect_owners;"));
}

test "native admin store: storage failure during upgrade leaves the prior schema usable" {
    var f = try Fixture.init();
    defer f.deinit();
    // A read-only file models a denied writable destination: the upgrade must fail typed
    // and leave schema 21 fully readable; refusing to open is also typed, never a reset.
    f.store.close();
    f.open = false;
    {
        var file = try std.fs.cwd().openFile(f.path, .{});
        defer file.close();
        try file.chmod(0o400);
    }
    if (durable.Store.open(t.allocator, f.path)) |opened| {
        var ro = opened;
        const result = ro.enableAdminState();
        try t.expect(std.meta.isError(result));
        try t.expectEqual(@as(i64, 21), try ro.inspectInteger("PRAGMA user_version;"));
        ro.close();
    } else |err| {
        try t.expect(err == error.ReadOnly or err == error.OpenFailed or err == error.AccessDenied or err == error.UnsafePermissions);
    }
    restoreMode(f.path);
    f.store = durable.Store.open(t.allocator, f.path) catch |err| {
        std.debug.print("reopen after restore failed: {s}\n", .{@errorName(err)});
        return err;
    };
    f.open = true;
    try t.expectEqual(@as(i64, 21), try f.userVersion());
}

/// SQLite creates WAL/SHM sidecars with the main file's mode, so a read-only main file
/// also leaves read-only sidecars behind; restore all three.
fn restoreMode(path: []const u8) void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    for ([_][]const u8{ "", "-wal", "-shm" }) |suffix| {
        const full = std.fmt.bufPrint(&buf, "{s}{s}", .{ path, suffix }) catch continue;
        var file = std.fs.cwd().openFile(full, .{}) catch continue;
        defer file.close();
        file.chmod(0o600) catch {};
    }
}

const retry = @import("core/native_retry.zig");

fn policy(maxretry: u16, bantime_s: i64) retry.Policy {
    return .{ .maxretry = maxretry, .window_us = 600 * 1_000_000, .duration = .{ .finite_us = bantime_s * 1_000_000 }, .max_subjects = 64 };
}

test "native admin store: retry policy transition keeps generation and state, refuses stale or in-flight jails" {
    var f = try Fixture.init();
    defer f.deinit();
    const generation = [_]u8{9} ** 32;
    try f.store.admitRetry("sshd", generation, policy(3, 60));
    try t.expectError(error.AdminStorageRequired, f.store.transitionRetryPolicy("sshd", generation, policy(3, 60), policy(2, 120)));
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    const before = try f.store.adminRevision();

    try t.expectError(error.RetryAdmissionRequired, f.store.transitionRetryPolicy("nginx", generation, policy(3, 60), policy(2, 120)));
    try t.expectError(error.RetryGenerationMismatch, f.store.transitionRetryPolicy("sshd", [_]u8{1} ** 32, policy(3, 60), policy(2, 120)));
    try t.expectError(error.StalePolicyTransition, f.store.transitionRetryPolicy("sshd", generation, policy(4, 60), policy(2, 120)));
    try t.expectError(error.InvalidRetryPolicy, f.store.transitionRetryPolicy("sshd", generation, policy(3, 60), policy(0, 120)));
    try t.expectEqual(before, try f.store.adminRevision());

    // An in-flight receipt for the jail blocks the transition until acknowledged.
    try f.store.inspectExec("INSERT INTO pending_receipts VALUES('sshd','/var/log/auth.log',zeroblob(32),'occ',zeroblob(32),zeroblob(1),5);");
    try t.expectError(error.RetryPolicyInFlight, f.store.transitionRetryPolicy("sshd", generation, policy(3, 60), policy(2, 120)));
    try f.store.inspectExec("DELETE FROM pending_receipts;");

    f.store.fail_at = .before_policy_transition_commit;
    try t.expectError(error.InjectedFailure, f.store.transitionRetryPolicy("sshd", generation, policy(3, 60), policy(2, 120)));
    f.store.fail_at = null;
    try f.store.validateRuntimeAdmissions(&.{.{ .jail = "sshd", .generation = generation, .policy = policy(3, 60) }}, null);
    try t.expectEqual(before, try f.store.adminRevision());

    try f.store.transitionRetryPolicy("sshd", generation, policy(3, 60), policy(2, 120));
    try t.expectEqual(before + 1, try f.store.adminRevision());
    try t.expectError(error.RetryGenerationMismatch, f.store.validateRuntimeAdmissions(&.{.{ .jail = "sshd", .generation = generation, .policy = policy(3, 60) }}, null));
    try f.store.validateRuntimeAdmissions(&.{.{ .jail = "sshd", .generation = generation, .policy = policy(2, 120) }}, null);
    try f.reopen();
    try enableThrough21(&f.store);
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try f.store.validateRuntimeAdmissions(&.{.{ .jail = "sshd", .generation = generation, .policy = policy(2, 120) }}, null);
}

test "native admin store: config generations commit unpublished, publish exclusively and discard safely" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try t.expectEqual(@as(?durable.Store.ConfigGenerationHead, null), try f.store.latestConfigGeneration());
    const g1 = [_]u8{1} ** 32;
    const g2 = [_]u8{2} ** 32;
    const digest = [_]u8{5} ** 32;
    try f.store.recordConfigGeneration(.{ .generation = g1, .config_digest = digest, .config_path = "/etc/fail2zig/config.toml", .committed_us = 10, .published = true, .mutation_revision = 0 }, &.{.{ .jail = "sshd", .digest = digest, .allowlist_snapshot = "" }});
    try t.expectError(error.ConfigGenerationExists, f.store.recordConfigGeneration(.{ .generation = g1, .config_digest = digest, .config_path = "/p", .committed_us = 11, .published = false, .mutation_revision = 0 }, &.{}));
    try t.expectError(error.InvalidAdminRequest, f.store.recordConfigGeneration(.{ .generation = g2, .config_digest = digest, .config_path = "", .committed_us = 11, .published = false, .mutation_revision = 0 }, &.{}));
    f.store.fail_at = .before_config_generation_commit;
    try t.expectError(error.InjectedFailure, f.store.recordConfigGeneration(.{ .generation = g2, .config_digest = digest, .config_path = "/p", .committed_us = 20, .published = false, .mutation_revision = 1 }, &.{.{ .jail = "sshd", .digest = digest, .allowlist_snapshot = "x" }}));
    f.store.fail_at = null;
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM config_generations;"));
    try f.store.recordConfigGeneration(.{ .generation = g2, .config_digest = digest, .config_path = "/p", .committed_us = 20, .published = false, .mutation_revision = 1 }, &.{.{ .jail = "sshd", .digest = digest, .allowlist_snapshot = "x" }});
    const head = (try f.store.latestConfigGeneration()).?;
    try t.expectEqualSlices(u8, &g2, &head.generation);
    try t.expect(!head.published);
    try f.store.publishConfigGeneration(g2);
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM config_generations WHERE published=1;"));
    try t.expect((try f.store.latestConfigGeneration()).?.published);
    try t.expectError(error.ConfigGenerationMissing, f.store.publishConfigGeneration([_]u8{3} ** 32));
    // Discard never removes a published row; unpublished rows cascade their jail rows.
    try f.store.discardUnpublishedConfigGeneration(g2);
    try t.expectEqual(@as(i64, 2), try f.store.inspectInteger("SELECT count(*) FROM config_generations;"));
    try f.store.discardUnpublishedConfigGeneration(g1);
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM config_generations;"));
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM config_generation_jails WHERE generation=zeroblob(0)||x'0101010101010101010101010101010101010101010101010101010101010101';"));
    try f.reopen();
    try enableThrough21(&f.store);
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try t.expectEqualSlices(u8, &g2, &(try f.store.latestConfigGeneration()).?.generation);
}

test "native admin store: reload commit moves every policy with its generation row or nothing" {
    var f = try Fixture.init();
    defer f.deinit();
    const g = [_]u8{9} ** 32;
    try f.store.admitRetry("sshd", g, policy(3, 60));
    try f.store.admitRetry("vsftpd", g, policy(5, 60));
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    const digest = [_]u8{4} ** 32;
    const gen = [_]u8{6} ** 32;
    const record = durable.Store.ConfigGenerationRecord{ .generation = gen, .config_digest = digest, .config_path = "/etc/fail2zig/config.toml", .committed_us = 50, .published = false, .mutation_revision = 0 };
    // Second transition is stale: nothing commits.
    try t.expectError(error.StalePolicyTransition, f.store.commitReloadGeneration(&.{
        .{ .jail = "sshd", .generation = g, .next_generation = g, .expected = policy(3, 60), .next = policy(2, 60) },
        .{ .jail = "vsftpd", .generation = g, .next_generation = g, .expected = policy(4, 60), .next = policy(2, 60) },
    }, record, &.{}, testClock()));
    try f.store.validateRuntimeAdmissions(&.{ .{ .jail = "sshd", .generation = g, .policy = policy(3, 60) }, .{ .jail = "vsftpd", .generation = g, .policy = policy(5, 60) } }, null);
    try t.expectEqual(@as(?durable.Store.ConfigGenerationHead, null), try f.store.latestConfigGeneration());
    try t.expectEqual(@as(u64, 0), try f.store.adminRevision());
    f.store.fail_at = .before_config_generation_commit;
    try t.expectError(error.InjectedFailure, f.store.commitReloadGeneration(&.{
        .{ .jail = "sshd", .generation = g, .next_generation = g, .expected = policy(3, 60), .next = policy(2, 60) },
        .{ .jail = "vsftpd", .generation = g, .next_generation = g, .expected = policy(5, 60), .next = policy(2, 60) },
    }, record, &.{.{ .jail = "sshd", .digest = digest, .allowlist_snapshot = "" }}, testClock()));
    f.store.fail_at = null;
    try f.store.validateRuntimeAdmissions(&.{ .{ .jail = "sshd", .generation = g, .policy = policy(3, 60) }, .{ .jail = "vsftpd", .generation = g, .policy = policy(5, 60) } }, null);
    try f.store.commitReloadGeneration(&.{
        .{ .jail = "sshd", .generation = g, .next_generation = g, .expected = policy(3, 60), .next = policy(2, 60) },
        .{ .jail = "vsftpd", .generation = g, .next_generation = g, .expected = policy(5, 60), .next = policy(2, 60) },
    }, record, &.{.{ .jail = "sshd", .digest = digest, .allowlist_snapshot = "" }}, testClock());
    try f.store.validateRuntimeAdmissions(&.{ .{ .jail = "sshd", .generation = g, .policy = policy(2, 60) }, .{ .jail = "vsftpd", .generation = g, .policy = policy(2, 60) } }, null);
    // The reload generation publishes inside its re-key transaction (BUG-023): the record's
    // `published=false` is overridden and no separate publish step exists.
    const head = (try f.store.latestConfigGeneration()).?;
    try t.expect(head.published);
    try t.expectEqual(@as(u64, 1), try f.store.adminRevision());
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT mutation_revision FROM config_generations;"));
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM config_generations WHERE published=1;"));
}

test "native admin store: generation re-key moves every generation-keyed row of the jail together" {
    var f = try Fixture.init();
    defer f.deinit();
    const g_old = [_]u8{1} ** 32;
    const g_new = [_]u8{2} ** 32;
    const g_other = [_]u8{3} ** 32;
    try f.store.admitRetry("sshd", g_old, policy(3, 60));
    try f.store.admitRetry("vsftpd", g_other, policy(3, 60));
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try f.store.inspectExec("INSERT INTO source_maintenance(jail,source,generation,head_sequence,reject_below_sequence,cleanup_revision,sweep_sequence) VALUES('sshd','/var/log/auth.log',x'0101010101010101010101010101010101010101010101010101010101010101',1,1,0,0);");
    try f.store.inspectExec("INSERT INTO source_maintenance(jail,source,generation,head_sequence,reject_below_sequence,cleanup_revision,sweep_sequence) VALUES('vsftpd','/var/log/vsftpd.log',x'0303030303030303030303030303030303030303030303030303030303030303',1,1,0,0);");
    try f.store.inspectExec("INSERT INTO replay_guards(jail,source,generation,occurrence_key,identity_key,receipt_us,source_sequence) VALUES('sshd','/var/log/auth.log',x'0101010101010101010101010101010101010101010101010101010101010101',zeroblob(32),zeroblob(32),5,1);");
    try f.store.inspectExec("INSERT INTO source_cursors(jail,source,cursor,occurrence,path) VALUES('sshd','/var/log/auth.log',CAST('{\"offset\":10,\"codec_configuration_hash\":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],\"prefix_len\":4}' AS BLOB),'occ','/var/log/auth.log');");
    const record = durable.Store.ConfigGenerationRecord{ .generation = [_]u8{6} ** 32, .config_digest = [_]u8{4} ** 32, .config_path = "/p", .committed_us = 50, .published = false, .mutation_revision = 0 };
    f.store.commitReloadGeneration(&.{.{ .jail = "sshd", .generation = g_old, .next_generation = g_new, .expected = policy(3, 60), .next = policy(2, 60), .cursor_rebinding = .{ .old = [_]u8{7} ** 32, .new = [_]u8{8} ** 32 } }}, record, &.{}, testClock()) catch |err| {
        std.debug.print("re-key failed: {s}\n", .{@errorName(err)});
        return err;
    };
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM source_cursors WHERE jail='sshd' AND instr(cursor,CAST('\"codec_configuration_hash\":[8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8]' AS BLOB))>0 AND instr(cursor,CAST('\"offset\":10' AS BLOB))>0;"));
    // The synthetic cursor is not a full session checkpoint; remove it before runtime admission.
    try f.store.inspectExec("DELETE FROM source_cursors WHERE jail='sshd';");
    try f.store.validateRuntimeAdmissions(&.{ .{ .jail = "sshd", .generation = g_new, .policy = policy(2, 60) }, .{ .jail = "vsftpd", .generation = g_other, .policy = policy(3, 60) } }, null);
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM source_maintenance WHERE jail='sshd' AND generation=x'0202020202020202020202020202020202020202020202020202020202020202';"));
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM source_maintenance WHERE jail='vsftpd' AND generation=x'0303030303030303030303030303030303030303030303030303030303030303';"));
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM retry_policies WHERE generation=x'0101010101010101010101010101010101010101010101010101010101010101';"));
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM replay_guards WHERE jail='sshd' AND generation=x'0202020202020202020202020202020202020202020202020202020202020202';"));
    // The old generation is no longer admissible for the jail.
    try t.expectError(error.RetryGenerationMismatch, f.store.validateRuntimeAdmissions(&.{.{ .jail = "sshd", .generation = g_old, .policy = policy(2, 60) }}, null));
}

test "native admin store: admin requests replay by identity, fence on mutation revision and retain bounded history" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    const gen = [_]u8{6} ** 32;
    try f.store.recordConfigGeneration(.{ .generation = gen, .config_digest = gen, .config_path = "/p", .committed_us = 1, .published = true, .mutation_revision = 0 }, &.{});
    const id1 = [_]u8{1} ** 32;
    try t.expectError(error.InvalidAdminRequest, f.store.admitAdminRequest([_]u8{0} ** 32, 0));
    try t.expectEqual(durable.Store.AdminAdmission.fresh, try f.store.admitAdminRequest(id1, 0));
    try t.expectError(error.StaleAdminRevision, f.store.admitAdminRequest(id1, 1));
    const r1 = try f.store.finishAdminRequest(.{ .request_id = id1, .kind = .group_pause, .subject = "sshd", .outcome = .applied, .generation = gen, .committed_us = 100, .detail = "" }, .{ .jail = "sshd", .enabled = true, .paused = true, .generation = gen, .changed_us = 100, .request_id = id1 });
    try t.expectEqual(@as(u64, 1), r1);
    try t.expectEqual(@as(u64, 1), try f.store.adminRevision());
    var state: durable.Store.JailAdminState = undefined;
    try t.expect(try f.store.jailAdminState("sshd", &state));
    try t.expect(state.paused and state.enabled);
    try t.expect(!try f.store.jailAdminState("vsftpd", &state));
    // Replay returns the recorded outcome even with a stale expected revision.
    const replay = try f.store.admitAdminRequest(id1, 0);
    try t.expectEqual(durable.Store.AdminOutcome.applied, replay.replayed.outcome);
    try t.expectEqual(durable.Store.AdminKind.group_pause, replay.replayed.kind);
    // A rejected outcome records without bumping the revision.
    const id2 = [_]u8{2} ** 32;
    try t.expectEqual(durable.Store.AdminAdmission.fresh, try f.store.admitAdminRequest(id2, 1));
    _ = try f.store.finishAdminRequest(.{ .request_id = id2, .kind = .ban, .subject = "x", .outcome = .rejected, .generation = gen, .committed_us = 101, .detail = "bad scope" }, null);
    try t.expectEqual(@as(u64, 1), try f.store.adminRevision());
    // Injected failure keeps the request unrecorded and the state unchanged.
    const id3 = [_]u8{3} ** 32;
    f.store.fail_at = .after_admin_request;
    try t.expectError(error.InjectedFailure, f.store.finishAdminRequest(.{ .request_id = id3, .kind = .group_resume, .subject = "sshd", .outcome = .applied, .generation = gen, .committed_us = 102, .detail = "" }, .{ .jail = "sshd", .enabled = true, .paused = false, .generation = gen, .changed_us = 102, .request_id = id3 }));
    f.store.fail_at = null;
    try t.expectEqual(@as(u64, 1), try f.store.adminRevision());
    try t.expect(try f.store.jailAdminState("sshd", &state));
    try t.expect(state.paused);
    try t.expectEqual(durable.Store.AdminAdmission.fresh, try f.store.admitAdminRequest(id3, 1));
    // Age-based reclamation: a request older than the retention window disappears, and the
    // reclaimed identity cannot execute again because the revision moved on.
    _ = try f.store.finishAdminRequest(.{ .request_id = id3, .kind = .group_resume, .subject = "sshd", .outcome = .applied, .generation = gen, .committed_us = 102 + durable.Store.admin_request_max_age_us + 1, .detail = "" }, .{ .jail = "sshd", .enabled = true, .paused = false, .generation = gen, .changed_us = 200, .request_id = id3 });
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM admin_requests;"));
    try t.expectError(error.StaleAdminRevision, f.store.admitAdminRequest(id1, 0));
    try t.expectEqual(@as(u64, 2), try f.store.adminRevision());
    try f.reopen();
    try enableThrough21(&f.store);
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try t.expect(try f.store.jailAdminState("sshd", &state));
    try t.expect(!state.paused);
}

test "native admin store: admin request retention is capped by count" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    const gen = [_]u8{6} ** 32;
    var i: u32 = 0;
    while (i < durable.Store.admin_request_retention + 8) : (i += 1) {
        var id = [_]u8{0} ** 32;
        std.mem.writeInt(u32, id[0..4], i + 1, .little);
        _ = try f.store.finishAdminRequest(.{ .request_id = id, .kind = .unban, .subject = "", .outcome = .applied, .generation = gen, .committed_us = 1000 + @as(i64, i), .detail = "" }, null);
    }
    try t.expectEqual(@as(i64, durable.Store.admin_request_retention), try f.store.inspectInteger("SELECT count(*) FROM admin_requests;"));
    var first = [_]u8{0} ** 32;
    std.mem.writeInt(u32, first[0..4], 1, .little);
    try t.expectError(error.StaleAdminRevision, f.store.admitAdminRequest(first, 0));
}

fn staticRead(_: ?*anyopaque) i64 {
    return 1_000_000;
}
fn testClock() effects.Clock {
    return .{ .prepared_us = 1_000_000, .context = null, .read = staticRead };
}
