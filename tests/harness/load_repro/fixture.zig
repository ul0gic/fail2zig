// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const engine = @import("engine_test");
const durable = engine.core.record_store;
const effects = engine.core.native_effect;
const history = engine.core.native_effect_history;
const detection = engine.core.native_detection_record;
const retry = engine.core.native_retry;
const action = engine.core.native_action_outcome;
const time_policy = engine.core.source_time_policy;

const usage =
    \\usage: f2z-load-fixture <churn|hot|pinned|reuse|oracle-cases> <out-dir> [key=value...]
    \\keys: seed count interval_ms bantime_s gap_ms evidence jails churn retention_s max_matches retention=shipped|skip sync=full|off
    \\
;
const second_us: i64 = 1_000_000;
// 2026-01-01T00:00:00Z; every state starts here so identical arguments give identical rows.
const epoch_us: i64 = 1_767_225_600 * second_us;
const source_name = "fixture";
const max_maintenance_steps = 100_000;
// The daemon binds its history consumer to this constant policy generation.
fn historyPolicyGeneration() [32]u8 {
    return effects.hashParts("fail2zig-native-confirmed-history-v1", &.{});
}
const key_tables = [_][]const u8{ "native_effects", "effect_owners", "effect_owner_revisions", "effect_intents", "effect_observations", "action_targets", "confirmed_effect_events", "confirmed_event_details", "confirmed_history_sequence", "retry_decision_details", "retry_decisions", "retry_states", "records" };

const Shape = enum { churn, hot, pinned, reuse, @"oracle-cases" };
const RetentionMode = enum { shipped, skip };
const SyncMode = enum { full, off };

const Options = struct {
    seed: u64 = 1,
    count: u64 = 0,
    interval_ms: u64 = 1000,
    bantime_s: u64 = 60,
    gap_ms: u64 = 1000,
    evidence: usize = 198,
    jails: u8 = 1,
    churn: u64 = 150,
    retention_s: i64 = 86_400,
    max_matches: u16 = 10,
    retention: RetentionMode = .shipped,
    sync: SyncMode = .full,

    fn defaults(shape: Shape) Options {
        return switch (shape) {
            .churn => .{ .count = 5000, .interval_ms = 200, .bantime_s = 60 },
            .hot => .{ .count = 40_000, .bantime_s = 1, .gap_ms = 1000 },
            .pinned => .{ .churn = 150, .interval_ms = 1000, .bantime_s = 60 },
            .reuse => .{ .count = 300, .bantime_s = 600, .gap_ms = 100_000 },
            .@"oracle-cases" => .{ .bantime_s = 10 },
        };
    }
    fn set(self: *Options, key: []const u8, value: []const u8) !void {
        if (std.mem.eql(u8, key, "retention")) {
            self.retention = std.meta.stringToEnum(RetentionMode, value) orelse return error.InvalidOption;
            return;
        }
        if (std.mem.eql(u8, key, "sync")) {
            self.sync = std.meta.stringToEnum(SyncMode, value) orelse return error.InvalidOption;
            return;
        }
        inline for (.{ "seed", "count", "interval_ms", "bantime_s", "gap_ms", "evidence", "jails", "churn", "retention_s", "max_matches" }) |name| {
            if (std.mem.eql(u8, key, name)) {
                @field(self, name) = try std.fmt.parseInt(@TypeOf(@field(self, name)), value, 10);
                return;
            }
        }
        return error.InvalidOption;
    }
    fn validate(self: Options) !void {
        if (self.bantime_s == 0 or self.bantime_s > 86_400 * 365 or self.interval_ms == 0 or self.jails == 0 or self.jails > 16 or
            self.evidence > retry.max_evidence_text_bytes or self.retention_s < 0 or self.retention_s > 86_400 * 3650 or
            self.max_matches > 1024 or self.count > 1_000_000 or self.churn > 100_000 or self.gap_ms > 86_400_000) return error.InvalidOption;
    }
};

const Clock = struct {
    now: i64 = epoch_us,
    fn read(ctx: ?*anyopaque) i64 {
        const self: *Clock = @ptrCast(@alignCast(ctx.?));
        return self.now;
    }
    fn value(self: *Clock) effects.Clock {
        return .{ .prepared_us = self.now, .context = self, .read = read };
    }
    fn advanceMs(self: *Clock, ms: u64) void {
        self.now += @as(i64, @intCast(ms)) * 1000;
    }
};

const Jail = struct { name: []const u8, generation: [32]u8, policy: retry.Policy };
const Lease = struct { key: effects.Hash, deadline: i64 };
const Refusal = struct { cycle: u64, operation: []const u8, error_name: []const u8 };
const StoreFailure = struct { operation: []const u8, failure: anyerror };
const Phase = struct { label: []const u8, cycle: u64, clock_us: i64, counts: [key_tables.len]i64, retained_from: i64, head: i64 };
const Stats = struct {
    bans: u64 = 0,
    kept_existing: u64 = 0,
    expired: u64 = 0,
    history_pages: u64 = 0,
    retention_deleted: u64 = 0,
    retention_calls: u64 = 0,
    retry_details_pruned: u64 = 0,
    spent_scopes_pruned: u64 = 0,
    max_active_leases: usize = 0,
};

// Heap-owned: the store's progress handler and the effect clock keep pointers into it.
const Gen = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    store: durable.Store = undefined,
    store_open: bool = false,
    options: Options,
    installation: effects.Installation,
    clock: Clock = .{},
    consumer: history.Consumer,
    jails: std.ArrayList(Jail),
    leases: std.ArrayList(Lease),
    phases: std.ArrayList(Phase),
    records: u64 = 0,
    cycle: u64 = 0,
    store_failure: ?StoreFailure = null,
    stats: Stats = .{},
    refusal: ?Refusal = null,
    maintenance: bool,
    evidence_buffer: [retry.max_evidence_text_bytes]u8 = undefined,

    fn create(allocator: std.mem.Allocator, dir: []const u8, name: []const u8, options: Options, maintenance: bool) !*Gen {
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}.sqlite", .{ dir, name });
        errdefer allocator.free(path);
        if (std.fs.cwd().access(path, .{})) |_| return error.FixtureOutputExists else |failure| if (failure != error.FileNotFound) return failure;
        var seed_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seed_bytes, options.seed, .little);
        const id_hash = effects.hashParts("fail2zig-load-fixture-installation-v1", &.{&seed_bytes});
        const installation = try effects.Installation.init(id_hash[0..16].*, .nftables, "load-fixture");
        const self = try allocator.create(Gen);
        self.* = .{ .allocator = allocator, .path = path, .options = options, .installation = installation, .consumer = try history.Consumer.init(installation, historyPolicyGeneration()), .jails = std.ArrayList(Jail).init(allocator), .leases = std.ArrayList(Lease).init(allocator), .phases = std.ArrayList(Phase).init(allocator), .maintenance = maintenance };
        return self;
    }
    fn destroy(self: *Gen) void {
        self.closeStore();
        for (self.jails.items) |jail| self.allocator.free(jail.name);
        self.jails.deinit();
        self.leases.deinit();
        self.phases.deinit();
        self.allocator.free(self.path);
        self.allocator.destroy(self);
    }
    // Records which production Store operation returned an error, so only its own
    // refusals are reported as results; every other error is a harness failure.
    fn stored(self: *Gen, operation: []const u8, result: anytype) @TypeOf(result) {
        return result catch |failure| {
            self.store_failure = .{ .operation = operation, .failure = failure };
            return failure;
        };
    }
    fn closeStore(self: *Gen) void {
        if (!self.store_open) return;
        self.store.close();
        self.store_open = false;
    }

    // Mirrors the daemon's runtime open and admission sequence, including the
    // per-transaction work guard, so construction hits the same refusals.
    fn openStore(self: *Gen) !void {
        self.store = try self.stored("Store.openRuntime", durable.Store.openRuntime(self.allocator, self.path));
        self.store_open = true;
        self.store.runtime_path = self.path;
        try self.stored("Store.configureRuntimeLimits", self.store.configureRuntimeLimits());
        // Durability of intermediate commits only; row contents and VM work are unchanged.
        if (self.options.sync == .off) try self.stored("Store.exec", self.store.exec("PRAGMA synchronous=OFF;"));
        try self.stored("Store.enableReceipts", self.store.enableReceipts(64));
        try self.stored("Store.enableNativeTime", self.store.enableNativeTime());
        try self.stored("Store.enableDetection", self.store.enableDetection());
        try self.stored("Store.enableClockRecovery", self.store.enableClockRecovery());
        try self.stored("Store.enableJournalDetection", self.store.enableJournalDetection());
        try self.stored("Store.enableRetry", self.store.enableRetry());
        try self.stored("Store.enableConsumers", self.store.enableConsumers());
        try self.stored("Store.enableTimeProvenance", self.store.enableTimeProvenance());
        try self.stored("Store.enableConsumerManifests", self.store.enableConsumerManifests());
        try self.stored("Store.enableConfirmedHistory", self.store.enableConfirmedHistory());
        try self.stored("Store.enableMaintenance", self.store.enableMaintenance());
        try self.stored("Store.enableCleanup", self.store.enableCleanup());
        try self.stored("Store.enableRetryLeases", self.store.enableRetryLeases());
        try self.stored("Store.enableApplicationHistory", self.store.enableApplicationHistory());
        try self.stored("Store.enableEscalation", self.store.enableEscalation());
        try self.stored("Store.enableCanonicalEffects", self.store.enableCanonicalEffects());
        try self.stored("Store.enableHistoryResets", self.store.enableHistoryResets());
        try self.stored("Store.enableActionTargets", self.store.enableActionTargets());
        try self.stored("Store.enableAdminState", self.store.enableAdminState());
        try self.stored("Store.enableMigrationState", self.store.enableMigrationState());
    }
    fn setup(self: *Gen) !void {
        try self.openStore();
        try self.stored("Store.admitInstallation", self.store.admitInstallation(self.installation, .{ .selector = self.installation.selector(), .disposition = .verified_absent }));
        const initial = try self.consumer.prepareInitial();
        defer initial.release();
        try self.stored("Store.bootstrapConfirmedHistory", self.store.bootstrapConfirmedHistory(self.consumer.manifest(), try initial.batch(self.clock.value()), self.installation));
        initial.publish();
    }
    fn addJail(self: *Gen, name: []const u8, duration: retry.Duration) !usize {
        var seed_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seed_bytes, self.options.seed, .little);
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        const jail = Jail{ .name = owned, .generation = effects.hashParts("fail2zig-load-fixture-jail-v1", &.{ name, &seed_bytes }), .policy = .{ .maxretry = 1, .window_us = 60 * second_us, .duration = duration, .max_subjects = 65536, .enforce = true } };
        try self.stored("Store.admitRetry", self.store.admitRetry(jail.name, jail.generation, jail.policy));
        try self.jails.append(jail);
        return self.jails.items.len - 1;
    }
    fn finite(self: *Gen) retry.Duration {
        return .{ .finite_us = @as(i64, @intCast(self.options.bantime_s)) * second_us };
    }
    fn evidenceText(self: *Gen, length: usize) ?[]const u8 {
        if (length == 0) return null;
        const prefix = std.fmt.bufPrint(&self.evidence_buffer, "fixture evidence seed={d} record={d} ", .{ self.options.seed, self.records }) catch self.evidence_buffer[0..0];
        @memset(self.evidence_buffer[prefix.len..], 'x');
        return self.evidence_buffer[0..length];
    }
    fn observation(self: *Gen, entry: effects.Entry) effects.Observation {
        return .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = effects.hashParts("fail2zig-load-fixture-observation-v1", &.{&entry.intent_id}), .observed_us = self.clock.now, .qualification = .complete_owned, .state = entry.desired };
    }

    // One detection through receipt and record commit, then the effect runtime's
    // dispatch, verified settlement and action-target reconciliation.
    fn ban(self: *Gen, jail_index: usize, subject: detection.Subject, evidence_bytes: usize) !void {
        const jail = self.jails.items[jail_index];
        self.records += 1;
        var occurrence_buffer: [32]u8 = undefined;
        const occurrence = try std.fmt.bufPrint(&occurrence_buffer, "fx-{d}", .{self.records});
        var raw_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(occurrence, &raw_hash, .{});
        const identity = durable.ReceiptIdentity{ .jail = jail.name, .source = source_name, .occurrence = occurrence, .cursor = occurrence, .raw_hash = raw_hash, .generation = jail.generation };
        const revision = try self.stored("Store.revision", self.store.revision(jail.name));
        const receipt = try self.stored("Store.beginReceipt", self.store.beginReceipt(identity, .{ .us = self.clock.now }, revision));
        const outcome = try time_policy.evaluate(.timestamped, .{ .parsed = receipt }, receipt, receipt, 1_000);
        _ = try self.stored("Store.commitRecord", self.store.commitRecord(.{
            .jail = jail.name,
            .source = source_name,
            .occurrence = occurrence,
            .cursor = occurrence,
            .raw_hash = raw_hash,
            .receipt = .{ .time = receipt, .generation = jail.generation },
            .native_time_outcome = outcome,
            .native_detection = .{ .kind = .candidate, .generation = jail.generation, .filter = try detection.Name.init("fixture"), .pattern = try detection.Name.init("failure"), .pattern_index = 0, .subject = subject },
            .native_retry = .{ .generation = jail.generation, .policy = jail.policy, .processing_us = @max(self.clock.now, receipt.us) },
            .retry_evidence = .{ .text = self.evidenceText(evidence_bytes) },
            .effects_clock = self.clock.value(),
            .expected_revision = revision,
            .disposition = outcome.disposition(),
            .checkpoint = "load-fixture",
        }));
        self.stats.bans += 1;
        const key = try (try effects.Scope.host(subject)).key(self.installation);
        const entry = try self.stored("Store.readEffect", self.store.readEffect(key, self.installation)) orelse return error.FixtureMissingEffect;
        if (entry.status != .pending) {
            self.stats.kept_existing += 1;
            return;
        }
        _ = try self.stored("Store.settleOutcome", self.store.settleOutcome(entry.token(), self.clock.now, self.observation(entry), self.clock.value()));
        try self.settleActionTargets(key, jail.name);
        if (entry.desired == .finite) {
            try self.leases.append(.{ .key = key, .deadline = entry.desired.finite });
            self.stats.max_active_leases = @max(self.stats.max_active_leases, self.leases.items.len);
        }
    }
    fn settleActionTargets(self: *Gen, key: effects.Hash, jail: []const u8) !void {
        var owners: [effects.max_page]effects.Owner = undefined;
        const count = try self.stored("Store.readOwners", self.store.readOwners(key, &owners));
        for (owners[0..count]) |owner| {
            if (!std.mem.eql(u8, owner.jail.slice(), jail)) continue;
            var targets: [action.max_targets_per_action]action.Target = undefined;
            if (try self.stored("Store.actionTargets", self.store.actionTargets(owner.decision_id, &targets)) == 0) return;
            for ([_]action.Kind{ .enforcement, .notification }) |kind| {
                try self.stored("Store.markActionTargetDispatched", self.store.markActionTargetDispatched(owner.decision_id, kind, self.clock.value()));
                try self.stored("Store.settleActionTarget", self.store.settleActionTarget(owner.decision_id, kind, .confirmed, self.clock.value()));
            }
            return;
        }
        return error.FixtureMissingOwner;
    }
    fn expireDue(self: *Gen) !void {
        var index: usize = 0;
        while (index < self.leases.items.len) {
            const lease = self.leases.items[index];
            if (lease.deadline > self.clock.now) {
                index += 1;
                continue;
            }
            _ = self.leases.orderedRemove(index);
            const entry = try self.stored("Store.readEffect", self.store.readEffect(lease.key, self.installation)) orelse return error.FixtureMissingEffect;
            const next = try self.stored("Store.prepareExpiry", self.store.prepareExpiry(lease.key, entry.revision, self.clock.value()));
            if (next.status != .pending) continue;
            _ = try self.stored("Store.settleOutcome", self.store.settleOutcome(next.token(), self.clock.now, self.observation(next), self.clock.value()));
            self.stats.expired += 1;
        }
    }
    fn consume(self: *Gen, through: ?u64) !void {
        var events: [history.max_page]history.Event = undefined;
        for (0..1 << 20) |_| {
            var size: usize = history.max_page;
            if (through) |last| {
                if (self.consumer.live.last_sequence >= last) return;
                size = @intCast(@min(size, last - self.consumer.live.last_sequence));
            }
            const page = try self.stored("Store.confirmedEffectPage", self.store.confirmedEffectPage(self.installation, self.consumer.live.last_sequence, null, events[0..size]));
            if (page.count == 0) return;
            const stage = try self.consumer.prepare(page, events[0..page.count], self.clock.now);
            defer stage.release();
            try self.stored("Store.commitConfirmedHistory", self.store.commitConfirmedHistory(self.consumer.manifest(), try stage.batch(self.clock.value()), page.token));
            stage.publish();
            self.stats.history_pages += 1;
        }
        return error.FixtureUnboundedHistory;
    }
    // The daemon's maintenance order: one retention step, else one retry-detail
    // prune, else one spent-scope prune; repeated here until nothing remains.
    fn maintain(self: *Gen) !void {
        for (0..max_maintenance_steps) |_| {
            if (self.options.retention == .shipped) {
                self.stats.retention_calls += 1;
                if (try self.stored("Store.cleanupConfirmedHistoryOne", self.store.cleanupConfirmedHistoryOne(.{ .age_us = self.options.retention_s * second_us, .max_matches = self.options.max_matches }, self.clock.now))) {
                    self.stats.retention_deleted += 1;
                    continue;
                }
            }
            if (try self.stored("Store.pruneRetryDecisionDetailsOne", self.store.pruneRetryDecisionDetailsOne())) {
                self.stats.retry_details_pruned += 1;
                continue;
            }
            if (try self.stored("Store.pruneSpentEffectOne", self.store.pruneSpentEffectOne())) {
                self.stats.spent_scopes_pruned += 1;
                continue;
            }
            return;
        }
        return error.FixtureUnboundedMaintenance;
    }
    fn turn(self: *Gen) !void {
        try self.consume(null);
        if (self.maintenance) try self.maintain();
    }
    fn phase(self: *Gen, label: []const u8) !void {
        var item = Phase{ .label = label, .cycle = self.cycle, .clock_us = self.clock.now, .counts = undefined, .retained_from = 0, .head = 0 };
        for (key_tables, 0..) |table, i| {
            var buffer: [96]u8 = undefined;
            item.counts[i] = try self.store.integer(try std.fmt.bufPrintZ(&buffer, "SELECT count(*) FROM {s};", .{table}));
        }
        item.retained_from = try self.store.integer("SELECT retained_from FROM confirmed_history_stream WHERE id=1;");
        item.head = try self.store.integer("SELECT head FROM confirmed_history_stream WHERE id=1;");
        try self.phases.append(item);
    }
    // A closed store leaves no WAL, so the main file is a complete copy.
    fn snapshot(self: *Gen, dir: []const u8, name: []const u8) ![]u8 {
        self.closeStore();
        var wal_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const wal = try std.fmt.bufPrint(&wal_buffer, "{s}-wal", .{self.path});
        if (std.fs.cwd().statFile(wal)) |stat| {
            if (stat.size != 0) return error.FixtureWalRemains;
        } else |failure| if (failure != error.FileNotFound) return failure;
        const target = try std.fmt.allocPrint(self.allocator, "{s}/{s}.sqlite", .{ dir, name });
        errdefer self.allocator.free(target);
        if (std.fs.cwd().access(target, .{})) |_| return error.FixtureOutputExists else |failure| if (failure != error.FileNotFound) return failure;
        try std.fs.cwd().copyFile(self.path, std.fs.cwd(), target, .{});
        try self.openStore();
        return target;
    }
};

fn churnSubject(seed: u64, index: u64) detection.Subject {
    const base: u32 = (198 << 24) | (18 << 16);
    const offset: u32 = @intCast((seed *% 7919 +% index) % 131_070 + 1);
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, base + offset, .big);
    return .{ .v4 = bytes };
}
fn host(a: u8, b: u8, c: u8, d: u8) detection.Subject {
    return .{ .v4 = .{ a, b, c, d } };
}

fn runChurn(gen: *Gen) !void {
    try gen.setup();
    const jail = try gen.addJail("churn", gen.finite());
    while (gen.cycle < gen.options.count) {
        gen.cycle += 1;
        gen.clock.advanceMs(gen.options.interval_ms);
        try gen.expireDue();
        try gen.ban(jail, churnSubject(gen.options.seed, gen.cycle), gen.options.evidence);
        try gen.turn();
        if (gen.cycle == 1 or gen.cycle % 1024 == 0) try gen.phase("progress");
    }
}
fn runHot(gen: *Gen) !void {
    try gen.setup();
    var names: [16][16]u8 = undefined;
    for (0..gen.options.jails) |i| _ = try gen.addJail(try std.fmt.bufPrint(&names[i], "hot-{d}", .{i}), gen.finite());
    const subject = host(203, 0, 113, 7);
    while (gen.cycle < gen.options.count) {
        gen.cycle += 1;
        try gen.expireDue();
        try gen.ban(@intCast((gen.cycle - 1) % gen.options.jails), subject, gen.options.evidence);
        try gen.turn();
        if (gen.cycle <= 2) try gen.phase("per-cycle");
        if (gen.cycle % 4096 == 0) try gen.phase("progress");
        gen.clock.advanceMs(gen.options.bantime_s * 1000 + gen.options.gap_ms);
    }
}
fn runPinned(gen: *Gen) !void {
    try gen.setup();
    const pinned = try gen.addJail("pinned", .permanent);
    const churn = try gen.addJail("churn", gen.finite());
    gen.clock.advanceMs(1000);
    try gen.ban(pinned, host(203, 0, 113, 200), gen.options.evidence);
    try gen.turn();
    while (gen.cycle < gen.options.churn) {
        gen.cycle += 1;
        gen.clock.advanceMs(gen.options.interval_ms);
        try gen.expireDue();
        try gen.ban(churn, churnSubject(gen.options.seed, gen.cycle), gen.options.evidence);
        try gen.turn();
    }
    gen.clock.advanceMs(gen.options.bantime_s * 1000 + 1000);
    try gen.expireDue();
    try gen.turn();
    try gen.phase("before-retention-age");
    gen.clock.now += (gen.options.retention_s + 3600) * second_us;
    try gen.turn();
    try gen.phase("after-retention-age");
}
fn runReuse(gen: *Gen) !void {
    try gen.setup();
    const jail = try gen.addJail("reuse", gen.finite());
    const subject = host(203, 0, 113, 9);
    while (gen.cycle < gen.options.count) {
        gen.cycle += 1;
        try gen.expireDue();
        try gen.ban(jail, subject, gen.options.evidence);
        try gen.turn();
        if (gen.cycle % 50 == 0) try gen.phase("progress");
        gen.clock.advanceMs(gen.options.bantime_s * 1000 + gen.options.gap_ms);
    }
    try gen.expireDue();
    try gen.turn();
    try gen.phase("final");
}

// Oracle states are built without retention maintenance: it is the operation
// under test, and the daemon skips it while the history consumer lags.
const OracleCase = struct {
    name: []const u8,
    build: *const fn (*Gen, []const u8, *std.ArrayList(Snapshot)) anyerror!void,
};
const Snapshot = struct { label: []const u8, path: []u8 };

fn rest(gen: *Gen) !void {
    gen.clock.advanceMs(gen.options.bantime_s * 1000 + 1000);
    try gen.expireDue();
}
fn step(gen: *Gen, jail: usize, subject: detection.Subject, evidence: usize) !void {
    gen.clock.advanceMs(1000);
    gen.cycle += 1;
    try gen.ban(jail, subject, evidence);
}
fn buildCompeting(gen: *Gen, _: []const u8, _: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    try step(gen, jail, host(192, 0, 2, 1), 16);
    try step(gen, jail, host(192, 0, 2, 2), 16);
    gen.clock.advanceMs(100_000);
    for (0..12) |round| {
        try step(gen, jail, host(192, 0, 2, 40), 16);
        if (round < 9) try step(gen, jail, host(192, 0, 2, 50), retry.max_evidence_text_bytes);
        try rest(gen);
    }
    try gen.consume(null);
}
fn buildLag(gen: *Gen, _: []const u8, _: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    for (0..100) |i| try step(gen, jail, host(198, 51, 100, @intCast(i + 1)), 16);
    try gen.consume(100);
    try step(gen, jail, host(192, 0, 2, 101), 16);
    try rest(gen);
    try step(gen, jail, host(192, 0, 2, 101), 16);
}
fn buildRebuild(gen: *Gen, _: []const u8, _: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    try step(gen, jail, host(192, 0, 2, 11), 16);
    try step(gen, jail, host(192, 0, 2, 10), 16);
    try rest(gen);
    try step(gen, jail, host(192, 0, 2, 11), 16);
    try step(gen, jail, host(192, 0, 2, 10), 16);
    try gen.consume(null);
}
fn buildEvidence(gen: *Gen, dir: []const u8, snapshots: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    const subject = host(192, 0, 2, 60);
    try step(gen, jail, subject, 0);
    try rest(gen);
    for (0..8) |_| {
        try step(gen, jail, subject, retry.max_evidence_text_bytes);
        try rest(gen);
    }
    try gen.consume(null);
    try snapshots.append(.{ .label = "at-limit", .path = try gen.snapshot(dir, "or6-at-limit") });
    try step(gen, jail, subject, 1);
    try gen.consume(null);
}
fn buildAdvancing(gen: *Gen, _: []const u8, _: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    for (1..5) |i| try step(gen, jail, host(192, 0, 2, @intCast(20 + i)), 16);
    gen.clock.advanceMs(100_000);
    for (0..3) |_| {
        try step(gen, jail, host(192, 0, 2, 30), 16);
        try rest(gen);
    }
    try gen.consume(null);
}
fn buildLiveInsert(gen: *Gen, dir: []const u8, snapshots: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    const p = host(192, 0, 2, 70);
    const q = host(192, 0, 2, 71);
    try step(gen, jail, p, 16);
    try step(gen, jail, q, 16);
    try rest(gen);
    try step(gen, jail, q, 16);
    try gen.consume(null);
    try snapshots.append(.{ .label = "before-insert", .path = try gen.snapshot(dir, "or9-before-insert") });
    try rest(gen);
    try step(gen, jail, p, 16);
    try gen.consume(null);
}
const oracle_cases = [_]OracleCase{
    .{ .name = "or1-competing", .build = buildCompeting },
    .{ .name = "or2-consumer-lag", .build = buildLag },
    .{ .name = "or3-partial-rebuild", .build = buildRebuild },
    .{ .name = "or6-over-limit", .build = buildEvidence },
    .{ .name = "or8-advancing-cutoff", .build = buildAdvancing },
    .{ .name = "or9-after-insert", .build = buildLiveInsert },
};

// Inspection uses a separate read-only connection without the runtime guard,
// so whole-database checks are not limited by the per-transaction allowance.
const Inspection = struct {
    fn tables(store: *durable.Store, allocator: std.mem.Allocator) !std.ArrayList([]u8) {
        var names = std.ArrayList([]u8).init(allocator);
        errdefer freeNames(&names, allocator);
        var rows = try store.statement("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;");
        defer rows.deinit();
        while (try rows.row()) try names.append(try allocator.dupe(u8, try rows.boundedBytes(0, 256)));
        return names;
    }
    fn freeNames(names: *std.ArrayList([]u8), allocator: std.mem.Allocator) void {
        for (names.items) |name| allocator.free(name);
        names.deinit();
    }
    fn count(store: *durable.Store, table: []const u8) !i64 {
        var buffer: [320]u8 = undefined;
        for (table) |c| if (c == '"') return error.FixtureUnexpectedTable;
        return store.integer(try std.fmt.bufPrintZ(&buffer, "SELECT count(*) FROM \"{s}\";", .{table}));
    }
};

fn writeCounts(ws: anytype, store: *durable.Store, allocator: std.mem.Allocator) !void {
    var names = try Inspection.tables(store, allocator);
    defer Inspection.freeNames(&names, allocator);
    try ws.objectField("table_counts");
    try ws.beginObject();
    for (names.items) |name| {
        try ws.objectField(name);
        try ws.write(try Inspection.count(store, name));
    }
    try ws.endObject();
}
fn writeQuery(ws: anytype, store: *durable.Store, field: []const u8, sql: [:0]const u8) !void {
    try ws.objectField(field);
    try ws.write(try store.integer(sql));
}
fn writeHex(ws: anytype, bytes: []const u8) !void {
    var buffer: [128]u8 = undefined;
    if (bytes.len > 64) return error.FixtureUnexpectedValue;
    try ws.write(try std.fmt.bufPrint(&buffer, "{}", .{std.fmt.fmtSliceHexLower(bytes)}));
}

fn writeState(ws: anytype, gen: *Gen, label: []const u8, path: []const u8) !void {
    var store = try durable.Store.openReadOnly(gen.allocator, path);
    defer store.close();
    try ws.beginObject();
    try ws.objectField("label");
    try ws.write(label);
    try ws.objectField("path");
    try ws.write(path);
    try ws.objectField("schema_version");
    try ws.write(try store.integer("PRAGMA user_version;"));
    try writeCounts(ws, &store, gen.allocator);

    try ws.objectField("integrity_check");
    try ws.beginArray();
    {
        var rows = try store.statement("PRAGMA integrity_check(20);");
        defer rows.deinit();
        while (try rows.row()) try ws.write(try rows.boundedBytes(0, 4096));
    }
    try ws.endArray();
    try ws.objectField("foreign_key_violations");
    {
        var rows = try store.statement("PRAGMA foreign_key_check;");
        defer rows.deinit();
        var violations: u64 = 0;
        while (try rows.row()) violations += 1;
        try ws.write(violations);
    }

    try ws.objectField("history_stream");
    try ws.beginObject();
    try writeQuery(ws, &store, "revision", "SELECT revision FROM confirmed_history_stream WHERE id=1;");
    try writeQuery(ws, &store, "head", "SELECT head FROM confirmed_history_stream WHERE id=1;");
    try writeQuery(ws, &store, "retained_from", "SELECT retained_from FROM confirmed_history_stream WHERE id=1;");
    try writeQuery(ws, &store, "min_sequence", "SELECT coalesce(min(sequence),0) FROM confirmed_history_sequence;");
    try writeQuery(ws, &store, "max_sequence", "SELECT coalesce(max(sequence),0) FROM confirmed_history_sequence;");
    try ws.endObject();

    try ws.objectField("consumer_checkpoints");
    try ws.beginArray();
    {
        var rows = try store.statement("SELECT kind,jail,source,rule,generation,payload FROM consumer_checkpoints ORDER BY kind,jail,source,rule;");
        defer rows.deinit();
        while (try rows.row()) {
            try ws.beginObject();
            try ws.objectField("kind");
            try ws.write(try rows.signed(0));
            try ws.objectField("jail");
            try ws.write(try rows.boundedBytes(1, 64));
            try ws.objectField("source");
            try ws.write(try rows.boundedBytes(2, 256));
            try ws.objectField("rule");
            try ws.write(try rows.boundedBytes(3, 256));
            try ws.objectField("generation");
            try writeHex(ws, try rows.boundedBytes(4, 32));
            const payload = try rows.boundedBytes(5, 1 << 20);
            if (history.Checkpoint.decode(payload)) |checkpoint| {
                try ws.objectField("history_last_sequence");
                try ws.write(checkpoint.last_sequence);
                try ws.objectField("history_watermark_us");
                try ws.write(checkpoint.confirmed_watermark_us);
            } else |_| {}
            try ws.endObject();
        }
    }
    try ws.endArray();
    try ws.objectField("retry_policy_generations");
    try ws.beginObject();
    {
        var rows = try store.statement("SELECT jail,generation FROM retry_policies ORDER BY jail;");
        defer rows.deinit();
        while (try rows.row()) {
            try ws.objectField(try rows.boundedBytes(0, 64));
            try writeHex(ws, try rows.boundedBytes(1, 32));
        }
    }
    try ws.endObject();
    try ws.objectField("installation");
    {
        var rows = try store.statement("SELECT identity FROM effect_installation;");
        defer rows.deinit();
        if (try rows.row()) try writeHex(ws, try rows.boundedBytes(0, 16)) else try ws.write(null);
    }

    try ws.objectField("detail_provenance");
    try ws.beginObject();
    try writeQuery(ws, &store, "retry_linked", "SELECT count(*) FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id;");
    try writeQuery(ws, &store, "unlinked", "SELECT count(*) FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE r.jail IS NULL;");
    try writeQuery(ws, &store, "null_evidence", "SELECT count(*) FROM confirmed_event_details WHERE evidence IS NULL;");
    try writeQuery(ws, &store, "retained_subjects", "SELECT count(*) FROM (SELECT DISTINCT r.family,r.subject FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id);");
    try ws.endObject();

    try ws.objectField("lifecycle");
    try ws.beginObject();
    try writeQuery(ws, &store, "live_or_pending_scopes", "SELECT count(*) FROM native_effects WHERE lease_kind<>0;");
    try writeQuery(ws, &store, "spent_scopes", "SELECT count(*) FROM native_effects WHERE lease_kind=0;");
    try writeQuery(ws, &store, "spent_scopes_referenced_by_history", "SELECT count(*) FROM native_effects n WHERE n.lease_kind=0 AND EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.scope_key=n.scope_key);");
    try writeQuery(ws, &store, "obsolete_owner_revisions", "SELECT count(*) FROM effect_owner_revisions h WHERE NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=h.scope_key AND o.jail=h.jail AND o.revision=h.revision);");
    try writeQuery(ws, &store, "obsolete_intents", "SELECT count(*) FROM effect_intents i WHERE NOT EXISTS(SELECT 1 FROM native_effects n WHERE n.intent_id=i.intent_id);");
    try writeQuery(ws, &store, "obsolete_observations", "SELECT count(*) FROM effect_observations o WHERE NOT EXISTS(SELECT 1 FROM native_effects n WHERE n.intent_id=o.intent_id);");
    try writeQuery(ws, &store, "action_targets_without_retained_event", "SELECT count(*) FROM action_targets a WHERE NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.scope_key=a.scope_key AND e.jail=a.jail AND e.decision_id=a.action_id);");
    try writeQuery(ws, &store, "unsettled_intents", "SELECT count(*) FROM effect_intents WHERE status IN(1,2);");
    try writeQuery(ws, &store, "unsettled_action_targets", "SELECT count(*) FROM action_targets WHERE status IN(1,2,5);");
    try writeQuery(ws, &store, "oldest_retained_confirmed_us", "SELECT coalesce(min(confirmed_us),0) FROM confirmed_effect_events;");
    try ws.endObject();

    try ws.objectField("invariants");
    try ws.beginObject();
    try writeQuery(ws, &store, "stream_contiguous", "SELECT (SELECT count(*) FROM confirmed_history_sequence)=(SELECT head-retained_from+1 FROM confirmed_history_stream WHERE id=1) AND (SELECT coalesce(min(sequence),(SELECT retained_from FROM confirmed_history_stream)) FROM confirmed_history_sequence)=(SELECT retained_from FROM confirmed_history_stream);");
    try writeQuery(ws, &store, "every_event_sequenced", "SELECT NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE NOT EXISTS(SELECT 1 FROM confirmed_history_sequence s WHERE s.event_id=e.event_id));");
    try writeQuery(ws, &store, "every_detail_retry_linked", "SELECT NOT EXISTS(SELECT 1 FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE r.jail IS NULL);");
    try writeQuery(ws, &store, "one_current_intent_per_scope", "SELECT NOT EXISTS(SELECT 1 FROM native_effects n WHERE n.intent_id IS NULL OR NOT EXISTS(SELECT 1 FROM effect_intents i WHERE i.intent_id=n.intent_id AND i.scope_key=n.scope_key));");
    try writeQuery(ws, &store, "current_owner_revision_recorded", "SELECT NOT EXISTS(SELECT 1 FROM effect_owners o WHERE NOT EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision));");
    try ws.endObject();

    if (try store.integer("SELECT count(*) FROM confirmed_history_sequence;") <= 256) {
        try ws.objectField("events");
        try ws.beginArray();
        var rows = try store.statement("SELECT s.sequence,e.confirmed_us,e.jail,r.subject,CASE WHEN d.event_id IS NULL THEN -1 WHEN d.evidence IS NULL THEN NULL ELSE length(CAST(d.evidence AS BLOB)) END,e.event_id FROM confirmed_history_sequence s JOIN confirmed_effect_events e USING(event_id) LEFT JOIN confirmed_event_details d USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id ORDER BY s.sequence;");
        defer rows.deinit();
        while (try rows.row()) {
            try ws.beginObject();
            try ws.objectField("sequence");
            try ws.write(try rows.signed(0));
            try ws.objectField("confirmed_us");
            try ws.write(try rows.signed(1));
            try ws.objectField("jail");
            try ws.write(try rows.boundedBytes(2, 64));
            try ws.objectField("subject");
            try writeHex(ws, try rows.boundedBytes(3, 16));
            try ws.objectField("evidence_bytes");
            try ws.write(try rows.optionalSigned(4));
            try ws.objectField("event_id");
            try writeHex(ws, try rows.boundedBytes(5, 32));
            try ws.endObject();
        }
        try ws.endArray();
    }
    try ws.endObject();
}

fn writeGen(ws: anytype, gen: *Gen) !void {
    try ws.objectField("clock_start_us");
    try ws.write(epoch_us);
    try ws.objectField("clock_end_us");
    try ws.write(gen.clock.now);
    try ws.objectField("cycles");
    try ws.write(gen.cycle);
    try ws.objectField("stats");
    try ws.write(gen.stats);
    try ws.objectField("active_leases_at_end");
    try ws.write(gen.leases.items.len);
    try ws.objectField("first_refusal");
    if (gen.refusal) |refusal| try ws.write(refusal) else try ws.write(null);
    try ws.objectField("phases");
    try ws.beginArray();
    for (gen.phases.items) |item| {
        try ws.beginObject();
        try ws.objectField("label");
        try ws.write(item.label);
        try ws.objectField("cycle");
        try ws.write(item.cycle);
        try ws.objectField("clock_us");
        try ws.write(item.clock_us);
        try ws.objectField("retained_from");
        try ws.write(item.retained_from);
        try ws.objectField("head");
        try ws.write(item.head);
        for (key_tables, item.counts) |table, value| {
            try ws.objectField(table);
            try ws.write(value);
        }
        try ws.endObject();
    }
    try ws.endArray();
}

fn fileSha256(path: []const u8, out: *[64]u8) !void {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const read = try file.read(&buffer);
        if (read == 0) break;
        hash.update(buffer[0..read]);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    _ = try std.fmt.bufPrint(out, "{}", .{std.fmt.fmtSliceHexLower(&digest)});
}

const Outcome = struct { harness_failure: ?[]const u8 = null };

fn runCase(gen: *Gen, body: anytype, args: anytype) Outcome {
    var outcome = Outcome{};
    @call(.auto, body, args) catch |failure| {
        const from_store = if (gen.store_failure) |recorded| recorded.failure == failure else false;
        if (from_store and failure != error.OutOfMemory and gen.jails.items.len != 0) {
            gen.refusal = .{ .cycle = gen.cycle, .operation = gen.store_failure.?.operation, .error_name = @errorName(failure) };
        } else outcome.harness_failure = @errorName(failure);
    };
    gen.closeStore();
    return outcome;
}

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);
    const stderr = std.io.getStdErr().writer();
    if (argv.len < 3) {
        try stderr.writeAll(usage);
        return 2;
    }
    const shape = std.meta.stringToEnum(Shape, argv[1]) orelse {
        try stderr.writeAll(usage);
        return 2;
    };
    var options = Options.defaults(shape);
    for (argv[3..]) |argument| {
        const split = std.mem.indexOfScalar(u8, argument, '=') orelse {
            try stderr.print("invalid option '{s}'\n{s}", .{ argument, usage });
            return 2;
        };
        options.set(argument[0..split], argument[split + 1 ..]) catch {
            try stderr.print("invalid option '{s}'\n{s}", .{ argument, usage });
            return 2;
        };
    }
    options.validate() catch {
        try stderr.writeAll("option out of range\n");
        return 2;
    };
    _ = std.c.umask(0o077);
    const dir = argv[2];
    try std.fs.cwd().makePath(dir);
    try std.posix.fchmodat(std.posix.AT.FDCWD, dir, 0o700, 0);
    const manifest_path = try std.fmt.allocPrint(allocator, "{s}/manifest.json", .{dir});
    defer allocator.free(manifest_path);
    if (std.fs.cwd().access(manifest_path, .{})) |_| {
        try stderr.print("refusing to overwrite {s}\n", .{manifest_path});
        return 2;
    } else |failure| if (failure != error.FileNotFound) return failure;

    const exe = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe);
    var exe_hash: [64]u8 = undefined;
    try fileSha256(exe, &exe_hash);

    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();
    var ws = std.json.writeStream(output.writer(), .{ .whitespace = .indent_2 });
    try ws.beginObject();
    try ws.objectField("shape");
    try ws.write(@tagName(shape));
    try ws.objectField("generator");
    try ws.write("tests/harness/load_repro/fixture.zig");
    try ws.objectField("generator_sha256");
    try ws.write(exe_hash[0..]);
    try ws.objectField("arguments");
    try ws.write(argv[1..]);
    try ws.objectField("options");
    try ws.write(options);
    try ws.objectField("construction");
    try ws.write(if (shape == .@"oracle-cases")
        "production Store APIs; retention maintenance not run during construction"
    else if (options.retention == .skip)
        "diagnostic: production Store APIs with the shipped retention step skipped; not an untouched daemon baseline"
    else
        "production Store APIs in the daemon's runtime order, including the shipped retention step");
    try ws.objectField("connection_synchronous");
    try ws.write(if (options.sync == .off) "OFF on the generator connection (construction speed only; not a durability or timing result)" else "FULL (runtime default)");

    var failed = false;
    var timer = try std.time.Timer.start();
    if (shape == .@"oracle-cases") {
        try ws.objectField("states");
        try ws.beginArray();
        for (oracle_cases) |case| {
            const gen = try Gen.create(allocator, dir, case.name, options, false);
            defer gen.destroy();
            var snapshots = std.ArrayList(Snapshot).init(allocator);
            defer {
                for (snapshots.items) |item| allocator.free(item.path);
                snapshots.deinit();
            }
            const outcome = runCase(gen, struct {
                fn body(g: *Gen, d: []const u8, s: *std.ArrayList(Snapshot), c: OracleCase) !void {
                    try g.setup();
                    try c.build(g, d, s);
                }
            }.body, .{ gen, dir, &snapshots, case });
            // Oracle states are small by design; any refusal means the state is wrong.
            if (gen.refusal != null or outcome.harness_failure != null) failed = true;
            try ws.beginObject();
            try ws.objectField("case");
            try ws.write(case.name);
            try ws.objectField("harness_failure");
            try ws.write(outcome.harness_failure);
            try writeGen(&ws, gen);
            try ws.objectField("snapshots");
            try ws.beginArray();
            for (snapshots.items) |item| try writeState(&ws, gen, item.label, item.path);
            try ws.endArray();
            try ws.objectField("state");
            try writeState(&ws, gen, "final", gen.path);
            try ws.endObject();
        }
        try ws.endArray();
    } else {
        const gen = try Gen.create(allocator, dir, @tagName(shape), options, true);
        defer gen.destroy();
        const outcome = switch (shape) {
            .churn => runCase(gen, runChurn, .{gen}),
            .hot => runCase(gen, runHot, .{gen}),
            .pinned => runCase(gen, runPinned, .{gen}),
            .reuse => runCase(gen, runReuse, .{gen}),
            .@"oracle-cases" => unreachable,
        };
        if (outcome.harness_failure != null) failed = true;
        try ws.objectField("harness_failure");
        try ws.write(outcome.harness_failure);
        try writeGen(&ws, gen);
        try ws.objectField("state");
        try writeState(&ws, gen, "final", gen.path);
    }
    try ws.objectField("runtime_ms");
    try ws.write(timer.read() / std.time.ns_per_ms);
    try ws.endObject();
    try output.append('\n');
    try std.fs.cwd().writeFile(.{ .sub_path = manifest_path, .data = output.items, .flags = .{ .mode = 0o600, .exclusive = true } });
    if (failed) {
        try stderr.writeAll("fixture harness failure; see manifest harness_failure and first_refusal\n");
        return 1;
    }
    return 0;
}
