// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const build_options = @import("build_options");
const diag_mod = @import("../core/diag.zig");
const durable = @import("../core/record_store.zig");
const effect = @import("../core/native_effect.zig");
const firewall = @import("../firewall/inspection.zig");
pub const observation = @import("native_firewall_observation.zig");

pub const Binding = struct { jail: []const u8, generation: [32]u8 };
pub const EffectDiagnostic = struct {
    backend: firewall.Transport,
    stage: firewall.OperationStage,
    cause: anyerror,
    mutation: firewall.MutationDisposition,
};
pub const Health = struct {
    ready: bool = false,
    uncertain: bool = false,
    overdue: usize = 0,
    confirmed: usize = 0,
    withdrawn: bool = false,
    cause: ?anyerror = null,
    diagnostic: ?EffectDiagnostic = null,
};
fn propagateFirewall(comptime T: type, cause: firewall.Error) firewall.Error!T {
    return cause;
}
fn transientReadback(cause: anyerror) bool {
    return cause == error.Changed or cause == error.DumpInterrupted or cause == error.Timeout or cause == error.Incomplete;
}
pub fn transientCause(cause: anyerror) bool {
    return transientReadback(cause);
}
const max_readback_wait_turns: u16 = 255;
// An audit starts this long before the knowledge window closes, so a dump at the ceiling finishes while knowledge is still fresh.
const audit_lead_ns: u64 = 5 * std.time.ns_per_s;
fn systemWall(_: ?*anyopaque) i64 {
    return std.time.microTimestamp();
}
fn systemMonotonic(_: ?*anyopaque) ?u64 {
    const ts = std.posix.clock_gettime(.MONOTONIC) catch return null;
    const seconds = std.math.cast(u64, ts.sec) orelse return null;
    const nanos = std.math.cast(u64, ts.nsec) orelse return null;
    return std.math.add(u64, std.math.mul(u64, seconds, std.time.ns_per_s) catch return null, nanos) catch null;
}
pub const Step = union(enum) {
    progress,
    wait: u64,
    idle,
    stop,
    fatal: anyerror,
};
pub const SliceLimits = struct {
    max_steps: u16 = 32,
    max_ns: u64 = 50 * std.time.ns_per_ms,
};
pub const StopSignal = struct {
    context: ?*anyopaque = null,
    requested: *const fn (?*anyopaque) bool,
};
pub const Counters = struct {
    rebuilds_completed: u64 = 0,
    rebuild_restarts: u64 = 0,
    incremental_updates: u64 = 0,
    full_readbacks: u64 = 0,
    acknowledged_batches: u64 = 0,
    redispatched: u64 = 0,
    events_applied: u64 = 0,
    events_dropped: u64 = 0,
    expiry_batches: u64 = 0,
    expiries_prepared: u64 = 0,
    overdue_expiries: u64 = 0,
    pending: u64 = 0,
    oldest_pending_us: ?i64 = null,
    overdue: u64 = 0,
    oldest_overdue_us: ?i64 = null,
    overdue_blocking: u64 = 0,
    oldest_overdue_blocking_us: ?i64 = null,
    overdue_bookkeeping: u64 = 0,
    dump_interrupted: u64 = 0,
    install_batches: u64 = 0,
};
pub const Slice = struct {
    outcome: Step,
    steps: u16 = 0,
    elapsed_ns: u64 = 0,
    longest_step_ns: u64 = 0,
};
const Inventory = struct { snapshot: firewall.Snapshot, start_us: i64, end_us: i64, start_ns: ?u64 };
const Marker = struct { sent_ns: ?u64, sent_wall_us: i64 };
const ExpiryClass = enum { kernel_expiring, deletion };
fn expiryClass(transport: firewall.Transport, scope: effect.Scope) ExpiryClass {
    const host = scope.canonical.subject.kind == .host and scope.canonical.protocols.isAll() and scope.canonical.ports.isAll();
    return if (host and transport != .iptables) .kernel_expiring else .deletion;
}
pub const live_bytes = @sizeOf(Manager) + effect.max_effects * (2 * @sizeOf(effect.Entry) + @sizeOf(bool) + 2 * (@sizeOf(?Marker) + 2 * @sizeOf(bool) + @sizeOf(?i64)));
pub const reserved_bytes = live_bytes + (firewall.Limits{}).max_bytes;
pub const Manager = struct {
    allocator: std.mem.Allocator,
    store: *durable.Store,
    inspector: firewall.Inspector,
    installation: effect.Installation,
    live: []effect.Entry,
    staged: []effect.Entry,
    outage_attempted: []bool,
    markers: []?Marker,
    staged_markers: []?Marker,
    confirmed: []bool,
    staged_confirmed: []bool,
    matched: []bool,
    staged_matched: []bool,
    owner_deadline_us: []?i64,
    staged_owner_deadline_us: []?i64,
    count: usize = 0,
    staged_count: usize = 0,
    staged_revision: ?u64 = null,
    staged_epoch: u64 = 0,
    cached_epoch: ?u64 = null,
    cursor: usize = 0,
    last_wall_us: i64,
    wall_context: ?*anyopaque = null,
    wall: *const fn (?*anyopaque) i64 = systemWall,
    monotonic_context: ?*anyopaque = null,
    monotonic: *const fn (?*anyopaque) ?u64 = systemMonotonic,
    wake_interval_ns: u64 = 100 * std.time.ns_per_ms,
    status: Health = .{},
    admitted: bool = false,
    repair_epoch: u64 = 1,
    stop_cursor: usize = 0,
    stop_retries: u8 = 0,
    stopping: bool = false,
    withdrawn: bool = false,
    observation_cache: ?*observation.Cache = null,
    readback_failures: u8 = 0,
    readback_wait: u16 = 0,
    counters: Counters = .{},
    last_verified_ns: ?u64 = null,
    next_deadline_us: ?i64 = null,
    verify_interval_ns: u64 = 0,
    live_selections: u8 = 0,
    inventory: ?Inventory = null,
    last_mutation_ns: ?u64 = null,
    last_mutation_wall_us: ?i64 = null,
    installed_live: u32 = 0,
    last_readback_ns: ?u64 = null,
    events_subscribed: bool = false,
    events_healthy: bool = false,
    events_dirty: bool = false,
    last_generation: ?u32 = null,
    own_ports: [64]u32 = [_]u32{0} ** 64,
    own_port_cursor: u8 = 0,
    view_revision: u64 = 0,
    last_readback_wall_us: ?i64 = null,
    legacy_targets_attempted: ?[32]u8 = null,
    owned_marks: std.StaticBitSet(firewall.max_inventory_entries) = undefined,

    pub fn create(a: std.mem.Allocator, store: *durable.Store, installation: effect.Installation) !*Manager {
        try installation.validate();
        const self = try a.create(Manager);
        errdefer a.destroy(self);
        const live = try a.alloc(effect.Entry, effect.max_effects);
        errdefer a.free(live);
        const staged = try a.alloc(effect.Entry, effect.max_effects);
        errdefer a.free(staged);
        const attempted = try a.alloc(bool, effect.max_effects);
        errdefer a.free(attempted);
        @memset(attempted, false);
        const markers = try a.alloc(?Marker, effect.max_effects);
        errdefer a.free(markers);
        @memset(markers, null);
        const staged_markers = try a.alloc(?Marker, effect.max_effects);
        errdefer a.free(staged_markers);
        @memset(staged_markers, null);
        const confirmed = try a.alloc(bool, effect.max_effects);
        errdefer a.free(confirmed);
        @memset(confirmed, false);
        const staged_confirmed = try a.alloc(bool, effect.max_effects);
        errdefer a.free(staged_confirmed);
        @memset(staged_confirmed, false);
        const matched = try a.alloc(bool, effect.max_effects);
        errdefer a.free(matched);
        @memset(matched, false);
        const staged_matched = try a.alloc(bool, effect.max_effects);
        errdefer a.free(staged_matched);
        @memset(staged_matched, false);
        const owner_deadline_us = try a.alloc(?i64, effect.max_effects);
        errdefer a.free(owner_deadline_us);
        @memset(owner_deadline_us, null);
        const staged_owner_deadline_us = try a.alloc(?i64, effect.max_effects);
        errdefer a.free(staged_owner_deadline_us);
        @memset(staged_owner_deadline_us, null);
        self.* = .{
            .allocator = a,
            .store = store,
            .installation = installation,
            .inspector = try firewall.Inspector.open(a, transportInstallation(installation), .{}),
            .live = live,
            .staged = staged,
            .outage_attempted = attempted,
            .markers = markers,
            .staged_markers = staged_markers,
            .confirmed = confirmed,
            .staged_confirmed = staged_confirmed,
            .matched = matched,
            .staged_matched = staged_matched,
            .owner_deadline_us = owner_deadline_us,
            .staged_owner_deadline_us = staged_owner_deadline_us,
            .last_wall_us = std.time.microTimestamp(),
        };
        return self;
    }
    pub fn destroy(self: *Manager) void {
        self.dropInventory();
        self.inspector.close();
        self.allocator.free(self.live);
        self.allocator.free(self.staged);
        self.allocator.free(self.outage_attempted);
        self.allocator.free(self.markers);
        self.allocator.free(self.staged_markers);
        self.allocator.free(self.confirmed);
        self.allocator.free(self.staged_confirmed);
        self.allocator.free(self.matched);
        self.allocator.free(self.staged_matched);
        self.allocator.free(self.owner_deadline_us);
        self.allocator.free(self.staged_owner_deadline_us);
        self.allocator.destroy(self);
    }
    pub fn attachObservationCache(self: *Manager, cache: *observation.Cache) void {
        self.observation_cache = cache;
    }
    fn forgetKernel(self: *Manager) void {
        self.dropInventory();
        @memset(self.markers[0..self.count], null);
        @memset(self.confirmed[0..self.count], false);
        @memset(self.matched[0..self.count], false);
        self.legacy_targets_attempted = null;
        self.view_revision +%= 1;
    }
    pub fn storageReopened(self: *Manager) void {
        self.forgetKernel();
        self.cached_epoch = null;
        self.staged_revision = null;
        self.staged_count = 0;
        self.admitted = false;
        self.status.ready = false;
        self.repair_epoch +|= 1;
        self.stop_cursor = 0;
        self.stop_retries = 0;
        self.stopping = false;
    }
    pub fn beginRepair(self: *Manager, expected_epoch: u64) !u64 {
        if (expected_epoch == 0 or expected_epoch != self.repair_epoch or self.repair_epoch == std.math.maxInt(u64)) return error.StaleRepairEpoch;
        self.repair_epoch += 1;
        self.forgetKernel();
        self.cached_epoch = null;
        self.staged_revision = null;
        self.staged_count = 0;
        self.cursor = 0;
        self.readback_failures = 0;
        self.readback_wait = 0;
        self.status.ready = false;
        self.status.uncertain = false;
        self.status.cause = null;
        return self.repair_epoch;
    }
    pub fn repairEpoch(self: *const Manager) u64 {
        return self.repair_epoch;
    }
    pub fn confirmedSubject(self: *const Manager, subject: @import("../core/native_detection_record.zig").Subject, now_us: i64) bool {
        if (self.status.uncertain and !(self.status.cause != null and transientCause(self.status.cause.?))) return false;
        const scope = effect.Scope.host(subject) catch return false;
        const key = scope.key(self.installation) catch return false;
        const index = self.findLive(key) orelse return false;
        return self.live[index].status == .applied and self.live[index].desired.live(now_us) and (self.confirmed[index] or self.status.ready);
    }
    pub fn confirmedKey(self: *const Manager, key: [32]u8, now_us: i64) bool {
        const index = self.findLive(key) orelse return false;
        return self.live[index].status == .applied and self.live[index].desired.live(now_us) and (self.confirmed[index] or self.status.ready);
    }
    fn recordFirewallFailure(self: *Manager, context: firewall.FailureContext) void {
        self.status.cause = context.cause;
        self.status.uncertain = true;
        self.status.diagnostic = .{
            .backend = context.backend,
            .stage = context.stage,
            .cause = context.cause,
            .mutation = context.mutation,
        };
        self.recordObservationFailure(context.stage, context.cause);
    }
    fn recordFirewallDirect(self: *Manager, stage: firewall.OperationStage, cause: firewall.Error) void {
        self.recordFirewallFailure(.{
            .backend = self.inspector.installation.transport,
            .stage = stage,
            .cause = cause,
            .mutation = .not_started,
        });
    }
    fn observationWall(self: *Manager) ?i64 {
        const now = self.wall(self.wall_context);
        return if (now < 0) null else now;
    }
    fn recordObservationFailure(self: *Manager, stage: firewall.OperationStage, cause: anyerror) void {
        const cache = self.observation_cache orelse return;
        cache.fail(.{
            .monotonic_ms = observation.monotonicMs(),
            .wall_us = self.observationWall(),
            .cause = cause,
            .stage = stage,
        });
    }
    fn captureObservation(self: *Manager, snapshot: *const firewall.Snapshot, origin: observation.Origin, wall_us: ?i64, inventory: observation.Inventory) void {
        const cache = self.observation_cache orelse return;
        cache.capture(snapshot, .{
            .monotonic_ms = observation.monotonicMs(),
            .wall_us = wall_us,
            .origin = origin,
            .inventory = inventory,
        });
    }
    fn validateAndCaptureObservation(self: *Manager, snapshot: *const firewall.Snapshot, origin: observation.Origin, wall_us: ?i64, stage: firewall.OperationStage) !void {
        self.validateInventory(snapshot) catch |failure| {
            self.captureObservation(snapshot, origin, wall_us, if (failure == error.UnownedInstalledEffect) .unexpected_entries else .not_checked);
            self.recordObservationFailure(stage, failure);
            return failure;
        };
        self.captureObservation(snapshot, origin, wall_us, .known_entries);
    }
    fn deferReadback(self: *Manager) Step {
        self.dropInventory();
        self.events_healthy = false;
        self.status.ready = false;
        self.readback_failures +|= 1;
        if (comptime build_options.diag) diag_mod.event(.readback_deferred, .{ .value = self.readback_failures });
        const shift: u4 = @intCast(@min(self.readback_failures - 1, 8));
        self.readback_wait = @min((@as(u16, 1) << shift) - 1, max_readback_wait_turns);
        return .{ .wait = self.waitDue() };
    }
    pub fn setClockRate(self: *Manager, rate: u32) void {
        self.inspector.clock_rate = rate;
    }
    fn clock(self: *Manager) !effect.Clock {
        const now = self.wall(self.wall_context);
        if (now < self.last_wall_us) return error.EffectClockReversed;
        self.last_wall_us = now;
        return .{ .prepared_us = now, .context = self.wall_context, .read = self.wall };
    }
    pub fn prolongRetry(self: *Manager, change: durable.Store.RetryProlongation) !durable.Store.RetryProlongationResult {
        errdefer |failure| {
            self.status.ready = false;
            self.status.uncertain = true;
            self.status.cause = failure;
        }
        const result = try self.store.prolongRetryDecision(change, try self.clock());
        if (result.changed) self.status.ready = false;
        return result;
    }
    pub fn admit(self: *Manager) !void {
        errdefer |failure| {
            self.status.ready = false;
            self.status.uncertain = true;
            self.status.cause = failure;
        }
        self.dropInventory();
        const saved = try self.store.readInstallation() orelse return error.InstallationRequired;
        if (!std.meta.eql(saved, self.installation)) return error.InstallationMismatch;
        const id = effect.hashParts("fail2zig-native-installation-intent-v1", &.{ &saved.id, &.{@intFromEnum(saved.backend)}, saved.selector() });
        var result = self.inspector.admitInstallation(.{ .installation = self.inspector.installation, .intent_id = id, .revision = 1 }) catch |failure| {
            self.recordFirewallDirect(.admission_probe, failure);
            return propagateFirewall(void, failure);
        };
        defer result.deinit();
        switch (result) {
            .installed => |installed| {
                self.captureObservation(&installed.snapshot, .admission, self.observationWall(), .not_checked);
                if (installed.created) std.log.info("{s}: scaffold installed and verified (selector={s})", .{ @tagName(saved.backend), saved.selector() });
                self.admitted = true;
            },
            .uncertain => |failure| {
                self.recordFirewallFailure(failure);
                return error.EffectBackendUncertain;
            },
        }
    }
    fn refreshTurn(self: *Manager, bindings: []const Binding) !bool {
        if (self.staged_revision == null) {
            self.staged_count = 0;
            self.staged_epoch = self.store.effect_publication_epoch;
        }
        if (self.staged_epoch != self.store.effect_publication_epoch) {
            self.staged_revision = null;
            self.counters.rebuild_restarts += 1;
            return false;
        }
        var rows: [effect.max_page]effect.Entry = undefined;
        const after = if (self.staged_count == 0) null else self.staged[self.staged_count - 1].scope_key;
        const page = try self.store.effectPage(after, self.staged_revision, &rows);
        if (page.count > self.staged.len - self.staged_count) return error.EffectCapacity;
        for (rows[0..page.count], 0..) |entry, offset| self.staged_owner_deadline_us[self.staged_count + offset] = try self.validateOwners(bindings, entry);
        @memcpy(self.staged[self.staged_count..][0..page.count], rows[0..page.count]);
        self.staged_count += page.count;
        self.staged_revision = page.revision;
        if (page.more) return false;
        if (self.staged_epoch != self.store.effect_publication_epoch) {
            self.staged_revision = null;
            self.counters.rebuild_restarts += 1;
            return false;
        }
        self.counters.rebuilds_completed += 1;
        for (self.staged[0..self.staged_count], 0..) |entry, index| {
            const carried = self.findLive(entry.scope_key);
            const same = carried != null and std.mem.eql(u8, &self.live[carried.?].intent_id, &entry.intent_id);
            self.staged_markers[index] = if (same) self.markers[carried.?] else null;
            self.staged_confirmed[index] = same and self.confirmed[carried.?];
            self.staged_matched[index] = false;
        }
        self.dropInventory();
        std.mem.swap([]effect.Entry, &self.live, &self.staged);
        std.mem.swap([]?Marker, &self.markers, &self.staged_markers);
        std.mem.swap([]bool, &self.confirmed, &self.staged_confirmed);
        std.mem.swap([]bool, &self.matched, &self.staged_matched);
        std.mem.swap([]?i64, &self.owner_deadline_us, &self.staged_owner_deadline_us);
        self.count = self.staged_count;
        self.cached_epoch = self.staged_epoch;
        self.view_revision +%= 1;
        self.staged_revision = null;
        self.cursor = self.count;
        self.legacy_targets_attempted = null;
        @memset(self.outage_attempted, false);
        return true;
    }
    fn catchUp(self: *Manager, bindings: []const Binding) !?Step {
        const cached = self.cached_epoch orelse return null;
        const current = self.store.effect_publication_epoch;
        if (current == std.math.maxInt(u64) or current <= cached or current - cached > durable.Store.attribution_ring) return null;
        var epoch = cached + 1;
        while (epoch <= current) : (epoch += 1) if (self.store.attributedChange(epoch) == null) return null;
        var spent_only = true;
        epoch = cached + 1;
        while (epoch <= current) : (epoch += 1) for (self.store.attributedChange(epoch).?.slice()) |key| {
            const found = self.findLive(key);
            if (try self.readScope(key)) |entry| {
                const owner_deadline = try self.validateOwners(bindings, entry);
                spent_only = false;
                if (found) |index| {
                    try self.replaceAt(index, entry, owner_deadline);
                } else {
                    if (self.count == self.live.len) return error.EffectCapacity;
                    try self.insertAt(self.insertionPoint(key), entry, owner_deadline);
                }
            } else if (found) |index| {
                const removed = self.live[index];
                if (removed.desired != .absent or removed.status != .absent) spent_only = false;
                self.removeAt(index);
            }
        };
        if (self.store.effect_publication_epoch != current) return null;
        self.cached_epoch = current;
        self.counters.incremental_updates += 1;
        if (spent_only and self.status.ready) {
            self.cursor = self.count;
            return .idle;
        }
        self.status.ready = false;
        self.cursor = self.count;
        return .progress;
    }
    fn replaceAt(self: *Manager, index: usize, entry: effect.Entry, owner_deadline: ?i64) !void {
        const previous = self.live[index];
        self.live[index] = entry;
        self.view_revision +%= 1;
        self.outage_attempted[index] = false;
        self.owner_deadline_us[index] = owner_deadline;
        if (!std.mem.eql(u8, &previous.intent_id, &entry.intent_id)) {
            self.markers[index] = null;
            self.confirmed[index] = false;
        }
        try self.refreshMatch(index);
    }
    fn insertAt(self: *Manager, at: usize, entry: effect.Entry, owner_deadline: ?i64) !void {
        const n = self.count;
        std.mem.copyBackwards(effect.Entry, self.live[at + 1 .. n + 1], self.live[at..n]);
        std.mem.copyBackwards(bool, self.outage_attempted[at + 1 .. n + 1], self.outage_attempted[at..n]);
        std.mem.copyBackwards(?Marker, self.markers[at + 1 .. n + 1], self.markers[at..n]);
        std.mem.copyBackwards(bool, self.confirmed[at + 1 .. n + 1], self.confirmed[at..n]);
        std.mem.copyBackwards(bool, self.matched[at + 1 .. n + 1], self.matched[at..n]);
        std.mem.copyBackwards(?i64, self.owner_deadline_us[at + 1 .. n + 1], self.owner_deadline_us[at..n]);
        self.live[at] = entry;
        self.view_revision +%= 1;
        self.outage_attempted[at] = false;
        self.markers[at] = null;
        self.confirmed[at] = false;
        self.matched[at] = false;
        self.owner_deadline_us[at] = owner_deadline;
        self.count += 1;
        try self.refreshMatch(at);
    }
    fn removeAt(self: *Manager, index: usize) void {
        const n = self.count;
        std.mem.copyForwards(effect.Entry, self.live[index .. n - 1], self.live[index + 1 .. n]);
        std.mem.copyForwards(bool, self.outage_attempted[index .. n - 1], self.outage_attempted[index + 1 .. n]);
        std.mem.copyForwards(?Marker, self.markers[index .. n - 1], self.markers[index + 1 .. n]);
        std.mem.copyForwards(bool, self.confirmed[index .. n - 1], self.confirmed[index + 1 .. n]);
        std.mem.copyForwards(bool, self.matched[index .. n - 1], self.matched[index + 1 .. n]);
        std.mem.copyForwards(?i64, self.owner_deadline_us[index .. n - 1], self.owner_deadline_us[index + 1 .. n]);
        self.count -= 1;
        self.view_revision +%= 1;
    }
    fn findLive(self: *const Manager, key: [32]u8) ?usize {
        const at = self.insertionPoint(key);
        return if (at < self.count and std.mem.eql(u8, &self.live[at].scope_key, &key)) at else null;
    }
    fn insertionPoint(self: *const Manager, key: [32]u8) usize {
        var low: usize = 0;
        var high: usize = self.count;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (std.mem.order(u8, &self.live[mid].scope_key, &key) == .lt) low = mid + 1 else high = mid;
        }
        return low;
    }
    fn validateOwners(self: *Manager, bindings: []const Binding, entry: effect.Entry) !?i64 {
        var owners: [effect.max_page]effect.Owner = undefined;
        const count = try self.store.effectOwners(entry.scope_key, entry.revision, &owners);
        return self.ownerDeadline(bindings, owners[0..count]);
    }
    fn ownerDeadline(self: *Manager, bindings: []const Binding, owners: []const effect.Owner) !?i64 {
        _ = self;
        var deadline: ?i64 = null;
        for (owners) |owner| {
            for (bindings) |binding| {
                if (!std.mem.eql(u8, binding.jail, owner.jail.slice())) continue;
                if (!std.mem.eql(u8, &binding.generation, &owner.generation)) return error.EffectGenerationMismatch;
                break;
            } else if (owner.lease == .absent) continue else return error.UnconfiguredStateOwner;
            if (owner.lease == .finite) deadline = if (deadline) |prior| @min(prior, owner.lease.finite) else owner.lease.finite;
        }
        return deadline;
    }
    fn readScope(self: *Manager, key: [32]u8) !?effect.Entry {
        try self.store.beginRead();
        errdefer self.store.rollback();
        const installation = try self.store.readInstallation() orelse return error.InstallationRequired;
        const entry = try self.store.readEffect(key, installation);
        try self.store.commitTransaction();
        return entry;
    }
    const Commit = enum { unchanged, changed };
    fn attributeCommit(self: *Manager, bindings: []const Binding, index: usize, pre: u64) !Commit {
        const post = self.store.effect_publication_epoch;
        if (post == std.math.maxInt(u64)) {
            self.cached_epoch = null;
            return .changed;
        }
        if (post == pre) {
            self.cached_epoch = null;
            return .unchanged;
        }
        const current = self.cached_epoch != null and self.cached_epoch.? == pre;
        if (!current or post < pre or post - pre != 1 or self.staged_revision != null) {
            self.cached_epoch = null;
            return .changed;
        }
        self.cached_epoch = null;
        const entry = try self.readScope(self.live[index].scope_key) orelse return .changed;
        const owner_deadline = try self.validateOwners(bindings, entry);
        if (self.store.effect_publication_epoch != post) return .changed;
        try self.replaceAt(index, entry, owner_deadline);
        self.cached_epoch = post;
        return .changed;
    }
    fn writeFailed(self: *Manager, pre: u64) void {
        if (self.store.reopen_required or self.store.effect_publication_epoch != pre) self.cached_epoch = null;
    }
    fn token(self: *Manager, entry: effect.Entry, lease: effect.Lease) firewall.DispatchToken {
        return .{ .installation = self.inspector.installation, .effect_id = entry.scope_key, .aggregate_revision = entry.revision, .scope = entry.scope.canonical, .operation = switch (lease) {
            .absent => .ensure_absent,
            .finite => |deadline| .{ .ensure_present = .{ .finite_deadline_us = deadline } },
            .permanent => .{ .ensure_present = .permanent },
        } };
    }
    fn validateInventory(self: *Manager, snapshot: *const firewall.Snapshot) !void {
        if (snapshot.state != .owned) return error.InstallationMismatch;
        const installed = snapshot.entries;
        if (installed.len > self.owned_marks.capacity()) return error.LimitExceeded;
        self.owned_marks.setRangeValue(.{ .start = 0, .end = installed.len }, false);
        for (self.live[0..self.count]) |entry| {
            const index = try snapshot.find(entry.scope.canonical) orelse continue;
            const found = installed[index];
            if (found.scope != null and (found.effect_id == null or !std.mem.eql(u8, &found.effect_id.?, &entry.scope_key))) continue;
            self.owned_marks.set(index);
        }
        for (0..installed.len) |index| if (!self.owned_marks.isSet(index)) return error.UnownedInstalledEffect;
    }
    fn keepInventory(self: *Manager, snapshot: firewall.Snapshot, start_us: i64, end_us: i64, start_ns: ?u64) void {
        self.dropInventory();
        self.inventory = .{ .snapshot = snapshot, .start_us = start_us, .end_us = end_us, .start_ns = start_ns };
        self.inspector.retained_bytes = snapshot.entries.len * @sizeOf(firewall.Entry);
    }
    fn dropInventory(self: *Manager) void {
        if (self.inventory) |*held| held.snapshot.deinit();
        self.inventory = null;
        self.inspector.retained_bytes = 0;
    }
    fn inventoryCurrent(self: *const Manager) bool {
        const held = self.inventory orelse return false;
        if (self.events_subscribed) return self.events_healthy;
        const sent_wall = self.last_mutation_wall_us orelse return true;
        if (held.start_ns) |start| if (self.last_mutation_ns) |sent| return start > sent;
        return held.start_us > sent_wall;
    }
    fn presentIn(held: *const Inventory, entry: effect.Entry) !bool {
        const found = try held.snapshot.find(entry.scope.canonical) orelse return false;
        const installed = held.snapshot.entries[found];
        return installed.scope == null or (installed.effect_id != null and std.mem.eql(u8, &installed.effect_id.?, &entry.scope_key));
    }
    fn refreshMatch(self: *Manager, index: usize) !void {
        const held = &(self.inventory orelse {
            self.matched[index] = false;
            return;
        });
        const entry = self.live[index];
        const matched = self.inspector.matchesSnapshot(&held.snapshot, self.token(entry, entry.desired), held.start_us, held.end_us) catch |failure| {
            if (transientReadback(failure)) {
                self.recordFirewallDirect(.readback, failure);
                self.dropInventory();
                self.matched[index] = false;
                return;
            }
            self.recordObservationFailure(.readback, failure);
            return propagateFirewall(void, failure);
        };
        self.matched[index] = matched;
        if (self.confirmed[index] != matched) self.view_revision +%= 1;
        self.confirmed[index] = matched;
    }
    fn recount(self: *Manager) !bool {
        var confirmed_count: usize = 0;
        var installed: u32 = 0;
        for (self.live[0..self.count], 0..) |entry, index| {
            try self.refreshMatch(index);
            const held = &(self.inventory orelse return false);
            if (entry.status == .applied and entry.desired.live(held.end_us) and self.confirmed[index]) confirmed_count += 1;
            if (entry.desired.live(held.end_us)) if (try held.snapshot.find(entry.scope.canonical)) |found| {
                const installed_entry = held.snapshot.entries[found];
                if (installed_entry.scope == null or (installed_entry.effect_id != null and std.mem.eql(u8, &installed_entry.effect_id.?, &entry.scope_key))) installed += 1;
            };
        }
        if (self.inventory == null) return false;
        self.installed_live = installed;
        self.status.confirmed = confirmed_count;
        return true;
    }
    fn evaluateInventory(self: *Manager) !bool {
        if (!try self.recount()) return false;
        const held = &(self.inventory orelse return false);
        self.readback_failures = 0;
        self.counters.full_readbacks += 1;
        self.counters.dump_interrupted = self.inspector.dump_interruptions;
        self.last_readback_ns = held.start_ns;
        self.last_readback_wall_us = held.end_us;
        self.events_healthy = self.events_subscribed;
        self.last_generation = null;
        if (self.status.diagnostic) |diagnostic| if (transientReadback(diagnostic.cause)) {
            self.status.diagnostic = null;
            self.status.cause = null;
            self.status.uncertain = false;
        };
        return true;
    }
    fn waitDue(self: *Manager) u64 {
        const base = self.monotonic(self.monotonic_context) orelse 0;
        return base +| self.wake_interval_ns *| self.readback_wait;
    }
    pub fn step(self: *Manager, bindings: []const Binding) Step {
        return self.stepInner(bindings) catch |failure| .{ .fatal = failure };
    }
    pub fn runSlice(self: *Manager, bindings: []const Binding, limits: SliceLimits, stop: ?StopSignal) Slice {
        const start = systemMonotonic(null);
        var slice = Slice{ .outcome = .progress };
        self.drainEvents();
        if (self.readback_wait != 0) {
            self.readback_wait -= 1;
            self.status.ready = false;
            slice.outcome = .{ .wait = self.waitDue() };
            return slice;
        }
        while (slice.steps < limits.max_steps) {
            if (stop) |signal| if (signal.requested(signal.context)) {
                slice.outcome = .stop;
                break;
            };
            const before = systemMonotonic(null);
            slice.outcome = self.step(bindings);
            const after = systemMonotonic(null);
            slice.steps += 1;
            if (before != null and after != null) slice.longest_step_ns = @max(slice.longest_step_ns, after.? -| before.?);
            // Without a monotonic reading the time budget cannot be enforced, so the slice ends after this step.
            if (start == null or after == null) break;
            slice.elapsed_ns = after.? -| start.?;
            if (slice.outcome != .progress or slice.elapsed_ns >= limits.max_ns) break;
        }
        return slice;
    }
    fn stepInner(self: *Manager, bindings: []const Binding) !Step {
        errdefer |failure| {
            if (!transientReadback(failure)) std.log.warn("native: effect runtime stopped at cursor {d} of {d}: {s}", .{ self.cursor, self.count, @errorName(failure) });
            self.dropInventory();
            self.status.ready = false;
            self.status.uncertain = true;
            self.status.cause = failure;
        }
        if (self.withdrawn) return self.withdrawnReadback();
        if (self.store.effect_publication_epoch == std.math.maxInt(u64)) return error.EffectCapacity;
        const sampled = try self.clock();
        if (self.readback_wait != 0) {
            self.status.ready = false;
            return .{ .wait = self.waitDue() };
        }
        if (!self.admitted) {
            self.admit() catch |failure| {
                if (transientReadback(failure)) return self.deferReadback();
                return @as(@TypeOf(failure)!Step, failure);
            };
            self.readback_failures = 0;
            return .progress;
        }
        if (self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch) {
            if (self.staged_revision == null) if (try self.catchUp(bindings)) |outcome| return outcome;
            self.status.ready = false;
            _ = try self.refreshTurn(bindings);
            return .progress;
        }
        const audit_interval = if (self.events_subscribed) self.verify_interval_ns -| audit_lead_ns else self.verify_interval_ns;
        if (self.status.ready and self.readback_wait == 0 and self.verify_interval_ns != 0) {
            const due = if (self.next_deadline_us) |deadline| deadline <= sampled.prepared_us else false;
            if (!due) if (self.last_verified_ns) |last| if (self.monotonic(self.monotonic_context)) |now| if (now -| last < audit_interval) return .idle;
        }
        if (self.events_subscribed and self.inventory != null and self.verify_interval_ns != 0) if (self.last_readback_ns) |last| if (self.monotonic(self.monotonic_context)) |now| {
            if (now -| last >= audit_interval) return self.readback(sampled);
        };
        if (self.cursor < self.count) return self.act(bindings, sampled);
        if (self.status.ready or !self.inventoryCurrent()) return self.readback(sampled);
        return self.select(bindings, sampled);
    }
    fn readback(self: *Manager, sampled: effect.Clock) !Step {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.readback) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const start_ns = self.monotonic(self.monotonic_context);
        if (comptime build_options.diag) diag_mod.readback(start_ns, self.last_verified_ns, self.verify_interval_ns, self.wake_interval_ns);
        self.discardEvents();
        var snapshot = self.inspector.inspect() catch |failure| {
            self.recordFirewallDirect(.readback, failure);
            if (transientReadback(failure)) return self.deferReadback();
            return propagateFirewall(Step, failure);
        };
        if (comptime build_options.diag) diag_mod.limit(.kernel_elements, snapshot.entries.len, firewall.max_inventory_entries);
        {
            const diag_compare = if (comptime build_options.diag) diag_mod.enter(.compare) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_compare);
            errdefer snapshot.deinit();
            try self.validateAndCaptureObservation(&snapshot, .readback, sampled.prepared_us, .readback);
        }
        self.keepInventory(snapshot, sampled.prepared_us, (try self.clock()).prepared_us, start_ns);
        const evaluated = evaluated_blk: {
            const diag_compare = if (comptime build_options.diag) diag_mod.enterContinued(.compare) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_compare);
            break :evaluated_blk try self.evaluateInventory();
        };
        if (!evaluated) return self.deferReadback();
        if (self.counters.redispatched != 0) {
            std.log.info("native: {d} applied effects were missing from the kernel since the last audit and were dispatched again", .{self.counters.redispatched});
            self.counters.redispatched = 0;
        }
        self.status.ready = false;
        return .progress;
    }
    fn expiryDue(self: *const Manager, index: usize, entry: effect.Entry, now_us: i64) bool {
        if (entry.status == .dispatched or self.markers[index] != null) return false;
        if (entry.desired == .finite) return !entry.desired.live(now_us);
        if (entry.desired == .permanent) if (self.owner_deadline_us[index]) |deadline| return deadline <= now_us;
        return false;
    }
    fn act(self: *Manager, bindings: []const Binding, sampled: effect.Clock) !Step {
        const index = self.cursor;
        const entry = self.live[index];
        self.cursor = self.count;
        if (entry.status == .superseded) {
            std.log.warn("native: superseded effect at view index {d} reached the act step", .{index});
            return error.InvalidEffect;
        }
        if (self.markers[index] != null or entry.status == .dispatched) return self.readback(sampled);
        if (self.expiryDue(index, entry, sampled.prepared_us)) {
            errdefer self.cursor = index;
            return self.expire(bindings, index, sampled);
        }
        if (entry.status == .pending or (self.inventory != null and !self.matched[index])) return self.dispatch(bindings, index, sampled);
        return self.readback(sampled);
    }
    const expiry_share: u8 = 4;
    fn select(self: *Manager, bindings: []const Binding, sampled: effect.Clock) !Step {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.select) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const held = &self.inventory.?;
        const now_us = sampled.prepared_us;
        var marker_pick: ?usize = null;
        var legacy_pick: ?usize = null;
        var live_pick: ?usize = null;
        var live_oldest_us: i64 = 0;
        var live_pending: u64 = 0;
        var oldest_pending_us: ?i64 = null;
        var removal_pick: ?usize = null;
        var removal_oldest_us: i64 = 0;
        var removal_pending: u64 = 0;
        var due_pick: ?usize = null;
        var due_count: u64 = 0;
        var settle_tokens: [durable.Store.max_expiry_batch]effect.Token = undefined;
        var settle_count: usize = 0;
        var settle_blocked: u64 = 0;
        var oldest_overdue_us: ?i64 = null;
        var blocking: u64 = 0;
        var oldest_blocking_us: ?i64 = null;
        var bookkeeping: u64 = 0;
        var next_deadline: ?i64 = null;
        var all_confirmed = true;
        const transport = self.inspector.installation.transport;
        for (self.live[0..self.count], 0..) |entry, index| {
            if (entry.status == .superseded) {
                std.log.warn("native: superseded effect at view index {d} reached the select step", .{index});
                return error.InvalidEffect;
            }
            if (self.markers[index] != null) {
                if (marker_pick == null) marker_pick = index;
                all_confirmed = false;
                continue;
            }
            if (entry.status == .dispatched) {
                if (legacy_pick == null) legacy_pick = index;
                all_confirmed = false;
                continue;
            }
            if (entry.desired == .finite and entry.status != .expired and entry.status != .absent) next_deadline = if (next_deadline) |prior| @min(prior, entry.desired.finite) else entry.desired.finite;
            if (entry.desired == .permanent) if (self.owner_deadline_us[index]) |deadline| {
                next_deadline = if (next_deadline) |prior| @min(prior, deadline) else deadline;
            };
            const matched = self.matched[index];
            if (self.expiryDue(index, entry, now_us)) {
                due_count += 1;
                const deadline = if (entry.desired == .finite) entry.desired.finite else self.owner_deadline_us[index].?;
                oldest_overdue_us = if (oldest_overdue_us) |prior| @min(prior, deadline) else deadline;
                if (expiryClass(transport, entry.scope) == .deletion and try presentIn(held, entry)) {
                    blocking += 1;
                    oldest_blocking_us = if (oldest_blocking_us) |prior| @min(prior, deadline) else deadline;
                } else bookkeeping += 1;
                if (due_pick == null) due_pick = index;
                all_confirmed = false;
                continue;
            }
            if (entry.desired == .absent) {
                if (matched) {
                    if (entry.status == .absent) continue;
                    oldest_overdue_us = if (oldest_overdue_us) |prior| @min(prior, entry.intent_us) else entry.intent_us;
                    bookkeeping += 1;
                    all_confirmed = false;
                    // An inventory read before the removal was prepared cannot settle it: the store refuses an outcome dated before its intent.
                    if (held.start_us < entry.intent_us) {
                        settle_blocked += 1;
                        continue;
                    }
                    if (settle_count < settle_tokens.len) {
                        settle_tokens[settle_count] = entry.token();
                        settle_count += 1;
                    }
                    continue;
                }
                // A kernel-expiring element read before its removal was prepared may still be timing out; only a later readback can call it drift.
                const class = expiryClass(transport, entry.scope);
                if (class == .kernel_expiring and held.start_us < entry.intent_us) {
                    settle_blocked += 1;
                    bookkeeping += 1;
                    all_confirmed = false;
                    continue;
                }
                removal_pending += 1;
                oldest_overdue_us = if (oldest_overdue_us) |prior| @min(prior, entry.intent_us) else entry.intent_us;
                if (class == .deletion) {
                    blocking += 1;
                    oldest_blocking_us = if (oldest_blocking_us) |prior| @min(prior, entry.intent_us) else entry.intent_us;
                } else bookkeeping += 1;
                if (removal_pick == null or entry.intent_us < removal_oldest_us) {
                    removal_pick = index;
                    removal_oldest_us = entry.intent_us;
                }
                all_confirmed = false;
                continue;
            }
            if (entry.status == .pending or !matched) {
                live_pending += 1;
                oldest_pending_us = if (oldest_pending_us) |prior| @min(prior, entry.intent_us) else entry.intent_us;
                if (live_pick == null or entry.intent_us < live_oldest_us) {
                    live_pick = index;
                    live_oldest_us = entry.intent_us;
                }
                all_confirmed = false;
                continue;
            }
            if (!self.confirmed[index]) all_confirmed = false;
        }
        self.next_deadline_us = next_deadline;
        self.counters.overdue_expiries = due_count;
        self.counters.pending = live_pending;
        self.counters.oldest_pending_us = oldest_pending_us;
        self.counters.overdue = blocking + bookkeeping;
        self.counters.oldest_overdue_us = oldest_overdue_us;
        self.counters.overdue_blocking = blocking;
        self.counters.oldest_overdue_blocking_us = oldest_blocking_us;
        self.counters.overdue_bookkeeping = bookkeeping;
        if (marker_pick) |index| return self.settleMarker(bindings, index);
        if (legacy_pick) |index| return self.settleLegacy(bindings, index);
        const expiry_backlog = removal_pending + due_count + settle_count;
        const expiry_work = removal_pick != null or due_pick != null or settle_count != 0;
        const share: u8 = if (expiry_backlog > live_pending) 1 else expiry_share;
        if (live_pick == null) self.live_selections = 0;
        if (expiry_work and (live_pick == null or self.live_selections >= share)) {
            self.live_selections = 0;
            self.status.ready = false;
            if (removal_pick orelse due_pick) |index| {
                self.cursor = index;
                return .progress;
            }
            return self.settleExpiredBatch(settle_tokens[0..settle_count]);
        }
        if (live_pick) |index| {
            self.live_selections +|= 1;
            self.status.ready = false;
            if (live_pending > 1) if (try self.installPending(bindings, sampled)) |outcome| return outcome;
            self.cursor = index;
            return .progress;
        }
        if (settle_blocked != 0) {
            self.dropInventory();
            return .progress;
        }
        if (try self.settleLegacyTargets(bindings)) |outcome| return outcome;
        if (!all_confirmed) {
            if (!self.events_subscribed) self.dropInventory();
            return .{ .wait = self.waitDue() };
        }
        if (comptime build_options.diag) self.store.diagKernelCheck(held.snapshot.entries.len, held.start_us, held.end_us);
        self.status = .{ .ready = true, .confirmed = self.status.confirmed };
        self.last_verified_ns = self.monotonic(self.monotonic_context);
        self.cursor = self.count;
        return .idle;
    }
    fn installPending(self: *Manager, bindings: []const Binding, sampled: effect.Clock) !?Step {
        var tokens: [firewall.max_install_messages]firewall.DispatchToken = undefined;
        var indices: [firewall.max_install_messages]usize = undefined;
        var stale: [firewall.max_install_messages]usize = undefined;
        var n: usize = 0;
        var stale_count: usize = 0;
        for (self.live[0..self.count], 0..) |entry, index| {
            if (n == tokens.len) break;
            if (self.markers[index] != null or entry.status == .dispatched or entry.status == .superseded or entry.desired == .absent) continue;
            if (entry.status != .pending and self.matched[index]) continue;
            if (self.expiryDue(index, entry, sampled.prepared_us)) continue;
            if (entry.desired == .finite and !entry.desired.live(sampled.prepared_us)) continue;
            if (!firewall.batchable(entry.scope.canonical)) continue;
            if (entry.status != .pending) {
                stale[stale_count] = index;
                stale_count += 1;
            }
            indices[n] = index;
            n += 1;
        }
        if (n < 2) return null;
        if (stale_count != 0) {
            const held = &self.inventory.?;
            self.counters.redispatched += stale_count;
            const dispatched = if (self.events_subscribed) sampled.prepared_us else held.start_us;
            const observed = if (self.events_subscribed) sampled.prepared_us else held.end_us;
            try self.settleBatch(bindings, stale[0..stale_count], dispatched, observed, .mismatch, held.snapshot.fingerprint);
            if (self.cached_epoch == null) return .progress;
        }
        const dispatch_clock = try self.clock();
        var pending: usize = 0;
        for (indices[0..n]) |index| {
            const entry = self.live[index];
            if (entry.status != .pending) continue;
            if (entry.desired == .finite and !entry.desired.live(dispatch_clock.prepared_us)) continue;
            tokens[pending] = self.token(entry, entry.desired);
            indices[pending] = index;
            pending += 1;
        }
        if (pending == 0) return .progress;
        n = pending;
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.dispatch) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const sent_ns = self.monotonic(self.monotonic_context);
        const prior_mutation_ns = self.last_mutation_ns;
        const prior_mutation_wall_us = self.last_mutation_wall_us;
        for (indices[0..n]) |index| self.markers[index] = .{ .sent_ns = sent_ns, .sent_wall_us = dispatch_clock.prepared_us };
        self.last_mutation_ns = sent_ns;
        self.last_mutation_wall_us = dispatch_clock.prepared_us;
        const outcome = self.inspector.installBatch(tokens[0..n], .{ .wall_us = dispatch_clock.prepared_us }, &self.inventory.?.snapshot) catch |failure| {
            self.recordFirewallDirect(.effect_dispatch, failure);
            if (!transientReadback(failure)) {
                std.log.warn("native: batch install of {d} effects refused: {s}", .{ n, @errorName(failure) });
                return error.EffectBackendUncertain;
            }
            for (indices[0..n]) |index| self.markers[index] = null;
            self.last_mutation_ns = prior_mutation_ns;
            self.last_mutation_wall_us = prior_mutation_wall_us;
            return self.deferReadback();
        };
        const consumed = outcome.consumed;
        for (indices[consumed..n]) |index| self.markers[index] = null;
        switch (outcome.result) {
            .uncertain => |failure| {
                self.recordFirewallFailure(failure);
                if (failure.mutation == .not_started) {
                    for (indices[0..consumed]) |index| self.markers[index] = null;
                    self.last_mutation_ns = prior_mutation_ns;
                    self.last_mutation_wall_us = prior_mutation_wall_us;
                }
                if (!transientReadback(failure.cause)) {
                    std.log.warn("native: batch install of {d} effects uncertain at {s}: {s}", .{ consumed, @tagName(failure.stage), @errorName(failure.cause) });
                    return error.EffectBackendUncertain;
                }
                return self.deferReadback();
            },
            .acknowledged => |acked| {
                for (indices[0..consumed]) |index| self.markers[index] = null;
                self.rememberOwnPort(acked.port_id);
                self.applyAcknowledged(indices[0..consumed]) catch |failure| {
                    std.log.warn("native: acknowledged batch of {d} effects could not enter the view: {s}", .{ consumed, @errorName(failure) });
                    return failure;
                };
                self.settleBatch(bindings, indices[0..consumed], dispatch_clock.prepared_us, acked.acked_wall_us, .desired, self.tokenFingerprint(indices[0..consumed])) catch |failure| {
                    std.log.warn("native: acknowledged batch of {d} effects could not be settled: {s}", .{ consumed, @errorName(failure) });
                    return failure;
                };
                self.refreshSettled(bindings, indices[0..consumed]) catch |failure| {
                    std.log.warn("native: settled batch of {d} effects could not be re-read: {s}", .{ consumed, @errorName(failure) });
                    return failure;
                };
                for (indices[0..consumed]) |index| if (self.live[index].status == .applied and self.confirmed[index]) {
                    self.status.confirmed += 1;
                };
                self.counters.install_batches += 1;
                self.counters.acknowledged_batches += 1;
                if (comptime build_options.diag) diag_mod.count(.acknowledged_batches, 1);
                return .progress;
            },
            .verified => |verified| {
                var snapshot = verified.snapshot;
                const after_ns = self.monotonic(self.monotonic_context);
                for (indices[0..consumed]) |index| self.markers[index] = null;
                {
                    errdefer snapshot.deinit();
                    try self.validateAndCaptureObservation(&snapshot, .effect, verified.observed_wall_us, .effect_verify);
                }
                self.keepInventory(snapshot, verified.observed_start_wall_us, verified.observed_wall_us, after_ns);
                try self.settleBatch(bindings, indices[0..consumed], dispatch_clock.prepared_us, verified.observed_wall_us, .desired, verified.snapshot.fingerprint);
                self.counters.install_batches += 1;
                if (!try self.evaluateInventory()) return self.deferReadback();
                return .progress;
            },
        }
    }
    const BatchState = enum { desired, mismatch };
    fn settleBatch(self: *Manager, bindings: []const Binding, indices: []const usize, dispatch_us: i64, observed_us: i64, state: BatchState, fingerprint: effect.Hash) !void {
        var items: [firewall.max_install_messages]durable.Store.InstallItem = undefined;
        for (indices, 0..) |index, k| {
            const entry = self.live[index];
            items[k] = .{ .token = entry.token(), .state = if (state == .desired) entry.desired else null };
        }
        const pre = self.store.effect_publication_epoch;
        {
            errdefer self.writeFailed(pre);
            _ = try self.store.settleInstalled(items[0..indices.len], dispatch_us, fingerprint, observed_us, try self.clock());
        }
        try self.attributeBatch(bindings, indices, pre);
    }
    fn attributeBatch(self: *Manager, bindings: []const Binding, indices: []const usize, pre: u64) !void {
        const post = self.store.effect_publication_epoch;
        const current = self.cached_epoch != null and self.cached_epoch.? == pre;
        self.cached_epoch = null;
        if (post == std.math.maxInt(u64)) return;
        if (post == pre) {
            std.log.warn("native: settlement of {d} effects changed no row at epoch {d}", .{ indices.len, pre });
            return error.InvalidEffect;
        }
        if (!current or post < pre or post - pre != 1 or self.staged_revision != null) return;
        try self.store.beginRead();
        errdefer self.store.rollback();
        const installation = try self.store.readInstallation() orelse return error.InstallationRequired;
        for (indices) |index| {
            const entry = try self.store.readEffect(self.live[index].scope_key, installation) orelse break;
            var owners: [effect.max_page]effect.Owner = undefined;
            const count = try self.store.readOwners(entry.scope_key, &owners);
            const owner_deadline = try self.ownerDeadline(bindings, owners[0..count]);
            try self.replaceAt(index, entry, owner_deadline);
        } else {
            try self.store.commitTransaction();
            if (self.store.effect_publication_epoch == post) self.cached_epoch = post;
            return;
        }
        try self.store.commitTransaction();
    }
    fn settleMarker(self: *Manager, bindings: []const Binding, index: usize) !Step {
        const marker = self.markers[index].?;
        self.markers[index] = null;
        if (!self.matched[index]) return .progress;
        const held = &self.inventory.?;
        const entry = self.live[index];
        try self.settle(bindings, index, entry, marker.sent_wall_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = entry.desired });
        return .progress;
    }
    fn settleLegacy(self: *Manager, bindings: []const Binding, index: usize) !Step {
        const held = &self.inventory.?;
        const entry = self.live[index];
        try self.settle(bindings, index, entry, held.start_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = if (self.matched[index]) entry.desired else null });
        return .progress;
    }
    fn settleLegacyTargets(self: *Manager, bindings: []const Binding) !?Step {
        if (self.store.schema_version < 21) return null;
        const key = try self.store.unsettledActionScope() orelse return null;
        if (self.legacy_targets_attempted) |prior| if (std.mem.eql(u8, &prior, &key)) return null;
        const index = self.findLive(key) orelse return null;
        const entry = self.live[index];
        if (entry.status != .applied or !self.matched[index]) return null;
        self.legacy_targets_attempted = key;
        const held = &self.inventory.?;
        try self.settle(bindings, index, entry, held.start_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = entry.desired });
        return .progress;
    }
    fn settleExpiredBatch(self: *Manager, tokens: []const effect.Token) !Step {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.expiry) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const held = &self.inventory.?;
        const pre = self.store.effect_publication_epoch;
        {
            errdefer self.writeFailed(pre);
            _ = try self.store.settleExpired(tokens, held.snapshot.fingerprint, held.end_us, try self.clock());
        }
        if (self.store.effect_publication_epoch == pre) {
            std.log.warn("native: expiry settlement of {d} effects changed no row at epoch {d}", .{ tokens.len, pre });
            return error.InvalidEffect;
        }
        if (self.events_subscribed) try self.forgetExpired(tokens);
        return .progress;
    }
    fn forgetExpired(self: *Manager, tokens: []const effect.Token) !void {
        const held = &self.inventory.?;
        for (self.live[0..self.count]) |entry| {
            if (entry.scope.canonical.subject.kind != .host) continue;
            for (tokens) |expired| if (std.mem.eql(u8, &expired.scope_key, &entry.scope_key)) {
                const host = firewall.legacyAddress(entry.scope.canonical) catch continue;
                _ = try held.snapshot.removeHost(.{ .address = host });
                break;
            };
        }
        self.inspector.retained_bytes = held.snapshot.entries.len * @sizeOf(firewall.Entry);
        _ = try self.recount();
    }
    fn applyAcknowledged(self: *Manager, indices: []const usize) !void {
        const held = &self.inventory.?;
        for (indices) |index| {
            const entry = self.live[index];
            const host = firewall.legacyAddress(entry.scope.canonical) catch return error.InvalidEffect;
            const remaining: ?u64 = switch (entry.desired) {
                .finite => |until| if (until > held.end_us) self.inspector.toKernelUs(@intCast(until - held.end_us)) / 1000 else 0,
                .permanent => null,
                .absent => return error.InvalidEffect,
            };
            if (try held.snapshot.upsertHost(.{ .address = host, .remaining_ms = remaining }) and entry.desired.live(held.end_us)) self.installed_live += 1;
            if (!self.confirmed[index] or !self.matched[index]) self.view_revision +%= 1;
            self.matched[index] = true;
            self.confirmed[index] = true;
        }
        self.inspector.retained_bytes = held.snapshot.entries.len * @sizeOf(firewall.Entry);
    }
    fn refreshSettled(self: *Manager, bindings: []const Binding, indices: []const usize) !void {
        var stale = false;
        for (indices) |index| stale = stale or self.live[index].status == .pending;
        if (!stale) return;
        try self.store.beginRead();
        errdefer self.store.rollback();
        const installation = try self.store.readInstallation() orelse return error.InstallationRequired;
        for (indices) |index| {
            if (self.live[index].status != .pending) continue;
            const entry = try self.store.readEffect(self.live[index].scope_key, installation) orelse continue;
            var owners: [effect.max_page]effect.Owner = undefined;
            const count = try self.store.readOwners(entry.scope_key, &owners);
            try self.replaceAt(index, entry, try self.ownerDeadline(bindings, owners[0..count]));
        }
        try self.store.commitTransaction();
    }
    fn tokenFingerprint(self: *Manager, indices: []const usize) effect.Hash {
        var digest = std.crypto.hash.sha2.Sha256.init(.{});
        digest.update(&self.installation.id);
        for (indices) |index| digest.update(&self.live[index].scope_key);
        var out: effect.Hash = undefined;
        digest.final(&out);
        return out;
    }
    fn drainEvents(self: *Manager) void {
        if (!self.events_subscribed or self.inventory == null or !self.admitted) return;
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.events) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        self.events_dirty = false;
        _ = self.inspector.drainEvents(.{ .context = self, .apply = applyKernelEvent }, 256) catch |failure| {
            if (failure == error.EventsLost) {
                self.counters.events_dropped += 1;
                if (comptime build_options.diag) diag_mod.count(.events_dropped, 1);
                if (comptime build_options.diag) diag_mod.event(.events_overflowed, .{ .value = self.counters.events_dropped });
            }
            self.loseEvents();
            return;
        };
        if (!self.events_dirty) return;
        const held = &self.inventory.?;
        self.validateInventory(&held.snapshot) catch {
            self.loseEvents();
            return;
        };
        _ = self.recount() catch {
            self.loseEvents();
            return;
        };
        self.status.ready = false;
        self.last_verified_ns = null;
        self.cursor = self.count;
    }
    fn discardEvents(self: *Manager) void {
        if (!self.events_subscribed) return;
        _ = self.inspector.drainEvents(.{ .context = self, .apply = ignoreKernelEvent }, 4096) catch {};
        self.last_generation = null;
    }
    fn rememberOwnPort(self: *Manager, port_id: u32) void {
        if (port_id == 0 or self.ownPort(port_id)) return;
        self.own_ports[self.own_port_cursor] = port_id;
        self.own_port_cursor = (self.own_port_cursor + 1) % @as(u8, self.own_ports.len);
    }
    fn ownPort(self: *const Manager, port_id: u32) bool {
        return port_id != 0 and std.mem.indexOfScalar(u32, &self.own_ports, port_id) != null;
    }
    fn loseEvents(self: *Manager) void {
        self.events_healthy = false;
        self.status.ready = false;
    }
    fn ignoreKernelEvent(_: *anyopaque, _: firewall.nft.Event) firewall.Error!void {}
    fn applyKernelEvent(ctx: *anyopaque, event: firewall.nft.Event) firewall.Error!void {
        const self: *Manager = @ptrCast(@alignCast(ctx));
        if (comptime build_options.diag) diag_mod.count(.events_received, 1);
        switch (event) {
            .generation => |generation| {
                if (self.last_generation) |last| if (generation.id != last +% 1) self.loseEvents();
                self.last_generation = generation.id;
            },
            .elements => |elements| {
                if (self.ownPort(elements.pid)) return;
                const held = &(self.inventory orelse return);
                const offset_ms = @divTrunc(self.wall(self.wall_context) - held.end_us, 1000);
                const delta = try self.inspector.applyEvent(&held.snapshot, elements, offset_ms) orelse return;
                const applied = delta.added + delta.replaced + delta.removed;
                self.counters.events_applied += applied;
                if (comptime build_options.diag) diag_mod.count(.events_applied, applied);
                if (delta.added != 0 or delta.removed != 0) self.events_dirty = true;
            },
            .other => {},
        }
    }
    fn dispatch(self: *Manager, bindings: []const Binding, index: usize, sampled: effect.Clock) !Step {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.dispatch) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        self.status.ready = false;
        var entry = self.live[index];
        if (entry.status != .pending) {
            const held = &(self.inventory orelse return self.readback(sampled));
            try self.settle(bindings, index, entry, held.start_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = null });
            if (self.cached_epoch == null) return .progress;
            entry = self.live[index];
            if (entry.status != .pending) return .progress;
        }
        const dispatch_clock = try self.clock();
        if (entry.desired == .finite and !entry.desired.live(dispatch_clock.prepared_us)) return .progress;
        const sent_ns = self.monotonic(self.monotonic_context);
        const prior_mutation_ns = self.last_mutation_ns;
        const prior_mutation_wall_us = self.last_mutation_wall_us;
        self.markers[index] = .{ .sent_ns = sent_ns, .sent_wall_us = dispatch_clock.prepared_us };
        self.last_mutation_ns = sent_ns;
        self.last_mutation_wall_us = dispatch_clock.prepared_us;
        const target = self.token(entry, entry.desired);
        const clock_sample = firewall.ClockSample{ .wall_us = dispatch_clock.prepared_us };
        const result = (if (self.inspector.installation.transport == .nftables and self.inventory != null)
            self.inspector.applyFromBaseline(target, clock_sample, &self.inventory.?.snapshot)
        else
            self.inspector.applyExact(target, clock_sample)) catch |failure| {
            if (failure == error.ExpiredIntent) {
                self.markers[index] = null;
                self.last_mutation_ns = prior_mutation_ns;
                self.last_mutation_wall_us = prior_mutation_wall_us;
                return .progress;
            }
            self.recordFirewallDirect(.effect_dispatch, failure);
            if (!transientReadback(failure)) return error.EffectBackendUncertain;
            self.markers[index] = null;
            self.last_mutation_ns = prior_mutation_ns;
            self.last_mutation_wall_us = prior_mutation_wall_us;
            return self.deferReadback();
        };
        switch (result) {
            .uncertain => |failure| {
                if (failure.cause == error.ExpiredIntent and failure.mutation == .not_started) {
                    self.markers[index] = null;
                    self.last_mutation_ns = prior_mutation_ns;
                    self.last_mutation_wall_us = prior_mutation_wall_us;
                    return .progress;
                }
                self.recordFirewallFailure(failure);
                if (failure.mutation == .not_started) {
                    self.markers[index] = null;
                    self.last_mutation_ns = prior_mutation_ns;
                    self.last_mutation_wall_us = prior_mutation_wall_us;
                }
                if (!transientReadback(failure.cause)) return error.EffectBackendUncertain;
                return self.deferReadback();
            },
            .verified => |verified| {
                var snapshot = verified.snapshot;
                const after_ns = self.monotonic(self.monotonic_context);
                self.markers[index] = null;
                if (!verified.changed) {
                    self.last_mutation_ns = prior_mutation_ns;
                    self.last_mutation_wall_us = prior_mutation_wall_us;
                    // Tool transports made a fresh pre-read in applyExact that may show an element expired since the held inventory; settle from it.
                    if (self.inspector.installation.transport == .nftables) {
                        if (self.inventory) |held| if (held.start_us < entry.intent_us) {
                            snapshot.deinit();
                            self.dropInventory();
                            return .progress;
                        };
                    }
                    if (self.inventory == null or self.inspector.installation.transport != .nftables) {
                        {
                            errdefer snapshot.deinit();
                            try self.validateAndCaptureObservation(&snapshot, .effect, verified.observed_wall_us, .effect_verify);
                        }
                        self.keepInventory(snapshot, verified.observed_start_wall_us, verified.observed_wall_us, sent_ns);
                        if (!try self.evaluateInventory()) return self.deferReadback();
                    } else snapshot.deinit();
                    const held = &self.inventory.?;
                    try self.settle(bindings, index, entry, held.start_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = entry.desired });
                    return .progress;
                }
                {
                    errdefer snapshot.deinit();
                    try self.validateAndCaptureObservation(&snapshot, .effect, verified.observed_wall_us, .effect_verify);
                }
                self.keepInventory(snapshot, verified.observed_start_wall_us, verified.observed_wall_us, after_ns);
                try self.settle(bindings, index, entry, dispatch_clock.prepared_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = self.inventory.?.snapshot.fingerprint, .observed_us = verified.observed_wall_us, .qualification = .complete_owned, .state = entry.desired });
                if (!try self.evaluateInventory()) return self.deferReadback();
                return .progress;
            },
        }
    }
    fn expire(self: *Manager, bindings: []const Binding, index: usize, sampled: effect.Clock) !Step {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.expiry) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        self.status.ready = false;
        const entry = self.live[index];
        const pre = self.store.effect_publication_epoch;
        var items: [durable.Store.max_expiry_batch]durable.Store.ExpiryItem = undefined;
        items[0] = .{ .key = entry.scope_key, .revision = entry.revision };
        var count: usize = 1;
        for (self.live[0..self.count], 0..) |other, i| {
            if (count == items.len) break;
            if (i == index or other.status == .dispatched or self.markers[i] != null or other.desired != .finite or other.desired.live(sampled.prepared_us)) continue;
            items[count] = .{ .key = other.scope_key, .revision = other.revision };
            count += 1;
        }
        if (count == 1) {
            {
                errdefer self.writeFailed(pre);
                _ = try self.store.prepareExpiry(entry.scope_key, entry.revision, sampled);
            }
            self.counters.expiry_batches += 1;
            self.counters.expiries_prepared += 1;
            return switch (try self.attributeCommit(bindings, index, pre)) {
                .changed => .progress,
                .unchanged => .{ .wait = self.waitDue() },
            };
        }
        const expired = blk: {
            errdefer self.writeFailed(pre);
            break :blk try self.store.prepareExpiries(items[0..count], sampled);
        };
        self.counters.expiry_batches += 1;
        self.counters.expiries_prepared += count;
        if (expired == 0 or self.store.effect_publication_epoch == pre) return .{ .wait = self.waitDue() };
        return .progress;
    }
    fn settle(self: *Manager, bindings: []const Binding, index: usize, entry: effect.Entry, dispatch_us: i64, observed: effect.Observation) !void {
        const pre = self.store.effect_publication_epoch;
        {
            errdefer self.writeFailed(pre);
            _ = try self.store.settleOutcome(entry.token(), dispatch_us, observed, try self.clock());
        }
        if (try self.attributeCommit(bindings, index, pre) == .unchanged) {
            std.log.warn("native: settlement of view index {d} changed no row at epoch {d}", .{ index, pre });
            return error.InvalidEffect;
        }
    }
    pub const StorageGate = enum { healthy, unhealthy };
    pub fn stopStep(self: *Manager, expected_repair_epoch: u64, gate: StorageGate) Step {
        if (gate != .healthy) return .{ .fatal = error.StorageUnhealthy };
        return self.stopStepInner(expected_repair_epoch, true) catch |failure| .{ .fatal = failure };
    }
    pub fn withdrawStep(self: *Manager, expected_repair_epoch: u64) Step {
        const result = self.stopStepInner(expected_repair_epoch, false) catch |failure| Step{ .fatal = failure };
        if (self.stopping or result == .idle) {
            self.withdrawn = true;
            self.status.ready = false;
            self.status.withdrawn = true;
            self.last_readback_ns = null;
            @memset(self.confirmed[0..self.count], false);
            self.view_revision +%= 1;
        }
        return result;
    }
    pub fn retireJail(self: *Manager, jail: []const u8, generation: [32]u8) Step {
        return self.retireJailInner(jail, generation) catch |failure| .{ .fatal = failure };
    }
    fn retireJailInner(self: *Manager, jail: []const u8, generation: [32]u8) !Step {
        errdefer |failure| {
            self.dropInventory();
            self.status.ready = false;
            self.status.uncertain = true;
            self.status.cause = failure;
        }
        if (self.withdrawn) return .idle;
        if (self.stopping or !self.admitted or self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch) return .progress;
        if (self.readback_wait != 0) return .{ .wait = self.waitDue() };
        const sampled = try self.clock();
        if (!self.inventoryCurrent()) return self.readback(sampled);
        var tokens: [firewall.max_withdraw_messages]firewall.DispatchToken = undefined;
        var batched: usize = 0;
        var budget: usize = 0;
        var in_flight = false;
        {
            var owners: [effect.max_page]effect.Owner = undefined;
            try self.store.beginRead();
            errdefer self.store.rollback();
            for (self.live[0..self.count], 0..) |entry, index| {
                if (entry.desired != .absent) continue;
                if (!try presentIn(&self.inventory.?, entry)) continue;
                const owner_count = try self.store.readOwners(entry.scope_key, &owners);
                for (owners[0..owner_count]) |owner| {
                    if (std.mem.eql(u8, owner.jail.slice(), jail) and std.mem.eql(u8, &owner.generation, &generation)) break;
                } else continue;
                if (entry.status == .dispatched or self.markers[index] != null) {
                    in_flight = true;
                    continue;
                }
                const cost = try firewall.withdrawCost(entry.scope.canonical);
                if (batched != 0 and budget + cost > firewall.max_withdraw_messages) break;
                tokens[batched] = self.token(entry, .absent);
                batched += 1;
                budget += cost;
                if (batched == tokens.len) break;
            }
            try self.store.commitTransaction();
        }
        if (batched == 0) return if (in_flight and !self.events_subscribed) .progress else .idle;
        self.status.ready = false;
        const sent_ns = self.monotonic(self.monotonic_context);
        const prior_mutation_ns = self.last_mutation_ns;
        const prior_mutation_wall_us = self.last_mutation_wall_us;
        self.last_mutation_ns = sent_ns;
        self.last_mutation_wall_us = sampled.prepared_us;
        const result = self.inspector.withdrawBatch(tokens[0..batched], .{ .wall_us = sampled.prepared_us }, &self.inventory.?.snapshot) catch |failure| {
            self.recordFirewallDirect(.effect_dispatch, failure);
            self.last_mutation_ns = prior_mutation_ns;
            self.last_mutation_wall_us = prior_mutation_wall_us;
            if (!transientReadback(failure)) return error.EffectBackendUncertain;
            return self.deferReadback();
        };
        switch (result) {
            .uncertain => |failure| {
                self.recordFirewallFailure(failure);
                if (failure.mutation == .not_started) {
                    self.last_mutation_ns = prior_mutation_ns;
                    self.last_mutation_wall_us = prior_mutation_wall_us;
                }
                if (!transientReadback(failure.cause)) return error.EffectBackendUncertain;
                return self.deferReadback();
            },
            .verified => |verified| {
                var snapshot = verified.snapshot;
                const after_ns = self.monotonic(self.monotonic_context);
                {
                    errdefer snapshot.deinit();
                    try self.validateAndCaptureObservation(&snapshot, .effect, verified.observed_wall_us, .effect_verify);
                }
                self.keepInventory(snapshot, verified.observed_start_wall_us, verified.observed_wall_us, after_ns);
                if (!try self.evaluateInventory()) return self.deferReadback();
                return .progress;
            },
        }
    }
    const max_stop_retries: u8 = 32;
    fn stopFailure(self: *Manager, cause: anyerror, fatal: anyerror) !Step {
        if (!transientCause(cause) or self.stop_retries >= max_stop_retries) return fatal;
        self.stop_retries += 1;
        self.dropInventory();
        return .{ .wait = self.waitDue() };
    }
    fn stopStepInner(self: *Manager, expected_repair_epoch: u64, require_ready: bool) !Step {
        if (expected_repair_epoch == 0 or expected_repair_epoch != self.repair_epoch) return error.StaleRepairEpoch;
        if (self.store.reopen_required) return error.ReopenRequired;
        if (!self.stopping) {
            if (!self.admitted or (require_ready and !self.status.ready) or self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch) return error.EffectReconciliationRequired;
            self.dropInventory();
            self.stopping = true;
            self.stop_cursor = 0;
            self.stop_retries = 0;
            self.status.ready = false;
        }
        errdefer |failure| {
            self.status.uncertain = true;
            self.status.cause = failure;
        }
        const sampled = try self.clock();
        while (self.stop_cursor < self.count) {
            var tokens: [firewall.max_withdraw_messages]firewall.DispatchToken = undefined;
            var batched: usize = 0;
            var budget: usize = 0;
            var next = self.stop_cursor;
            while (next < self.count and batched < tokens.len) : (next += 1) {
                const entry = self.live[next];
                if (entry.desired == .absent) continue;
                const cost = try firewall.withdrawCost(entry.scope.canonical);
                if (batched != 0 and budget + cost > firewall.max_withdraw_messages) break;
                tokens[batched] = self.token(entry, .absent);
                batched += 1;
                budget += cost;
            }
            if (batched == 0) {
                self.stop_cursor = next;
                continue;
            }
            if (self.inventory == null) {
                const start_ns = self.monotonic(self.monotonic_context);
                var snapshot = self.inspector.inspect() catch |failure| {
                    self.recordFirewallDirect(.readback, failure);
                    return self.stopFailure(failure, failure);
                };
                {
                    errdefer snapshot.deinit();
                    try self.validateAndCaptureObservation(&snapshot, .stop, sampled.prepared_us, .readback);
                }
                self.keepInventory(snapshot, sampled.prepared_us, (try self.clock()).prepared_us, start_ns);
            }
            const result = self.inspector.withdrawBatch(tokens[0..batched], .{ .wall_us = sampled.prepared_us }, &self.inventory.?.snapshot) catch |failure| {
                self.recordFirewallDirect(.effect_dispatch, failure);
                return self.stopFailure(failure, failure);
            };
            switch (result) {
                .uncertain => |failure| {
                    self.recordFirewallFailure(failure);
                    return self.stopFailure(failure.cause, error.EffectBackendUncertain);
                },
                .verified => |verified| {
                    var snapshot = verified.snapshot;
                    {
                        errdefer snapshot.deinit();
                        try self.validateAndCaptureObservation(&snapshot, .stop, verified.observed_wall_us, .effect_verify);
                    }
                    self.keepInventory(snapshot, verified.observed_start_wall_us, verified.observed_wall_us, self.monotonic(self.monotonic_context));
                },
            }
            self.stop_cursor = next;
            return .progress;
        }
        var final = self.inspector.inspect() catch |failure| {
            self.recordFirewallDirect(.readback, failure);
            return self.stopFailure(failure, failure);
        };
        defer final.deinit();
        try self.validateAndCaptureObservation(&final, .stop, sampled.prepared_us, .readback);
        if (final.entries.len != 0) {
            self.recordObservationFailure(.readback, error.UnownedInstalledEffect);
            return error.UnownedInstalledEffect;
        }
        self.dropInventory();
        self.stopping = false;
        self.stop_cursor = 0;
        self.stop_retries = 0;
        self.admitted = false;
        self.cached_epoch = null;
        self.count = 0;
        self.view_revision +%= 1;
        self.status = .{};
        return .idle;
    }
    fn withdrawnReadback(self: *Manager) !Step {
        const start_ns = self.monotonic(self.monotonic_context);
        if (self.last_readback_ns) |last| if (start_ns) |now| if (now -| last < self.verify_interval_ns) return .idle;
        const sampled = try self.clock();
        var snapshot = self.inspector.inspect() catch |failure| {
            self.recordFirewallDirect(.readback, failure);
            if (transientReadback(failure)) return self.deferReadback();
            return propagateFirewall(Step, failure);
        };
        defer snapshot.deinit();
        if (snapshot.state != .owned) return error.InstallationMismatch;
        self.captureObservation(&snapshot, .readback, sampled.prepared_us, .not_checked);
        self.readback_failures = 0;
        self.counters.full_readbacks += 1;
        self.last_readback_ns = start_ns;
        self.last_readback_wall_us = (try self.clock()).prepared_us;
        self.installed_live = std.math.cast(u32, snapshot.entries.len) orelse return error.LimitExceeded;
        self.status.ready = false;
        self.status.withdrawn = true;
        if (self.status.diagnostic) |diagnostic| if (transientReadback(diagnostic.cause)) {
            self.status.diagnostic = null;
            self.status.cause = null;
            self.status.uncertain = false;
        };
        return .idle;
    }
    pub const Residual = struct {
        installed: ?usize,
        cause: ?anyerror = null,
    };
    pub fn residualInstalled(self: *Manager) Residual {
        var snapshot = self.inspector.inspect() catch |failure| {
            self.recordFirewallDirect(.readback, failure);
            return .{ .installed = null, .cause = failure };
        };
        defer snapshot.deinit();
        if (snapshot.state != .owned) return .{ .installed = null, .cause = error.InstallationMismatch };
        return .{ .installed = snapshot.entries.len };
    }
    pub fn expireDuringOutage(self: *Manager) !void {
        self.status.ready = false;
        errdefer |failure| {
            self.status.uncertain = true;
            self.status.cause = failure;
        }
        const clock_sample = try self.clock();
        self.status.overdue = 0;
        for (self.live[0..self.count]) |entry| if (entry.desired == .finite and !entry.desired.live(clock_sample.prepared_us)) {
            self.status.overdue += 1;
        };
        if (self.store.reopen_required or !self.admitted or self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch or self.store.effect_publication_epoch == std.math.maxInt(u64)) return;
        for (self.live[0..self.count], 0..) |entry, i| {
            if (entry.desired != .finite or entry.desired.live(clock_sample.prepared_us) or self.outage_attempted[i]) continue;
            self.outage_attempted[i] = true;
            self.status.uncertain = true;
            self.dropInventory();
            var result = self.inspector.applyExact(self.token(entry, .absent), .{ .wall_us = clock_sample.prepared_us }) catch |failure| {
                self.recordFirewallDirect(.effect_dispatch, failure);
                return propagateFirewall(void, failure);
            };
            defer result.deinit();
            switch (result) {
                .uncertain => |failure| self.recordFirewallFailure(failure),
                .verified => |*observed| self.captureObservation(&observed.snapshot, .outage, observed.observed_wall_us, .not_checked),
            }
            return;
        }
    }
};

pub fn transportInstallation(value: effect.Installation) firewall.Installation {
    return .{ .id = value.id, .transport = switch (value.backend) {
        .nftables => .nftables,
        .iptables => .iptables,
        .ipset => .ipset,
    } };
}
pub fn address(scope: effect.Scope) shared.IpAddress {
    return switch (scope.canonical.subject.family) {
        .v4 => .{ .ipv4 = std.mem.readInt(u32, scope.canonical.subject.address[0..4], .big) },
        .v6 => .{ .ipv6 = std.mem.readInt(u128, &scope.canonical.subject.address, .big) },
    };
}
