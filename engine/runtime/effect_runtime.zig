// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Holds the effect Manager's state and sequences its phases: admission, the step and slice loop, the act step and selection.
// Holds: Health turns ready only in select, from a current inventory where every live effect is confirmed and none is pending or due.

const std = @import("std");
const shared = @import("shared");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const durable = @import("../store/store.zig");
const effect = @import("../effect/effect.zig");
const firewall = @import("../firewall/inspection.zig");
pub const observation = @import("firewall_observation.zig");

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
pub fn propagateFirewall(comptime T: type, cause: firewall.Error) firewall.Error!T {
    return cause;
}
pub fn transientReadback(cause: anyerror) bool {
    return cause == error.Changed or cause == error.DumpInterrupted or cause == error.Timeout or cause == error.Incomplete;
}
pub fn transientCause(cause: anyerror) bool {
    return transientReadback(cause);
}
const max_readback_wait_turns: u16 = 255;
// Why: With events subscribed, an audit starts this long before the verify interval ends, so a dump at the ceiling finishes inside it.
pub const audit_lead_ns: u64 = 5 * std.time.ns_per_s;
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
pub const Marker = struct { sent_ns: ?u64, sent_wall_us: i64 };
const ExpiryClass = enum { kernel_expiring, deletion };
pub fn expiryClass(transport: firewall.Transport, scope: effect.Scope) ExpiryClass {
    const host = scope.canonical.subject.kind == .host and scope.canonical.protocols.isAll() and scope.canonical.ports.isAll();
    return if (host and transport != .iptables) .kernel_expiring else .deletion;
}
pub const live_bytes = @sizeOf(Manager) + effect.max_effects * (2 * @sizeOf(effect.Entry) + @sizeOf(bool) + 2 * (@sizeOf(?Marker) + 2 * @sizeOf(bool) + @sizeOf(?i64)));
pub const reserved_bytes = live_bytes + (firewall.Limits{}).max_bytes;
pub const JailRetirementWithdrawalCursor = struct { after: ?effect.Hash = null, revisit: ?effect.Hash = null, inventory_epoch: ?u64 = null };
pub const JailRetirementWithdrawalResult = union(enum) { step: Step, verified: durable.Store.JailRetirementFinishProof };
pub const ViewAuthority = enum { none, runtime, retirement_observation };
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
    view_authority: ViewAuthority = .none,
    staged_authority: ViewAuthority = .none,
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
    inventory_discontinuity: u64 = 0,
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
    pub fn forgetKernel(self: *Manager) void {
        self.dropInventory();
        @memset(self.markers[0..self.count], null);
        @memset(self.confirmed[0..self.count], false);
        @memset(self.matched[0..self.count], false);
        self.legacy_targets_attempted = null;
        self.view_revision +%= 1;
    }
    pub fn storageReopened(self: *Manager) void {
        self.discardViewAuthority();
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
    pub fn confirmedKey(self: *const Manager, key: [32]u8, now_us: i64) bool {
        const index = self.findLive(key) orelse return false;
        return self.live[index].status == .applied and self.live[index].desired.live(now_us) and (self.confirmed[index] or self.status.ready);
    }
    pub fn appliedKey(self: *const Manager, key: [32]u8, now_us: i64) bool {
        const index = self.findLive(key) orelse return false;
        return self.live[index].status == .applied and self.live[index].desired.live(now_us);
    }
    pub fn recordFirewallFailure(self: *Manager, context: firewall.FailureContext) void {
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
    pub fn recordFirewallDirect(self: *Manager, stage: firewall.OperationStage, cause: firewall.Error) void {
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
    pub fn recordObservationFailure(self: *Manager, stage: firewall.OperationStage, cause: anyerror) void {
        const cache = self.observation_cache orelse return;
        cache.fail(.{
            .monotonic_ms = observation.monotonicMs(),
            .wall_us = self.observationWall(),
            .cause = cause,
            .stage = stage,
        });
    }
    pub fn captureObservation(self: *Manager, snapshot: *const firewall.Snapshot, origin: observation.Origin, wall_us: ?i64, inventory: observation.Inventory) void {
        const cache = self.observation_cache orelse return;
        cache.capture(snapshot, .{
            .monotonic_ms = observation.monotonicMs(),
            .wall_us = wall_us,
            .origin = origin,
            .inventory = inventory,
        });
    }
    pub fn validateAndCaptureObservation(self: *Manager, snapshot: *const firewall.Snapshot, origin: observation.Origin, wall_us: ?i64, stage: firewall.OperationStage) !void {
        self.validateInventory(snapshot) catch |failure| {
            self.captureObservation(snapshot, origin, wall_us, if (failure == error.UnownedInstalledEffect) .unexpected_entries else .not_checked);
            self.recordObservationFailure(stage, failure);
            return failure;
        };
        self.captureObservation(snapshot, origin, wall_us, .known_entries);
    }
    pub fn deferReadback(self: *Manager) Step {
        self.dropInventory();
        self.events_healthy = false;
        self.status.ready = false;
        self.backOff();
        return .{ .wait = self.waitDue() };
    }
    pub fn backOff(self: *Manager) void {
        self.readback_failures +|= 1;
        if (comptime build_options.diag) diag_mod.event(.readback_deferred, .{ .value = self.readback_failures });
        const shift: u4 = @intCast(@min(self.readback_failures - 1, 8));
        self.readback_wait = @min((@as(u16, 1) << shift) - 1, max_readback_wait_turns);
    }
    pub fn setClockRate(self: *Manager, rate: u32) void {
        self.inspector.clock_rate = rate;
    }
    pub fn clock(self: *Manager) !effect.Clock {
        const now = self.wall(self.wall_context);
        if (now < self.last_wall_us) return error.EffectClockReversed;
        self.last_wall_us = now;
        return .{ .prepared_us = now, .context = self.wall_context, .read = self.wall };
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
    pub fn token(self: *Manager, entry: effect.Entry, lease: effect.Lease) firewall.DispatchToken {
        return .{ .installation = self.inspector.installation, .effect_id = entry.scope_key, .aggregate_revision = entry.revision, .scope = entry.scope.canonical, .operation = switch (lease) {
            .absent => .ensure_absent,
            .finite => |deadline| .{ .ensure_present = .{ .finite_deadline_us = deadline } },
            .permanent => .{ .ensure_present = .permanent },
        } };
    }
    pub fn presentIn(held: *const Inventory, entry: effect.Entry) !bool {
        const found = try held.snapshot.find(entry.scope.canonical) orelse return false;
        const installed = held.snapshot.entries[found];
        return installed.scope == null or (installed.effect_id != null and std.mem.eql(u8, &installed.effect_id.?, &entry.scope_key));
    }
    pub fn waitDue(self: *Manager) u64 {
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
            // Why: Without a monotonic reading the time budget cannot be enforced, so the slice ends after this step.
            if (start == null or after == null) break;
            slice.elapsed_ns = after.? -| start.?;
            if (slice.outcome != .progress or slice.elapsed_ns >= limits.max_ns) break;
        }
        return slice;
    }
    fn stepInner(self: *Manager, bindings: []const Binding) !Step {
        if (self.view_authority == .retirement_observation or self.staged_authority == .retirement_observation) self.discardViewAuthority();
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
            _ = try self.refreshTurn(bindings, .runtime);
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
        var settle_ready: u64 = 0;
        var settle_blocked: u64 = 0;
        var oldest_overdue_us: ?i64 = null;
        var blocking: u64 = 0;
        var oldest_blocking_us: ?i64 = null;
        var bookkeeping: u64 = 0;
        var next_deadline: ?i64 = null;
        var all_confirmed = true;
        const transport = self.inspector.installation.transport;
        var install_indices: [firewall.max_install_messages]usize = undefined;
        var stale_indices: [firewall.max_install_messages]usize = undefined;
        var install_count: usize = 0;
        var stale_count: usize = 0;
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
            if (self.expiryDeadline(index, entry)) |deadline| {
                next_deadline = if (next_deadline) |prior| @min(prior, deadline) else deadline;
            }
            const matched = self.matched[index];
            if (self.expiryDue(index, entry, now_us)) {
                due_count += 1;
                const deadline = self.expiryDeadline(index, entry).?;
                oldest_overdue_us = if (oldest_overdue_us) |prior| @min(prior, deadline) else deadline;
                if (!entry.desired.live(now_us) and expiryClass(transport, entry.scope) == .deletion and try presentIn(held, entry)) {
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
                    // Why: The store refuses an outcome dated before its intent, so an inventory read before the removal cannot settle it.
                    if (held.start_us < entry.intent_us) {
                        settle_blocked += 1;
                        continue;
                    }
                    if (settle_count < settle_tokens.len) {
                        settle_tokens[settle_count] = entry.token();
                        settle_count += 1;
                    }
                    settle_ready += 1;
                    continue;
                }
                // Why: A kernel-expiring element read before its removal was prepared may be timing out; only a later readback shows drift.
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
                if (install_count < install_indices.len and
                    (entry.desired != .finite or entry.desired.live(now_us)) and
                    firewall.batchable(entry.scope.canonical))
                {
                    if (entry.status != .pending) {
                        stale_indices[stale_count] = index;
                        stale_count += 1;
                    }
                    install_indices[install_count] = index;
                    install_count += 1;
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
        if (comptime build_options.diag) {
            diag_mod.gauge(.expiry_due, due_count);
            diag_mod.gauge(.expiry_removal_pending, removal_pending);
            diag_mod.gauge(.expiry_settle_ready, settle_ready);
            diag_mod.gauge(.expiry_readback_blocked, settle_blocked);
            diag_mod.gauge(.live_pending, live_pending);
        }
        if (marker_pick) |index| return self.settleMarker(bindings, index);
        if (legacy_pick) |index| return self.settleLegacy(bindings, index, sampled);
        const expiry_backlog = removal_pending + due_count + settle_ready + settle_blocked;
        const expiry_work = expiry_backlog != 0;
        const share: u8 = if (expiry_backlog > live_pending) 1 else expiry_share;
        if (live_pick == null) self.live_selections = 0;
        if (expiry_work and (live_pick == null or self.live_selections >= share)) {
            self.status.ready = false;
            if (settle_count != 0) {
                self.live_selections = 0;
                if (comptime build_options.diag) diag_mod.count(.expiry_settle_selected, 1);
                return self.settleExpiredBatch(settle_tokens[0..settle_count]);
            }
            if (removal_pick) |index| {
                self.live_selections = 0;
                if (comptime build_options.diag) diag_mod.count(.expiry_remove_selected, 1);
                self.cursor = index;
                return .progress;
            }
            if (settle_blocked != 0) {
                if (comptime build_options.diag) diag_mod.count(.expiry_readback_selected, 1);
                return self.readback(sampled);
            }
            if (comptime build_options.diag) diag_mod.count(.expiry_prepare_selected, 1);
            self.cursor = due_pick.?;
            return .progress;
        }
        if (live_pick) |index| {
            self.live_selections +|= 1;
            self.status.ready = false;
            if (live_pending > 1) if (try self.installPending(bindings, sampled, install_indices[0..install_count], stale_indices[0..stale_count])) |outcome| return outcome;
            self.cursor = index;
            return .progress;
        }
        if (try self.settleLegacyTargets(bindings, sampled)) |outcome| return outcome;
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

    pub usingnamespace @import("effect_view.zig").Methods(@This());

    pub usingnamespace @import("effect_inventory.zig").Methods(@This());

    pub usingnamespace @import("effect_retirement.zig").Methods(@This());

    pub usingnamespace @import("effect_expiry.zig").Methods(@This());

    pub usingnamespace @import("effect_dispatch.zig").Methods(@This());

    pub usingnamespace @import("effect_settlement.zig").Methods(@This());

    pub usingnamespace @import("effect_stop.zig").Methods(@This());

    pub usingnamespace @import("effect_events.zig").Methods(@This());
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
