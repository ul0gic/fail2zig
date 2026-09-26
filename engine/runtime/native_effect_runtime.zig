// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const builtin = @import("builtin");
const shared = @import("shared");
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
    cause: ?anyerror = null,
    diagnostic: ?EffectDiagnostic = null,
};
fn propagateFirewall(comptime T: type, cause: firewall.Error) firewall.Error!T {
    return cause;
}
/// A readback or mutation can fail without any fault of ours: a kernel element
/// timeout between two tool passes, an interrupted netlink dump, a batch the kernel
/// rejected against a stale baseline, or a slow backend. Such outcomes leave
/// enforcement uncertain until the next accepted readback and are retried; they are
/// never storage or gate failures.
fn transientReadback(cause: anyerror) bool {
    return cause == error.Changed or cause == error.DumpInterrupted or cause == error.Timeout or cause == error.Incomplete;
}
pub fn transientCause(cause: anyerror) bool {
    return transientReadback(cause);
}
const max_readback_wait_turns: u16 = 255;
fn systemWall(_: ?*anyopaque) i64 {
    return std.time.microTimestamp();
}
fn systemMonotonic(_: ?*anyopaque) ?u64 {
    const ts = std.posix.clock_gettime(.MONOTONIC) catch return null;
    const seconds = std.math.cast(u64, ts.sec) orelse return null;
    const nanos = std.math.cast(u64, ts.nsec) orelse return null;
    return std.math.add(u64, std.math.mul(u64, seconds, std.time.ns_per_s) catch return null, nanos) catch null;
}
/// Outcome of one reconciliation step; errors are reported as `fatal`.
pub const Step = union(enum) {
    /// Work was loaded, committed or verified; another step may follow now.
    progress,
    /// Nothing more is useful before this monotonic instant in nanoseconds.
    wait: u64,
    /// The view is confirmed and nothing is divergent.
    idle,
    /// The caller requested stop between steps.
    stop,
    fatal: anyerror,
};
pub const SliceLimits = struct {
    max_steps: u16 = 32,
    max_ns: u64 = 50 * std.time.ns_per_ms,
};
/// Checked between steps; must not block.
pub const StopSignal = struct {
    context: ?*anyopaque = null,
    requested: *const fn (?*anyopaque) bool,
};
pub const Counters = struct {
    rebuilds_completed: u64 = 0,
    /// Staged rebuilds discarded because the publication epoch moved mid-rebuild.
    rebuild_restarts: u64 = 0,
    incremental_updates: u64 = 0,
    /// Complete readbacks accepted as the inventory.
    full_readbacks: u64 = 0,
    /// Batched expiry preparation: commits and scopes they carried.
    expiry_batches: u64 = 0,
    expiries_prepared: u64 = 0,
    /// Entries past their deadline still awaiting expiry bookkeeping at the last selection.
    overdue_expiries: u64 = 0,
    /// Live entries awaiting dispatch at the last selection, and the oldest intent among them.
    pending: u64 = 0,
    oldest_pending_us: ?i64 = null,
    /// Removals and expiry bookkeeping outstanding at the last selection, and the oldest
    /// deadline among them (a prepared removal counts from its preparation).
    overdue: u64 = 0,
    oldest_overdue_us: ?i64 = null,
    /// The overdue split by what the entry still does: a deletion-class rule past its
    /// deadline that the inventory shows installed still blocks traffic; everything else
    /// overdue is bookkeeping (kernel-expiring elements, and rules already gone).
    overdue_blocking: u64 = 0,
    oldest_overdue_blocking_us: ?i64 = null,
    overdue_bookkeeping: u64 = 0,
    /// Interrupted kernel dumps seen by the inspector, immediate retries included.
    dump_interrupted: u64 = 0,
};
pub const Slice = struct {
    /// The outcome that ended the slice; `progress` means the budget ran out.
    outcome: Step,
    steps: u16 = 0,
    elapsed_ns: u64 = 0,
    longest_step_ns: u64 = 0,
};
/// The most recent accepted readback, with the wall interval it was observed in and
/// the monotonic instant it started, which orders it against our own sends.
const Inventory = struct { snapshot: firewall.Snapshot, start_us: i64, end_us: i64, start_ns: ?u64 };
/// An attempt whose outcome the kernel has not yet shown us. It settles at the first
/// readback that started after the send; losing it is safe because the durable intent
/// stays `pending` and a repeated dispatch is idempotent.
const Marker = struct { sent_ns: ?u64, sent_wall_us: i64 };
/// How an entry leaves the kernel at its deadline: a set element with a timeout goes
/// on its own and only needs bookkeeping; a rule outlives its deadline until deleted.
const ExpiryClass = enum { kernel_expiring, deletion };
fn expiryClass(transport: firewall.Transport, scope: effect.Scope) ExpiryClass {
    const host = scope.canonical.subject.kind == .host and scope.canonical.protocols.isAll() and scope.canonical.ports.isAll();
    return if (host and transport != .iptables) .kernel_expiring else .deletion;
}
pub const reserved_bytes = @sizeOf(Manager) + effect.max_effects * (2 * @sizeOf(effect.Entry) + @sizeOf(bool) + 2 * (@sizeOf(?Marker) + 2 * @sizeOf(bool) + @sizeOf(?i64))) + (firewall.Limits{}).max_bytes;
pub const Manager = struct {
    allocator: std.mem.Allocator,
    store: *durable.Store,
    inspector: firewall.Inspector,
    installation: effect.Installation,
    live: []effect.Entry,
    staged: []effect.Entry,
    outage_attempted: []bool,
    /// Per-entry state parallel to `live`, carried across a rebuild by scope and intent.
    markers: []?Marker,
    staged_markers: []?Marker,
    /// The entry matched the last accepted readback.
    confirmed: []bool,
    staged_confirmed: []bool,
    /// The entry's desired state holds in the held inventory.
    matched: []bool,
    staged_matched: []bool,
    /// Earliest finite co-owner deadline; a permanent scope owes its bookkeeping then.
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
    /// Period of the outer wake that counts readback backoff down; used only to
    /// report when a wait is due.
    wake_interval_ns: u64 = 100 * std.time.ns_per_ms,
    status: Health = .{},
    admitted: bool = false,
    repair_epoch: u64 = 1,
    stop_cursor: usize = 0,
    stopping: bool = false,
    observation_cache: ?*observation.Cache = null,
    readback_failures: u8 = 0,
    readback_wait: u16 = 0,
    /// Bounded diagnostics for the daemon's periodic view-progress log line.
    counters: Counters = .{},
    /// Monotonic time of the last selection that confirmed the whole set.
    last_verified_ns: ?u64 = null,
    /// Earliest finite deadline in the view; expiry work is due once it passes.
    next_deadline_us: ?i64 = null,
    /// A confirmed, unchanged view is re-read from the kernel at this cadence, which
    /// bounds detection of external drift; storage changes invalidate it immediately.
    /// Zero verifies on every wake, the Manager's default contract; the daemon sets the
    /// bounded interval it publishes.
    verify_interval_ns: u64 = 0,
    /// Live dispatches since expiry work was last served.
    live_selections: u8 = 0,
    /// The last accepted readback. Selection, confirmation and readiness read it; a
    /// newer accepted readback replaces it, and it is dropped when it can no longer
    /// describe the kernel or the view it was validated against.
    inventory: ?Inventory = null,
    /// The most recent send of our own; a readback proves anything about the kernel
    /// only if it started after it.
    last_mutation_ns: ?u64 = null,
    last_mutation_wall_us: ?i64 = null,
    /// Desired-live entries present in the last accepted readback.
    installed_live: u32 = 0,
    last_readback_ns: ?u64 = null,
    last_readback_wall_us: ?i64 = null,
    /// Scope whose older-release action targets were re-settled once for this view.
    legacy_targets_attempted: ?[32]u8 = null,
    owned_marks: std.StaticBitSet(firewall.max_inventory_entries) = undefined,
    /// Makes accepted readbacks confirm nothing, so a persistently unconfirmable
    /// kernel view can be exercised without a backend fault.
    test_readback_disagrees: if (builtin.is_test) bool else void = if (builtin.is_test) false else {},

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
    /// The caller retains ownership and must keep the cache alive until after
    /// the worker stops using this Manager.
    pub fn attachObservationCache(self: *Manager, cache: *observation.Cache) void {
        self.observation_cache = cache;
    }
    /// Kernel knowledge does not survive a storage reopen or repair: the next readback
    /// starts from nothing and every pending intent is re-dispatched idempotently.
    fn forgetKernel(self: *Manager) void {
        self.dropInventory();
        @memset(self.markers[0..self.count], null);
        @memset(self.confirmed[0..self.count], false);
        @memset(self.matched[0..self.count], false);
        self.legacy_targets_attempted = null;
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
    /// A subject is confirmed when its live decision matched the last accepted readback.
    /// Neither whole-set readiness nor a fresh readback is required: knowledge is carried
    /// while stale, so a transient readback failure does not revoke it. A manager made
    /// uncertain by any other cause vouches for nothing until its next accepted readback.
    pub fn confirmedSubject(self: *const Manager, subject: @import("../core/native_detection_record.zig").Subject, now_us: i64) bool {
        if (self.status.uncertain and !(self.status.cause != null and transientCause(self.status.cause.?))) return false;
        const scope = effect.Scope.host(subject) catch return false;
        for (self.live[0..self.count], 0..) |entry, index| if (std.meta.eql(entry.scope, scope)) {
            return entry.status == .applied and entry.desired.live(now_us) and (self.confirmed[index] or self.status.ready);
        };
        return false;
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
    fn observationWall() ?i64 {
        const now = std.time.microTimestamp();
        return if (now < 0) null else now;
    }
    fn recordObservationFailure(self: *Manager, stage: firewall.OperationStage, cause: anyerror) void {
        const cache = self.observation_cache orelse return;
        cache.fail(.{
            .monotonic_ms = observation.monotonicMs(),
            .wall_us = observationWall(),
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
    /// The first retry follows on the next wake so a single race costs one wake;
    /// consecutive failures double the skipped wakes up to the cap.
    fn deferReadback(self: *Manager) Step {
        self.dropInventory();
        self.status.ready = false;
        self.readback_failures +|= 1;
        const shift: u4 = @intCast(@min(self.readback_failures - 1, 8));
        self.readback_wait = @min((@as(u16, 1) << shift) - 1, max_readback_wait_turns);
        return .{ .wait = self.waitDue(null) };
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
                self.captureObservation(&installed.snapshot, .admission, observationWall(), .not_checked);
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
        // An attempt or confirmation belongs to one intent of one scope; the rebuilt
        // view keeps it exactly where that intent is still current.
        for (self.staged[0..self.staged_count], 0..) |entry, index| {
            const carried = self.findLive(entry.scope_key);
            const same = carried != null and std.mem.eql(u8, &self.live[carried.?].intent_id, &entry.intent_id);
            self.staged_markers[index] = if (same) self.markers[carried.?] else null;
            self.staged_confirmed[index] = same and self.confirmed[carried.?];
            self.staged_matched[index] = false;
        }
        // The rebuilt view may own a different set of entries than the held
        // inventory was validated against.
        self.dropInventory();
        std.mem.swap([]effect.Entry, &self.live, &self.staged);
        std.mem.swap([]?Marker, &self.markers, &self.staged_markers);
        std.mem.swap([]bool, &self.confirmed, &self.staged_confirmed);
        std.mem.swap([]bool, &self.matched, &self.staged_matched);
        std.mem.swap([]?i64, &self.owner_deadline_us, &self.staged_owner_deadline_us);
        self.count = self.staged_count;
        self.cached_epoch = self.staged_epoch;
        self.staged_revision = null;
        self.cursor = self.count;
        self.legacy_targets_attempted = null;
        @memset(self.outage_attempted, false);
        return true;
    }
    /// Folds attributed single-scope commits since `cached_epoch` into the view in
    /// place, keeping scope-key order. Null means an epoch is unknown or touched more
    /// than one scope, so the caller rebuilds the whole view instead. The held
    /// inventory survives: it describes the kernel, which these commits did not touch.
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
    /// A replaced intent starts over: a marker or confirmation of the previous intent
    /// says nothing about the new desired state.
    fn replaceAt(self: *Manager, index: usize, entry: effect.Entry, owner_deadline: ?i64) !void {
        const previous = self.live[index];
        self.live[index] = entry;
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
    /// Checks every owner against the configured jails and returns the earliest finite
    /// owner deadline, the instant a permanent scope owes co-owner bookkeeping.
    fn validateOwners(self: *Manager, bindings: []const Binding, entry: effect.Entry) !?i64 {
        var owners: [effect.max_page]effect.Owner = undefined;
        const count = try self.store.effectOwners(entry.scope_key, entry.revision, &owners);
        var deadline: ?i64 = null;
        for (owners[0..count]) |owner| {
            for (bindings) |binding| {
                if (!std.mem.eql(u8, binding.jail, owner.jail.slice())) continue;
                if (!std.mem.eql(u8, &binding.generation, &owner.generation)) return error.EffectGenerationMismatch;
                break;
            } else return error.UnconfiguredStateOwner;
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
    /// Folds the manager's own committed write to `live[index]` into the cached view.
    /// Only a write that found the view current and alone advanced the epoch by one
    /// is applied in place, after rereading that scope and its owners and checking
    /// the epoch again. A no-op, saturation or any other writer's change leaves the
    /// view uncached so the next step rebuilds it from storage.
    fn attributeCommit(self: *Manager, bindings: []const Binding, index: usize, pre: u64) !Commit {
        const post = self.store.effect_publication_epoch;
        // A saturated epoch cannot show whether anything committed.
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
    /// A write that failed after COMMIT may have committed; the store then requires a
    /// reopen. A clean rollback leaves storage, and so the cached view, unchanged.
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
    /// Every installed entry needs a desired entry with its exact canonical scope that,
    /// when the installed entry is scoped, also carries its effect identity.
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
        // Charged against the inspector's byte limit while held across later reads.
        self.inspector.retained_bytes = snapshot.entries.len * @sizeOf(firewall.Entry);
    }
    fn dropInventory(self: *Manager) void {
        if (self.inventory) |*held| held.snapshot.deinit();
        self.inventory = null;
        self.inspector.retained_bytes = 0;
    }
    /// True when the held inventory started after our most recent send, so it shows
    /// that send's outcome. Monotonic order when both instants have it, wall order
    /// otherwise; the manager's wall clock never runs backwards.
    fn inventoryCurrent(self: *const Manager) bool {
        const held = self.inventory orelse return false;
        const sent_wall = self.last_mutation_wall_us orelse return true;
        if (held.start_ns) |start| if (self.last_mutation_ns) |sent| return start > sent;
        return held.start_us > sent_wall;
    }
    /// Whether the entry's scope is installed in the held inventory, by ownership rather
    /// than by match: a rule past its deadline no longer matches but still blocks.
    fn presentIn(held: *const Inventory, entry: effect.Entry) !bool {
        const found = try held.snapshot.find(entry.scope.canonical) orelse return false;
        const installed = held.snapshot.entries[found];
        return installed.scope == null or (installed.effect_id != null and std.mem.eql(u8, &installed.effect_id.?, &entry.scope_key));
    }
    fn disagrees(self: *const Manager) bool {
        return if (comptime builtin.is_test) self.test_readback_disagrees else false;
    }
    /// Re-judges one entry against the held inventory after the entry or the
    /// inventory changed. A transient judgement failure drops the inventory.
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
        self.confirmed[index] = matched and !self.disagrees();
    }
    /// Judges every entry against a newly held inventory and publishes what it shows:
    /// installed live entries, confirmed decisions, the readback instant, and the end of
    /// any transient uncertainty. False means a transient judgement failure dropped it.
    fn evaluateInventory(self: *Manager) !bool {
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
        const held = &(self.inventory orelse return false);
        self.readback_failures = 0;
        self.counters.full_readbacks += 1;
        self.counters.dump_interrupted = self.inspector.dump_interruptions;
        self.last_readback_ns = held.start_ns;
        self.last_readback_wall_us = held.end_us;
        self.installed_live = installed;
        self.status.confirmed = confirmed_count;
        if (self.status.diagnostic) |diagnostic| if (transientReadback(diagnostic.cause)) {
            self.status.diagnostic = null;
            self.status.cause = null;
            self.status.uncertain = false;
        };
        return true;
    }
    fn waitDue(self: *Manager, now_ns: ?u64) u64 {
        const base = now_ns orelse self.monotonic(self.monotonic_context) orelse 0;
        return base +| self.wake_interval_ns *| self.readback_wait;
    }
    /// Runs one bounded reconciliation step. It never consumes readback backoff;
    /// only `runSlice`, called once per outer wake, counts it down.
    pub fn step(self: *Manager, bindings: []const Binding) Step {
        return self.stepInner(bindings) catch |failure| .{ .fatal = failure };
    }
    /// Runs steps for one outer wake until an outcome other than `progress`, the
    /// step or time budget, or a stop request checked between steps. The budget is
    /// cooperative: a step already running (backend readback, inventory validation,
    /// SQL) is never interrupted, so `longest_step_ns` bounds the overshoot.
    pub fn runSlice(self: *Manager, bindings: []const Binding, limits: SliceLimits, stop: ?StopSignal) Slice {
        const start = self.monotonic(self.monotonic_context);
        var slice = Slice{ .outcome = .progress };
        if (self.readback_wait != 0) {
            self.readback_wait -= 1;
            self.status.ready = false;
            slice.outcome = .{ .wait = self.waitDue(start) };
            return slice;
        }
        while (slice.steps < limits.max_steps) {
            if (stop) |signal| if (signal.requested(signal.context)) {
                slice.outcome = .stop;
                break;
            };
            const before = self.monotonic(self.monotonic_context);
            slice.outcome = self.step(bindings);
            const after = self.monotonic(self.monotonic_context);
            slice.steps += 1;
            if (before != null and after != null) slice.longest_step_ns = @max(slice.longest_step_ns, after.? -| before.?);
            // Without a monotonic reading the time budget cannot be enforced; stop
            // after this step rather than trust an unbounded slice.
            if (start == null or after == null) break;
            slice.elapsed_ns = after.? -| start.?;
            if (slice.outcome != .progress or slice.elapsed_ns >= limits.max_ns) break;
        }
        return slice;
    }
    /// One pass in steps: the view follows storage; a selected entry is acted on; then
    /// either the kernel is read back or the held inventory selects the next work.
    fn stepInner(self: *Manager, bindings: []const Binding) !Step {
        errdefer |failure| {
            self.dropInventory();
            self.status.ready = false;
            self.status.uncertain = true;
            self.status.cause = failure;
        }
        if (self.store.effect_publication_epoch == std.math.maxInt(u64)) return error.EffectCapacity;
        const sampled = try self.clock();
        if (self.readback_wait != 0) {
            self.status.ready = false;
            return .{ .wait = self.waitDue(null) };
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
        if (self.status.ready and self.readback_wait == 0 and self.verify_interval_ns != 0) {
            const due = if (self.next_deadline_us) |deadline| deadline <= sampled.prepared_us else false;
            if (!due) if (self.last_verified_ns) |last| if (self.monotonic(self.monotonic_context)) |now| if (now -| last < self.verify_interval_ns) return .idle;
        }
        if (self.cursor < self.count) return self.act(bindings, sampled);
        // A confirmed view is verified again only by a fresh readback; an inventory that
        // predates our last send cannot show that send's outcome.
        if (self.status.ready or !self.inventoryCurrent()) return self.readback(sampled);
        return self.select(bindings, sampled);
    }
    fn readback(self: *Manager, sampled: effect.Clock) !Step {
        const start_ns = self.monotonic(self.monotonic_context);
        var snapshot = self.inspector.inspect() catch |failure| {
            self.recordFirewallDirect(.readback, failure);
            if (transientReadback(failure)) return self.deferReadback();
            return propagateFirewall(Step, failure);
        };
        {
            errdefer snapshot.deinit();
            try self.validateAndCaptureObservation(&snapshot, .readback, sampled.prepared_us, .readback);
        }
        self.keepInventory(snapshot, sampled.prepared_us, (try self.clock()).prepared_us, start_ns);
        if (!try self.evaluateInventory()) return self.deferReadback();
        self.status.ready = false;
        return .progress;
    }
    fn expiryDue(self: *const Manager, index: usize, entry: effect.Entry, now_us: i64) bool {
        if (entry.status == .dispatched or self.markers[index] != null) return false;
        if (entry.desired == .finite) return !entry.desired.live(now_us);
        if (entry.desired == .permanent) if (self.owner_deadline_us[index]) |deadline| return deadline <= now_us;
        return false;
    }
    /// Acts on the selected entry. Dispatch needs evidence of divergence: a pending
    /// intent, or an inventory that shows the desired state missing. Anything else
    /// is verified by a readback first.
    fn act(self: *Manager, bindings: []const Binding, sampled: effect.Clock) !Step {
        const index = self.cursor;
        const entry = self.live[index];
        self.cursor = self.count;
        if (entry.status == .superseded) return error.InvalidEffect;
        if (self.markers[index] != null or entry.status == .dispatched) return self.readback(sampled);
        if (self.expiryDue(index, entry, sampled.prepared_us)) {
            // A failed expiry commit that provably rolled back leaves the view intact; the
            // next step retries this entry directly rather than reading the kernel first.
            errdefer self.cursor = index;
            return self.expire(bindings, index, sampled);
        }
        if (entry.status == .pending or (self.inventory != null and !self.matched[index])) return self.dispatch(bindings, index, sampled);
        return self.readback(sampled);
    }
    const expiry_share: u8 = 4;
    /// Chooses the next work from the held inventory (refined enforcement, selection
    /// policy). Outstanding attempts and older-release rows settle first, then live
    /// dispatches and expiry work share the worker: live keeps at least every other
    /// selection, expiry work is served at parity while its backlog exceeds the live
    /// backlog and otherwise once per `expiry_share` live dispatches, continuously
    /// when nothing live is pending; overdue removals precede bookkeeping batches.
    fn select(self: *Manager, bindings: []const Binding, sampled: effect.Clock) !Step {
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
            if (entry.status == .superseded) return error.InvalidEffect;
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
                    // An inventory read before the removal was prepared cannot settle it:
                    // the outcome would be dated before its intent, which the store refuses.
                    // A fresh readback, taken when nothing else is selectable, settles it.
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
                // Present past its deadline. A kernel-expiring element seen before its
                // removal was prepared may still be timing out; only a later readback
                // can call it drift.
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
        // An emptied live backlog resets the share, so a ban that arrives after a quiet
        // spell is enforced before any pending expiry work.
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
            self.cursor = index;
            return .progress;
        }
        if (settle_blocked != 0) {
            self.dropInventory();
            return .progress;
        }
        if (try self.settleLegacyTargets(bindings)) |outcome| return outcome;
        if (!all_confirmed) {
            // Nothing diverges, yet the readback confirms nothing; the next wake reads
            // the kernel again rather than repeat this inventory.
            self.dropInventory();
            return .{ .wait = self.waitDue(null) };
        }
        self.status = .{ .ready = true, .confirmed = self.status.confirmed };
        self.last_verified_ns = self.monotonic(self.monotonic_context);
        self.cursor = self.count;
        return .idle;
    }
    /// The readback that ends an uncertain attempt: the desired state present settles
    /// the intent with the send's wall time; absent, the intent stays pending and is
    /// dispatched again from this inventory.
    fn settleMarker(self: *Manager, bindings: []const Binding, index: usize) !Step {
        const marker = self.markers[index].?;
        self.markers[index] = null;
        if (!self.matched[index]) return .progress;
        const held = &self.inventory.?;
        const entry = self.live[index];
        try self.settle(bindings, index, entry, marker.sent_wall_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = entry.desired });
        return .progress;
    }
    /// A row an earlier release left `dispatched` is an attempt of unknown send time;
    /// any readback after admission decides it, and the store keeps the stored dispatch
    /// time for the ordering check.
    fn settleLegacy(self: *Manager, bindings: []const Binding, index: usize) !Step {
        const held = &self.inventory.?;
        const entry = self.live[index];
        try self.settle(bindings, index, entry, held.start_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = if (self.matched[index]) entry.desired else null });
        return .progress;
    }
    /// Action targets an earlier release marked dispatched without settling stay
    /// unsettled until their scope settles again; a confirmed scope is re-settled once
    /// per view so its outcome commit carries them.
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
    /// Removals the held inventory proves absent settle together; the commit is
    /// attributed to every scope in the batch and the next step folds them in.
    fn settleExpiredBatch(self: *Manager, tokens: []const effect.Token) !Step {
        const held = &self.inventory.?;
        const pre = self.store.effect_publication_epoch;
        {
            errdefer self.writeFailed(pre);
            _ = try self.store.settleExpired(tokens, held.snapshot.fingerprint, held.end_us, try self.clock());
        }
        if (self.store.effect_publication_epoch == pre) return error.InvalidEffect;
        return .progress;
    }
    /// One mutation with its own readback. The attempt is marked in memory before the
    /// send; the readback that returns with the result becomes the inventory and the
    /// outcome commit records the send's wall time with the observation. An applied
    /// entry the inventory shows divergent first records that observation, so the
    /// repair is a new attempt of the same intent.
    fn dispatch(self: *Manager, bindings: []const Binding, index: usize, sampled: effect.Clock) !Step {
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
            self.recordFirewallDirect(.effect_dispatch, failure);
            if (!transientReadback(failure)) return error.EffectBackendUncertain;
            self.markers[index] = null;
            self.last_mutation_ns = prior_mutation_ns;
            self.last_mutation_wall_us = prior_mutation_wall_us;
            return self.deferReadback();
        };
        switch (result) {
            .uncertain => |failure| {
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
                    // Nothing was sent: the desired state already held in the baseline.
                    self.last_mutation_ns = prior_mutation_ns;
                    self.last_mutation_wall_us = prior_mutation_wall_us;
                    // A held inventory read before this intent existed cannot date its
                    // outcome; the next step reads the kernel and settles from that.
                    if (self.inventory) |held| if (held.start_us < entry.intent_us) {
                        snapshot.deinit();
                        self.dropInventory();
                        return .progress;
                    };
                    if (self.inventory == null) {
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
    /// A no-op expiry commit is not progress: it would repeat on the rebuilt view,
    /// so the retry waits for the next wake.
    /// Prepares the selected expired entry together with up to `max_expiry_batch - 1`
    /// other entries past their deadline in one commit; the attributed epoch then folds
    /// every prepared scope into the view on the next step. A single entry keeps the
    /// original in-place attribution.
    fn expire(self: *Manager, bindings: []const Binding, index: usize, sampled: effect.Clock) !Step {
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
                .unchanged => .{ .wait = self.waitDue(null) },
            };
        }
        const expired = blk: {
            errdefer self.writeFailed(pre);
            break :blk try self.store.prepareExpiries(items[0..count], sampled);
        };
        self.counters.expiry_batches += 1;
        self.counters.expiries_prepared += count;
        if (expired == 0 or self.store.effect_publication_epoch == pre) return .{ .wait = self.waitDue(null) };
        // The commit is attributed to every scope in the batch; the next step folds them in.
        return .progress;
    }
    fn settle(self: *Manager, bindings: []const Binding, index: usize, entry: effect.Entry, dispatch_us: i64, observed: effect.Observation) !void {
        const pre = self.store.effect_publication_epoch;
        {
            errdefer self.writeFailed(pre);
            _ = try self.store.settleOutcome(entry.token(), dispatch_us, observed, try self.clock());
        }
        if (try self.attributeCommit(bindings, index, pre) == .unchanged) return error.InvalidEffect;
    }
    /// The storage gate as the caller observed it when shutdown began. The daemon
    /// decides the phase; the parameter makes dispatch through an unhealthy gate
    /// impossible by construction.
    pub const StorageGate = enum { healthy, unhealthy };
    /// Withdraws one realized entry per call. It dispatches only removals and writes
    /// no storage. An unhealthy gate means durable intent may be unreadable or
    /// unconfirmed, so it refuses before any dispatch; use `residualInstalled` then.
    pub fn stopStep(self: *Manager, expected_repair_epoch: u64, gate: StorageGate) Step {
        return self.stopStepInner(expected_repair_epoch, gate) catch |failure| .{ .fatal = failure };
    }
    fn stopStepInner(self: *Manager, expected_repair_epoch: u64, gate: StorageGate) !Step {
        if (gate != .healthy) return error.StorageUnhealthy;
        if (expected_repair_epoch == 0 or expected_repair_epoch != self.repair_epoch) return error.StaleRepairEpoch;
        if (self.store.reopen_required) return error.ReopenRequired;
        self.dropInventory();
        if (!self.stopping) {
            if (!self.admitted or !self.status.ready or self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch) return error.EffectReconciliationRequired;
            self.stopping = true;
            self.stop_cursor = 0;
            self.status.ready = false;
        }
        errdefer |failure| {
            self.status.uncertain = true;
            self.status.cause = failure;
        }
        const sampled = try self.clock();
        while (self.stop_cursor < self.count) {
            const entry = self.live[self.stop_cursor];
            if (entry.desired == .absent) {
                self.stop_cursor += 1;
                continue;
            }
            var result = self.inspector.applyExact(self.token(entry, .absent), .{ .wall_us = sampled.prepared_us }) catch |failure| {
                self.recordFirewallDirect(.effect_dispatch, failure);
                return propagateFirewall(Step, failure);
            };
            defer result.deinit();
            switch (result) {
                .uncertain => |failure| {
                    self.recordFirewallFailure(failure);
                    return error.EffectBackendUncertain;
                },
                .verified => |*observed| try self.validateAndCaptureObservation(&observed.snapshot, .stop, observed.observed_wall_us, .effect_verify),
            }
            self.stop_cursor += 1;
            return .progress;
        }
        var final = self.inspector.inspect() catch |failure| {
            self.recordFirewallDirect(.readback, failure);
            return propagateFirewall(Step, failure);
        };
        defer final.deinit();
        try self.validateAndCaptureObservation(&final, .stop, sampled.prepared_us, .readback);
        if (final.entries.len != 0) {
            self.recordObservationFailure(.readback, error.UnownedInstalledEffect);
            return error.UnownedInstalledEffect;
        }
        self.stopping = false;
        self.stop_cursor = 0;
        self.admitted = false;
        self.cached_epoch = null;
        self.count = 0;
        self.status = .{};
        return .idle;
    }
    pub const Residual = struct {
        /// Entries left in the owned kernel set; null when it could not be read.
        installed: ?usize,
        cause: ?anyerror = null,
    };
    /// Shutdown without a writable store: reads the owned inventory once and leaves
    /// it installed. It neither dispatches nor touches storage, so restart
    /// reconciles every entry from durable intent.
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
        self.dropInventory();
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

test "native effect runtime: absent inventory is distinct from unexpected owned entries" {
    const t = std.testing;
    const installation = firewall.Installation{ .id = [_]u8{0x71} ** 16, .transport = .nftables };
    var cache = observation.Cache.init(installation, [_]u8{0x72} ** 16);
    var manager: Manager = undefined;
    manager.observation_cache = &cache;
    manager.count = 0;
    manager.live = &.{};
    var snapshot = firewall.Snapshot{
        .allocator = t.allocator,
        .installation = installation,
        .state = .absent,
        .entries = &.{},
        .fingerprint = [_]u8{0} ** 32,
        .observed_start_ns = 0,
        .observed_end_ns = 0,
    };
    try t.expectError(error.InstallationMismatch, manager.validateAndCaptureObservation(&snapshot, .readback, null, .readback));
    var page: observation.Page = undefined;
    try cache.readPage(.{}, &page);
    try t.expectEqual(.absent, page.metadata.state);
    try t.expectEqual(.not_checked, page.metadata.inventory);
    var entries = [_]firewall.Entry{.{ .address = .{ .ipv4 = 0xc0000201 } }};
    snapshot.state = .owned;
    snapshot.entries = &entries;
    try t.expectError(error.UnownedInstalledEffect, manager.validateAndCaptureObservation(&snapshot, .readback, null, .readback));
    try cache.readPage(.{}, &page);
    try t.expectEqual(.unexpected_entries, page.metadata.inventory);
    try t.expectEqual(@as(usize, 1), page.count);
}
