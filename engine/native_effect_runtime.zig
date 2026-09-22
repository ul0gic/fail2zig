// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const durable = @import("core/record_store.zig");
const effect = @import("core/native_effect.zig");
const action_outcome = @import("core/native_action_outcome.zig");
const firewall = @import("firewall/inspection.zig");
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
/// Two dumps can disagree without any fault, for example when a kernel element
/// timeout expires between them. Such readbacks leave enforcement uncertain and are
/// retried by the manager; they are not persistence failures.
fn transientReadback(cause: anyerror) bool {
    return cause == error.Changed or cause == error.Timeout or cause == error.Incomplete;
}
const max_readback_wait_turns: u16 = 255;
/// True when `next` is `previous` minus at least one entry whose desired lease and
/// kernel status are both absent, with every remaining entry unchanged. Both lists are
/// ordered by scope key.
fn removedOnlySpent(previous: []const effect.Entry, next: []const effect.Entry) bool {
    if (next.len >= previous.len) return false;
    var i: usize = 0;
    for (next) |entry| {
        while (i < previous.len and !std.mem.eql(u8, &previous[i].scope_key, &entry.scope_key)) : (i += 1) {
            if (previous[i].desired != .absent or previous[i].status != .absent) return false;
        }
        if (i == previous.len or !std.meta.eql(previous[i], entry)) return false;
        i += 1;
    }
    for (previous[i..]) |rest| if (rest.desired != .absent or rest.status != .absent) return false;
    return true;
}
fn systemWall(_: ?*anyopaque) i64 {
    return std.time.microTimestamp();
}
pub const reserved_bytes = @sizeOf(Manager) + effect.max_effects * (2 * @sizeOf(effect.Entry) + @sizeOf(bool)) + (firewall.Limits{}).max_bytes;
pub const Manager = struct {
    allocator: std.mem.Allocator,
    store: *durable.Store,
    inspector: firewall.Inspector,
    installation: effect.Installation,
    live: []effect.Entry,
    staged: []effect.Entry,
    outage_attempted: []bool,
    count: usize = 0,
    staged_count: usize = 0,
    staged_revision: ?u64 = null,
    staged_epoch: u64 = 0,
    cached_epoch: ?u64 = null,
    cursor: usize = 0,
    last_wall_us: i64,
    wall_context: ?*anyopaque = null,
    wall: *const fn (?*anyopaque) i64 = systemWall,
    status: Health = .{},
    admitted: bool = false,
    repair_epoch: u64 = 1,
    stop_cursor: usize = 0,
    stopping: bool = false,
    observation_cache: ?*observation.Cache = null,
    readback_failures: u8 = 0,
    readback_wait: u16 = 0,
    refresh_was_ready: bool = false,
    refresh_removed_only: bool = false,

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
        self.* = .{ .allocator = a, .store = store, .installation = installation, .inspector = try firewall.Inspector.open(a, transportInstallation(installation), .{}), .live = live, .staged = staged, .outage_attempted = attempted, .last_wall_us = std.time.microTimestamp() };
        return self;
    }
    pub fn destroy(self: *Manager) void {
        self.inspector.close();
        self.allocator.free(self.live);
        self.allocator.free(self.staged);
        self.allocator.free(self.outage_attempted);
        self.allocator.destroy(self);
    }
    /// The caller retains ownership and must keep the cache alive until after
    /// the worker stops using this Manager.
    pub fn attachObservationCache(self: *Manager, cache: *observation.Cache) void {
        self.observation_cache = cache;
    }
    pub fn storageReopened(self: *Manager) void {
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
    pub fn confirmedSubject(self: *const Manager, subject: @import("core/native_detection_record.zig").Subject, now_us: i64) bool {
        if (self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch or !self.status.ready) return false;
        const scope = effect.Scope.host(subject) catch return false;
        for (self.live[0..self.count]) |entry| if (std.meta.eql(entry.scope, scope)) return entry.status == .applied and entry.desired.live(now_us);
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
    /// The first retry follows on the next turn so a single race costs one turn;
    /// consecutive failures double the skipped turns up to the cap.
    fn deferReadback(self: *Manager) bool {
        self.status.ready = false;
        self.readback_failures +|= 1;
        const shift: u4 = @intCast(@min(self.readback_failures - 1, 8));
        self.readback_wait = @min((@as(u16, 1) << shift) - 1, max_readback_wait_turns);
        return false;
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
            return false;
        }
        var rows: [effect.max_page]effect.Entry = undefined;
        const after = if (self.staged_count == 0) null else self.staged[self.staged_count - 1].scope_key;
        const page = try self.store.effectPage(after, self.staged_revision, &rows);
        if (page.count > self.staged.len - self.staged_count) return error.EffectCapacity;
        for (rows[0..page.count]) |entry| {
            var owners: [effect.max_page]effect.Owner = undefined;
            const count = try self.store.effectOwners(entry.scope_key, entry.revision, &owners);
            for (owners[0..count]) |owner| {
                for (bindings) |binding| {
                    if (!std.mem.eql(u8, binding.jail, owner.jail.slice())) continue;
                    if (!std.mem.eql(u8, &binding.generation, &owner.generation)) return error.EffectGenerationMismatch;
                    break;
                } else return error.UnconfiguredStateOwner;
            }
        }
        @memcpy(self.staged[self.staged_count..][0..page.count], rows[0..page.count]);
        self.staged_count += page.count;
        self.staged_revision = page.revision;
        if (page.more) return false;
        if (self.staged_epoch != self.store.effect_publication_epoch) {
            self.staged_revision = null;
            return false;
        }
        self.refresh_removed_only = removedOnlySpent(self.live[0..self.count], self.staged[0..self.staged_count]);
        std.mem.swap([]effect.Entry, &self.live, &self.staged);
        self.count = self.staged_count;
        self.cached_epoch = self.staged_epoch;
        self.staged_revision = null;
        self.cursor = self.count;
        @memset(self.outage_attempted, false);
        return true;
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
        for (snapshot.entries) |installed| {
            const installed_scope = installed.scope orelse firewall.CanonicalScope{ .subject = firewall.canonical_scope.Subject.host(installed.address) };
            for (self.live[0..self.count]) |entry| {
                if (!std.meta.eql(installed_scope, entry.scope.canonical)) continue;
                if (installed.scope != null and (installed.effect_id == null or !std.mem.eql(u8, &installed.effect_id.?, &entry.scope_key))) continue;
                break;
            } else return error.UnownedInstalledEffect;
        }
    }
    fn reconcileActionTargets(self: *Manager, entry: effect.Entry) !bool {
        if (self.store.schema_version < 21) return true;
        var owners: [effect.max_page]effect.Owner = undefined;
        const owner_count = try self.store.effectOwners(entry.scope_key, entry.revision, &owners);
        for (owners[0..owner_count]) |owner| {
            var targets: [action_outcome.max_targets_per_action]action_outcome.Target = undefined;
            const count = try self.store.actionTargets(owner.decision_id, &targets);
            if (count == 0) continue;
            if (count != action_outcome.max_targets_per_action) return error.InvalidActionTarget;
            for (targets[0..count]) |target| {
                if (!std.mem.eql(u8, &target.scope_key, &entry.scope_key) or !std.mem.eql(u8, target.jail.slice(), owner.jail.slice())) return error.InvalidActionTarget;
                switch (target.kind) {
                    .enforcement => switch (target.status) {
                        .pending, .uncertain => {
                            self.status.ready = false;
                            try self.store.markActionTargetDispatched(target.action_id, .enforcement, try self.clock());
                            return false;
                        },
                        .dispatched => {
                            self.status.ready = false;
                            try self.store.settleActionTarget(target.action_id, .enforcement, .confirmed, try self.clock());
                            return false;
                        },
                        .confirmed => {},
                        .failed, .suppressed_restored => return error.InvalidActionTarget,
                    },
                    .notification => switch (target.status) {
                        .pending, .uncertain => {
                            self.status.ready = false;
                            try self.store.markActionTargetDispatched(target.action_id, .notification, try self.clock());
                            return false;
                        },
                        .dispatched => {
                            self.status.ready = false;
                            try self.store.settleActionTarget(target.action_id, .notification, .confirmed, try self.clock());
                            return false;
                        },
                        .confirmed, .failed, .suppressed_restored => {},
                    },
                }
            }
        }
        return true;
    }
    pub fn turn(self: *Manager, bindings: []const Binding) !bool {
        errdefer |failure| {
            self.status.ready = false;
            self.status.uncertain = true;
            self.status.cause = failure;
        }
        if (self.store.effect_publication_epoch == std.math.maxInt(u64)) return error.EffectCapacity;
        const sampled = try self.clock();
        if (self.readback_wait != 0) {
            self.readback_wait -= 1;
            self.status.ready = false;
            return false;
        }
        if (!self.admitted) {
            self.admit() catch |failure| switch (failure) {
                error.Changed, error.Timeout, error.Incomplete => return self.deferReadback(),
                else => |other| return @as(@TypeOf(other)!bool, other),
            };
            self.readback_failures = 0;
            return false;
        }
        if (self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch) {
            if (self.staged_revision == null) self.refresh_was_ready = self.status.ready and self.cached_epoch != null;
            self.status.ready = false;
            // Pruning spent scopes deletes only rows that are already absent in the
            // kernel; the confirmed view stays valid without another full readback.
            if (try self.refreshTurn(bindings) and self.refresh_was_ready and self.refresh_removed_only) {
                self.status.ready = true;
                self.cursor = 0;
                return true;
            }
            return false;
        }
        if (self.cursor == self.count) {
            var snapshot = self.inspector.inspect() catch |failure| {
                self.recordFirewallDirect(.readback, failure);
                if (transientReadback(failure)) return self.deferReadback();
                return propagateFirewall(bool, failure);
            };
            defer snapshot.deinit();
            self.readback_failures = 0;
            try self.validateAndCaptureObservation(&snapshot, .readback, sampled.prepared_us, .readback);
            const end = try self.clock();
            const unsettled = try self.store.unsettledActionScope();
            // Enforcing a live ban comes before expiry bookkeeping: expired kernel
            // elements already time out on their own, while a new ban protects nothing
            // until it is dispatched.
            var next: ?usize = null;
            for (self.live[0..self.count], 0..) |entry, index| {
                const matches = self.inspector.matchesSnapshot(&snapshot, self.token(entry, entry.desired), sampled.prepared_us, end.prepared_us) catch |failure| {
                    if (transientReadback(failure)) {
                        self.recordFirewallDirect(.readback, failure);
                        return self.deferReadback();
                    }
                    self.recordObservationFailure(.readback, failure);
                    return propagateFirewall(bool, failure);
                };
                const outcome_pending = if (unsettled) |scope_key| std.mem.eql(u8, &scope_key, &entry.scope_key) else false;
                if (!matches or outcome_pending or entry.status == .pending or entry.status == .dispatched) {
                    if (entry.desired.live(end.prepared_us)) {
                        next = index;
                        break;
                    }
                    if (next == null) next = index;
                }
            }
            if (next) |index| {
                self.cursor = index;
                self.status.ready = false;
                return false;
            }
            self.status = .{ .ready = true };
            for (self.live[0..self.count]) |entry| if (entry.status == .applied and entry.desired.live(sampled.prepared_us)) {
                self.status.confirmed += 1;
            };
            self.cursor = 0;
            return true;
        }
        const entry = self.live[self.cursor];
        if (entry.status == .superseded) return error.InvalidEffect;
        if (entry.status != .dispatched and entry.desired == .finite and !entry.desired.live(sampled.prepared_us)) {
            self.status.ready = false;
            _ = try self.store.prepareExpiry(entry.scope_key, entry.revision, sampled);
            return false;
        }
        if (entry.status == .pending) {
            self.status.ready = false;
            try self.store.markDispatched(entry.token(), sampled);
            const dispatch_clock = try self.clock();
            var result = self.inspector.applyExact(self.token(entry, entry.desired), .{ .wall_us = dispatch_clock.prepared_us }) catch |failure| {
                self.recordFirewallDirect(.effect_dispatch, failure);
                return error.EffectBackendUncertain;
            };
            defer result.deinit();
            switch (result) {
                .uncertain => |failure| {
                    self.recordFirewallFailure(failure);
                    return error.EffectBackendUncertain;
                },
                .verified => |*observed| {
                    try self.validateAndCaptureObservation(&observed.snapshot, .effect, observed.observed_wall_us, .effect_verify);
                    _ = try self.store.settleVerified(entry.token(), .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = observed.snapshot.fingerprint, .observed_us = observed.observed_wall_us, .qualification = .complete_owned, .state = entry.desired }, try self.clock());
                },
            }
            return false;
        }
        var observed = self.inspector.observeExact(self.token(entry, entry.desired), .{ .wall_us = sampled.prepared_us }) catch |failure| {
            self.recordFirewallDirect(.readback, failure);
            if (transientReadback(failure)) return self.deferReadback();
            return propagateFirewall(bool, failure);
        };
        defer observed.deinit();
        self.readback_failures = 0;
        try self.validateAndCaptureObservation(&observed.snapshot, .effect, observed.observed_wall_us, .effect_verify);
        if (entry.status == .dispatched or !observed.matches_desired) {
            self.status.ready = false;
            _ = try self.store.settleVerified(entry.token(), .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = observed.snapshot.fingerprint, .observed_us = observed.observed_wall_us, .qualification = .complete_owned, .state = if (observed.matches_desired) entry.desired else null }, try self.clock());
            return false;
        }
        if (!try self.reconcileActionTargets(entry)) return false;
        if (entry.desired == .permanent) {
            var owners: [effect.max_page]effect.Owner = undefined;
            const owner_count = try self.store.effectOwners(entry.scope_key, entry.revision, &owners);
            for (owners[0..owner_count]) |owner| if (owner.lease == .finite and !owner.lease.live(sampled.prepared_us)) {
                self.status.ready = false;
                _ = try self.store.prepareExpiry(entry.scope_key, entry.revision, sampled);
                return false;
            };
        }
        // While unconfirmed, the next full readback finds the next divergent entry;
        // stepping one entry per turn would make each change cost the whole table.
        if (!self.status.ready) {
            self.cursor = self.count;
            return false;
        }
        self.cursor += 1;
        return true;
    }
    pub fn stopTurn(self: *Manager, expected_repair_epoch: u64) !bool {
        if (expected_repair_epoch == 0 or expected_repair_epoch != self.repair_epoch) return error.StaleRepairEpoch;
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
                return propagateFirewall(bool, failure);
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
            return false;
        }
        var final = self.inspector.inspect() catch |failure| {
            self.recordFirewallDirect(.readback, failure);
            return propagateFirewall(bool, failure);
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
        return true;
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
