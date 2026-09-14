// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Serialized durable effect execution. The coordinator holds its database and
//! namespace authority across each call; status consumers receive detached data.
const std = @import("std");
const shared = @import("shared");
const durable = @import("core/record_store.zig");
const effect = @import("core/native_effect.zig");
const firewall = @import("firewall/inspection.zig");

pub const Binding = struct { jail: []const u8, generation: [32]u8 };
pub const Health = struct { ready: bool = false, uncertain: bool = false, overdue: usize = 0, confirmed: usize = 0, cause: ?anyerror = null };
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
    status: Health = .{},
    admitted: bool = false,

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
    pub fn storageReopened(self: *Manager) void {
        // A process-local epoch starts over with the reopened Store. No old
        // cached owner authority may survive that change by numeric coincidence.
        self.cached_epoch = null;
        self.staged_revision = null;
        self.staged_count = 0;
        self.admitted = false;
        self.status.ready = false;
    }
    pub fn confirmedSubject(self: *const Manager, subject: @import("core/native_detection_record.zig").Subject, now_us: i64) bool {
        if (self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch or !self.status.ready) return false;
        const scope = effect.Scope.host(subject) catch return false;
        for (self.live[0..self.count]) |entry| if (std.meta.eql(entry.scope, scope)) return entry.status == .applied and entry.desired.live(now_us);
        return false;
    }
    fn clock(self: *Manager) !effect.Clock {
        const now = std.time.microTimestamp();
        if (now < self.last_wall_us) return error.EffectClockReversed;
        self.last_wall_us = now;
        return .{ .prepared_us = now };
    }
    /// Installation row is the immutable desired scaffold, revision one. Its
    /// canonical identity deterministically binds the durable creation intent.
    pub fn admit(self: *Manager) !void {
        errdefer |failure| {
            self.status.ready = false;
            self.status.uncertain = true;
            self.status.cause = failure;
        }
        const saved = try self.store.readInstallation() orelse return error.InstallationRequired;
        if (!std.meta.eql(saved, self.installation)) return error.InstallationMismatch;
        const id = effect.hashParts("fail2zig-native-installation-intent-v1", &.{ &saved.id, &.{@intFromEnum(saved.backend)}, saved.selector() });
        var result = try self.inspector.admitInstallation(.{ .installation = self.inspector.installation, .intent_id = id, .revision = 1 });
        defer result.deinit();
        switch (result) {
            .installed => self.admitted = true,
            .uncertain => |cause| {
                self.status.cause = cause;
                self.status.uncertain = true;
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
        std.mem.swap([]effect.Entry, &self.live, &self.staged);
        self.count = self.staged_count;
        self.cached_epoch = self.staged_epoch;
        self.staged_revision = null;
        self.cursor = 0;
        @memset(self.outage_attempted, false);
        return true;
    }
    fn token(self: *Manager, entry: effect.Entry, lease: effect.Lease) firewall.DispatchToken {
        return .{ .installation = self.inspector.installation, .effect_id = entry.scope_key, .aggregate_revision = entry.revision, .scope = .{ .address = address(entry.scope), .prefix = if (entry.scope.family == .v4) 32 else 128 }, .operation = switch (lease) {
            .absent => .ensure_absent,
            .finite => |deadline| .{ .ensure_present = .{ .finite_deadline_us = deadline } },
            .permanent => .{ .ensure_present = .permanent },
        } };
    }
    fn validateInventory(self: *Manager, snapshot: *const firewall.Snapshot) !void {
        if (snapshot.state != .owned) return error.InstallationMismatch;
        for (snapshot.entries) |installed| {
            for (self.live[0..self.count]) |entry| if (installed.address.eql(address(entry.scope))) break else continue else return error.UnownedInstalledEffect;
        }
    }
    /// One bounded page or one scope operation per turn. False fences new
    /// ingestion while required recovery or freshly committed effects are pending.
    pub fn turn(self: *Manager, bindings: []const Binding) !bool {
        errdefer |failure| {
            self.status.ready = false;
            self.status.uncertain = true;
            self.status.cause = failure;
        }
        if (self.store.effect_publication_epoch == std.math.maxInt(u64)) return error.EffectCapacity;
        const sampled = try self.clock();
        if (!self.admitted) {
            try self.admit();
            return false;
        }
        if (self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch) {
            self.status.ready = false;
            _ = try self.refreshTurn(bindings);
            return false;
        }
        if (self.cursor == self.count) {
            // Even an empty database must not adopt an unrecorded owned element.
            var snapshot = try self.inspector.inspect();
            defer snapshot.deinit();
            try self.validateInventory(&snapshot);
            const end = try self.clock();
            for (self.live[0..self.count], 0..) |entry, index| {
                if (!try self.inspector.matchesSnapshot(&snapshot, self.token(entry, entry.desired), sampled.prepared_us, end.prepared_us)) {
                    self.cursor = index;
                    self.status.ready = false;
                    return false;
                }
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
                self.status.cause = failure;
                self.status.uncertain = true;
                return error.EffectBackendUncertain;
            };
            defer result.deinit();
            switch (result) {
                .uncertain => |cause| {
                    self.status.cause = cause;
                    self.status.uncertain = true;
                    return error.EffectBackendUncertain;
                },
                .verified => |*observed| {
                    try self.validateInventory(&observed.snapshot);
                    _ = try self.store.settleVerified(entry.token(), .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = observed.snapshot.fingerprint, .observed_us = observed.observed_wall_us, .qualification = .complete_owned, .state = entry.desired }, try self.clock());
                },
            }
            return false;
        }
        var observed = try self.inspector.observeExact(self.token(entry, entry.desired), .{ .wall_us = sampled.prepared_us });
        defer observed.deinit();
        try self.validateInventory(&observed.snapshot);
        if (entry.status == .dispatched or !observed.matches_desired) {
            self.status.ready = false;
            _ = try self.store.settleVerified(entry.token(), .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = observed.snapshot.fingerprint, .observed_us = observed.observed_wall_us, .qualification = .complete_owned, .state = if (observed.matches_desired) entry.desired else null }, try self.clock());
            return false;
        }
        if (entry.desired == .permanent) {
            // A permanent aggregate still needs each elapsed finite co-owner
            // committed absent. Do this only after complete readback proves the
            // permanent effect remains installed; prepareExpiry then preserves
            // the permanent aggregate and never dispatches a physical removal.
            var owners: [effect.max_page]effect.Owner = undefined;
            const owner_count = try self.store.effectOwners(entry.scope_key, entry.revision, &owners);
            for (owners[0..owner_count]) |owner| if (owner.lease == .finite and !owner.lease.live(sampled.prepared_us)) {
                self.status.ready = false;
                _ = try self.store.prepareExpiry(entry.scope_key, entry.revision, sampled);
                return false;
            };
        }
        self.cursor += 1;
        return self.status.ready;
    }
    /// Sole exception to storage fencing: exact finite expiry already committed
    /// in a coherent owner view. One pre-reserved uncertain slot per scope; no
    /// new intent, extension, broad flush or database-dependent allocation.
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
            var result = try self.inspector.applyExact(self.token(entry, .absent), .{ .wall_us = clock_sample.prepared_us });
            defer result.deinit();
            if (result == .uncertain) self.status.cause = result.uncertain;
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
    return switch (scope.family) {
        .v4 => .{ .ipv4 = std.mem.readInt(u32, scope.address[0..4], .big) },
        .v6 => .{ .ipv6 = std.mem.readInt(u128, &scope.address, .big) },
    };
}
