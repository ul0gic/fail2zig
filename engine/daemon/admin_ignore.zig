// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Adds and removes runtime ignore entries for a jail and lifts the bans an added entry covers when unban is requested.
// Holds: A configured ignoreip entry is never removed at runtime; a removal of one is refused and names the configuration to edit.

const std = @import("std");
const shared = @import("shared");
const config = @import("../config/config.zig");
const detection = @import("../detect/detection_record.zig");
const effect = @import("../effect/effect.zig");
const inspection = @import("../firewall/inspection.zig");
const durable = @import("../store/store.zig");
const ignore_set = @import("../detect/ignore_set.zig");
const RuntimeIgnoreEntry = @import("../store/ignore_entries.zig").RuntimeIgnoreEntry;
const admin = @import("admin.zig");
const adminReadback = admin.adminReadback;
const daemon = @import("daemon.zig");
const Jail = daemon.Jail;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const AdminOutcomeView = Coordinator.AdminOutcomeView;
        const AdminRequest = Coordinator.AdminRequest;
        const IgnoreRelation = Coordinator.IgnoreRelation;
        const IgnoreWork = Coordinator.IgnoreWork;
        const configuredIgnoreDeadlines = Coordinator.configuredIgnoreDeadlines;
        const findConfigJail = Coordinator.findConfigJail;
        const ignoreCell = Coordinator.ignoreCell;
        const max_lifted_bans = Coordinator.max_lifted_bans;
        const max_listed_bans = Coordinator.max_listed_bans;
        const monotonic = Coordinator.monotonic;
        const wallClockEffect = Coordinator.wallClockEffect;
        const ignore_lift_budget_ms: u64 = 1000;
        const ignore_lift_settle_ms: u64 = 2000;

        pub fn ignoreRefusal(self: *Coordinator, request: *AdminRequest, outcome: durable.Store.AdminOutcome, comptime fmt: []const u8, args: anytype) AdminOutcomeView {
            return self.adminDetail(request, (AdminOutcomeView{ .outcome = outcome, .kind = request.kind }).withReason(fmt, args), null);
        }
        pub fn ignoreUncertain(self: *Coordinator, request: *AdminRequest) AdminOutcomeView {
            return self.ignoreRefusal(request, .uncertain, "the ignore entry may or may not have been recorded; run fail2zig ignore list --jail {s} to see the current list", .{request.jailName()});
        }
        pub fn recordConfiguredCover(ignore_state: *IgnoreWork, list: *const ignore_set.EffectiveIgnore, entry: shared.types.IgnoreEntry, include_equal: bool) void {
            var found: [ignore_set.max_entries_per_part]*const ignore_set.Item = undefined;
            const covering = list.covering(entry, &found);
            for (found[0..covering], 0..) |item, slot| ignore_state.configured[slot] = item.entry;
            ignore_state.configured_count = covering;
            for (list.entries) |item| {
                if (item.entry.order(entry) != .eq) continue;
                ignore_state.source = item.source;
                if (include_equal and item.source != .runtime and ignore_state.configured_count < ignore_state.configured.len) {
                    ignore_state.configured[ignore_state.configured_count] = item.entry;
                    ignore_state.configured_count += 1;
                }
            }
            std.sort.pdq(shared.types.IgnoreEntry, ignore_state.configured[0..ignore_state.configured_count], {}, entryLess);
        }
        pub fn entryLess(_: void, a: shared.types.IgnoreEntry, b: shared.types.IgnoreEntry) bool {
            return a.order(b) == .lt;
        }
        pub fn subjectEntry(subject: inspection.canonical_scope.Subject) shared.types.IgnoreEntry {
            return .{ .family = switch (subject.family) {
                .v4 => .v4,
                .v6 => .v6,
            }, .address = subject.address, .prefix = subject.prefix };
        }
        pub fn banRelation(entry: shared.types.IgnoreEntry, ban: shared.types.IgnoreEntry) ?IgnoreRelation {
            if (entry.family != ban.family) return null;
            if (ban.prefix >= entry.prefix) return if (entry.contains(ban.network())) .inside_entry else null;
            return if (ban.contains(entry.network())) .contains_entry else null;
        }
        const RelatedBan = struct { order: shared.types.IgnoreEntry, index: u32, relation: IgnoreRelation };
        pub fn relatedLess(_: void, a: RelatedBan, b: RelatedBan) bool {
            return a.order.order(b.order) == .lt;
        }
        pub fn collectRelatedBans(self: *Coordinator, request: *AdminRequest, jail: *Jail) !void {
            const ignore_state = request.ignore.?;
            const entry = request.ignore_entry.?;
            ignore_state.jail_enabled = jail.admin_enabled;
            ignore_state.jail_paused = jail.admin_paused;
            const enforces = self.jailEnforces(jail);
            if (enforces) {
                self.publishOwners() catch |failure| if (failure != error.StaleEffect) return failure;
                if (self.owner_publication_pending) return error.EffectReconciliationRequired;
            } else {
                try self.publishJail(jail);
                if (jail.retry_revision == null) return error.RetryEligibilityPending;
            }
            const now = self.clock.wallUs();
            const range = jail.owner_range;
            const found = try self.allocator.alloc(RelatedBan, if (enforces) range.len else jail.active.len);
            defer self.allocator.free(found);
            var count: usize = 0;
            var inside: usize = 0;
            if (enforces) {
                for (self.owner_active[range.start..][0..range.len], range.start..) |owner, i| {
                    if (!owner.lease.live(now)) continue;
                    const ban = subjectEntry(owner.scope.canonical.subject);
                    const relation = banRelation(entry, ban) orelse continue;
                    found[count] = .{ .order = ban, .index = @intCast(i), .relation = relation };
                    count += 1;
                    inside += @intFromBool(relation == .inside_entry);
                }
            } else for (jail.active[0..jail.active.len], 0..) |decision, i| {
                if (!decision.lease.live(now)) continue;
                const ban = subjectEntry(decisionScope(decision.subject).subject);
                const relation = banRelation(entry, ban) orelse continue;
                found[count] = .{ .order = ban, .index = @intCast(i), .relation = relation };
                count += 1;
                inside += @intFromBool(relation == .inside_entry);
            }
            std.sort.pdq(RelatedBan, found[0..count], {}, relatedLess);
            ignore_state.bans_total = count;
            ignore_state.inside_total = inside;
            ignore_state.ban_count = @min(count, if (request.unban) ignore_state.bans.len else max_listed_bans);
            for (found[0..ignore_state.ban_count], ignore_state.bans[0..ignore_state.ban_count]) |item, *slot| {
                if (enforces) {
                    const owner = self.owner_active[item.index];
                    slot.* = .{
                        .canonical = owner.scope.canonical,
                        .key = owner.key,
                        .deadline_us = leaseDeadline(owner.lease),
                        .confirmed = self.owner_confirmed[item.index] and self.confirmationKnown(monotonic(self)),
                        .relation = item.relation,
                    };
                } else {
                    const decision = jail.active[item.index];
                    slot.* = .{ .canonical = decisionScope(decision.subject), .key = [_]u8{0} ** 32, .deadline_us = leaseDeadline(decision.lease), .confirmed = false, .relation = item.relation };
                }
            }
        }
        pub fn leaseDeadline(lease: anytype) ?i64 {
            return switch (lease) {
                .finite => |value| value,
                else => null,
            };
        }
        pub fn decisionScope(subject: detection.Subject) inspection.CanonicalScope {
            const address: shared.IpAddress = switch (subject) {
                .v4 => |v| .{ .ipv4 = std.mem.readInt(u32, &v, .big) },
                .v6 => |v| .{ .ipv6 = std.mem.readInt(u128, &v, .big) },
            };
            return .{ .subject = inspection.canonical_scope.Subject.host(address) };
        }
        pub fn liftIgnoredBans(self: *Coordinator, request: *AdminRequest, jail: ?*Jail) void {
            const ignore_state = request.ignore.?;
            const name = request.jailName();
            const budget_end = monotonic(self) + ignore_lift_budget_ms;
            for (ignore_state.bans[0..ignore_state.ban_count], 0..) |*ban, index| {
                if (ban.relation == .contains_entry) {
                    ban.lift = .refused;
                    ban.reason = "network ban wider than the entry";
                    continue;
                }
                const manager_enforces = self.effects != null and jail != null and self.jailEnforces(jail.?);
                if (!manager_enforces) {
                    ban.lift = .refused;
                    ban.reason = "jail is log-only; manual bans require an enforcing backend";
                    continue;
                }
                if (monotonic(self) >= budget_end) {
                    ban.lift = .refused;
                    ban.reason = "not attempted within the command's time limit; run the command again";
                    continue;
                }
                const current = self.store.currentOwner(ban.key, name) catch |failure| {
                    ban.lift = .unknown;
                    ban.reason = @errorName(failure);
                    continue;
                } orelse {
                    ban.lift = .refused;
                    ban.reason = "no owner for this scope in the jail";
                    continue;
                };
                if (current.lease == .absent) {
                    ban.lift = .refused;
                    ban.reason = "owner already released";
                    continue;
                }
                // Why: The transition id derives from the request id and ban index, so replaying the request reuses the same ids.
                var counter: [4]u8 = undefined;
                std.mem.writeInt(u32, &counter, @intCast(index), .little);
                const transition = effect.hashParts("fail2zig-ignore-unban-v1", &.{ &request.request_id, &counter });
                const prepared = self.clock.wallUs();
                _ = self.store.transitionOwner(.{ .scope = ban.canonical, .jail = name, .current_generation = current.generation, .next_generation = current.generation, .expected_owner_revision = current.revision, .transition_id = transition, .mode = .release, .occurred_us = prepared }, .{ .prepared_us = prepared, .context = self, .read = wallClockEffect }) catch |failure| {
                    ban.reason = @errorName(failure);
                    ban.lift = switch (failure) {
                        error.StaleEffect, error.EffectGenerationMismatch, error.EffectReconciliationRequired => .refused,
                        else => .unknown,
                    };
                    continue;
                };
                ban.lift = .pending;
                ignore_state.lifting = true;
                ignore_state.mutated = true;
                request.mutation_committed = true;
            }
        }
        pub fn settleIgnoreLifts(self: *Coordinator, request: *AdminRequest, ignore_state: *IgnoreWork) void {
            const manager = self.effects.?;
            const readback = adminReadback(manager.status, manager.cached_epoch, self.store.effect_publication_epoch);
            const now = self.clock.wallUs();
            var pending: usize = 0;
            for (ignore_state.bans[0..ignore_state.ban_count]) |*ban| {
                if (ban.lift != .pending) continue;
                switch (readback) {
                    .uncertain => {
                        ban.lift = .unknown;
                        ban.reason = "effect outcome uncertain";
                    },
                    .pending => pending += 1,
                    .coherent => {
                        var removed = true;
                        for (manager.live[0..manager.count]) |live| if (std.mem.eql(u8, &live.scope_key, &ban.key)) {
                            removed = live.status == .absent or live.status == .expired or !live.desired.live(now);
                        };
                        if (removed) ban.lift = .confirmed else pending += 1;
                    },
                }
            }
            if (pending != 0 and monotonic(self) < request.deadline_ms) return;
            for (ignore_state.bans[0..ignore_state.ban_count]) |*ban| if (ban.lift == .pending) {
                ban.lift = .incomplete;
                ban.reason = "kernel removal not confirmed within the deadline";
            };
            if (ignore_state.lifting) self.publishOwners() catch |failure| if (failure != error.StaleEffect) {
                std.log.warn("native: owner view not republished after ignore lifts: {s}", .{@errorName(failure)});
            };
            self.completeAdmin(request, self.finishIgnoreAdd(request));
        }
        pub fn finishIgnoreAdd(self: *Coordinator, request: *AdminRequest) AdminOutcomeView {
            const ignore_state = request.ignore.?;
            var reported: durable.Store.AdminOutcome = .applied;
            var enforced = true;
            for (ignore_state.bans[0..ignore_state.ban_count]) |ban| switch (ban.lift) {
                .unknown => {
                    reported = .uncertain;
                    enforced = false;
                },
                .incomplete => {
                    if (reported != .uncertain) reported = .partial;
                    enforced = false;
                },
                .refused => if (reported == .applied) {
                    reported = .rejected;
                },
                .kept, .pending, .confirmed => {},
            };
            const recorded: durable.Store.AdminOutcome = if (reported == .rejected and ignore_state.mutated) .partial else reported;
            var finished = self.adminDetail(request, (AdminOutcomeView{ .outcome = recorded, .kind = request.kind, .enforced = enforced }), null);
            if (finished.outcome == recorded) finished.outcome = reported;
            return finished;
        }
        pub fn executeIgnoreAdd(self: *Coordinator, request: *AdminRequest) !AdminOutcomeView {
            const ignore_state = request.ignore.?;
            const entry = request.ignore_entry.?;
            const name = request.jailName();
            const jail_cfg = findConfigJail(self.live_cfg, name) orelse return self.ignoreRefusal(request, .rejected, "jail '{s}' is not configured", .{name});
            if (jail_cfg.rule_files.len != 0) return self.ignoreRefusal(request, .rejected, "jail '{s}' uses rule_files; manage its exclusions through ignore_file", .{name});
            const jail = self.findJail(name);
            if (jail) |value| if (ignoreCell(value) == null) return self.ignoreRefusal(request, .rejected, "jail '{s}' reads internal events and has no ignore list", .{name});
            var runtime: [ignore_set.max_entries_per_part + 1]RuntimeIgnoreEntry = undefined;
            const runtime_count = try self.store.ignoreEntries(name, runtime[0..ignore_set.max_entries_per_part]);
            const literals = jail_cfg.ignoreip orelse self.live_cfg.defaults.ignoreip;
            const resolved = config.resolveJailFromConfig(jail_cfg, self.live_cfg.defaults);
            const now = self.clock.wallUs();
            const deadlines = try configuredIgnoreDeadlines(self.allocator, &self.store, name, literals, resolved.ignoretime_s, .read, now);
            defer self.allocator.free(deadlines);
            const own: []const shared.IpAddress = if (resolved.ignoreself) self.selfAddressList() else &.{};
            const before = try ignore_set.EffectiveIgnore.build(self.allocator, literals, deadlines, runtime[0..runtime_count], own, now);
            defer before.deinit(self.allocator);
            var existing: ?ignore_set.Source = null;
            for (before.entries) |item| if (item.entry.order(entry) == .eq and item.source != .self and !item.expired) {
                existing = item.source;
            };
            var entry_text: [64]u8 = undefined;
            const canonical = entry.canonical(&entry_text);
            if (request.duration_s != null and existing != null and existing.? == .config)
                return self.ignoreRefusal(request, .rejected, "--for applies to runtime entries only; {s} is configured in ignoreip", .{canonical});
            const expires_us: ?i64 = if (request.duration_s orelse resolved.ignoretime_s) |seconds| now + @as(i64, @intCast(seconds)) * std.time.us_per_s else null;
            ignore_state.expires_us = expires_us;
            const recorded = existing != null and existing.? != .config;
            if (!recorded and before.entries.len + @intFromBool(existing == null) > ignore_set.distinct_bound)
                return self.ignoreRefusal(
                    request,
                    .rejected,
                    "jail {s} already has {d} ignore entries (configuration and runtime combined), the limit. Remove one with fail2zig ignore remove first.",
                    .{ name, before.entries.len },
                );
            runtime[runtime_count] = .{ .entry = entry, .expires_us = expires_us };
            if (recorded) for (runtime[0..runtime_count]) |*item| if (item.entry.order(entry) == .eq) {
                if (item.expires_us) |held| if (expires_us == null or expires_us.? > held) {
                    item.expires_us = expires_us;
                };
            };
            const after = ignore_set.EffectiveIgnore.build(self.allocator, literals, deadlines, runtime[0 .. runtime_count + @intFromBool(!recorded)], own, now) catch |failure| switch (failure) {
                error.IgnoreCapacityExceeded => return self.ignoreRefusal(
                    request,
                    .rejected,
                    "jail {s} already has {d} ignore entries (configuration and runtime combined), the limit. Remove one with fail2zig ignore remove first.",
                    .{ name, before.entries.len },
                ),
                else => return failure,
            };
            var installed = false;
            defer if (!installed) after.deinit(self.allocator);
            if (jail) |value| try self.collectRelatedBans(request, value);
            if (request.unban and ignore_state.inside_total > max_lifted_bans)
                return self.ignoreRefusal(
                    request,
                    .rejected,
                    "{s} covers {d} bans in {s}; --unban lifts at most {d} per command. Nothing changed. Add the entry without --unban, then lift bans with fail2zig unban.",
                    .{ canonical, ignore_state.inside_total, name, max_lifted_bans },
                );
            ignore_state.entry_state = .present;
            const result = self.store.addIgnoreEntry(name, entry, now, expires_us) catch |failure| {
                if (failure == error.IgnoreCapacity)
                    return self.ignoreRefusal(
                        request,
                        .rejected,
                        "jail {s} already has {d} ignore entries (configuration and runtime combined), the limit. Remove one with fail2zig ignore remove first.",
                        .{ name, before.entries.len },
                    );
                if (failure == error.StorageCapacity)
                    return self.ignoreRefusal(
                        request,
                        .rejected,
                        "state file at capacity (StorageCapacity); the entry for jail {s} was not added. Retry when fail2zig status shows intake open.",
                        .{name},
                    );
                std.log.err("native admin: ignore entry commit failed: {s}", .{@errorName(failure)});
                return self.ignoreUncertain(request);
            };
            if (result != .present) {
                ignore_state.entry_state = .added;
                ignore_state.mutated = true;
                request.mutation_committed = true;
            }
            recordConfiguredCover(ignore_state, after, entry, false);
            if (jail) |value| {
                self.replaceIgnoreList(value, after);
                installed = true;
            }
            if (ignore_state.entry_state == .added) {
                const lifting = if (request.unban) ignore_state.inside_total else 0;
                if (lifting != 0)
                    std.log.info(
                        "native: jail={} ignore entry added: {} (runtime); unban requested for {d} {s}",
                        .{ std.zig.fmtEscapes(name), std.zig.fmtEscapes(canonical), lifting, if (lifting == 1) "ban" else "bans" },
                    )
                else
                    std.log.info("native: jail={} ignore entry added: {} (runtime); existing bans unchanged", .{ std.zig.fmtEscapes(name), std.zig.fmtEscapes(canonical) });
            }
            if (request.unban) self.liftIgnoredBans(request, jail);
            if (ignore_state.lifting) {
                request.expect_absent = true;
                request.scope_key = [_]u8{0} ** 32;
                request.phase = .awaiting;
                request.deadline_ms = monotonic(self) + ignore_lift_settle_ms;
                return .{ .outcome = .applied, .kind = request.kind, .generation = self.published_generation };
            }
            return self.finishIgnoreAdd(request);
        }
        pub fn executeIgnoreRemove(self: *Coordinator, request: *AdminRequest) !AdminOutcomeView {
            const ignore_state = request.ignore.?;
            const entry = request.ignore_entry.?;
            const name = request.jailName();
            ignore_state.entry_state = .not_removed;
            const jail_cfg = findConfigJail(self.live_cfg, name);
            if (jail_cfg == null) {
                var stored: [128]durable.Store.IgnoreJailCount = undefined;
                const stored_count = try self.store.ignoreEntryJails(&stored);
                var known = false;
                for (stored[0..stored_count]) |item| if (std.mem.eql(u8, item.jail[0..item.jail_len], name)) {
                    known = true;
                };
                if (!known) return self.ignoreRefusal(request, .rejected, "jail '{s}' is not configured", .{name});
            }
            const jail = self.findJail(name);
            var runtime: [ignore_set.max_entries_per_part]RuntimeIgnoreEntry = undefined;
            const runtime_count = try self.store.ignoreEntries(name, &runtime);
            const literals: []const []const u8 = if (jail_cfg) |value| (if (value.rule_files.len != 0) &.{} else value.ignoreip orelse self.live_cfg.defaults.ignoreip) else &.{};
            const resolved: ?config.ResolvedJailConfig = if (jail_cfg) |value| config.resolveJailFromConfig(value, self.live_cfg.defaults) else null;
            const now = self.clock.wallUs();
            const deadlines = try configuredIgnoreDeadlines(self.allocator, &self.store, name, literals, if (resolved) |value| value.ignoretime_s else null, .read, now);
            defer self.allocator.free(deadlines);
            const own: []const shared.IpAddress = if (resolved != null and resolved.?.ignoreself) self.selfAddressList() else &.{};
            const before = try ignore_set.EffectiveIgnore.build(self.allocator, literals, deadlines, runtime[0..runtime_count], own, now);
            defer before.deinit(self.allocator);
            var entry_text: [64]u8 = undefined;
            const canonical = entry.canonical(&entry_text);
            var existing: ?ignore_set.Source = null;
            for (before.entries) |item| if (item.entry.order(entry) == .eq and item.source != .self and !item.expired) {
                existing = item.source;
            };
            if (existing != null and existing.? == .config) {
                ignore_state.entry_state = .config_only;
                recordConfiguredCover(ignore_state, before, entry, true);
                if (self.config_path.len != 0 and self.config_path.len <= 96)
                    return self.ignoreRefusal(
                        request,
                        .rejected,
                        "{s} is set in the configuration file for jail {s} and cannot be removed at runtime. Edit ignoreip in {s} and run fail2zig reload.",
                        .{ canonical, name, self.config_path },
                    );
                return self.ignoreRefusal(
                    request,
                    .rejected,
                    "{s} is set in the configuration file for jail {s} and cannot be removed at runtime. Edit ignoreip in the configuration file and run fail2zig reload.",
                    .{ canonical, name },
                );
            }
            if (existing == null) {
                ignore_state.entry_state = .absent;
                recordConfiguredCover(ignore_state, before, entry, false);
                return self.ignoreRefusal(request, .absent, "jail {s} has no runtime ignore entry {s}.", .{ name, canonical });
            }
            var kept: [ignore_set.max_entries_per_part]RuntimeIgnoreEntry = undefined;
            var kept_count: usize = 0;
            for (runtime[0..runtime_count]) |item| if (item.entry.order(entry) != .eq) {
                kept[kept_count] = item;
                kept_count += 1;
            };
            const after = try ignore_set.EffectiveIgnore.build(self.allocator, literals, deadlines, kept[0..kept_count], own, now);
            var installed = false;
            defer if (!installed) after.deinit(self.allocator);
            const removed = self.store.removeIgnoreEntry(name, entry) catch |failure| {
                std.log.err("native admin: ignore entry removal failed: {s}", .{@errorName(failure)});
                return self.ignoreUncertain(request);
            };
            if (!removed) {
                ignore_state.entry_state = .absent;
                recordConfiguredCover(ignore_state, after, entry, false);
                return self.ignoreRefusal(request, .absent, "jail {s} has no runtime ignore entry {s}.", .{ name, canonical });
            }
            ignore_state.entry_state = .removed;
            ignore_state.mutated = true;
            request.mutation_committed = true;
            recordConfiguredCover(ignore_state, after, entry, true);
            if (jail) |value| if (ignoreCell(value) != null) {
                self.replaceIgnoreList(value, after);
                installed = true;
            };
            std.log.info(
                "native: jail={} ignore entry removed: {} (runtime); configuration still covers it: {s}",
                .{ std.zig.fmtEscapes(name), std.zig.fmtEscapes(canonical), if (ignore_state.configured_count != 0) "yes" else "no" },
            );
            return self.adminDetail(request, .{ .outcome = .applied, .kind = request.kind, .enforced = true }, null);
        }
    };
}
