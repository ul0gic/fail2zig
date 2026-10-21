// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const config = @import("config/native.zig");
const detection = @import("core/native_detection_record.zig");
const effect = @import("core/native_effect.zig");
const effect_runtime = @import("runtime/native_effect_runtime.zig");
const firewall_observation = effect_runtime.observation;
const history = @import("core/native_effect_history.zig");
const inspection = @import("firewall/inspection.zig");
const durable = @import("core/record_store.zig");
const pipeline = @import("core/record_pipeline.zig");
const files = @import("core/durable_file_source.zig");
const ignore_set = @import("core/native_ignore_set.zig");
const native_banip = @import("config/native_banip.zig");
const RuntimeIgnoreEntry = @import("store/ignore_entries.zig").RuntimeIgnoreEntry;
const build_options = @import("build_options");
const version = build_options.version;
const diag_mod = @import("core/diag.zig");
const query_v1 = @import("net/query_v1.zig");
const readiness = @import("core/readiness.zig");
const metrics_mod = @import("core/metrics.zig");
const ban_origin = @import("core/ban_origin.zig");
const daemon = @import("native_daemon.zig");
const max_jails = daemon.max_jails;
const max_sources_per_jail = daemon.max_sources_per_jail;
const Jail = daemon.Jail;
const SourceStatus = daemon.SourceStatus;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const configuredIgnoreDeadlines = Coordinator.configuredIgnoreDeadlines;
        const findConfigJail = Coordinator.findConfigJail;
        const formatListSubject = Coordinator.formatListSubject;
        const ignoreCell = Coordinator.ignoreCell;
        const ignoreSourceText = Coordinator.ignoreSourceText;
        const jailPaused = Coordinator.jailPaused;
        const monotonic = Coordinator.monotonic;
        const observationMs = Coordinator.observationMs;
        const observationSound = Coordinator.observationSound;
        const quiet_interval_ms = Coordinator.quiet_interval_ms;
        const sessionProcessor = Coordinator.sessionProcessor;
        pub fn publishPool(self: *Coordinator, now_ms: u64) !void {
            if (self.last_pool_ms) |last| if (now_ms -| last < quiet_interval_ms) return;
            self.last_pool_ms = now_ms;
            const occupancy = try self.store.retryPoolOccupancy(self.clock.wallUs());
            self.metrics_state.setPoolOccupancy(occupancy.tracked, occupancy.banned);
            for (self.jails) |jail| {
                self.metrics_state.jailSetPoolEvictions(jail.name, self.store.evictionCount(jail.name));
                const processor = sessionProcessor(&jail);
                self.metrics_state.jailSetFailuresCounted(jail.name, jail.failures_carried +| if (processor) |value| value.failures_counted else 0);
                self.metrics_state.jailSetIgnoredDetections(jail.name, jail.ignored_carried +| if (processor) |value| value.ignored_detections else 0);
            }
            const footprint = try self.store.stateFileFootprint();
            self.metrics_state.setStateFile(footprint.bytes, footprint.pages);
            self.mutex.lock();
            self.published_pool = occupancy;
            self.published_footprint = footprint;
            self.mutex.unlock();
        }
        const LossJson = struct { sequence: u64, wall_us: i64, reason: []const u8, inode: u64, committed_offset: u64, observed_size: ?u64 };
        const SourceJson = struct {
            jail: []const u8,
            kind: []const u8,
            path: ?[]const u8,
            on_truncation: ?[]const u8,
            state: []const u8,
            cause: ?[]const u8,
            inode: ?u64,
            committed_offset: ?u64,
            observed_size: ?u64,
            repair: ?[]const u8,
            loss_events: u16,
            last_loss: ?LossJson,
        };
        const redacted_text = "<redacted>";
        pub fn sourceStatusOrder(_: void, a: *const SourceStatus, b: *const SourceStatus) bool {
            return switch (std.mem.order(u8, a.jail, b.jail)) {
                .lt => true,
                .gt => false,
                .eq => std.mem.lessThan(u8, a.path orelse "", b.path orelse ""),
            };
        }
        pub fn lossJson(event: files.LossEvent) LossJson {
            return .{ .sequence = event.sequence, .wall_us = event.wall_us, .reason = @tagName(event.reason), .inode = event.inode, .committed_offset = event.committed_offset, .observed_size = event.observed_size };
        }
        pub fn writeSources(self: *const Coordinator, writer: anytype, redact: bool) !void {
            var ordered: [max_jails * (max_sources_per_jail + 1)]*const SourceStatus = undefined;
            var count: usize = 0;
            for (self.jails) |*jail| for (jail.source_status) |*entry| {
                ordered[count] = entry;
                count += 1;
            };
            std.sort.pdq(*const SourceStatus, ordered[0..count], {}, sourceStatusOrder);
            try writer.writeByte('[');
            for (ordered[0..count], 0..) |entry, index| {
                if (index != 0) try writer.writeByte(',');
                try std.json.stringify(SourceJson{
                    .jail = entry.jail,
                    .kind = @tagName(entry.kind),
                    .path = if (entry.path != null and redact) redacted_text else entry.path,
                    .on_truncation = if (entry.on_truncation) |policy| @tagName(policy) else null,
                    .state = @tagName(entry.state),
                    .cause = entry.cause,
                    .inode = entry.inode,
                    .committed_offset = entry.committed_offset,
                    .observed_size = entry.observed_size,
                    .repair = if (entry.repair != null and redact) redacted_text else entry.repair,
                    .loss_events = entry.loss_events,
                    .last_loss = if (entry.last_loss) |event| lossJson(event) else null,
                }, .{}, writer);
            }
            try writer.writeByte(']');
        }
        pub fn statusPayload(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, redact: bool) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            const gate = self.published_health;
            const sampled_wall = self.observationWall();
            const sampled_ms = observationMs();
            const effect_ms = monotonic(self);
            const observation = self.worker_observation.read(sampled_ms, sampled_wall);
            var healthy = gate.phase == .healthy and observationSound(observation);
            var decisions: u64 = 0;
            var installed: u32 = 0;
            var unhealthy_sources: u32 = 0;
            var paused_sources: u32 = 0;
            var unpaused_unhealthy: u32 = 0;
            var blocked_source: ?[]const u8 = null;
            const now = sampled_wall orelse self.start_us;
            for (self.jails) |jail| {
                healthy = healthy and jail.healthy;
                if (!jail.healthy) unhealthy_sources += 1;
                if (!jail.healthy and !jailPaused(&jail)) unpaused_unhealthy += 1;
                if (!jail.healthy and blocked_source == null) if (jail.source_error) |cause| if (pipeline.Pipeline.commitBlocked(cause)) {
                    blocked_source = @errorName(cause);
                };
                for (jail.source_status) |entry| paused_sources += @intFromBool(entry.state == .paused);
                decisions +|= jail.summary.decisions;
                installed +|= self.confirmedCount(jail, now, effect_ms) orelse 0;
            }
            if (self.published_effects) |effects| healthy = healthy and !(effects.uncertain and !self.published_view.transient_uncertain);
            if (self.backend_failure != null) healthy = false;
            const known = self.knowledge(effect_ms);
            const withdrawn = if (self.published_effects) |effects| effects.withdrawn else false;
            const protection: []const u8 = if (!healthy or withdrawn) "degraded" else if (self.published_effects == null) "log-only" else if (known.? == .none) "unknown" else if (known.? == .stale or self.overBlocking()) "degraded" else "active";
            const active_bans: ?u32 = if (known) |k| (if (k == .none) null else self.published_view.installed_live) else installed;
            const knowledge_cause: ?[]const u8 = if (known) |k| switch (k) {
                .stale => "ReadbackStale",
                .none => if (self.published_effects.?.cause == null) "ReadbackPending" else null,
                .fresh => null,
            } else null;
            const generation_hex = std.fmt.bytesToHex(self.published_generation, .lower);
            const effect_diagnostic = if (self.published_effects) |effects| effects.diagnostic else null;
            const none_cause: []const u8 = if (paused_sources != 0 and unpaused_unhealthy == 0) "SourcePaused" else blocked_source orelse "none";
            const payload_start = out.items.len;
            try std.json.stringify(.{ .version = version, .runtime = "native", .generation = &generation_hex, .mutation_revision = self.published_revision, .state = protection, .protection = protection, .protection_cause = if (self.backend_failure) |failure| @as(?[]const u8, @errorName(failure)) else null, .active_bans = active_bans, .total_bans = self.published_confirmations, .knowledge = if (known) |k| @as(?[]const u8, @tagName(k)) else null, .confirmed_at_us = if (known != null and known.? != .none) self.published_view.readback_wall_us else null, .knowledge_age_ms = if (known != null and known.? != .none) self.knowledgeAgeMs(effect_ms) else null, .pending_bans = if (known != null) @as(?u64, self.published_view.pending) else null, .oldest_pending_ms = if (known != null) ageMs(now, self.published_view.oldest_pending_us) else null, .overdue_removals = if (known != null) @as(?u64, self.published_view.overdue_blocking) else null, .oldest_overdue_ms = if (known != null) ageMs(now, self.published_view.oldest_overdue_blocking_us) else null, .overdue_bookkeeping = if (known != null) @as(?u64, self.published_view.overdue -| self.published_view.overdue_blocking) else null, .dump_interrupted = if (known != null) @as(?u64, self.published_view.dump_interrupted) else null, .storage = @tagName(gate.phase), .cause = if (gate.phase == .intervention and gate.last_failure != null) @errorName(gate.last_failure.?.cause) else if (observation.clock_uncertain) "ClockUncertain" else if (observation.stalled) "WorkerStalled" else if (withdrawn) "FirewallWithdrawn" else if (known != null and known.? == .none and knowledge_cause != null) knowledge_cause.? else if (self.overBlocking()) "EffectRemovalOverdue" else if (knowledge_cause) |cause| cause else if (gate.last_failure) |failure| @errorName(failure.cause) else if (self.published_effects) |effects| if (effects.cause) |cause| @errorName(cause) else none_cause else if (self.backend_failure) |failure| @errorName(failure) else none_cause, .sqlite_code = if (gate.last_failure) |failure| failure.diagnostics.sqlite_code else null, .next_retry_ms = gate.next_retry_ms, .committed_records = gate.committed_records, .decisions_total = decisions, .jails_active = self.jails.len, .unhealthy_sources = unhealthy_sources, .backend = self.published_backend, .effect_backend = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.backend)) else null, .effect_stage = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.stage)) else null, .effect_cause = if (effect_diagnostic) |detail| @as(?[]const u8, @errorName(detail.cause)) else null, .effect_mutation = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.mutation)) else null, .effects_uncertain = observation.expiry_uncertain or (if (self.published_effects) |effects| effects.uncertain else false), .overdue_effects = if (self.published_effects) |effects| effects.overdue else 0, .worker_busy = observation.busy, .worker_stalled = observation.stalled, .worker_busy_age_ms = observation.busy_age_ms, .worker_heartbeat_age_ms = observation.heartbeat_age_ms, .clock_uncertain = observation.clock_uncertain, .expiry_overdue = observation.expiry_overdue, .expiry_uncertain = observation.expiry_uncertain, .next_committed_expiry_us = observation.next_committed_expiry_us, .memory_admission_bytes = self.resources.snapshot().used_bytes, .uptime_seconds = if (observation.clock_uncertain) @as(?u64, null) else @as(u64, @intCast(@max(0, @divTrunc(now -| self.start_us, 1_000_000)))) }, .{ .emit_null_optional_fields = false }, out.writer(a));
            if (out.items.len == payload_start or out.items[out.items.len - 1] != '}') return error.InvalidStatusPayload;
            out.items.len -= 1;
            const writer = out.writer(a);
            try writer.print(",\"paused_sources\":{d}", .{paused_sources});
            if (self.published_footprint) |footprint| try writer.print(",\"state_file_bytes\":{d},\"state_file_pages\":{d},\"state_file_max_pages\":{d}", .{ footprint.bytes, footprint.pages, footprint.max_pages });
            if (self.published_pool) |pool| try writer.print(",\"pool_tracked\":{d},\"pool_banned\":{d},\"pool_tracking_limit\":{d},\"pool_ban_limit\":{d}", .{ pool.tracked, pool.banned, pool.tracking_limit, pool.ban_limit });
            try writer.writeAll(",\"sources\":");
            try self.writeSources(writer, redact);
            try writer.writeByte('}');
        }
        pub fn knowledgeAgeMs(self: *const Coordinator, now_ms: ?u64) ?u64 {
            const readback = self.published_view.readback_ns orelse return null;
            const now = now_ms orelse return null;
            return ((now *| std.time.ns_per_ms) -| readback) / std.time.ns_per_ms;
        }
        pub fn ageMs(now_us: i64, then_us: ?i64) ?u64 {
            const then = then_us orelse return null;
            return @intCast(@max(0, @divTrunc(now_us -| then, 1000)));
        }
        pub fn bans(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            try self.writeBans(out, a, null);
        }
        pub fn writeBans(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, selected: ?shared.JailId) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            const sampled_wall = self.observationWall();
            const observation = self.worker_observation.read(observationMs(), sampled_wall);
            const w = out.writer(a);
            try w.writeAll("[");
            var first = true;
            for (self.jails) |jail| {
                if (selected) |name| if (!std.mem.eql(u8, name.slice(), jail.name)) continue;
                if (self.jailEnforces(&jail)) {
                    for (self.owner_active[0..self.owner_count], 0..) |owner, i| {
                        if (!std.mem.eql(u8, owner.jail.slice(), jail.name)) continue;
                        if (!observation.clock_uncertain and sampled_wall != null and !owner.lease.live(sampled_wall.?)) continue;
                        if (!first) try w.writeByte(',');
                        first = false;
                        var buffer: [64]u8 = undefined;
                        const formatted = try formatListSubject(owner.scope.canonical.subject, &buffer);
                        const confirmed = self.owner_confirmed[i] and self.confirmationKnown(monotonic(self));
                        const expiry_us: ?i64 = switch (owner.lease) {
                            .finite => |value| value,
                            .permanent => null,
                            .absent => return error.InvalidEffect,
                        };
                        try std.json.stringify(.{ .ip = formatted, .jail = owner.jail.slice(), .origin = @tagName(owner.origin), .expired = false, .expiry_us = expiry_us, .ban_expiry = if (expiry_us) |value| @divFloor(value, 1_000_000) else null, .permanent = owner.lease == .permanent, .ban_count = owner.ordinal, .enforced = confirmed, .confirmed = confirmed }, .{}, w);
                    }
                    continue;
                }
                for (jail.active[0..jail.summary.active], 0..) |decision, i| {
                    if (!observation.clock_uncertain and sampled_wall != null and !decision.lease.live(sampled_wall.?)) continue;
                    if (!first) try w.writeByte(',');
                    first = false;
                    const address: shared.IpAddress = switch (decision.subject) {
                        .v4 => |v| .{ .ipv4 = std.mem.readInt(u32, &v, .big) },
                        .v6 => |v| .{ .ipv6 = std.mem.readInt(u128, &v, .big) },
                    };
                    var buffer: [64]u8 = undefined;
                    const formatted = try std.fmt.bufPrint(&buffer, "{}", .{address});
                    const confirmed = jail.confirmed[i] and self.confirmationKnown(monotonic(self));
                    const expiry_us: ?i64 = switch (decision.lease) {
                        .finite => |value| value,
                        .permanent => null,
                        .absent => return error.InvalidRetryState,
                    };
                    try std.json.stringify(.{ .ip = formatted, .jail = jail.name, .origin = @tagName(shared.types.Origin.detection), .expired = false, .expiry_us = expiry_us, .ban_expiry = if (expiry_us) |value| @divFloor(value, 1_000_000) else null, .permanent = decision.lease == .permanent, .ban_count = decision.ordinal, .enforced = confirmed, .confirmed = confirmed }, .{}, w);
                }
            }
            if (self.history_reader) |*reader| {
                var arena_state = std.heap.ArenaAllocator.init(a);
                defer arena_state.deinit();
                const now = sampled_wall orelse self.start_us;
                for (self.jails) |jail| {
                    if (selected) |name| if (!std.mem.eql(u8, name.slice(), jail.name)) continue;
                    for (try self.expiredBans(reader, arena_state.allocator(), jail.name, now)) |expired| {
                        if (!first) try w.writeByte(',');
                        first = false;
                        var buffer: [64]u8 = undefined;
                        try std.json.stringify(.{ .ip = expired.entry.canonical(&buffer), .jail = jail.name, .origin = @tagName(shared.types.Origin.config), .expired = true, .expiry_us = expired.expires_us, .ban_expiry = @divFloor(expired.expires_us, 1_000_000), .permanent = false, .ban_count = 0, .enforced = false, .confirmed = false }, .{}, w);
                    }
                }
            }
            try w.writeAll("]");
            if (out.items.len > shared.protocol.max_payload_size - 16) return error.SnapshotLimit;
        }
        const ExpiredBan = struct { entry: shared.types.IgnoreEntry, decision_id: [32]u8, expires_us: i64 };
        pub fn expiredBans(self: *Coordinator, reader: *durable.Store, arena: std.mem.Allocator, jail_name: []const u8, now_us: i64) ![]const ExpiredBan {
            const jail_cfg = findConfigJail(self.live_cfg, jail_name) orelse return &.{};
            const entries = try arena.alloc(ban_origin.BanListEntry, native_banip.max_banip_entries);
            const count = try native_banip.effectiveBanList(self.live_cfg, jail_cfg, entries);
            const timed = try arena.alloc(shared.types.TimedEntry, count);
            for (entries[0..count], timed) |item, *slot| slot.* = .{ .entry = item.entry, .duration_s = item.duration_s };
            const deadlines = try arena.alloc(?i64, count);
            try reader.configEntryDeadlines(.banip, jail_name, timed, deadlines);
            var expired: std.ArrayListUnmanaged(ExpiredBan) = .{};
            for (entries[0..count], deadlines) |item, deadline| {
                const expires_us = deadline orelse continue;
                if (expires_us > now_us) continue;
                try expired.append(arena, .{ .entry = item.entry, .decision_id = item.decisionId(), .expires_us = expires_us });
            }
            return expired.items;
        }
        pub fn expiredKey(index: usize) query_v1.ItemKey {
            var bytes = [_]u8{0xff} ** 33;
            std.mem.writeInt(u16, bytes[31..33], @intCast(index), .big);
            return query_v1.ItemKey.init(&bytes);
        }
        pub fn expiredIndex(cursor: []const u8) ?usize {
            if (cursor.len != 33 or !std.mem.allEqual(u8, cursor[0..31], 0xff)) return null;
            return std.mem.readInt(u16, cursor[31..33], .big);
        }
        pub fn expiredScopeItem(expired: ExpiredBan, index: usize) !query_v1.ScopeItem {
            const address = expired.entry.network();
            const full: u8 = if (expired.entry.family == .v4) 32 else 128;
            const subject = if (expired.entry.prefix == full) inspection.canonical_scope.Subject.host(address) else try inspection.canonical_scope.Subject.network(address, expired.entry.prefix);
            return .{ .scope = try query_v1.projectScope(.{ .subject = subject }), .lease = .finite, .deadline_us = expired.expires_us, .decision_id = expired.decision_id, .confirmed = false, .ban_count = 0, .key = expiredKey(index), .origin = .config, .expired = true };
        }
        pub fn metrics(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            self.mutex.lock();
            defer self.mutex.unlock();
            const observation = self.observedWorker();
            var snapshot = self.metrics_state.snapshot();
            snapshot.native = .{ .storage_healthy = self.published_health.phase == .healthy and observationSound(observation), .committed_records = self.published_health.committed_records, .worker_stalled = observation.stalled, .worker_busy = observation.busy, .worker_heartbeat_age_ms = observation.heartbeat_age_ms, .worker_busy_age_ms = observation.busy_age_ms, .clock_uncertain = observation.clock_uncertain, .expiry_overdue = observation.expiry_overdue, .expiry_uncertain = observation.expiry_uncertain };
            if (self.published_pool) |pool| {
                snapshot.pool_tracked = pool.tracked;
                snapshot.pool_banned = pool.banned;
                snapshot.pool_tracking_limit = pool.tracking_limit;
                snapshot.pool_ban_limit = pool.ban_limit;
            }
            const now = self.observationWall() orelse self.start_us;
            const effect_ms = monotonic(self);
            var live: usize = 0;
            for (snapshot.perJail()) |series| {
                const jail = self.findJail(series.name()) orelse continue;
                var kept = series;
                kept.active_bans = self.confirmedCount(jail.*, now, effect_ms) orelse 0;
                kept.source_state = sourceState(jail);
                snapshot.jails[live] = kept;
                live += 1;
            }
            snapshot.jails_len = live;
            try metrics_mod.renderPrometheus(&snapshot, out.writer(a));
            if (comptime build_options.diag) try diag_mod.writeMetrics(out.writer(a));
            if (comptime build_options.diag) {
                const sample = self.clock.snapshot();
                try out.writer(a).print("f2z_diag_clock_rate {d}\nf2z_diag_clock_wall_us {d}\nf2z_diag_clock_regressions {d}\n", .{ sample.rate, sample.wall_us, sample.regressions });
            }
        }
        pub fn sourceState(jail: *const Jail) u8 {
            if (jail.source_error) |cause| if (pipeline.Pipeline.commitBlocked(cause)) return 3;
            if (jail.source_missing) return 2;
            if (jailPaused(jail) or !jail.healthy) return 1;
            return 0;
        }
        pub fn healthView(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            const report = self.readinessReport();
            try readiness.writeJson(report, out.writer(a));
        }
        const StatusQuery = struct { coordinator: *Coordinator, redact: bool };
        pub fn statusCallback(ctx: ?*anyopaque, a: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
            const query: *StatusQuery = @ptrCast(@alignCast(ctx.?));
            var unmanaged: std.ArrayListUnmanaged(u8) = .{};
            defer unmanaged.deinit(a);
            try query.coordinator.statusPayload(&unmanaged, a, query.redact);
            try out.appendSlice(unmanaged.items);
        }
        pub fn healthCallback(ctx: ?*anyopaque, a: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
            var unmanaged: std.ArrayListUnmanaged(u8) = .{};
            defer unmanaged.deinit(a);
            try healthView(ctx, &unmanaged, a);
            try out.appendSlice(unmanaged.items);
        }
        pub fn continuityRender(ctx: ?*anyopaque, arena: std.mem.Allocator, cursor: ?u64, limit: u16, redact: bool, out: *query_v1.JsonStream) anyerror!void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
            const events = try arena.alloc(files.LossEvent, limit);
            const count = try reader.continuityEvents(null, cursor, events, arena);
            try out.objectField("items");
            try out.beginArray();
            for (events[0..count]) |event| {
                try out.beginObject();
                try out.objectField("sequence");
                try out.write(event.sequence);
                try out.objectField("jail");
                try out.write(event.jail);
                try out.objectField("path");
                try out.write(if (redact) redacted_text else event.path);
                try out.objectField("wall_us");
                try out.write(event.wall_us);
                try out.objectField("reason");
                try out.write(@tagName(event.reason));
                try out.objectField("inode");
                try out.write(event.inode);
                try out.objectField("committed_offset");
                try out.write(event.committed_offset);
                try out.objectField("observed_size");
                try out.write(event.observed_size);
                try out.endObject();
            }
            try out.endArray();
            try out.objectField("next_cursor");
            if (count == limit and count != 0) {
                var buffer: [20]u8 = undefined;
                try out.write(try std.fmt.bufPrint(&buffer, "{d}", .{events[count - 1].sequence}));
            } else try out.write(null);
        }
        pub fn writeIgnoreJail(out: *query_v1.JsonStream, name: []const u8, enabled: bool, ignore_file: ?[]const u8, items: []const ignore_set.Item, hostnames: []const []const u8, redact: bool, now_us: i64) !void {
            try out.beginObject();
            try out.objectField("jail");
            try out.write(name);
            try out.objectField("enabled");
            try out.write(enabled);
            try out.objectField("count");
            try out.write(items.len + hostnames.len);
            try out.objectField("ignore_file");
            try out.write(if (ignore_file != null and redact) @as(?[]const u8, redacted_text) else ignore_file);
            try out.objectField("entries");
            try out.beginArray();
            for (items) |item| {
                var buffer: [64]u8 = undefined;
                try out.beginObject();
                try out.objectField("address");
                try out.write(if (redact) redacted_text else item.entry.canonical(&buffer));
                try out.objectField("source");
                try out.write(ignoreSourceText(item.source).?);
                const expired = if (item.expires_us) |deadline| deadline <= now_us else false;
                try out.objectField("expires_us");
                try out.write(item.expires_us);
                try out.objectField("remaining_s");
                if (item.expires_us) |deadline| try out.write(if (expired) 0 else @as(u64, @intCast(@divFloor(deadline - now_us + std.time.us_per_s - 1, std.time.us_per_s)))) else try out.write(null);
                try out.objectField("expired");
                try out.write(expired);
                try out.endObject();
            }
            for (hostnames) |literal| {
                try out.beginObject();
                try out.objectField("address");
                try out.write(if (redact) redacted_text else literal);
                try out.objectField("source");
                try out.write("config");
                try out.objectField("expires_us");
                try out.write(null);
                try out.objectField("remaining_s");
                try out.write(null);
                try out.objectField("expired");
                try out.write(false);
                try out.endObject();
            }
            try out.endArray();
            try out.endObject();
        }
        pub fn configuredIgnoreItems(arena: std.mem.Allocator, reader: *durable.Store, cfg: *const config.Config, name: []const u8, literals: []const []const u8, runtime: []const RuntimeIgnoreEntry, own: []const shared.IpAddress, now_us: i64, hostnames: *[]const []const u8) ![]const ignore_set.Item {
            const jail_cfg = findConfigJail(cfg, name);
            const resolved: ?config.ResolvedJailConfig = if (jail_cfg) |value| config.resolveJailFromConfig(value, cfg.defaults) else null;
            const deadlines = try configuredIgnoreDeadlines(arena, reader, name, literals, if (resolved) |value| value.ignoretime_s else null, .read, now_us);
            const parseable = try arena.alloc([]const u8, literals.len);
            const parseable_deadlines = try arena.alloc(?i64, literals.len);
            const names = try arena.alloc([]const u8, literals.len);
            var parseable_count: usize = 0;
            var name_count: usize = 0;
            for (literals, deadlines) |literal, deadline| {
                if (shared.types.TimedEntry.parse(literal, null)) |_| {
                    parseable[parseable_count] = literal;
                    parseable_deadlines[parseable_count] = deadline;
                    parseable_count += 1;
                } else |_| {
                    names[name_count] = literal;
                    name_count += 1;
                }
            }
            std.sort.pdq([]const u8, names[0..name_count], {}, hostnameLess);
            hostnames.* = names[0..name_count];
            const listed: []const shared.IpAddress = if (resolved != null and resolved.?.ignoreself) own else &.{};
            const list = try ignore_set.EffectiveIgnore.build(arena, parseable[0..parseable_count], parseable_deadlines[0..parseable_count], runtime, listed, now_us);
            return list.entries;
        }
        pub fn hostnameLess(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
        pub fn jailNameLess(self: *const Coordinator, a: usize, b: usize) bool {
            return std.mem.lessThan(u8, self.jails[a].name, self.jails[b].name);
        }
        pub fn ignoreRender(ctx: ?*anyopaque, arena: std.mem.Allocator, jail_filter: ?[]const u8, redact: bool, out: *query_v1.JsonStream) anyerror!void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
            var stored: [128]durable.Store.IgnoreJailCount = undefined;
            const stored_count = try reader.ignoreEntryJails(&stored);
            var filtered: [ignore_set.max_entries_per_part]RuntimeIgnoreEntry = undefined;
            var filtered_count: usize = 0;
            if (jail_filter) |name| filtered_count = try reader.ignoreEntries(name, &filtered);
            try out.objectField("limit");
            try out.write(ignore_set.distinct_bound);
            try out.objectField("jails");
            try out.beginArray();
            self.mutex.lock();
            defer self.mutex.unlock();
            var order: [max_jails]usize = undefined;
            var selected: usize = 0;
            for (self.jails, 0..) |jail, index| {
                if (jail_filter) |name| if (!std.mem.eql(u8, name, jail.name)) continue;
                order[selected] = index;
                selected += 1;
            }
            std.sort.pdq(usize, order[0..selected], @as(*const Coordinator, self), jailNameLess);
            const now = self.observationWall() orelse self.start_us;
            for (order[0..selected]) |index| {
                const jail = &self.jails[index];
                const jail_cfg = findConfigJail(self.live_cfg, jail.name);
                var hostnames: []const []const u8 = &.{};
                const items = if (ignoreCell(jail)) |cell| cell.*.entries else blk: {
                    const literals = if (jail_cfg) |value| value.ignoreip orelse self.live_cfg.defaults.ignoreip else &[_][]const u8{};
                    break :blk try configuredIgnoreItems(arena, reader, self.live_cfg, jail.name, literals, &.{}, self.selfAddressList(), now, &hostnames);
                };
                try writeIgnoreJail(out, jail.name, jail.admin_enabled, if (jail_cfg) |value| value.ignore_file else null, items, hostnames, redact, now);
            }
            if (jail_filter) |name| if (selected == 0) {
                const jail_cfg = findConfigJail(self.live_cfg, name);
                if (jail_cfg == null and filtered_count == 0) return error.UnknownJail;
                var hostnames: []const []const u8 = &.{};
                const literals = if (jail_cfg) |value| (if (value.rule_files.len != 0) &[_][]const u8{} else value.ignoreip orelse self.live_cfg.defaults.ignoreip) else &[_][]const u8{};
                const items = try configuredIgnoreItems(arena, reader, self.live_cfg, name, literals, filtered[0..filtered_count], &.{}, now, &hostnames);
                try writeIgnoreJail(out, name, false, if (jail_cfg) |value| value.ignore_file else null, items, hostnames, redact, now);
            };
            try out.endArray();
            try out.objectField("unconfigured");
            try out.beginArray();
            if (jail_filter == null) for (stored[0..stored_count]) |item| {
                const name = item.jail[0..item.jail_len];
                if (findConfigJail(self.live_cfg, name) != null) continue;
                try out.beginObject();
                try out.objectField("jail");
                try out.write(name);
                try out.objectField("runtime_entries");
                try out.write(item.count);
                try out.endObject();
            };
            try out.endArray();
        }
        const history_scan_pages = 16;
        pub fn historyRead(ctx: ?*anyopaque, jail: ?[]const u8, after_sequence: u64, limit: u16, out: *std.ArrayList(query_v1.HistoryEvent)) anyerror!query_v1.HistoryRead {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
            const installation = try reader.readInstallation() orelse return .{ .more = false, .resume_after = after_sequence };
            var events: [history.max_page]history.Event = undefined;
            var after = after_sequence;
            var appended: usize = 0;
            var pages: usize = 0;
            while (appended < limit and pages < history_scan_pages) : (pages += 1) {
                const page = try reader.confirmedEffectPage(installation, after, null, &events);
                if (page.count == 0) return .{ .more = false, .resume_after = after };
                for (events[0..page.count]) |event| {
                    if (appended == limit) return .{ .more = true, .resume_after = after };
                    after = event.sequence;
                    if (jail) |wanted| if (!std.mem.eql(u8, wanted, event.jail.slice())) continue;
                    try out.append(.{ .sequence = event.sequence, .event_id = event.event_id, .jail = try out.allocator.dupe(u8, event.jail.slice()), .decision_id = event.decision_id, .confirmed_us = event.confirmed_us, .scope = try query_v1.projectScope(event.scope.canonical), .native_retry = event.native_retry, .origin = event.origin });
                    appended += 1;
                }
                if (!page.more) return .{ .more = false, .resume_after = after };
            }
            return .{ .more = true, .resume_after = after };
        }
        pub fn firewallOrigin(ctx: ?*anyopaque, scope: inspection.CanonicalScope) ?shared.types.Origin {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            const installation = self.startup_installation orelse return null;
            const exact = effect.Scope.exact(scope) catch return null;
            const key = exact.key(installation) catch return null;
            self.mutex.lock();
            defer self.mutex.unlock();
            for (self.owner_active[0..self.owner_count]) |owner| if (std.mem.eql(u8, &owner.key, &key)) return owner.origin;
            return null;
        }
        pub fn firewallRead(ctx: ?*anyopaque, request: firewall_observation.PageRequest, out: *firewall_observation.Page) anyerror!void {
            const cache: *firewall_observation.Cache = @ptrCast(@alignCast(ctx.?));
            try cache.readPage(request, out);
        }
        pub fn queryResponse(self: *Coordinator, a: std.mem.Allocator, body: []const u8, peer_class: query_v1.PeerClass) !shared.Response {
            var arena_state = std.heap.ArenaAllocator.init(a);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            var scope_storage: []query_v1.ScopeItem = &.{};
            defer a.free(scope_storage);
            const requested_kind = query_v1.requestedKind(arena, body);
            if (requested_kind == .stats) {
                self.mutex.lock();
                var snapshot = self.published_stats;
                const generation = if (snapshot.available) self.stats_generation else self.published_generation;
                const now_ms = observationMs();
                const now_wall = self.observationWall();
                const observation = self.worker_observation.read(now_ms, now_wall);
                if (snapshot.available) {
                    const effect_ms = monotonic(self);
                    const known = self.knowledge(effect_ms) orelse .none;
                    snapshot.knowledge = @tagName(known);
                    snapshot.knowledge_age_ms = if (known == .none) null else self.knowledgeAgeMs(effect_ms);
                    if (known == .none) snapshot.last_observed_installed = null;
                    if (!observation.clock_uncertain) {
                        if (now_ms) |now| if (self.stats_published_ms) |then| {
                            if (now >= then) snapshot.snapshot_age_ms = now - then;
                        };
                        if (now_wall) |now| snapshot.uptime_seconds = @intCast(@max(0, @divTrunc(now -| self.start_us, 1_000_000)));
                    }
                } else {
                    snapshot.reason = if (self.backend_failure != null or self.suppress_enforcement) "backend_unavailable" else if (self.startup_backend != null) "not_published" else "log_only";
                    snapshot.backend = if (self.startup_backend) |backend| @tagName(backend) else null;
                }
                self.mutex.unlock();
                const result = try query_v1.handle(a, body, peer_class, generation, .{ .stats = snapshot });
                return switch (result) {
                    .payload => |bytes| .{ .ok = .{ .payload = bytes } },
                    .failure => |failure| .{ .err = .{ .code = failure.code, .message = try a.dupe(u8, failure.message) } },
                };
            }
            const firewall_request = requested_kind != null and requested_kind.? == .firewall;
            var generation: [32]u8 = undefined;
            var config_view: ?query_v1.ConfigView = null;
            var scopes_view: ?query_v1.ScopesView = null;
            var firewall_source: ?query_v1.FirewallSource = null;
            {
                self.mutex.lock();
                defer self.mutex.unlock();
                generation = self.published_generation;
                if (firewall_request) {
                    firewall_source = if (self.firewall_observation_cache) |cache|
                        .{ .cache = .{ .ctx = cache, .read = firewallRead, .origin_ctx = self, .origin = firewallOrigin } }
                    else
                        .{ .unavailable = self.firewall_observation_unavailable };
                } else {
                    const cfg = self.live_cfg;
                    const jail_configs = try arena.alloc(query_v1.JailConfig, self.jails.len);
                    const jail_scopes = try arena.alloc(query_v1.JailScopes, self.jails.len);
                    const window: ?query_v1.ScopesWindow = if (requested_kind == .scopes) query_v1.scopesWindow(arena, body) else null;
                    var counts: [max_jails]usize = [_]usize{0} ** max_jails;
                    var live_counts: [max_jails]usize = [_]usize{0} ** max_jails;
                    var expired_lists: [max_jails][]const ExpiredBan = [_][]const ExpiredBan{&.{}} ** max_jails;
                    var starts: [max_jails]usize = [_]usize{0} ** max_jails;
                    var takes: [max_jails]usize = [_]usize{0} ** max_jails;
                    var total: usize = 0;
                    const now = self.observationWall() orelse self.start_us;
                    if (window) |win| {
                        var filter: ?usize = null;
                        if (win.jail) |name| for (self.jails, 0..) |jail, i| {
                            if (std.mem.eql(u8, jail.name, name)) filter = i;
                        };
                        const first: usize = if (win.cursor_jail) |value| value else filter orelse 0;
                        var remaining: usize = win.limit;
                        for (self.jails, 0..) |jail, i| {
                            counts[i] = if (self.jailEnforces(&jail)) blk: {
                                var count: usize = 0;
                                for (self.owner_active[0..self.owner_count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), jail.name)) {
                                    count += 1;
                                };
                                break :blk count;
                            } else jail.summary.active;
                            live_counts[i] = counts[i];
                            if (self.history_reader) |*reader| expired_lists[i] = try self.expiredBans(reader, arena, jail.name, now);
                            counts[i] += expired_lists[i].len;
                            if (i < first or (filter != null and filter.? != i)) continue;
                            starts[i] = if (i == first and win.cursor_jail != null) self.keysetStart(&jail, win.cursor_key.slice(), live_counts[i]) else 0;
                            takes[i] = @min(remaining, counts[i] - starts[i]);
                            remaining -= takes[i];
                            total += takes[i];
                        }
                    }
                    scope_storage = try a.alloc(query_v1.ScopeItem, total);
                    var scope_offset: usize = 0;
                    for (self.jails, 0..) |jail, i| {
                        const source_cfg = findConfigJail(cfg, jail.name);
                        const bantime: u64 = switch (jail.policy.duration) {
                            .finite_us => |value| @intCast(@divTrunc(value, 1_000_000)),
                            .permanent => 0,
                        };
                        jail_configs[i] = .{ .name = jail.name, .enabled = jail.admin_enabled, .filter = if (source_cfg) |c| c.filter else "", .source = @tagName(jail.plan), .logpath = if (source_cfg) |c| c.logpath else &.{}, .maxretry = jail.policy.maxretry, .findtime = @intCast(@divTrunc(jail.policy.window_us, 1_000_000)), .bantime = bantime, .bantime_permanent = jail.policy.duration == .permanent, .banaction = if (self.jailEnforces(&jail)) self.published_backend else "log-only", .ignoreip = if (source_cfg) |c| (c.ignoreip orelse cfg.defaults.ignoreip) else &.{} };
                        const items = scope_storage[scope_offset..][0..takes[i]];
                        scope_offset += takes[i];
                        var filled: usize = 0;
                        if (self.jailEnforces(&jail)) {
                            var k: usize = 0;
                            var seen: usize = 0;
                            for (self.owner_active[0..self.owner_count], 0..) |owner, owner_index| {
                                if (!std.mem.eql(u8, owner.jail.slice(), jail.name)) continue;
                                if (seen < starts[i]) {
                                    seen += 1;
                                    continue;
                                }
                                if (k == items.len) break;
                                items[k] = .{ .scope = try query_v1.projectScope(owner.scope.canonical), .lease = if (owner.lease == .permanent) .permanent else .finite, .deadline_us = if (owner.lease == .finite) owner.lease.finite else null, .decision_id = owner.decision_id, .confirmed = self.owner_confirmed[owner_index] and owner.lease.live(now) and self.confirmationKnown(monotonic(self)), .ban_count = owner.ordinal, .key = query_v1.ItemKey.init(&owner.key), .origin = owner.origin };
                                k += 1;
                            }
                            filled = k;
                        } else {
                            filled = @min(items.len, live_counts[i] -| starts[i]);
                            for (jail.active[starts[i]..][0..filled], 0..) |decision, k| {
                                var address = [_]u8{0} ** 16;
                                const family: query_v1.Family = switch (decision.subject) {
                                    .v4 => |v| blk: {
                                        @memcpy(address[0..4], &v);
                                        break :blk .v4;
                                    },
                                    .v6 => |v| blk: {
                                        @memcpy(address[0..16], &v);
                                        break :blk .v6;
                                    },
                                };
                                items[k] = .{ .scope = .{ .family = family, .address = address, .prefix = if (family == .v4) 32 else 128 }, .lease = if (decision.lease == .permanent) .permanent else .finite, .deadline_us = if (decision.lease == .finite) decision.lease.finite else null, .decision_id = null, .confirmed = jail.confirmed[starts[i] + k] and decision.lease.live(now) and self.confirmationKnown(monotonic(self)), .ban_count = decision.ordinal, .key = decisionKey(decision.subject), .origin = .detection };
                            }
                        }
                        while (filled < items.len) : (filled += 1) {
                            const index = starts[i] + filled - live_counts[i];
                            items[filled] = try expiredScopeItem(expired_lists[i][index], index);
                        }
                        jail_scopes[i] = .{ .name = jail.name, .items = items, .count = counts[i], .offset = starts[i] };
                    }
                    config_view = .{ .jails = jail_configs, .global = .{ .log_level = @tagName(cfg.global.log_level), .firewall = @tagName(cfg.global.firewall), .metrics_enabled = cfg.global.metrics_enabled, .metrics_bind = cfg.global.metrics_bind, .metrics_port = cfg.global.metrics_port, .socket_path = cfg.global.socket_path, .state_file = cfg.global.state_file, .dns_server = cfg.global.dns_server, .timezone_root = cfg.global.timezone_root } };
                    if (window != null) scopes_view = .{ .jails = jail_scopes };
                }
            }
            var status_query = StatusQuery{ .coordinator = self, .redact = peer_class == .monitor };
            const result = try query_v1.handle(a, body, peer_class, generation, .{ .status = .{ .ctx = &status_query, .func = statusCallback }, .health = .{ .ctx = self, .func = healthCallback }, .config = config_view, .scopes = scopes_view, .history = .{ .ctx = self, .read = historyRead }, .firewall = firewall_source, .ignore = .{ .ctx = self, .render = ignoreRender }, .continuity = .{ .ctx = self, .render = continuityRender } });
            return switch (result) {
                .payload => |bytes| .{ .ok = .{ .payload = bytes } },
                .failure => |failure| .{ .err = .{ .code = failure.code, .message = try a.dupe(u8, failure.message) } },
            };
        }
        pub fn decisionKey(subject: detection.Subject) query_v1.ItemKey {
            var bytes: [17]u8 = undefined;
            return switch (subject) {
                .v4 => |v| blk: {
                    bytes[0] = 4;
                    @memcpy(bytes[1..5], &v);
                    break :blk query_v1.ItemKey.init(bytes[0..5]);
                },
                .v6 => |v| blk: {
                    bytes[0] = 6;
                    @memcpy(bytes[1..17], &v);
                    break :blk query_v1.ItemKey.init(bytes[0..17]);
                },
            };
        }
        pub fn keysetStart(self: *const Coordinator, jail: *const Jail, cursor: []const u8, live: usize) usize {
            if (expiredIndex(cursor)) |index| return live + index + 1;
            var count: usize = 0;
            if (self.jailEnforces(jail)) {
                for (self.owner_active[0..self.owner_count]) |owner| {
                    if (!std.mem.eql(u8, owner.jail.slice(), jail.name)) continue;
                    if (std.mem.order(u8, &owner.key, cursor) == .gt) break;
                    count += 1;
                }
            } else for (jail.active[0..jail.summary.active]) |decision| {
                const key = decisionKey(decision.subject);
                if (std.mem.order(u8, key.slice(), cursor) == .gt) break;
                count += 1;
            }
            return count;
        }
    };
}
