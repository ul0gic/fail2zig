// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Builds the status, metrics and health pages from published daemon state.
// Holds: Status and metrics values are captured while the coordinator mutex is held and serialized only after it is released.

const std = @import("std");
const files = @import("../source/durable_file_source.zig");
const pipeline = @import("../source/record_pipeline.zig");
const build_options = @import("build_options");
const version = build_options.version;
const diag_mod = @import("../diag/diag.zig");
const query_v1 = @import("../net/query_v1.zig");
const readiness = @import("../platform/readiness.zig");
const metrics_mod = @import("../diag/metrics.zig");
const http = @import("../net/http.zig");
const daemon = @import("daemon.zig");
const Jail = daemon.Jail;
const query_mod = @import("query.zig");
const CaptureMemory = query_mod.CaptureMemory;
const legacy_allowance = query_mod.legacy_allowance;
const LossJson = query_mod.LossJson;
const SourceJson = query_mod.SourceJson;
const status_capture_bytes = query_mod.status_capture_bytes;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const jailPaused = Coordinator.jailPaused;
        const monotonic = Coordinator.monotonic;
        const observationMs = Coordinator.observationMs;
        const observationSound = Coordinator.observationSound;
        const redacted_text = Coordinator.redacted_text;
        pub fn lossJson(event: files.LossEvent) LossJson {
            return .{
                .sequence = event.sequence,
                .wall_us = event.wall_us,
                .reason = @tagName(event.reason),
                .inode = event.inode,
                .committed_offset = event.committed_offset,
                .observed_size = event.observed_size,
            };
        }
        fn captureSources(self: *const Coordinator, memory: *CaptureMemory, redact: bool) ![]SourceJson {
            var count: usize = 0;
            for (self.jails) |jail| count += jail.source_status.len;
            const result = try memory.fixed.allocator().alloc(SourceJson, count);
            var offset: usize = 0;
            for (self.jails) |jail| for (jail.source_status) |entry| {
                result[offset] = .{
                    .jail = try memory.text(entry.jail),
                    .kind = @tagName(entry.kind),
                    .path = if (entry.path) |path| (if (redact) redacted_text else try memory.text(path)) else null,
                    .on_truncation = if (entry.on_truncation) |policy| @tagName(policy) else null,
                    .state = @tagName(entry.state),
                    .cause = if (entry.cause) |cause| try memory.text(cause) else null,
                    .inode = entry.inode,
                    .committed_offset = entry.committed_offset,
                    .observed_size = entry.observed_size,
                    .repair = if (entry.repair) |repair| (if (redact) redacted_text else try memory.text(repair)) else null,
                    .loss_events = entry.loss_events,
                    .last_loss = if (entry.last_loss) |event| lossJson(event) else null,
                };
                offset += 1;
            };
            return result;
        }
        fn renderSources(writer: anytype, sources: []SourceJson) !void {
            std.sort.pdq(SourceJson, sources, {}, struct {
                fn less(_: void, x: SourceJson, y: SourceJson) bool {
                    return switch (std.mem.order(u8, x.jail, y.jail)) {
                        .lt => true,
                        .gt => false,
                        .eq => std.mem.lessThan(u8, x.path orelse "", y.path orelse ""),
                    };
                }
            }.less);
            try std.json.stringify(sources, .{}, writer);
        }
        fn rangeConfirmed(self: *const Coordinator, jail: *const Jail, now: i64, known: bool) u32 {
            if (!known or !self.jailEnforces(jail)) return 0;
            const range = jail.owner_range;
            var count: u32 = 0;
            for (self.owner_active[range.start..][0..range.len], self.owner_confirmed[range.start..][0..range.len]) |owner, confirmed| {
                if (confirmed and owner.lease.live(now)) count += 1;
            }
            return count;
        }
        pub fn statusPayload(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, redact: bool) !void {
            return self.statusPayloadLimit(out, a, redact, legacy_allowance);
        }
        pub fn statusPayloadLimit(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, redact: bool, limit: usize) !void {
            var memory = try CaptureMemory.init(a, status_capture_bytes);
            defer memory.deinit(a);
            var generation_hex: [64]u8 = undefined;
            const captured = blk: {
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
                var missing_sources: u32 = 0;
                var missing_known = true;
                var unpaused_unhealthy: u32 = 0;
                var blocked_source: ?[]const u8 = null;
                var source_cause: ?[]const u8 = null;
                var waiting_sources: u32 = 0;
                const now = sampled_wall orelse self.start_us;
                for (self.jails) |jail| {
                    if (jail.plan == .file and (!jail.source_signature.built or !jail.source_signature.presence_known)) missing_known = false;
                    healthy = healthy and jail.healthy;
                    waiting_sources += @intFromBool(Coordinator.capacityWaiting(&jail));
                    if (!jail.healthy) unhealthy_sources += 1;
                    if (!jail.healthy and !jailPaused(&jail)) {
                        unpaused_unhealthy += 1;
                        if (source_cause == null) if (jail.source_error) |cause| {
                            source_cause = @errorName(cause);
                        };
                    }
                    if (!jail.healthy and blocked_source == null) if (jail.source_error) |cause| if (pipeline.Pipeline.commitBlocked(cause)) {
                        blocked_source = @errorName(cause);
                    };
                    for (jail.source_status) |entry| {
                        paused_sources += @intFromBool(entry.state == .paused);
                        missing_sources += @intFromBool(entry.state == .missing);
                    }
                    decisions +|= jail.summary.decisions;
                    installed +|= self.rangeConfirmed(&jail, now, self.confirmationKnown(effect_ms));
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
                generation_hex = std.fmt.bytesToHex(self.published_generation, .lower);
                const effect_diagnostic = if (self.published_effects) |effects| effects.diagnostic else null;
                const none_cause: []const u8 = if (paused_sources != 0 and unpaused_unhealthy == 0) "SourcePaused" else blocked_source orelse source_cause orelse "none";
                break :blk .{
                    .payload = .{
                        .version = version,
                        .runtime = "native",
                        .generation = &generation_hex,
                        .mutation_revision = self.published_revision,
                        .state = protection,
                        .protection = protection,
                        .protection_cause = if (self.backend_failure) |failure| @as(?[]const u8, @errorName(failure)) else null,
                        .active_bans = active_bans,
                        .total_bans = self.published_confirmations,
                        .knowledge = if (known) |k| @as(?[]const u8, @tagName(k)) else null,
                        .confirmed_at_us = if (known != null and known.? != .none) self.published_view.readback_wall_us else null,
                        .knowledge_age_ms = if (known != null and known.? != .none) self.knowledgeAgeMs(effect_ms) else null,
                        .pending_bans = if (known != null) @as(?u64, self.published_view.pending) else null,
                        .oldest_pending_ms = if (known != null) ageMs(now, self.published_view.oldest_pending_us) else null,
                        .overdue_removals = if (known != null) @as(?u64, self.published_view.overdue_blocking) else null,
                        .oldest_overdue_ms = if (known != null) ageMs(now, self.published_view.oldest_overdue_blocking_us) else null,
                        .overdue_bookkeeping = if (known != null) @as(?u64, self.published_view.overdue -| self.published_view.overdue_blocking) else null,
                        .dump_interrupted = if (known != null) @as(?u64, self.published_view.dump_interrupted) else null,
                        .storage = @tagName(gate.phase),
                        .cause = if (gate.phase == .intervention and gate.last_failure != null) @errorName(gate.last_failure.?.cause) else if (observation.clock_uncertain) "ClockUncertain" else if (observation.stalled) "WorkerStalled" else if (withdrawn) "FirewallWithdrawn" else if (known != null and known.? == .none and knowledge_cause != null) knowledge_cause.? else if (self.overBlocking()) "EffectRemovalOverdue" else if (knowledge_cause) |cause| cause else if (gate.last_failure) |failure| @errorName(failure.cause) else if (self.published_effects) |effects| if (effects.cause) |cause| @errorName(cause) else none_cause else if (self.backend_failure) |failure| @errorName(failure) else none_cause,
                        .sqlite_code = if (gate.last_failure) |failure| failure.diagnostics.sqlite_code else null,
                        .next_retry_ms = gate.next_retry_ms,
                        .committed_records = gate.committed_records,
                        .decisions_total = decisions,
                        .jails_active = self.jails.len,
                        .unhealthy_sources = unhealthy_sources,
                        .missing_sources = if (missing_known) @as(?u32, missing_sources) else null,
                        .backend = self.published_backend,
                        .effect_backend = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.backend)) else null,
                        .effect_stage = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.stage)) else null,
                        .effect_cause = if (effect_diagnostic) |detail| @as(?[]const u8, @errorName(detail.cause)) else null,
                        .effect_mutation = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.mutation)) else null,
                        .effects_uncertain = observation.expiry_uncertain or (if (self.published_effects) |effects| effects.uncertain else false),
                        .overdue_effects = if (self.published_effects) |effects| effects.overdue else 0,
                        .worker_busy = observation.busy,
                        .worker_stalled = observation.stalled,
                        .worker_busy_age_ms = observation.busy_age_ms,
                        .worker_heartbeat_age_ms = observation.heartbeat_age_ms,
                        .clock_uncertain = observation.clock_uncertain,
                        .expiry_overdue = observation.expiry_overdue,
                        .expiry_uncertain = observation.expiry_uncertain,
                        .next_committed_expiry_us = observation.next_committed_expiry_us,
                        .memory_admission_bytes = self.resources.snapshot().used_bytes,
                        .uptime_seconds = if (observation.clock_uncertain) @as(?u64, null) else @as(u64, @intCast(@max(0, @divTrunc(now -| self.start_us, 1_000_000)))),
                    },
                    .paused = paused_sources,
                    .waiting_sources = waiting_sources,
                    .intake_waiting = self.published_intake_waiting,
                    .footprint = self.published_footprint,
                    .pool = self.published_pool,
                    .sources = try self.captureSources(&memory, redact),
                };
            };
            var sink = query_v1.ByteSink{ .out = out, .allocator = a, .limit = limit };
            const writer = sink.writer();
            const payload_start = out.items.len;
            try std.json.stringify(captured.payload, .{ .emit_null_optional_fields = false }, writer);
            if (out.items.len == payload_start or out.items[out.items.len - 1] != '}') return error.InvalidStatusPayload;
            out.items.len -= 1;
            try writer.print(",\"paused_sources\":{d}", .{captured.paused});
            if (captured.footprint) |footprint| {
                try writer.print(
                    ",\"state_file_bytes\":{d},\"state_file_pages\":{d},\"state_file_max_pages\":{d},\"state_file_used_pages\":{d},\"state_file_capacity_pages\":{d},\"state_file_owed_pages\":",
                    .{ footprint.bytes, footprint.pages, footprint.max_pages, footprint.used_pages, footprint.capacity_pages },
                );
                try std.json.stringify(footprint.owed_pages, .{}, writer);
            }
            try writer.print(",\"intake\":\"{s}\",\"intake_cause\":", .{if (captured.intake_waiting) "waiting" else "open"});
            try std.json.stringify(if (captured.intake_waiting) @as(?[]const u8, "StorageCapacity") else null, .{}, writer);
            try writer.print(",\"waiting_sources\":{d}", .{captured.waiting_sources});
            try writer.print(",\"pool_sample_available\":{},\"pool_sample_pending\":{},\"pool_sample_as_of_us\":", .{ captured.pool.sample != null, captured.pool.pending });
            try std.json.stringify(if (captured.pool.sample) |sample| @as(?i64, sample.as_of_us) else null, .{}, writer);
            if (captured.pool.sample) |sample| {
                const pool = sample.occupancy;
                try writer.print(",\"pool_tracked\":{d},\"pool_banned\":{d},\"pool_tracking_limit\":{d},\"pool_ban_limit\":{d}", .{ pool.tracked, pool.banned, pool.tracking_limit, pool.ban_limit });
            }
            try writer.writeAll(",\"sources\":");
            try renderSources(writer, captured.sources);
            try writer.print(",\"schema_version\":{d}}}", .{query_v1.schema_version});
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
        pub fn metrics(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            self.mutex.lock();
            const captured = blk: {
                defer self.mutex.unlock();
                const observation = self.observedWorker();
                var snapshot = self.metrics_state.snapshot();
                snapshot.native = .{
                    .storage_healthy = self.published_health.phase == .healthy and observationSound(observation),
                    .committed_records = self.published_health.committed_records,
                    .worker_stalled = observation.stalled,
                    .worker_busy = observation.busy,
                    .worker_heartbeat_age_ms = observation.heartbeat_age_ms,
                    .worker_busy_age_ms = observation.busy_age_ms,
                    .clock_uncertain = observation.clock_uncertain,
                    .expiry_overdue = observation.expiry_overdue,
                    .expiry_uncertain = observation.expiry_uncertain,
                };
                snapshot.pool_sample_available = self.published_pool.sample != null;
                snapshot.pool_sample_pending = self.published_pool.pending;
                snapshot.pool_sample_as_of_us = if (self.published_pool.sample) |sample| sample.as_of_us else null;
                if (self.published_pool.sample) |sample| {
                    const pool = sample.occupancy;
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
                    kept.active_bans = self.rangeConfirmed(jail, now, self.confirmationKnown(effect_ms));
                    kept.source_state = sourceState(jail);
                    snapshot.jails[live] = kept;
                    live += 1;
                }
                snapshot.jails_len = live;
                break :blk .{ .snapshot = snapshot, .clock = if (comptime build_options.diag) self.clock.snapshot() else {} };
            };
            var sink = query_v1.ByteSink{ .out = out, .allocator = a, .limit = http.max_response_bytes };
            const writer = sink.writer();
            try metrics_mod.renderPrometheus(&captured.snapshot, writer);
            if (comptime build_options.diag) try diag_mod.writeMetrics(writer);
            if (comptime build_options.diag) {
                const sample = captured.clock;
                try writer.print("f2z_diag_clock_rate {d}\nf2z_diag_clock_wall_us {d}\nf2z_diag_clock_regressions {d}\n", .{ sample.rate, sample.wall_us, sample.regressions });
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
            var sink = query_v1.ByteSink{ .out = out, .allocator = a, .limit = http.max_response_bytes };
            try readiness.writeJson(report, sink.writer());
        }
        pub const StatusQuery = struct { coordinator: *Coordinator, redact: bool };
        pub fn statusCallback(ctx: ?*anyopaque, a: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
            const query: *StatusQuery = @ptrCast(@alignCast(ctx.?));
            var unmanaged: std.ArrayListUnmanaged(u8) = .{};
            defer unmanaged.deinit(a);
            try query.coordinator.statusPayload(&unmanaged, a, query.redact);
            if (unmanaged.items.len > query_v1.max_response_bytes) return error.ResponseTooLarge;
            try out.ensureTotalCapacityPrecise(query_v1.max_response_bytes);
            out.appendSliceAssumeCapacity(unmanaged.items);
        }
        pub fn healthCallback(ctx: ?*anyopaque, a: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
            var unmanaged: std.ArrayListUnmanaged(u8) = .{};
            defer unmanaged.deinit(a);
            try healthView(ctx, &unmanaged, a);
            if (unmanaged.items.len > query_v1.max_response_bytes) return error.ResponseTooLarge;
            try out.ensureTotalCapacityPrecise(query_v1.max_response_bytes);
            out.appendSliceAssumeCapacity(unmanaged.items);
        }
    };
}
