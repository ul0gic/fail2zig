// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Answers IPC commands and the HTTP status source from published daemon state.
// Holds: A monitor peer is refused the ban list, gets redacted status, and has its queries run with the monitor class.

const std = @import("std");
const shared = @import("shared");
const config = @import("../config/config.zig");
const detection = @import("../detect/detection_record.zig");
const effect = @import("../effect/effect.zig");
const effect_runtime = @import("../runtime/effect_runtime.zig");
const inspection = @import("../firewall/inspection.zig");
const pipeline = @import("../source/record_pipeline.zig");
const health = @import("../platform/storage_health.zig");
const ipc = @import("../net/ipc.zig");
const http = @import("../net/http.zig");
const build_options = @import("build_options");
const diag_command = @import("../net/diag_command.zig");
const query_v1 = @import("../net/query_v1.zig");
const readiness = @import("../platform/readiness.zig");
const daemon = @import("daemon.zig");
const firewall_observation = daemon.firewall_observation;
const version = daemon.version;
const max_jails = daemon.max_jails;
const Jail = daemon.Jail;
const Knowledge = daemon.Knowledge;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const monotonic = Coordinator.monotonic;
        const observationMs = Coordinator.observationMs;
        const observationSound = Coordinator.observationSound;
        const capacityWaiting = Coordinator.capacityWaiting;
        const jailPaused = Coordinator.jailPaused;
        const JailListRow = Coordinator.JailListRow;

        pub fn status(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            try self.statusPayloadLimit(out, a, true, http.max_response_bytes);
        }

        pub fn knowledge(self: *const Coordinator, now_ms: ?u64) ?Knowledge {
            const effects = self.published_effects orelse return null;
            const view = self.published_view;
            if (effects.uncertain and !view.transient_uncertain) return .none;
            const readback = view.readback_ns orelse return if (effects.ready) .fresh else .none;
            if (view.events_subscribed and !view.events_healthy) return .stale;
            const now = now_ms orelse return .stale;
            const age_ns = (now *| std.time.ns_per_ms) -| readback;
            return if (age_ns <= view.verify_interval_ns +| view.wake_interval_ns) .fresh else .stale;
        }

        fn enforcementActive(self: *const Coordinator, observation: health.WorkerStatus, now_ms: ?u64) bool {
            if (!observationSound(observation) or self.published_health.phase != .healthy or self.backend_failure != null or self.overBlocking()) return false;
            if (self.published_effects) |effects| if (effects.withdrawn) return false;
            return (self.knowledge(now_ms) orelse return false) == .fresh;
        }

        pub fn confirmationKnown(self: *const Coordinator, now_ms: ?u64) bool {
            if (self.owner_publication_pending or self.published_owners_mark == null) return false;
            return if (self.knowledge(now_ms)) |known| known != .none else false;
        }

        pub fn confirmedCount(self: *const Coordinator, jail: Jail, now: i64, now_ms: ?u64) ?u32 {
            if (!self.jailEnforces(&jail)) return 0;
            if (!self.confirmationKnown(now_ms)) return null;
            if (self.knowledge(now_ms)) |known| if (known == .none) return null;
            var count: u32 = 0;
            const range = jail.owner_range;
            for (self.owner_active[range.start..][0..range.len], self.owner_confirmed[range.start..][0..range.len]) |owner, confirmed| if (confirmed and owner.lease.live(now)) {
                count += 1;
            };
            return count;
        }

        pub fn formatListSubject(subject: inspection.canonical_scope.Subject, buffer: *[64]u8) ![]const u8 {
            const address: shared.IpAddress = switch (subject.family) {
                .v4 => .{ .ipv4 = std.mem.readInt(u32, subject.address[0..4], .big) },
                .v6 => .{ .ipv6 = std.mem.readInt(u128, &subject.address, .big) },
            };
            return switch (subject.kind) {
                .host => std.fmt.bufPrint(buffer, "{}", .{address}),
                .network => std.fmt.bufPrint(buffer, "{}/{d}", .{ address, subject.prefix }),
            };
        }

        pub fn commandAuth(ctx: ?*anyopaque, cmd: shared.Command, peer: ipc.Peer, a: std.mem.Allocator) !shared.Response {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            if (cmd == .list and peer.class == .monitor) return .{ .err = .{ .code = 403, .message = try a.dupe(u8, "administrator required for ban details") } };
            if (cmd == .query_v1) return self.queryResponse(a, cmd.query_v1.slice(), switch (peer.class) {
                .admin => .admin,
                .monitor => .monitor,
            });
            if (cmd == .status) {
                var output: std.ArrayListUnmanaged(u8) = .{};
                defer output.deinit(a);
                try self.statusPayload(&output, a, peer.class == .monitor);
                return .{ .ok = .{ .payload = try output.toOwnedSlice(a) } };
            }
            if (cmd == .admin_v1 or cmd == .reload_v1) {
                var output: std.ArrayListUnmanaged(u8) = .{};
                defer output.deinit(a);
                return switch (cmd) {
                    .admin_v1 => |request| self.adminResponse(&output, a, request, peer.uid),
                    else => self.reloadResponse(&output, a, peer.uid),
                };
            }
            return command(ctx, cmd, a);
        }

        fn readinessInputs(self: *Coordinator, jails: *[max_jails]readiness.Jail) readiness.Inputs {
            const observation = self.observedWorker();
            for (self.jails, 0..) |jail, i| jails[i] = .{
                .healthy = jail.healthy or capacityWaiting(&jail),
                .source_error = if (jail.source_error) |cause| !pipeline.Pipeline.commitBlocked(cause) else false,
                .enforce = self.jailEnforces(&jail),
                .source_paused = jailPaused(&jail),
            };
            return .{
                .config_loaded = self.generation_admitted,
                .storage_phase = self.published_health.phase,
                .worker = observation,
                .jails = jails[0..self.jails.len],
                .effects = if (self.published_effects) |effects| .{ .ready = effects.ready, .uncertain = effects.uncertain, .overdue = effects.overdue != 0 } else null,
                .admin_generation_admitted = self.generation_admitted,
                .admin_serving = if (self.admin_serving) |serving| serving.load(.acquire) else true,
            };
        }

        pub fn readinessReport(self: *Coordinator) readiness.Report {
            var jails: [max_jails]readiness.Jail = undefined;
            self.mutex.lock();
            defer self.mutex.unlock();
            return readiness.derive(self.readinessInputs(&jails));
        }

        pub fn initializeObservationCache(self: *Coordinator, admitted: bool, installation: effect.Installation) void {
            if (!admitted) {
                self.firewall_observation_unavailable = .memory_budget;
                return;
            }
            const cache = self.allocator.create(firewall_observation.Cache) catch {
                self.firewall_observation_unavailable = .allocation_failed;
                return;
            };
            var nonce: [16]u8 = undefined;
            std.crypto.random.bytes(&nonce);
            cache.* = firewall_observation.Cache.init(effect_runtime.transportInstallation(installation), nonce);
            self.firewall_observation_cache = cache;
            self.firewall_observation_unavailable = .not_observed;
        }

        pub fn findConfigJail(cfg: *const config.Config, name: []const u8) ?*const config.JailConfig {
            for (cfg.jails) |*jail| if (std.mem.eql(u8, jail.name, name)) return jail;
            return null;
        }

        fn writeJails(self: *Coordinator, output: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
            var rows: [max_jails]JailListRow = undefined;
            const count = capture: {
                self.mutex.lock();
                defer self.mutex.unlock();
                const wall = self.observationWall();
                const observation = self.worker_observation.read(observationMs(), wall);
                const effect_ms = monotonic(self);
                for (self.jails, 0..) |jail, i| rows[i] = .{
                    .name = try detection.Name.init(jail.name),
                    .healthy = jail.healthy and self.published_health.phase == .healthy and observationSound(observation),
                    .enabled = jail.admin_enabled,
                    .paused = jail.admin_paused,
                    .disable_cleanup_pending = jail.disable_cleanup_pending,
                    .active_bans = self.confirmedCount(jail, wall orelse self.start_us, effect_ms),
                    .maxretry = jail.policy.maxretry,
                    .findtime = @divTrunc(jail.policy.window_us, 1_000_000),
                    .bantime = switch (jail.policy.duration) {
                        .finite_us => |value| @divTrunc(value, 1_000_000),
                        .permanent => null,
                    },
                    .action = if (self.jailEnforces(&jail)) self.published_backend else "log-only",
                    .enforce_configured = jail.policy.enforce,
                    .enforcing = self.jailEnforces(&jail) and self.enforcementActive(observation, effect_ms),
                    .source = std.meta.activeTag(jail.plan),
                    .source_healthy = jail.healthy,
                    .source_paused = jailPaused(&jail),
                    .source_missing = jail.source_missing,
                    .revision = jail.revision,
                    .decisions = jail.summary.decisions,
                    .cause = jail.source_error,
                    .diagnostic = jail.source_diagnostic,
                };
                break :capture self.jails.len;
            };
            var sink = query_v1.ByteSink{ .out = output, .allocator = a, .limit = shared.protocol.max_payload_size - 16 };
            const w = sink.writer();
            w.writeByte('[') catch |failure| return if (failure == error.ResponseTooLarge) error.SnapshotLimit else failure;
            for (rows[0..count], 0..) |row, i| {
                if (i != 0) try w.writeByte(',');
                std.json.stringify(
                    .{
                        .name = row.name.slice(),
                        .healthy = row.healthy,
                        .enabled = row.enabled,
                        .paused = row.paused,
                        .disable_cleanup_pending = row.disable_cleanup_pending,
                        .active_bans = row.active_bans,
                        .maxretry = row.maxretry,
                        .findtime = row.findtime,
                        .bantime = row.bantime,
                        .bantime_permanent = row.bantime == null,
                        .action = row.action,
                        .enforce_configured = row.enforce_configured,
                        .enforcing = row.enforcing,
                        .log_source = @tagName(row.source),
                        .source_healthy = row.source_healthy,
                        .source_paused = row.source_paused,
                        .source_missing = row.source_missing,
                        .source = @tagName(row.source),
                        .revision = row.revision,
                        .decisions = row.decisions,
                        .cause = if (row.cause) |cause| @errorName(cause) else "none",
                        .source_exit_code = if (row.diagnostic) |detail| detail.exit_code else null,
                        .source_signal = if (row.diagnostic) |detail| detail.signal else null,
                        .source_stderr_present = if (row.diagnostic) |detail| @as(?bool, detail.stderr_present) else null,
                    },
                    .{},
                    w,
                ) catch |failure| return if (failure == error.ResponseTooLarge) error.SnapshotLimit else failure;
            }
            try w.writeByte(']');
        }

        pub fn command(ctx: ?*anyopaque, cmd: shared.Command, a: std.mem.Allocator) !shared.Response {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            var output: std.ArrayListUnmanaged(u8) = .{};
            defer output.deinit(a);
            switch (cmd) {
                .status => try self.statusPayload(&output, a, true),
                .version => try std.json.stringify(.{ .daemon_version = version }, .{}, output.writer(a)),
                .list => |selected| try self.writeBans(&output, a, selected.jail),
                .list_jails => try self.writeJails(&output, a),
                .ban, .unban => return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "legacy ban/unban are retired; use admin_v1") } },
                .reload => return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "legacy reload is retired; use reload_v1") } },
                .reload_v1, .admin_v1 => return error.MutationHandlerNotInstalled,
                .query_v1 => |body| return self.queryResponse(a, body.slice(), .monitor),
                .diag_v1 => |body| if (comptime build_options.diag) return self.diagResponse(a, body.slice()) else return .{ .err = .{
                    .code = 400,
                    .message = try a.dupe(u8, "diag commands need a diag build"),
                } },
            }
            return .{ .ok = .{ .payload = try output.toOwnedSlice(a) } };
        }

        fn diagResponse(self: *Coordinator, a: std.mem.Allocator, body: []const u8) !shared.Response {
            self.mutex.lock();
            const effects_live = self.effects != null;
            const installed_live = self.published_view.installed_live;
            self.mutex.unlock();
            const response = try diag_command.handle(&self.clock, effects_live, installed_live, body, a);
            if (response == .ok) self.wake.signal();
            return response;
        }
    };
}
