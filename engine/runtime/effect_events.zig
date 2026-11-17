// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Applies kernel element and generation events to the held inventory between full readbacks.
// Holds: A generation gap or lost event marks events unhealthy, so the inventory stops counting as current until a readback.

const std = @import("std");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const firewall = @import("../firewall/inspection.zig");

pub fn Methods(comptime Manager: type) type {
    return struct {
        pub fn drainEvents(self: *Manager) void {
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
        pub fn discardEvents(self: *Manager) void {
            if (!self.events_subscribed) return;
            _ = self.inspector.drainEvents(.{ .context = self, .apply = ignoreKernelEvent }, 4096) catch {};
            self.last_generation = null;
        }
        pub fn rememberOwnPort(self: *Manager, port_id: u32) void {
            if (port_id == 0 or self.ownPort(port_id)) return;
            self.own_ports[self.own_port_cursor] = port_id;
            self.own_port_cursor = (self.own_port_cursor + 1) % @as(u8, self.own_ports.len);
        }
        pub fn ownPort(self: *const Manager, port_id: u32) bool {
            return port_id != 0 and std.mem.indexOfScalar(u32, &self.own_ports, port_id) != null;
        }
        pub fn loseEvents(self: *Manager) void {
            self.inventory_discontinuity +|= 1;
            self.events_healthy = false;
            self.status.ready = false;
        }
        fn ignoreKernelEvent(_: *anyopaque, _: firewall.nft.Event) firewall.Error!void {}
        fn applyKernelEvent(ctx: *anyopaque, event: firewall.nft.Event) firewall.Error!void {
            const self: *Manager = @ptrCast(@alignCast(ctx));
            if (comptime build_options.diag) diag_mod.count(.events_received, 1);
            switch (event) {
                .generation => |generation| {
                    // Why: nf_tables_commit raises generation id by one per commit (net/netfilter/nf_tables_api.c); a gap is lost events.
                    if (self.last_generation) |last| if (generation.id != last +% 1) self.loseEvents();
                    self.last_generation = generation.id;
                },
                .elements => |elements| {
                    // Why: Acknowledged batches are applied to the snapshot, so events from this process's netlink ports are skipped.
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
    };
}
