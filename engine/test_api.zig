// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Gathers selected engine runtime, core and firewall modules under one import root for builds outside the daemon.
// Holds: Nothing reachable from here imports main.zig, native_daemon.zig or the cli module, so builds on it link no daemon or client.

pub const native_effect_runtime = @import("runtime/effect_runtime.zig");
pub const core = struct {
    pub const durable_file_source = @import("source/durable_file_source.zig");
    pub const journal_policy = @import("source/journal_policy.zig");
    pub const native_action_outcome = @import("effect/action_outcome.zig");
    pub const native_detection_record = @import("detect/detection_record.zig");
    pub const native_effect = @import("effect/effect.zig");
    pub const native_effect_history = @import("effect/effect_history.zig");
    pub const native_retry = @import("detect/retry.zig");
    pub const record_pipeline = @import("source/record_pipeline.zig");
    pub const record_store = @import("source/record_store.zig");
    pub const source_record = @import("source/source_record.zig");
    pub const source_time_policy = @import("source/source_time_policy.zig");
};
pub const firewall = struct {
    pub const command = @import("firewall/command.zig");
    pub const inspection = @import("firewall/inspection.zig");
    pub const netlink = @import("firewall/netlink.zig");
    pub const nftables = @import("firewall/nftables.zig");
};
