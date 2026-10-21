// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
pub const core = struct {
    pub const durable_file_source = @import("core/durable_file_source.zig");
    pub const journal_policy = @import("core/journal_policy.zig");
    pub const native_action_outcome = @import("core/native_action_outcome.zig");
    pub const native_detection_record = @import("core/native_detection_record.zig");
    pub const native_effect = @import("core/native_effect.zig");
    pub const native_effect_history = @import("core/native_effect_history.zig");
    pub const native_retry = @import("core/native_retry.zig");
    pub const record_pipeline = @import("core/record_pipeline.zig");
    pub const record_store = @import("core/record_store.zig");
    pub const source_record = @import("core/source_record.zig");
    pub const source_time_policy = @import("core/source_time_policy.zig");
};
pub const firewall = struct {
    pub const command = @import("firewall/command.zig");
    pub const inspection = @import("firewall/inspection.zig");
    pub const netlink = @import("firewall/netlink.zig");
    pub const nftables = @import("firewall/nftables.zig");
};
