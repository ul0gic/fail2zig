// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const shared = @import("shared");
const effect = @import("native_effect.zig");
const ban_origins = @import("../store/ban_origins.zig");

pub const Origin = shared.types.Origin;
pub const OwnerOrigin = ban_origins.OwnerOrigin;

pub const BanListEntry = struct {
    entry: shared.types.IgnoreEntry,
    jail: []const u8,
    duration_s: ?u64,

    pub fn decisionId(self: BanListEntry) effect.Hash {
        var buffer: [shared.types.IgnoreEntry.max_text_bytes]u8 = undefined;
        return effect.hashParts("fail2zig-banip-v1", &.{ self.jail, self.entry.canonical(&buffer) });
    }
};

pub const DetectionOutcome = enum { ban, receipt_only };
pub const ManualOutcome = enum { set_manual, extend_as_manual, refuse_config };
pub const refused_config_text = "banned by config: edit banip";

pub fn detectionOutcome(current: ?OwnerOrigin) DetectionOutcome {
    const owner = current orelse return .ban;
    return switch (owner.origin) {
        .detection => .ban,
        .manual, .config => .receipt_only,
    };
}

pub fn manualOutcome(current: ?OwnerOrigin) ManualOutcome {
    const owner = current orelse return .set_manual;
    return switch (owner.origin) {
        .detection, .manual => .extend_as_manual,
        .config => .refuse_config,
    };
}
