// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Bounded native action-target identity and outcome types. Dispatch remains in
//! typed callers; this module contains no provider, command or network logic.
const std = @import("std");
const detection = @import("native_detection_record.zig");

pub const max_metadata_bytes: usize = 512;
pub const max_targets_per_action: usize = 2;
pub const max_rows: usize = 65_536;
pub const Error = error{ InvalidActionTarget, ActionTargetStorageRequired, ActionTargetCapacity, StaleActionTarget, ActionTargetProofRequired };

pub const Kind = enum(u8) { enforcement = 1, notification = 2 };
pub const Status = enum(u8) { pending = 1, dispatched, confirmed, failed, uncertain, suppressed_restored };
pub const Settlement = enum { confirmed, failed, uncertain };

pub const Intent = struct {
    action_id: [32]u8,
    scope_key: [32]u8,
    jail: []const u8,
    restored: bool = false,
    metadata: ?[]const u8 = null,

    pub fn validate(self: Intent) Error!void {
        if (std.mem.allEqual(u8, &self.action_id, 0) or std.mem.allEqual(u8, &self.scope_key, 0)) return error.InvalidActionTarget;
        _ = detection.Name.init(self.jail) catch return error.InvalidActionTarget;
        if (self.metadata) |value| {
            if (value.len == 0 or value.len > max_metadata_bytes or std.mem.indexOfScalar(u8, value, 0) != null or !std.unicode.utf8ValidateSlice(value)) return error.InvalidActionTarget;
        }
    }
};

pub const Target = struct {
    action_id: [32]u8,
    scope_key: [32]u8,
    jail: detection.Name,
    kind: Kind,
    required: bool,
    restored: bool,
    status: Status,
    intent_us: i64,
    dispatch_us: ?i64,
    settled_us: ?i64,
    metadata_len: u16,
    metadata_bytes: [max_metadata_bytes]u8 = [_]u8{0} ** max_metadata_bytes,

    pub fn metadata(self: *const Target) []const u8 {
        return self.metadata_bytes[0..self.metadata_len];
    }
};
