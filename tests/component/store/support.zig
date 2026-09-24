// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
pub const std = @import("std");
pub const builtin = @import("builtin");
pub const engine = @import("engine_test");
pub const store_mod = engine.core.record_store;
pub const Store = store_mod.Store;
pub const Error = store_mod.Error;
pub const Limits = store_mod.Limits;
pub const Record = store_mod.Record;
pub const ReceiptIdentity = store_mod.ReceiptIdentity;
pub const CommitStage = store_mod.CommitStage;
pub const CommitResult = store_mod.CommitResult;
pub const Db = store_mod.testing.db;
pub const OpenDiagnostic = store_mod.OpenDiagnostic;
pub const OpenStage = store_mod.OpenStage;
pub const OpenPosixCause = store_mod.OpenPosixCause;
pub const latest_schema = store_mod.latest_schema;
pub const sqliteError = store_mod.testing.sqlite_error;
pub const embedded_api = store_mod.testing.embedded;
pub const native_time = engine.core.native_time;
pub const time_policy = engine.core.source_time_policy;
pub const native_record = engine.core.native_time_record;
pub const detection = engine.core.native_detection_record;
pub const retry = engine.core.native_retry;
pub const action_context = engine.core.native_action_context;
pub const consumers = engine.core.native_consumer;
pub const effects = engine.core.native_effect;
pub const effect_history = engine.core.native_effect_history;
pub const application_history = engine.core.native_application_history;
pub const action_outcome = engine.core.native_action_outcome;

pub const ReceiptFixture = struct {
    pub const identity = ReceiptIdentity{ .jail = "fixture", .source = "ordinary", .occurrence = "one", .cursor = "next", .raw_hash = [_]u8{7} ** 32, .generation = [_]u8{9} ** 32 };
    pub fn record(stamp: i64) Record {
        return .{ .jail = identity.jail, .source = identity.source, .occurrence = identity.occurrence, .cursor = identity.cursor, .raw_hash = identity.raw_hash, .receipt = .{ .time = .{ .us = stamp }, .generation = identity.generation }, .disposition = "ordinary", .checkpoint = "state", .action_intent = "inert-fixture-intent" };
    }
};

pub const DetectionFixture = struct {
    pub const stamp: i64 = 9_007_199_254_740_993;
    pub fn record() !Record {
        var value = ReceiptFixture.record(stamp);
        value.action_intent = null;
        value.native_time_outcome = try time_policy.evaluate(.timestamped, .{ .parsed = .{ .us = stamp } }, .{ .us = stamp }, .{ .us = stamp }, 600_000_000);
        value.disposition = value.native_time_outcome.?.disposition();
        value.native_detection = .{ .kind = .candidate, .generation = [_]u8{3} ** 32, .filter = try detection.Name.init("sshd"), .pattern = try detection.Name.init("invalid-user"), .pattern_index = 2, .subject = .{ .v4 = .{ 203, 0, 113, 7 } } };
        return value;
    }
    pub fn admit(store: *Store) !void {
        try store.enableReceipts(1);
        try store.enableNativeTime();
        _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = stamp }, 0);
    }
};
