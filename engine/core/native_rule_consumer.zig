// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Stable owner adapter. Stages are local until the coordinator commits their
//! checkpoint with the source occurrence and publishes once. No store or DNS I/O.
const std = @import("std");
const rules = @import("native_rules.zig");
const correlation = @import("native_correlation.zig");
pub const version: u16 = 1;
pub const counter_count = @typeInfo(rules.Kind).@"enum".fields.len;
const header_bytes = 40 + counter_count * 8;
pub const checkpoint_bytes = header_bytes + correlation.checkpoint_bytes;
pub const Counters = [counter_count]u64;
pub const Prepared = struct {
    owner: *Consumer,
    checkpoint: []const u8,
    outcome: ?rules.Outcome,
    prepared_us: ?i64 = null,
    valid_until_us: ?i64 = null,
    /// Coordinator rechecks with a fresh clock after acquiring its writer lock.
    /// This transient bound must not become an expiry for the checkpoint row.
    pub fn validateCommit(self: Prepared, now_us: i64) !void {
        if (self.prepared_us) |floor| if (now_us < floor) return error.ConsumerClockReversed;
        if (self.valid_until_us) |expiry| if (now_us >= expiry) return error.ConsumerExpired;
    }
    /// Publication is infallible and allocation-free; caller owns the commit gate.
    pub fn publish(self: Prepared) void {
        self.owner.counters = self.owner.staged;
        if (self.owner.correlation_stage) |stage| stage.publish();
    }
    /// Releasing without publish aborts every staged counter/context change.
    pub fn release(self: Prepared) void {
        if (self.owner.correlation_stage) |stage| stage.release();
        self.owner.correlation_stage = null;
        self.owner.in_flight = false;
    }
};
pub const Consumer = struct {
    program: *const rules.Program,
    binding: [32]u8,
    scratch: rules.Scratch = .{},
    counters: Counters = [_]u64{0} ** counter_count,
    staged: Counters = [_]u64{0} ** counter_count,
    bytes: [checkpoint_bytes]u8 = undefined,
    contexts: ?correlation.Session,
    correlation_stage: ?correlation.Prepared = null,
    in_flight: bool = false,

    /// Move into its final stable address before preparing. Program must outlive
    /// this owner. Incarnation is trusted collector identity, never a log field.
    pub fn init(program: *const rules.Program, jail: []const u8, incarnation: []const u8, parent_generation: [32]u8, hostname_enabled: bool) !Consumer {
        if (jail.len == 0 or jail.len > 64 or incarnation.len == 0 or incarnation.len > 16384 or
            std.mem.indexOfScalar(u8, jail, 0) != null or std.mem.indexOfScalar(u8, incarnation, 0) != null) return error.InvalidConsumerBinding;
        if (program.metadata().subject_kind == .hostname and !hostname_enabled) return error.HostnameResolutionRequired;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-native-rule-consumer-v1\x00");
        for ([_][]const u8{ &program.generation, &parent_generation, jail, incarnation }) |part| {
            var length: [8]u8 = undefined;
            std.mem.writeInt(u64, &length, part.len, .little);
            hash.update(&length);
            hash.update(part);
        }
        var binding: [32]u8 = undefined;
        hash.final(&binding);
        return .{ .program = program, .binding = binding, .contexts = if (program.metadata().correlation) |c| try correlation.Session.init(binding, c.ttl_seconds, program.metadata().subject_kind == .hostname) else null };
    }
    pub fn prepare(self: *Consumer, input: rules.Input, timing: correlation.Timing) !Prepared {
        if (self.in_flight) return error.ConsumerBusy;
        if (!input.complete) return error.IncompleteRecord;
        if (!std.mem.eql(u8, input.source, self.program.metadata().source)) return error.ConsumerSourceMismatch;
        try timing.validate();
        var outcome: rules.Outcome = undefined;
        if (self.contexts) |*contexts| {
            const observation = try self.program.analyze(input, &self.scratch);
            self.correlation_stage = try contexts.prepare(observation, timing);
            outcome = self.correlation_stage.?.outcome.?;
        } else outcome = try self.program.evaluate(input, &self.scratch);
        errdefer {
            if (self.correlation_stage) |stage| stage.release();
            self.correlation_stage = null;
        }
        var next = self.counters;
        const index = @intFromEnum(outcome.kind);
        if (next[index] >= std.math.maxInt(i64)) return error.ConsumerCounterOverflow;
        next[index] += 1;
        self.encode(next);
        self.staged = next;
        self.in_flight = true;
        return .{ .owner = self, .checkpoint = &self.bytes, .outcome = outcome, .prepared_us = timing.processing_us, .valid_until_us = if (self.correlation_stage) |stage| stage.valid_until_us else null };
    }
    pub fn prepareRestore(self: *Consumer, saved: []const u8) !Prepared {
        if (self.in_flight) return error.ConsumerBusy;
        if (saved.len != checkpoint_bytes or !std.mem.eql(u8, saved[0..4], "F2NR")) return error.InvalidRuleCheckpoint;
        if (std.mem.readInt(u16, saved[4..6], .little) != version or saved[6] > 1 or saved[7] != 0) return error.UnsupportedRuleCheckpoint;
        if (!std.mem.eql(u8, saved[8..40], &self.binding) or (saved[6] == 1) != (self.contexts != null)) return error.RuleGenerationMismatch;
        var counters: Counters = undefined;
        for (&counters, 0..) |*counter, i| {
            counter.* = std.mem.readInt(u64, saved[40 + i * 8 ..][0..8], .little);
            if (counter.* > std.math.maxInt(i64)) return error.InvalidRuleCheckpoint;
        }
        if (self.contexts) |*contexts| {
            self.correlation_stage = try contexts.prepareRestore(saved[header_bytes..]);
        } else if (!std.mem.allEqual(u8, saved[header_bytes..], 0)) return error.InvalidRuleCheckpoint;
        self.encode(counters);
        self.staged = counters;
        self.in_flight = true;
        return .{ .owner = self, .checkpoint = &self.bytes, .outcome = null };
    }
    /// Required first-use manifest rows preserve zero counters and empty context;
    /// no synthetic record is evaluated to obtain canonical checkpoint bytes.
    pub fn prepareSnapshot(self: *Consumer) !Prepared {
        if (self.in_flight) return error.ConsumerBusy;
        for (self.counters) |counter| if (counter > std.math.maxInt(i64)) return error.ConsumerCounterOverflow;
        if (self.contexts) |*contexts| self.correlation_stage = try contexts.prepareSnapshot();
        self.encode(self.counters);
        self.staged = self.counters;
        self.in_flight = true;
        return .{ .owner = self, .checkpoint = &self.bytes, .outcome = null };
    }
    fn encode(self: *Consumer, counters: Counters) void {
        @memset(&self.bytes, 0);
        @memcpy(self.bytes[0..4], "F2NR");
        std.mem.writeInt(u16, self.bytes[4..6], version, .little);
        self.bytes[6] = @intFromBool(self.contexts != null);
        @memcpy(self.bytes[8..40], &self.binding);
        for (counters, 0..) |counter, i| std.mem.writeInt(u64, self.bytes[40 + i * 8 ..][0..8], counter, .little);
        if (self.correlation_stage) |stage| @memcpy(self.bytes[header_bytes..], stage.checkpoint);
    }
};
