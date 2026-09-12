// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Origin-qualified native SSH journal consumer. No tag or MESSAGE-based
//! authentication; excluded origins are committed without matching a subject.
const std = @import("std");
const builtin = @import("native_builtin_detector.zig");
const origin = @import("native_journal_origin.zig");
const stored = @import("native_detection_record.zig");
const time = @import("source_time_policy.zig");
const records = @import("source_record.zig");
pub const Detector = struct {
    base: *const builtin.Detector,
    profile: origin.Profile,
    generation: [32]u8,

    pub fn init(base: *const builtin.Detector, profile: origin.Profile) !Detector {
        if (!std.mem.eql(u8, base.entry.name, "sshd") or base.body != .whole) return error.UnsupportedJournalDetector;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-native-journal-detection-v1\x00");
        hash.update(&base.generation);
        hash.update(&profile.generation);
        var generation: [32]u8 = undefined;
        hash.final(&generation);
        return .{ .base = base, .profile = profile, .generation = generation };
    }
    pub fn consumer(self: *const Detector) stored.JournalConsumer {
        return .{ .generation = self.generation, .context = self, .evaluate = consume };
    }
    fn consume(decoded: []const u8, fields: ?[]const records.JournalField, admitted: time.Result, context: ?*const anyopaque) !stored.Outcome {
        const self: *const Detector = @ptrCast(@alignCast(context.?));
        if (admitted == .eligible) if (self.profile.rejection(fields)) |kind| {
            const result = stored.Outcome{ .kind = kind, .generation = self.generation, .filter = try stored.Name.init("sshd") };
            try result.validate(admitted);
            return result;
        };
        const adapter = self.base.consumer();
        var result = try adapter.evaluate(decoded, admitted, adapter.context);
        result.generation = self.generation;
        return result;
    }
};
