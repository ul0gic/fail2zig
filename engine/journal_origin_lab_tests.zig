// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Explicit read-only captured-lab gate. Not part of the default test suite:
//! requires a captured journal and independently obtained host machine identity.
const std = @import("std");
const t = std.testing;
const options = @import("journal_lab_options");
const transport = @import("core/native_journal_transport.zig");
const origin = @import("core/native_journal_origin.zig");
const journal = @import("core/native_journal_detector.zig");
const builtin = @import("core/native_builtin_detector.zig");
const policy = @import("core/source_time_policy.zig");
const time = @import("core/native_time.zig");

test "lab journal: captured OpenSSH failures and successful logins pass origin-qualified native detection" {
    const filename = options.fixture orelse return error.CapturedJournalRequired;
    const machine_id = options.machine_id orelse return error.CapturedMachineIdentityRequired;
    const data = try std.fs.cwd().readFileAlloc(t.allocator, filename, 2 * 1024 * 1024);
    defer t.allocator.free(data);
    const scratch = try t.allocator.alloc(u8, transport.parse_bytes);
    defer t.allocator.free(scratch);
    const profile = try origin.Profile.init(machine_id, &.{ "/usr/sbin/sshd", "/usr/lib/openssh/sshd-session" });
    var base = try builtin.Detector.init(t.allocator, .{ .filter = "sshd", .body = .whole, .ignore_capacity = 0, .max_decoded_bytes = 2048 });
    defer base.deinit(t.allocator);
    const detector = try journal.Detector.init(&base, profile);
    const consumer = detector.consumer();
    var rows: usize = 0;
    var positives: usize = 0;
    var accepted_logins: usize = 0;
    var missing_origin: usize = 0;
    var candidates: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, data, '\n');
    while (lines.next()) |line| {
        if (rows >= 1024) return error.CapturedJournalLimit;
        rows += 1;
        const entry = try transport.decode(scratch, line, 2048);
        const stamp = try time.Timestamp.fromJournal(entry.realtime_us orelse return error.MissingJournalTimestamp);
        // Historical classification only: receipt is a fixture at event time.
        // This does not make old captured data eligible for a live daemon ban.
        const admitted = policy.Result{ .eligible = .{ .timestamp = stamp, .original = stamp, .receipt = stamp, .origin = .event } };
        const result = try consumer.evaluate(entry.message, entry.fields, admitted, consumer.context);
        if (std.mem.startsWith(u8, entry.message, "Invalid user ") or std.mem.startsWith(u8, entry.message, "Failed password ")) {
            try t.expectEqual(@import("core/native_detection_record.zig").Kind.candidate, result.kind);
            positives += 1;
        }
        if (std.mem.startsWith(u8, entry.message, "Accepted ")) {
            try t.expectEqual(@import("core/native_detection_record.zig").Kind.no_match, result.kind);
            accepted_logins += 1;
        }
        if (result.kind == .origin_missing) {
            try t.expect(result.subject == null);
            missing_origin += 1;
        }
        if (result.kind == .candidate) candidates += 1;
    }
    try t.expect(rows > 0 and positives > 0 and accepted_logins > 0);
    std.debug.print("captured SSH records={d}, known failures={d}, successful logins excluded={d}, missing origin excluded={d}, candidates={d}\n", .{ rows, positives, accepted_logins, missing_origin, candidates });
}
