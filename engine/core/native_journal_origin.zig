// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const records = @import("source_record.zig");
const detection = @import("native_detection_record.zig");
pub const version: u16 = 1;
pub const Profile = struct {
    machine_id: [32]u8,
    executables: []const []const u8,
    generation: [32]u8,

    pub fn init(machine_id: []const u8, executables: []const []const u8) !Profile {
        if (machine_id.len != 32 or std.mem.allEqual(u8, machine_id, '0')) return error.InvalidJournalMachine;
        for (machine_id) |c| if (!(std.ascii.isDigit(c) or (c >= 'a' and c <= 'f'))) return error.InvalidJournalMachine;
        if (executables.len == 0 or executables.len > 8) return error.InvalidJournalExecutables;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-local-sshd-syslog-origin-v1\x00");
        hash.update(machine_id);
        for (executables, 0..) |path, index| {
            if (path.len < 2 or path.len > 4096 or path[0] != '/' or std.mem.indexOfAny(u8, path, "\x00\r\n") != null) return error.InvalidJournalExecutable;
            var parts = std.mem.splitScalar(u8, path[1..], '/');
            while (parts.next()) |part| if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidJournalExecutable;
            for (executables[0..index]) |previous| if (std.mem.eql(u8, previous, path)) return error.DuplicateJournalExecutable;
            hash.update(path);
            hash.update(&.{0});
        }
        var generation: [32]u8 = undefined;
        hash.final(&generation);
        return .{ .machine_id = machine_id[0..32].*, .executables = executables, .generation = generation };
    }

    pub fn rejection(self: *const Profile, fields: ?[]const records.JournalField) ?detection.Kind {
        const values = fields orelse return .origin_missing;
        if (values.len > 256) return .origin_ambiguous;
        const names = [_][]const u8{ "_MACHINE_ID", "_UID", "_EXE", "_TRANSPORT" };
        var found = [_]?[]const u8{null} ** names.len;
        for (values) |field| for (names, 0..) |name, index| {
            if (std.mem.eql(u8, field.name, name)) {
                if (found[index] != null) return .origin_ambiguous;
                found[index] = field.value;
            }
        };
        for (found) |value| if (value == null or value.?.len == 0) return .origin_missing;
        if (!std.mem.eql(u8, found[0].?, &self.machine_id)) return .origin_machine;
        if (!std.mem.eql(u8, found[1].?, "0")) return .origin_uid;
        if (!std.mem.eql(u8, found[3].?, "syslog")) return .origin_transport;
        for (self.executables) |path| if (std.mem.eql(u8, found[2].?, path)) return null;
        return .origin_executable;
    }
};
