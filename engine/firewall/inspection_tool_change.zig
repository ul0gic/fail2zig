// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Changes this installation's iptables, ip6tables and ipset state through their tools and routes each exact change to its backend.
// Holds: A mutating tool command that prints anything to stdout fails as UnknownState and is not counted as a mutation.

const std = @import("std");
const nft = @import("nftables.zig");
const mem = @import("std").mem;
const ClockSample = @import("inspection.zig").ClockSample;
const DispatchToken = @import("inspection.zig").DispatchToken;
const Entry = @import("inspection.zig").Entry;
const Error = @import("inspection.zig").Error;
const MutationProgress = @import("inspection.zig").MutationProgress;
const ScopedRuleMetadata = @import("inspection.zig").ScopedRuleMetadata;
const Snapshot = @import("inspection.zig").Snapshot;
const legacyAddress = @import("inspection.zig").legacyAddress;
const scoped_comment_bytes = @import("inspection.zig").scoped_comment_bytes;
const findEntry = @import("inspection_entries.zig").findEntry;
const leaseDeadline = @import("inspection_entries.zig").leaseDeadline;
const timingTransport = @import("inspection_entries.zig").timingTransport;
const FixedScopedOperation = @import("inspection_tool_read.zig").FixedScopedOperation;
const FixedScopedVariants = @import("inspection_tool_read.zig").FixedScopedVariants;
const Tokens = @import("inspection_tool_read.zig").Tokens;
const buildFixedScopedArgv = @import("inspection_tool_read.zig").buildFixedScopedArgv;
const fixedScopedMetadata = @import("inspection_tool_read.zig").fixedScopedMetadata;
const setName = @import("inspection_tool_read.zig").setName;

pub fn Methods(comptime Inspector: type) type {
    return struct {
        const restore_line_bytes: usize = 128;
        // Why: iptables-nft sends one netlink batch per COMMIT; on 1.8.11 a 768-rule COMMIT failed with "Message too long" and 512 passed.
        const iptables_rules_per_commit: usize = 256;
        pub fn installIpset(self: *Inspector, tokens: []const DispatchToken, clock: ClockSample, elapsed: *std.time.Timer, timer: *std.time.Timer, progress: *MutationProgress) Error!usize {
            var name_buf: [28]u8 = undefined;
            const name = self.installation.name(&name_buf);
            const input = self.allocator.alloc(u8, tokens.len * restore_line_bytes) catch return error.OutOfMemory;
            defer self.allocator.free(input);
            var stream = std.io.fixedBufferStream(input);
            const now = try self.clockAt(clock, elapsed);
            for (tokens) |token| {
                const address = try legacyAddress(token.scope);
                var set_buf: [31]u8 = undefined;
                const set = try setName(name, address == .ipv6, &set_buf);
                const units = try self.kernelUnits(token.operation, timingTransport(.ipset, token.scope), now);
                stream.writer().print("add {s} {} timeout {d} -exist\n", .{ set, address, units }) catch return error.LimitExceeded;
            }
            try self.restore(&.{ self.ipset_path, "restore" }, stream.getWritten(), timer, progress);
            return tokens.len;
        }
        pub fn installIptables(self: *Inspector, tokens: []const DispatchToken, baseline: *const Snapshot, timer: *std.time.Timer, progress: *MutationProgress) Error!usize {
            var name_buf: [28]u8 = undefined;
            const name = self.installation.name(&name_buf);
            const input = self.allocator.alloc(u8, tokens.len * restore_line_bytes + restore_line_bytes) catch return error.OutOfMemory;
            defer self.allocator.free(input);
            for ([_]bool{ false, true }) |v6| {
                var stream = std.io.fixedBufferStream(input);
                const writer = stream.writer();
                var rules: usize = 0;
                for (tokens) |token| {
                    const address = try legacyAddress(token.scope);
                    if ((address == .ipv6) != v6) continue;
                    if (try findEntry(baseline.entries, token.scope, token.effect_id) != null) continue;
                    if (rules % iptables_rules_per_commit == 0) writer.writeAll(if (rules == 0) "*filter\n" else "COMMIT\n*filter\n") catch return error.LimitExceeded;
                    writer.print("-I {s} 1 -s {} -j DROP\n", .{ name, address }) catch return error.LimitExceeded;
                    rules += 1;
                }
                if (rules == 0) continue;
                writer.writeAll("COMMIT\n") catch return error.LimitExceeded;
                // Why: Without --noflush, iptables-restore deletes every existing rule in the filter table first (iptables-restore(8)).
                try self.restore(&.{ if (v6) self.ip6tables_restore_path else self.iptables_restore_path, "--wait=1", "--noflush" }, stream.getWritten(), timer, progress);
            }
            return tokens.len;
        }
        pub fn restore(self: *Inspector, argv: []const []const u8, input: []const u8, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
            const result = try self.runTool(argv, input, timer, progress);
            defer result.deinit(self.allocator);
            if (result.stdout.len != 0) return error.UnknownState;
            try self.afterMutation(1);
        }
        pub fn mutateExact(self: *Inspector, token: DispatchToken, existing: ?Entry, units: u64, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
            var name_buf: [28]u8 = undefined;
            const name = self.installation.name(&name_buf);
            if (self.installation.transport == .nftables) {
                try self.mutateNft(token, name, existing != null, units, timer, progress);
                try self.afterMutation(1);
                return;
            }
            const scoped_address = legacyAddress(token.scope) catch return self.mutateFixedScoped(token, name, timer, progress);
            var address_buf: [64]u8 = undefined;
            const address = std.fmt.bufPrint(&address_buf, "{}", .{scoped_address}) catch return error.UnsupportedScope;
            var count: usize = 0;
            if (self.installation.transport == .ipset) {
                var set_buf: [31]u8 = undefined;
                const set = try setName(name, scoped_address == .ipv6, &set_buf);
                if (token.operation == .ensure_absent) {
                    try self.mutateCommand(&.{ self.ipset_path, "del", set, address }, timer, &count, progress);
                } else {
                    var timeout_buf: [24]u8 = undefined;
                    const timeout = std.fmt.bufPrint(&timeout_buf, "{d}", .{units}) catch return error.UnsupportedDeadline;
                    try self.mutateCommand(&.{ self.ipset_path, "add", set, address, "timeout", timeout, "-exist" }, timer, &count, progress);
                }
            } else {
                const binary = if (scoped_address == .ipv4) self.iptables_path else self.ip6tables_path;
                if (token.operation == .ensure_absent) try self.mutateCommand(&.{ binary, "-w", "1", "-D", name, "-s", address, "-j", "DROP" }, timer, &count, progress) else try self.mutateCommand(
                    &.{ binary, "-w", "1", "-I", name, "1", "-s", address, "-j", "DROP" },
                    timer,
                    &count,
                    progress,
                );
            }
        }
        pub fn mutateFixedScoped(self: *Inspector, token: DispatchToken, name: []const u8, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
            const v6 = token.scope.subject.family == .v6;
            const binary = if (v6) self.ip6tables_path else self.iptables_path;
            const part_count = nft.scopeRulePartCount(token.scope) catch return error.UnsupportedScope;
            const installed = try self.listFixedScoped(token, name, binary, v6, timer);
            var metadata = ScopedRuleMetadata{ .effect_id = token.effect_id, .part = 0, .count = @intCast(part_count), .deadline_us = null, .scope = token.scope };
            var mutations: usize = 0;
            if (token.operation == .ensure_present) {
                metadata.deadline_us = leaseDeadline(token.operation.ensure_present);
                for (0..part_count) |part| {
                    if (installed.count(metadata.deadline_us, part) != 0) continue;
                    metadata.part = @intCast(part);
                    try self.runFixedScoped(binary, name, metadata, .insert, timer, &mutations, progress);
                }
            }
            for (installed.variants[0..installed.len]) |variant| {
                const kept: u16 = @intFromBool(token.operation == .ensure_present and variant.deadline_us == leaseDeadline(token.operation.ensure_present));
                metadata.deadline_us = variant.deadline_us;
                for (0..part_count) |part| {
                    if (variant.counts[part] <= kept) continue;
                    metadata.part = @intCast(part);
                    for (0..variant.counts[part] - kept) |_| try self.runFixedScoped(binary, name, metadata, .delete, timer, &mutations, progress);
                }
            }
            if (mutations == 0) return error.Changed;
        }
        pub fn runFixedScoped(self: *Inspector, binary: []const u8, chain: []const u8, metadata: ScopedRuleMetadata, operation: FixedScopedOperation, timer: *std.time.Timer, mutations: *usize, progress: *MutationProgress) Error!void {
            var argv: [24][]const u8 = undefined;
            var subject_buf: [64]u8 = undefined;
            var port_buf: [16]u8 = undefined;
            var comment_buf: [scoped_comment_bytes]u8 = undefined;
            try self.mutateCommand(try buildFixedScopedArgv(&argv, &subject_buf, &port_buf, &comment_buf, binary, chain, metadata, operation), timer, mutations, progress);
        }
        pub fn listFixedScoped(self: *Inspector, token: DispatchToken, name: []const u8, binary: []const u8, v6: bool, timer: *std.time.Timer) Error!FixedScopedVariants {
            const result = try self.run(&.{ binary, "-w", "1", "-S" }, timer);
            defer result.deinit(self.allocator);
            if (result.stdout.len == 0 or result.stdout[result.stdout.len - 1] != '\n') return error.Incomplete;
            var found = FixedScopedVariants{};
            var lines = mem.splitScalar(u8, result.stdout, '\n');
            while (lines.next()) |line| {
                if (line.len == 0) continue;
                const t = try Tokens.parse(line);
                if (t.count < 2) return error.UnknownState;
                if (!mem.eql(u8, t.values[0], "-A") or !mem.eql(u8, t.values[1], name)) continue;
                const metadata = (try fixedScopedMetadata(t, name, v6)) orelse continue;
                if (!mem.eql(u8, &metadata.effect_id, &token.effect_id)) continue;
                if (!std.meta.eql(metadata.scope, token.scope)) return error.ForeignState;
                found.note(metadata.deadline_us, metadata.part);
            }
            return found;
        }
        pub fn mutateCommand(self: *Inspector, argv: []const []const u8, timer: *std.time.Timer, count: *usize, progress: *MutationProgress) Error!void {
            const result = try self.runTracked(argv, timer, progress);
            defer result.deinit(self.allocator);
            if (result.stdout.len != 0) return error.UnknownState;
            count.* += 1;
            try self.afterMutation(count.*);
        }
        pub fn createInstallation(self: *Inspector, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
            var name_buf: [28]u8 = undefined;
            const name = self.installation.name(&name_buf);
            var marker_buf: [44]u8 = undefined;
            const marker = self.installation.marker(&marker_buf);
            if (self.installation.transport == .nftables) {
                try self.createNft(name, marker, timer, progress);
                try self.afterMutation(1);
                return;
            }
            var mutations: usize = 0;
            for ([_][]const u8{ self.iptables_path, self.ip6tables_path }, 0..) |binary, index| {
                try self.mutateCommand(&.{ binary, "-w", "1", "-N", name }, timer, &mutations, progress);
                // Why: parseIptables reads the chain as owned only when it holds this marked RETURN rule.
                try self.mutateCommand(&.{ binary, "-w", "1", "-A", name, "-m", "comment", "--comment", marker, "-j", "RETURN" }, timer, &mutations, progress);
                if (self.installation.transport == .ipset) {
                    var set_buf: [31]u8 = undefined;
                    const set = try setName(name, index == 1, &set_buf);
                    // Why: maxelem equals max_inventory_entries, the most entries a readback accepts.
                    try self.mutateCommand(
                        &.{ self.ipset_path, "create", set, "hash:ip", "family", if (index == 0) "inet" else "inet6", "timeout", "0", "maxelem", "131072" },
                        timer,
                        &mutations,
                        progress,
                    );
                    try self.mutateCommand(&.{ binary, "-w", "1", "-I", name, "1", "-m", "set", "--match-set", set, "src", "-j", "DROP" }, timer, &mutations, progress);
                }
                try self.mutateCommand(&.{ binary, "-w", "1", "-I", "INPUT", "1", "-m", "comment", "--comment", marker, "-j", name }, timer, &mutations, progress);
            }
        }
    };
}
