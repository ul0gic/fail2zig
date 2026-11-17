// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Checks the state for repairable effect absence evidence and, with --apply, returns the eligible intents to pending.
// Holds: Nothing is written without --apply, and no evidence is repaired before a state backup is taken and its SHA-256 printed.

const std = @import("std");
const shared = @import("shared");
const cli = @import("cli");
const config = @import("../config/config.zig");
const paths = @import("../config/paths.zig");
const durable = @import("../source/record_store.zig");
const effects = @import("../effect/effect.zig");

const Options = struct { config_path: []const u8 = "/etc/fail2zig/config.toml", apply: bool = false };
const Summary = struct { examined: usize = 0, eligible: usize = 0, repaired: usize = 0 };

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, stdout: anytype, stderr: anytype) shared.ExitClass {
    for (args) |arg| if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
        stdout.writeAll(cli.args.help_repair_effect_evidence) catch return .rejected;
        return .success;
    };
    const options = parse(args) orelse {
        stderr.writeAll(cli.args.help_repair_effect_evidence) catch {};
        return .usage;
    };
    execute(allocator, options, stdout) catch |failure| {
        stderr.print("repair-effect-evidence: refused: {s}; stop the daemon and preserve the state and any repair backup; only recognized absence evidence can be repaired\n", .{@errorName(failure)}) catch {};
        return .rejected;
    };
    return .success;
}

fn parse(args: []const []const u8) ?Options {
    var options = Options{};
    var mode_set = false;
    var config_set = false;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--check") or std.mem.eql(u8, arg, "--apply")) {
            if (mode_set) return null;
            mode_set = true;
            options.apply = std.mem.eql(u8, arg, "--apply");
        } else if (std.mem.eql(u8, arg, "--config")) {
            if (config_set or index + 1 >= args.len) return null;
            config_set = true;
            index += 1;
            if (args[index].len == 0) return null;
            options.config_path = args[index];
        } else return null;
    }
    return options;
}

fn scan(store: *durable.Store, repair: bool) !Summary {
    var summary = Summary{};
    var after: ?effects.Hash = null;
    while (true) {
        const page = try store.effectEvidencePage(after, repair, .{ .prepared_us = std.time.microTimestamp() });
        summary.examined += page.examined;
        summary.eligible += page.eligible;
        summary.repaired += page.repaired;
        if (summary.examined > effects.max_effects) return error.EffectCapacity;
        if (page.done) return summary;
        after = page.after;
    }
}

fn execute(allocator: std.mem.Allocator, options: Options, stdout: anytype) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const cfg = try config.Config.loadFile(arena.allocator(), options.config_path);
    const state_path = cfg.global.state_file;
    const authority = try paths.lockStateIfPresent(state_path) orelse return error.FileNotFound;
    defer authority.close();
    // Why: The lock is held on a descriptor, so each open by path is checked to still name the locked device and inode.
    if (!paths.stateMatchesAuthority(authority, state_path)) return error.OpenFailed;
    const checked = blk: {
        var store = try durable.Store.openReadOnly(allocator, state_path);
        defer store.close();
        if (!paths.stateMatchesAuthority(authority, state_path)) return error.OpenFailed;
        break :blk try scan(&store, false);
    };
    try stdout.print("repair-effect-evidence: checked {d} scopes; {d} eligible; no effect evidence changed\n", .{ checked.examined, checked.eligible });
    if (!options.apply or checked.eligible == 0) return;
    var store = try durable.Store.openExisting(allocator, state_path);
    defer store.close();
    if (!paths.stateMatchesAuthority(authority, state_path)) return error.OpenFailed;
    store.runtime_path = state_path;
    try store.configureRuntimeLimits();
    var backup_path: [std.fs.max_path_bytes]u8 = undefined;
    var partial_path: [std.fs.max_path_bytes]u8 = undefined;
    const backup = try store.takeEffectEvidenceBackup(state_path, &backup_path, &partial_path);
    try stdout.print("repair-effect-evidence: backup={} sha256={s}\n", .{ std.zig.fmtEscapes(backup.path), std.fmt.fmtSliceHexLower(&backup.sha256) });
    if (!paths.stateMatchesAuthority(authority, state_path)) return error.OpenFailed;
    const applied = try scan(&store, true);
    if (applied.repaired != checked.eligible or applied.examined != checked.examined) return error.StaleEffect;
    try stdout.print("repair-effect-evidence: {d} intents returned to pending; start the daemon to obtain fresh kernel evidence; retain the backup\n", .{applied.repaired});
}
