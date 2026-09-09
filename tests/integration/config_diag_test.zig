// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");

const testing = std.testing;

const daemon_path = "zig-out/bin/fail2zig";
const max_output_bytes: usize = 1 << 20;

const Run = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: *Run, a: std.mem.Allocator) void {
        a.free(self.stdout);
        a.free(self.stderr);
    }

    fn exitCode(self: *const Run) ?u8 {
        return switch (self.term) {
            .Exited => |code| code,
            else => null,
        };
    }
};

fn validateConfig(a: std.mem.Allocator, config_path: []const u8) !Run {
    const argv = [_][]const u8{ daemon_path, "--validate-config", "--config", config_path };
    var child = std.process.Child.init(&argv, a);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();

    var out: std.ArrayListUnmanaged(u8) = .{};
    errdefer out.deinit(a);
    var err_out: std.ArrayListUnmanaged(u8) = .{};
    errdefer err_out.deinit(a);
    try child.collectOutput(a, &out, &err_out, max_output_bytes);
    const term = try child.wait();

    return .{
        .term = term,
        .stdout = try out.toOwnedSlice(a),
        .stderr = try err_out.toOwnedSlice(a),
    };
}

fn hasErrorReturnTrace(text: []const u8) bool {
    if (std.mem.indexOf(u8, text, "error return trace") != null) return true;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, text, i, "0x")) |pos| {
        var j = pos + 2;
        while (j < text.len and std.ascii.isHex(text[j])) : (j += 1) {}
        if (j > pos + 2 and std.mem.startsWith(u8, text[j..], " in ")) return true;
        i = pos + 2;
    }
    return false;
}

fn lineOf(text: []const u8, needle: []const u8) ?usize {
    const pos = std.mem.indexOf(u8, text, needle) orelse return null;
    return 1 + std.mem.count(u8, text[0..pos], "\n");
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("expected to find \"{s}\" in:\n{s}\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

fn expectNotContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) {
        std.debug.print("expected NOT to find \"{s}\" in:\n{s}\n", .{ needle, haystack });
        return error.TestUnexpectedContains;
    }
}

const Fixture = struct {
    a: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    root: []const u8,
    config_path: []const u8,

    fn init(a: std.mem.Allocator) !Fixture {
        if (builtin.os.tag != .linux) return error.SkipZigTest;
        std.fs.cwd().access(daemon_path, .{}) catch return error.SkipZigTest;

        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
        const abs = try tmp.dir.realpath(".", &abs_buf);
        const root = try a.dupe(u8, abs);
        errdefer a.free(root);
        const config_path = try std.fmt.allocPrint(a, "{s}/config.toml", .{root});
        errdefer a.free(config_path);
        return .{ .a = a, .tmp = tmp, .root = root, .config_path = config_path };
    }

    fn deinit(self: *Fixture) void {
        self.a.free(self.config_path);
        self.a.free(self.root);
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn write(self: *Fixture, text: []const u8) !void {
        var f = try std.fs.cwd().createFile(self.config_path, .{ .truncate = true, .mode = 0o640 });
        defer f.close();
        try f.writeAll(text);
        try f.chmod(0o640);
    }

    fn fortyLineConfig(self: *Fixture, line37: []const u8) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        errdefer buf.deinit(self.a);
        const w = buf.writer(self.a);
        try w.print(
            \\[global]
            \\socket_path = "{s}/sock/fail2zig.sock"
            \\state_file = "{s}/state.bin"
            \\metrics_bind = "127.0.0.1"
            \\metrics_port = 19199
            \\memory_ceiling_mb = 64
            \\
            \\[defaults]
            \\banaction = "log-only"
            \\bantime = 600
            \\findtime = 600
            \\maxretry = 5
            \\
            \\
        , .{ self.root, self.root });
        var n: usize = 14;
        while (n <= 30) : (n += 1) try w.print("# padding line {d}\n", .{n});
        try w.print(
            \\[jails.sshd]
            \\enabled = true
            \\filter = "sshd"
            \\source = "file"
            \\logpath = ["{s}/auth.log"]
            \\maxretry = 3
            \\{s}
            \\bantime = 60
            \\findtime = 120
            \\# end of fixture
            \\
        , .{ self.root, line37 });
        return buf.toOwnedSlice(self.a);
    }
};

test "integration: --validate-config on a 40-line config names line 37 for the bad key" {
    const a = testing.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit();

    const text = try fx.fortyLineConfig("bogus_key = 1");
    defer a.free(text);
    try testing.expectEqual(@as(usize, 40), std.mem.count(u8, text, "\n"));
    try testing.expectEqual(@as(?usize, 37), lineOf(text, "bogus_key"));
    try fx.write(text);

    var r = try validateConfig(a, fx.config_path);
    defer r.deinit(a);

    try testing.expectEqual(@as(?u8, 1), r.exitCode());
    const position = try std.fmt.allocPrint(a, "config: {s}:37:1: UnknownKey (key 'bogus_key' in [jails.sshd])", .{fx.config_path});
    defer a.free(position);
    try expectContains(r.stderr, position);
    try expectNotContains(r.stdout, "config: OK");
    try testing.expect(!hasErrorReturnTrace(r.stderr));
}

test "integration: --validate-config on the same 40 lines with a valid line 37 passes" {
    const a = testing.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit();

    const text = try fx.fortyLineConfig("ignoreip = [\"127.0.0.1\"]");
    defer a.free(text);
    try fx.write(text);

    var r = try validateConfig(a, fx.config_path);
    defer r.deinit(a);

    try testing.expectEqual(@as(?u8, 0), r.exitCode());
    try expectContains(r.stdout, "config: OK (1 jail(s) configured)");
    try expectNotContains(r.stderr, ":37:");
}

test "integration: --validate-config resolves backend = \"systemd\" to journald and warns once" {
    const a = testing.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit();

    const text = try fx.fortyLineConfig("backend = \"systemd\"");
    defer a.free(text);
    const stripped = try std.mem.replaceOwned(u8, a, text, "source = \"file\"\n", "");
    defer a.free(stripped);
    try fx.write(stripped);

    var r = try validateConfig(a, fx.config_path);
    defer r.deinit(a);

    try testing.expectEqual(@as(?u8, 0), r.exitCode());
    try expectContains(r.stdout, "config: jail 'sshd' enabled=true filter=sshd source=journald banaction=log-only");
    try expectContains(r.stdout, "config: OK (1 jail(s) configured)");
    try expectContains(r.stderr, "[jails.sshd] 'backend' is a deprecated fail2ban compatibility alias");
    try expectContains(r.stderr, "use source = \"journald\"");
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, r.stderr, "deprecated"));
    try testing.expect(!hasErrorReturnTrace(r.stderr));
}

test "integration: --validate-config rejects backend + source in the same jail at the second key" {
    const a = testing.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit();

    const text = try fx.fortyLineConfig("backend = \"systemd\"");
    defer a.free(text);
    try fx.write(text);

    var r = try validateConfig(a, fx.config_path);
    defer r.deinit(a);

    try testing.expectEqual(@as(?u8, 1), r.exitCode());
    const position = try std.fmt.allocPrint(a, "config: {s}:37:", .{fx.config_path});
    defer a.free(position);
    try expectContains(r.stderr, position);
    try expectContains(r.stderr, "InvalidValue (key 'backend' in [jails.sshd])");
}

test "integration: SYS-021 --validate-config warns when state_file lives under /run" {
    const a = testing.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit();

    const text = try fx.fortyLineConfig("# line 37");
    defer a.free(text);
    const persistent = try std.fmt.allocPrint(a, "state_file = \"{s}/state.bin\"\n", .{fx.root});
    defer a.free(persistent);
    const volatile_state = "/run/fail2zig-diag-test/state.bin";
    const swapped = try std.mem.replaceOwned(u8, a, text, persistent, "state_file = \"" ++ volatile_state ++ "\"\n");
    defer a.free(swapped);
    try testing.expect(std.mem.indexOf(u8, swapped, volatile_state) != null);
    try fx.write(swapped);

    var r = try validateConfig(a, fx.config_path);
    defer r.deinit(a);

    try testing.expectEqual(@as(?u8, 0), r.exitCode());
    try expectContains(r.stdout, "config: OK (1 jail(s) configured)");
    try expectContains(r.stderr, volatile_state);
    try expectContains(r.stderr, "will not survive");
    try expectContains(r.stderr, "/var/lib/fail2zig");
}

test "integration: SYS-021 --validate-config stays quiet for a state_file under a persistent dir" {
    const a = testing.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit();

    const text = try fx.fortyLineConfig("# line 37");
    defer a.free(text);
    try fx.write(text);

    var r = try validateConfig(a, fx.config_path);
    defer r.deinit(a);

    try testing.expectEqual(@as(?u8, 0), r.exitCode());
    try expectNotContains(r.stderr, "will not survive");
}
