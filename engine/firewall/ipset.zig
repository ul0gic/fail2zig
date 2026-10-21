// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const mem = std.mem;
const shared = @import("shared");
const backend = @import("backend.zig");
const iptables = @import("iptables.zig");

pub const CommandBuilder = struct {
    set_name: []const u8,

    pub fn createSet(
        self: CommandBuilder,
        argv: *[9][]const u8,
        timeout_str: []const u8,
        maxelem_str: []const u8,
    ) [][]const u8 {
        argv[0] = "ipset";
        argv[1] = "create";
        argv[2] = self.set_name;
        argv[3] = "hash:ip";
        argv[4] = "timeout";
        argv[5] = timeout_str;
        argv[6] = "maxelem";
        argv[7] = maxelem_str;
        argv[8] = "-exist";
        return argv[0..9];
    }

    pub fn destroySet(self: CommandBuilder, argv: *[3][]const u8) [][]const u8 {
        argv[0] = "ipset";
        argv[1] = "destroy";
        argv[2] = self.set_name;
        return argv[0..3];
    }

    pub fn addEntry(
        self: CommandBuilder,
        argv: *[7][]const u8,
        ip_str: []const u8,
        timeout_str: []const u8,
    ) [][]const u8 {
        argv[0] = "ipset";
        argv[1] = "add";
        argv[2] = self.set_name;
        argv[3] = ip_str;
        if (timeout_str.len == 0) {
            argv[4] = "-exist";
            return argv[0..5];
        }
        argv[4] = "timeout";
        argv[5] = timeout_str;
        argv[6] = "-exist";
        return argv[0..7];
    }

    pub fn delEntry(
        self: CommandBuilder,
        argv: *[5][]const u8,
        ip_str: []const u8,
    ) [][]const u8 {
        argv[0] = "ipset";
        argv[1] = "del";
        argv[2] = self.set_name;
        argv[3] = ip_str;
        argv[4] = "-exist";
        return argv[0..5];
    }

    pub fn flushSet(self: CommandBuilder, argv: *[3][]const u8) [][]const u8 {
        argv[0] = "ipset";
        argv[1] = "flush";
        argv[2] = self.set_name;
        return argv[0..3];
    }

    pub fn listSet(self: CommandBuilder, argv: *[3][]const u8) [][]const u8 {
        argv[0] = "ipset";
        argv[1] = "list";
        argv[2] = self.set_name;
        return argv[0..3];
    }

    pub fn installMatchRule(
        self: CommandBuilder,
        argv: *[10][]const u8,
        binary: []const u8,
    ) [][]const u8 {
        argv[0] = binary;
        argv[1] = "-I";
        argv[2] = "INPUT";
        argv[3] = "-m";
        argv[4] = "set";
        argv[5] = "--match-set";
        argv[6] = self.set_name;
        argv[7] = "src";
        argv[8] = "-j";
        argv[9] = "DROP";
        return argv[0..10];
    }

    pub fn removeMatchRule(
        self: CommandBuilder,
        argv: *[10][]const u8,
        binary: []const u8,
    ) [][]const u8 {
        argv[0] = binary;
        argv[1] = "-D";
        argv[2] = "INPUT";
        argv[3] = "-m";
        argv[4] = "set";
        argv[5] = "--match-set";
        argv[6] = self.set_name;
        argv[7] = "src";
        argv[8] = "-j";
        argv[9] = "DROP";
        return argv[0..10];
    }
};

pub fn parseListOutput(
    allocator: std.mem.Allocator,
    stdout: []const u8,
) std.mem.Allocator.Error![]shared.IpAddress {
    var list = std.ArrayList(shared.IpAddress).init(allocator);
    errdefer list.deinit();

    var line_it = mem.splitScalar(u8, stdout, '\n');
    var past_members_header = false;
    while (line_it.next()) |line| {
        if (!past_members_header) {
            if (mem.startsWith(u8, line, "Members:")) past_members_header = true;
            continue;
        }
        if (line.len == 0) continue;
        var tokens = mem.tokenizeAny(u8, line, " \t");
        const first = tokens.next() orelse continue;
        const ip = shared.IpAddress.parse(first) catch continue;
        try list.append(ip);
    }
    return list.toOwnedSlice();
}

pub fn setName(
    buf: []u8,
    prefix: []const u8,
    jail: []const u8,
) error{BufferTooSmall}![]const u8 {
    return iptables.chainName(buf, prefix, jail);
}

pub const IpsetBackend = struct {
    allocator: ?std.mem.Allocator = null,
    config: ?backend.BackendConfig = null,
    initialized: bool = false,
};

pub const vtable: backend.BackendVTable = .{
    .initFn = initImpl,
    .deinitFn = deinitImpl,
    .banFn = banImpl,
    .unbanFn = unbanImpl,
    .listBansFn = listBansImpl,
    .flushFn = flushImpl,
    .isAvailableFn = isAvailableImpl,
};

pub fn probeAvailable() bool {
    return binaryExists("ipset") and iptables.probeAvailable();
}

fn binaryExists(name: []const u8) bool {
    const path_env = std.posix.getenv("PATH") orelse return false;
    var it = mem.splitScalar(u8, path_env, ':');
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        var stack_buf: [std.fs.max_path_bytes]u8 = undefined;
        const total_len = dir.len + 1 + name.len;
        if (total_len > stack_buf.len) continue;
        @memcpy(stack_buf[0..dir.len], dir);
        stack_buf[dir.len] = '/';
        @memcpy(stack_buf[dir.len + 1 .. total_len], name);
        std.posix.access(stack_buf[0..total_len], std.posix.X_OK) catch continue;
        return true;
    }
    return false;
}

fn castSelf(ctx: *anyopaque) *IpsetBackend {
    return @ptrCast(@alignCast(ctx));
}

fn initImpl(
    ctx: *anyopaque,
    config: backend.BackendConfig,
    allocator: std.mem.Allocator,
) backend.BackendError!void {
    const self = castSelf(ctx);
    if (self.initialized) return;
    if (!probeAvailable()) return error.NotAvailable;
    self.allocator = allocator;
    self.config = config;
    for ([_][]const u8{ "ipv4", "ipv6" }, [_][]const u8{ "inet", "inet6" }, [_][]const u8{ "iptables", "ip6tables" }) |suffix, family, binary| {
        var buf: [128]u8 = undefined;
        const name = setName(&buf, config.chain_prefix, suffix) catch return error.SystemError;
        if (name.len > 31) return error.SystemError;
        if (try iptables.runCommand(allocator, &.{ "ipset", "create", name, "hash:ip", "family", family, "timeout", "0", "maxelem", "1048576", "-exist" }) != .ok) return error.SystemError;
        const check = try iptables.runCommand(allocator, &.{ binary, "-C", "INPUT", "-m", "set", "--match-set", name, "src", "-j", "DROP" });
        if (check != .ok) {
            if (check != .not_found) return error.SystemError;
            var args: [10][]const u8 = undefined;
            if (try iptables.runCommand(allocator, (CommandBuilder{ .set_name = name }).installMatchRule(&args, binary)) != .ok) return error.SystemError;
        }
    }
    self.initialized = true;
}

fn deinitImpl(ctx: *anyopaque) void {
    const self = castSelf(ctx);
    self.initialized = false;
}

fn banImpl(
    ctx: *anyopaque,
    ip: shared.IpAddress,
    _: shared.JailId,
    duration: shared.Duration,
) backend.BackendError!void {
    _ = duration;
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    const allocator = self.allocator orelse return error.NotAvailable;
    const cfg = self.config orelse return error.NotAvailable;

    var name_buf: [128]u8 = undefined;
    const set = setName(&name_buf, cfg.chain_prefix, if (ip == .ipv4) "ipv4" else "ipv6") catch {
        return error.SystemError;
    };
    const builder: CommandBuilder = .{ .set_name = set };

    var ip_buf: [48]u8 = undefined;
    const ip_str = std.fmt.bufPrint(&ip_buf, "{}", .{ip}) catch {
        return error.SystemError;
    };
    var argv_storage: [7][]const u8 = undefined;
    const argv = builder.addEntry(&argv_storage, ip_str, "0");

    const exit_class = try iptables.runCommand(allocator, argv);
    switch (exit_class) {
        .ok => return,
        .already_exists => return error.AlreadyBanned,
        .not_found, .locked, .other => return error.SystemError,
    }
}

fn unbanImpl(
    ctx: *anyopaque,
    ip: shared.IpAddress,
    _: shared.JailId,
) backend.BackendError!void {
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    const allocator = self.allocator orelse return error.NotAvailable;
    const cfg = self.config orelse return error.NotAvailable;

    var name_buf: [128]u8 = undefined;
    const set = setName(&name_buf, cfg.chain_prefix, if (ip == .ipv4) "ipv4" else "ipv6") catch {
        return error.SystemError;
    };
    const builder: CommandBuilder = .{ .set_name = set };

    var ip_buf: [48]u8 = undefined;
    const ip_str = std.fmt.bufPrint(&ip_buf, "{}", .{ip}) catch {
        return error.SystemError;
    };
    var argv_storage: [5][]const u8 = undefined;
    const argv = builder.delEntry(&argv_storage, ip_str);

    const exit_class = try iptables.runCommand(allocator, argv);
    switch (exit_class) {
        .ok => return,
        .not_found => return error.NotBanned,
        .already_exists, .locked, .other => return error.SystemError,
    }
}

fn listBansImpl(ctx: *anyopaque, _: shared.JailId, allocator: std.mem.Allocator) backend.BackendError![]shared.IpAddress {
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    const cfg = self.config orelse return error.NotAvailable;
    var list = std.ArrayList(shared.IpAddress).init(allocator);
    errdefer list.deinit();
    for ([_][]const u8{ "ipv4", "ipv6" }) |suffix| {
        var buf: [128]u8 = undefined;
        const name = setName(&buf, cfg.chain_prefix, suffix) catch return error.SystemError;
        const result = try iptables.command.run(allocator, &.{ "ipset", "list", name }, 2000);
        defer result.deinit(allocator);
        if (result.code != 0) return error.SystemError;
        const ips = try parseListOutput(allocator, result.stdout);
        defer allocator.free(ips);
        try list.appendSlice(ips);
    }
    return list.toOwnedSlice();
}

fn flushImpl(ctx: *anyopaque, _: shared.JailId) backend.BackendError!void {
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    const allocator = self.allocator orelse return error.NotAvailable;
    const cfg = self.config orelse return error.NotAvailable;
    for ([_][]const u8{ "ipv4", "ipv6" }) |suffix| {
        var buf: [128]u8 = undefined;
        const name = setName(&buf, cfg.chain_prefix, suffix) catch return error.SystemError;
        if (try iptables.runCommand(allocator, &.{ "ipset", "flush", name }) != .ok) return error.SystemError;
    }
}

fn isAvailableImpl(ctx: *anyopaque) bool {
    _ = ctx;
    return probeAvailable();
}
