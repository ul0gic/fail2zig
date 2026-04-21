//! ipset backend — ipset sets + one iptables jump rule per jail.
//!
//! Why this exists: `iptables -s <ip> -j DROP` rules are O(n) per
//! packet. For a jail with thousands of bans, that destroys CPU.
//! ipset stores the ban list in a kernel hash set, and a single
//! iptables rule (`-m set --match-set`) does O(1) lookup against
//! it. It's the right backend for the iptables era.
//!
//! Architecture:
//!   - `ipset create fail2zig-<jail> hash:ip timeout <bantime> maxelem 65536`
//!   - `iptables -I INPUT -m set --match-set fail2zig-<jail> src -j DROP`
//!
//! Bans/unbans go to `ipset`, which is the hot path; the iptables
//! rule is installed exactly once per jail at `init()` time and
//! torn down on `deinit()` if the config says so.
//!
//! Tests assert argv construction + list parsing without executing.

const std = @import("std");
const mem = std.mem;
const shared = @import("shared");
const backend = @import("backend.zig");
const iptables = @import("iptables.zig");

/// Per-operation argv builder for `ipset`.
pub const CommandBuilder = struct {
    set_name: []const u8,

    /// `ipset create <set> hash:ip timeout <t> maxelem 65536`.
    /// `timeout_str` and `maxelem_str` are caller-owned buffers so
    /// argv stays a flat `[][]const u8`.
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
        argv[8] = "-exist"; // idempotent — don't fail if set exists
        return argv[0..9];
    }

    /// `ipset destroy <set>`.
    pub fn destroySet(self: CommandBuilder, argv: *[3][]const u8) [][]const u8 {
        argv[0] = "ipset";
        argv[1] = "destroy";
        argv[2] = self.set_name;
        return argv[0..3];
    }

    /// `ipset add <set> <ip> timeout <t>`. `timeout_str` can be
    /// an empty slice to omit the timeout tail.
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

    /// `ipset del <set> <ip>`.
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

    /// `ipset flush <set>`.
    pub fn flushSet(self: CommandBuilder, argv: *[3][]const u8) [][]const u8 {
        argv[0] = "ipset";
        argv[1] = "flush";
        argv[2] = self.set_name;
        return argv[0..3];
    }

    /// `ipset list <set>`.
    pub fn listSet(self: CommandBuilder, argv: *[3][]const u8) [][]const u8 {
        argv[0] = "ipset";
        argv[1] = "list";
        argv[2] = self.set_name;
        return argv[0..3];
    }

    /// `iptables -I INPUT -m set --match-set <set> src -j DROP`.
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

    /// `iptables -D INPUT -m set --match-set <set> src -j DROP`.
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

/// Parse `ipset list <set>` output. Member lines look like:
///
///     Name: fail2zig-sshd
///     Type: hash:ip
///     Revision: 6
///     Header: family inet hashsize 1024 maxelem 65536 timeout 600
///     Size in memory: 408
///     References: 1
///     Number of entries: 2
///     Members:
///     1.2.3.4 timeout 589
///     5.6.7.8 timeout 122
///
/// We scan until the `Members:` header, then treat each subsequent
/// non-empty line's first token as an IP.
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

/// Compose the set name: `<prefix>-<jail>`.
pub fn setName(
    buf: []u8,
    prefix: []const u8,
    jail: []const u8,
) error{BufferTooSmall}![]const u8 {
    return iptables.chainName(buf, prefix, jail);
}

// ===========================================================================
// Backend state + vtable wiring
// ===========================================================================

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
    return binaryExists("ipset") and binaryExists("iptables");
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
        std.fs.accessAbsolute(stack_buf[0..total_len], .{ .mode = .read_only }) catch continue;
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
    self.initialized = true;
    // Set creation deferred until Phase 4 ban lifecycle wire-up.
}

fn deinitImpl(ctx: *anyopaque) void {
    const self = castSelf(ctx);
    self.initialized = false;
}

fn banImpl(
    ctx: *anyopaque,
    ip: shared.IpAddress,
    jail: shared.JailId,
    duration: shared.Duration,
) backend.BackendError!void {
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    const allocator = self.allocator orelse return error.NotAvailable;
    const cfg = self.config orelse return error.NotAvailable;

    var name_buf: [128]u8 = undefined;
    const set = setName(&name_buf, cfg.chain_prefix, jail.slice()) catch {
        return error.SystemError;
    };
    const builder: CommandBuilder = .{ .set_name = set };

    var ip_buf: [48]u8 = undefined;
    const ip_str = std.fmt.bufPrint(&ip_buf, "{}", .{ip}) catch {
        return error.SystemError;
    };
    var timeout_buf: [24]u8 = undefined;
    const timeout_str = std.fmt.bufPrint(&timeout_buf, "{d}", .{duration}) catch {
        return error.SystemError;
    };

    var argv_storage: [7][]const u8 = undefined;
    const argv = builder.addEntry(&argv_storage, ip_str, timeout_str);

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
    jail: shared.JailId,
) backend.BackendError!void {
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    const allocator = self.allocator orelse return error.NotAvailable;
    const cfg = self.config orelse return error.NotAvailable;

    var name_buf: [128]u8 = undefined;
    const set = setName(&name_buf, cfg.chain_prefix, jail.slice()) catch {
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

fn listBansImpl(
    ctx: *anyopaque,
    jail: shared.JailId,
    allocator: std.mem.Allocator,
) backend.BackendError![]shared.IpAddress {
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    const cfg = self.config orelse return error.NotAvailable;

    var name_buf: [128]u8 = undefined;
    const set = setName(&name_buf, cfg.chain_prefix, jail.slice()) catch {
        return error.SystemError;
    };
    const builder: CommandBuilder = .{ .set_name = set };
    var argv_storage: [3][]const u8 = undefined;
    const argv = builder.listSet(&argv_storage);

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Close;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return error.SystemError;
    const stdout_reader = child.stdout orelse {
        _ = child.wait() catch {};
        return error.SystemError;
    };
    const stdout_buf = stdout_reader.readToEndAlloc(allocator, 1024 * 1024) catch {
        _ = child.wait() catch {};
        return error.SystemError;
    };
    defer allocator.free(stdout_buf);
    const term = child.wait() catch return error.SystemError;
    switch (term) {
        .Exited => |c| if (c != 0) return try allocator.alloc(shared.IpAddress, 0),
        else => return error.SystemError,
    }
    return parseListOutput(allocator, stdout_buf) catch return error.OutOfMemory;
}

fn flushImpl(ctx: *anyopaque, jail: shared.JailId) backend.BackendError!void {
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    const allocator = self.allocator orelse return error.NotAvailable;
    const cfg = self.config orelse return error.NotAvailable;

    var name_buf: [128]u8 = undefined;
    const set = setName(&name_buf, cfg.chain_prefix, jail.slice()) catch {
        return error.SystemError;
    };
    const builder: CommandBuilder = .{ .set_name = set };
    var argv_storage: [3][]const u8 = undefined;
    const argv = builder.flushSet(&argv_storage);
    _ = try iptables.runCommand(allocator, argv);
}

fn isAvailableImpl(ctx: *anyopaque) bool {
    _ = ctx;
    return probeAvailable();
}

// ===========================================================================
// Tests
// ===========================================================================

test "ipset: CommandBuilder.createSet emits hash:ip + timeout + maxelem" {
    const cb: CommandBuilder = .{ .set_name = "fail2zig-sshd" };
    var argv_storage: [9][]const u8 = undefined;
    const argv = cb.createSet(&argv_storage, "600", "65536");
    try std.testing.expectEqual(@as(usize, 9), argv.len);
    try std.testing.expectEqualStrings("ipset", argv[0]);
    try std.testing.expectEqualStrings("create", argv[1]);
    try std.testing.expectEqualStrings("fail2zig-sshd", argv[2]);
    try std.testing.expectEqualStrings("hash:ip", argv[3]);
    try std.testing.expectEqualStrings("timeout", argv[4]);
    try std.testing.expectEqualStrings("600", argv[5]);
    try std.testing.expectEqualStrings("maxelem", argv[6]);
    try std.testing.expectEqualStrings("65536", argv[7]);
    try std.testing.expectEqualStrings("-exist", argv[8]);
}

test "ipset: CommandBuilder.addEntry includes timeout when non-empty" {
    const cb: CommandBuilder = .{ .set_name = "fail2zig-sshd" };
    var argv_storage: [7][]const u8 = undefined;
    const argv = cb.addEntry(&argv_storage, "1.2.3.4", "30");
    try std.testing.expectEqual(@as(usize, 7), argv.len);
    try std.testing.expectEqualStrings("ipset", argv[0]);
    try std.testing.expectEqualStrings("add", argv[1]);
    try std.testing.expectEqualStrings("fail2zig-sshd", argv[2]);
    try std.testing.expectEqualStrings("1.2.3.4", argv[3]);
    try std.testing.expectEqualStrings("timeout", argv[4]);
    try std.testing.expectEqualStrings("30", argv[5]);
    try std.testing.expectEqualStrings("-exist", argv[6]);
}

test "ipset: CommandBuilder.addEntry omits timeout when empty" {
    const cb: CommandBuilder = .{ .set_name = "fail2zig-sshd" };
    var argv_storage: [7][]const u8 = undefined;
    const argv = cb.addEntry(&argv_storage, "1.2.3.4", "");
    try std.testing.expectEqual(@as(usize, 5), argv.len);
    try std.testing.expectEqualStrings("1.2.3.4", argv[3]);
    try std.testing.expectEqualStrings("-exist", argv[4]);
}

test "ipset: CommandBuilder.delEntry emits del + ip" {
    const cb: CommandBuilder = .{ .set_name = "fail2zig-sshd" };
    var argv_storage: [5][]const u8 = undefined;
    const argv = cb.delEntry(&argv_storage, "10.0.0.1");
    try std.testing.expectEqual(@as(usize, 5), argv.len);
    try std.testing.expectEqualStrings("ipset", argv[0]);
    try std.testing.expectEqualStrings("del", argv[1]);
    try std.testing.expectEqualStrings("fail2zig-sshd", argv[2]);
    try std.testing.expectEqualStrings("10.0.0.1", argv[3]);
    try std.testing.expectEqualStrings("-exist", argv[4]);
}

test "ipset: CommandBuilder.installMatchRule emits iptables -m set match" {
    const cb: CommandBuilder = .{ .set_name = "fail2zig-sshd" };
    var argv_storage: [10][]const u8 = undefined;
    const argv = cb.installMatchRule(&argv_storage, "iptables");
    try std.testing.expectEqual(@as(usize, 10), argv.len);
    try std.testing.expectEqualStrings("iptables", argv[0]);
    try std.testing.expectEqualStrings("-I", argv[1]);
    try std.testing.expectEqualStrings("INPUT", argv[2]);
    try std.testing.expectEqualStrings("-m", argv[3]);
    try std.testing.expectEqualStrings("set", argv[4]);
    try std.testing.expectEqualStrings("--match-set", argv[5]);
    try std.testing.expectEqualStrings("fail2zig-sshd", argv[6]);
    try std.testing.expectEqualStrings("src", argv[7]);
    try std.testing.expectEqualStrings("-j", argv[8]);
    try std.testing.expectEqualStrings("DROP", argv[9]);
}

test "ipset: parseListOutput extracts members from ipset list output" {
    const sample =
        "Name: fail2zig-sshd\n" ++
        "Type: hash:ip\n" ++
        "Revision: 6\n" ++
        "Header: family inet hashsize 1024 maxelem 65536 timeout 600\n" ++
        "Size in memory: 408\n" ++
        "References: 1\n" ++
        "Number of entries: 2\n" ++
        "Members:\n" ++
        "1.2.3.4 timeout 589\n" ++
        "5.6.7.8 timeout 122\n";
    const list = try parseListOutput(std.testing.allocator, sample);
    defer std.testing.allocator.free(list);
    try std.testing.expectEqual(@as(usize, 2), list.len);
    try std.testing.expectEqual(
        (try shared.IpAddress.parse("1.2.3.4")).ipv4,
        list[0].ipv4,
    );
    try std.testing.expectEqual(
        (try shared.IpAddress.parse("5.6.7.8")).ipv4,
        list[1].ipv4,
    );
}

test "ipset: parseListOutput handles IPv6 members" {
    const sample =
        "Name: fail2zig-sshd6\n" ++
        "Type: hash:ip\n" ++
        "Header: family inet6 maxelem 65536 timeout 600\n" ++
        "Members:\n" ++
        "2001:db8::1 timeout 500\n" ++
        "::1 timeout 42\n";
    const list = try parseListOutput(std.testing.allocator, sample);
    defer std.testing.allocator.free(list);
    try std.testing.expectEqual(@as(usize, 2), list.len);
    try std.testing.expectEqual(@as(u128, 1), list[1].ipv6);
}

test "ipset: parseListOutput returns empty when no Members: header" {
    const sample = "Name: empty\nType: hash:ip\nHeader: ...\n";
    const list = try parseListOutput(std.testing.allocator, sample);
    defer std.testing.allocator.free(list);
    try std.testing.expectEqual(@as(usize, 0), list.len);
}

test "ipset: setName composes the set identifier" {
    var buf: [64]u8 = undefined;
    const s = try setName(&buf, "fail2zig", "nginx");
    try std.testing.expectEqualStrings("fail2zig-nginx", s);
}

test "ipset: IpsetBackend uninit ban returns NotAvailable" {
    var be: backend.Backend = .{ .ipset = IpsetBackend{} };
    const ip = try shared.IpAddress.parse("1.2.3.4");
    const jail = try shared.JailId.fromSlice("sshd");
    try std.testing.expectError(error.NotAvailable, be.ban(ip, jail, 600));
}

test "ipset: probeAvailable returns same value across calls" {
    try std.testing.expectEqual(probeAvailable(), probeAvailable());
}
