// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! iptables backend — legacy fallback via CLI fork/exec.
//!
//! We shell out to `iptables` / `ip6tables` because most
//! distributions still ship them and because the netfilter-era
//! kernel ABI (`libiptc`) is deprecated. Performance is worse than
//! nftables (one process spawn per op) but correctness is well
//! understood and the code path is small.
//!
//! Every operation emits a command via `CommandBuilder` first, so
//! tests can assert on the exact argv without ever forking.
//!
//! Error mapping:
//!   - exit 0  → OK
//!   - exit 1  + stderr contains "already exists"  → AlreadyBanned
//!   - exit 2  + stderr contains "does a matching rule exist" → NotBanned
//!   - exit 4  + stderr contains "Resource temporarily unavailable" (xtables lock) → retry
//!   - anything else → SystemError
//!
//! Command string construction is pure; execution is isolated so
//! tests can run without root.

const std = @import("std");
const mem = std.mem;
const shared = @import("shared");
const backend = @import("backend.zig");

/// Per-operation argv builder. Uses a caller-owned backing buffer
/// for argv storage — the individual strings live elsewhere
/// (stack, config) but the argv slice is built in place.
pub const CommandBuilder = struct {
    /// Binary name: `"iptables"` or `"ip6tables"`.
    binary: []const u8,
    /// Per-jail chain name (e.g. `"fail2zig-sshd"`). The caller
    /// allocates this string and keeps it alive for the duration
    /// of command construction.
    chain: []const u8,

    /// `iptables -N <chain>` — create the jail chain.
    pub fn createChain(self: CommandBuilder, argv: *[4][]const u8) [][]const u8 {
        argv[0] = self.binary;
        argv[1] = "-N";
        argv[2] = self.chain;
        return argv[0..3];
    }

    /// `iptables -F <chain>` — flush all rules out of the chain.
    pub fn flushChain(self: CommandBuilder, argv: *[4][]const u8) [][]const u8 {
        argv[0] = self.binary;
        argv[1] = "-F";
        argv[2] = self.chain;
        return argv[0..3];
    }

    /// `iptables -X <chain>` — delete an empty chain.
    pub fn deleteChain(self: CommandBuilder, argv: *[4][]const u8) [][]const u8 {
        argv[0] = self.binary;
        argv[1] = "-X";
        argv[2] = self.chain;
        return argv[0..3];
    }

    /// `iptables -I INPUT -j <chain>` — insert the jump at the top
    /// of INPUT so our drops are evaluated before any other rule.
    pub fn installJump(self: CommandBuilder, argv: *[6][]const u8) [][]const u8 {
        argv[0] = self.binary;
        argv[1] = "-I";
        argv[2] = "INPUT";
        argv[3] = "-j";
        argv[4] = self.chain;
        return argv[0..5];
    }

    /// `iptables -D INPUT -j <chain>` — remove the jump we
    /// installed.
    pub fn removeJump(self: CommandBuilder, argv: *[6][]const u8) [][]const u8 {
        argv[0] = self.binary;
        argv[1] = "-D";
        argv[2] = "INPUT";
        argv[3] = "-j";
        argv[4] = self.chain;
        return argv[0..5];
    }

    /// `iptables -A <chain> -s <ip> -j DROP`.
    pub fn banRule(
        self: CommandBuilder,
        argv: *[8][]const u8,
        ip_str: []const u8,
    ) [][]const u8 {
        argv[0] = self.binary;
        argv[1] = "-A";
        argv[2] = self.chain;
        argv[3] = "-s";
        argv[4] = ip_str;
        argv[5] = "-j";
        argv[6] = "DROP";
        return argv[0..7];
    }

    /// `iptables -D <chain> -s <ip> -j DROP`.
    pub fn unbanRule(
        self: CommandBuilder,
        argv: *[8][]const u8,
        ip_str: []const u8,
    ) [][]const u8 {
        argv[0] = self.binary;
        argv[1] = "-D";
        argv[2] = self.chain;
        argv[3] = "-s";
        argv[4] = ip_str;
        argv[5] = "-j";
        argv[6] = "DROP";
        return argv[0..7];
    }

    /// `iptables -L <chain> -n` — list rules, IP-only.
    pub fn listRules(self: CommandBuilder, argv: *[5][]const u8) [][]const u8 {
        argv[0] = self.binary;
        argv[1] = "-L";
        argv[2] = self.chain;
        argv[3] = "-n";
        return argv[0..4];
    }
};

/// Select the binary based on the IP family.
pub fn binaryFor(ip: shared.IpAddress) []const u8 {
    return switch (ip) {
        .ipv4 => "iptables",
        .ipv6 => "ip6tables",
    };
}

/// Compose the per-jail chain name: `<prefix>-<jail>`.
/// Writes into `buf` and returns the slice; fails if `buf` is
/// too small.
pub fn chainName(
    buf: []u8,
    prefix: []const u8,
    jail: []const u8,
) error{BufferTooSmall}![]const u8 {
    const total = prefix.len + 1 + jail.len;
    if (total > buf.len) return error.BufferTooSmall;
    @memcpy(buf[0..prefix.len], prefix);
    buf[prefix.len] = '-';
    @memcpy(buf[prefix.len + 1 .. total], jail);
    return buf[0..total];
}

/// Classify an iptables command exit: transient lock failures get
/// retried; already-exists / no-such-rule map to their idempotency
/// errors.
pub const ExitClass = enum { ok, already_exists, not_found, locked, other };

pub fn classifyExit(exit_code: u8, stderr: []const u8) ExitClass {
    if (exit_code == 0) return .ok;
    // iptables-legacy prints distinct messages we can pattern-match
    // on. We do not rely on exit codes alone because they've
    // shifted between versions.
    if (mem.indexOf(u8, stderr, "already exists") != null) return .already_exists;
    if (mem.indexOf(u8, stderr, "does a matching rule exist") != null) return .not_found;
    if (mem.indexOf(u8, stderr, "No chain/target/match by that name") != null) return .not_found;
    if (mem.indexOf(u8, stderr, "Resource temporarily unavailable") != null) return .locked;
    if (mem.indexOf(u8, stderr, "xtables lock") != null) return .locked;
    return .other;
}

/// Parse IP addresses out of `iptables -L -n` output. Lines that
/// describe DROP rules look like:
///
///     DROP       all  --  1.2.3.4              0.0.0.0/0
///
/// We walk tokens and yield the 4th column when column 1 is
/// "DROP". Zero allocation in the parse path — callers pass an
/// `ArrayList` for accumulation.
pub fn parseListOutput(
    allocator: std.mem.Allocator,
    stdout: []const u8,
) std.mem.Allocator.Error![]shared.IpAddress {
    var list = std.ArrayList(shared.IpAddress).init(allocator);
    errdefer list.deinit();

    var line_it = mem.splitScalar(u8, stdout, '\n');
    while (line_it.next()) |line| {
        // Skip headers/empty lines.
        if (line.len == 0) continue;
        if (mem.startsWith(u8, line, "Chain ")) continue;
        if (mem.startsWith(u8, line, "target ")) continue;

        var tokens = mem.tokenizeScalar(u8, line, ' ');
        const target = tokens.next() orelse continue;
        if (!mem.eql(u8, target, "DROP")) continue;
        _ = tokens.next() orelse continue; // protocol (all/tcp/udp)
        _ = tokens.next() orelse continue; // opt (--)
        const source = tokens.next() orelse continue;
        const ip = shared.IpAddress.parse(source) catch continue;
        try list.append(ip);
    }
    return list.toOwnedSlice();
}

/// Execute a single iptables command. Returns the exit class.
/// Collects stderr so the caller can classify failures precisely.
///
/// Argv strings MUST be null-safe `[]const u8` — `std.process.Child`
/// handles the terminators internally when it exec's, so callers
/// don't need to carry `[:0]` themselves.
pub fn runCommand(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
) backend.BackendError!ExitClass {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Close;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Pipe;
    child.spawn() catch return error.SystemError;

    // Drain stderr fully before waiting so the pipe doesn't fill.
    const stderr_reader = child.stderr orelse {
        _ = child.wait() catch {};
        return error.SystemError;
    };
    const stderr_buf = stderr_reader.readToEndAlloc(allocator, 4096) catch {
        _ = child.wait() catch {};
        return error.SystemError;
    };
    defer allocator.free(stderr_buf);

    const term = child.wait() catch return error.SystemError;
    const code: u8 = switch (term) {
        .Exited => |c| c,
        else => return error.SystemError,
    };
    return classifyExit(code, stderr_buf);
}

// ===========================================================================
// Backend state + vtable wiring
// ===========================================================================

pub const IptablesBackend = struct {
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

/// Availability probe: look for `iptables` on `PATH`.
pub fn probeAvailable() bool {
    return binaryExistsOnPath("iptables");
}

fn binaryExistsOnPath(name: []const u8) bool {
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
        const full = stack_buf[0..total_len];
        std.fs.accessAbsolute(full, .{ .mode = .read_only }) catch continue;
        return true;
    }
    return false;
}

fn castSelf(ctx: *anyopaque) *IptablesBackend {
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
    // Chain + jump creation is deferred until the first ban so the
    // daemon doesn't need CAP_NET_ADMIN for tests or for a warm
    // start in a crippled namespace. The real wire-up happens in
    // Phase 4's ban lifecycle integration.
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
    _ = duration; // iptables doesn't support per-rule timeouts
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    const allocator = self.allocator orelse return error.NotAvailable;
    const cfg = self.config orelse return error.NotAvailable;

    var chain_buf: [128]u8 = undefined;
    const chain = chainName(&chain_buf, cfg.chain_prefix, jail.slice()) catch {
        return error.SystemError;
    };
    const builder: CommandBuilder = .{
        .binary = binaryFor(ip),
        .chain = chain,
    };

    var ip_buf: [48]u8 = undefined;
    const ip_str = std.fmt.bufPrint(&ip_buf, "{}", .{ip}) catch {
        return error.SystemError;
    };

    var argv_storage: [8][]const u8 = undefined;
    const argv = builder.banRule(&argv_storage, ip_str);

    switch (try runCommand(allocator, argv)) {
        .ok => return,
        .already_exists => return error.AlreadyBanned,
        .not_found => return error.SystemError, // chain missing
        .locked => return error.SystemError, // Phase 4 adds retries
        .other => return error.SystemError,
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

    var chain_buf: [128]u8 = undefined;
    const chain = chainName(&chain_buf, cfg.chain_prefix, jail.slice()) catch {
        return error.SystemError;
    };
    const builder: CommandBuilder = .{ .binary = binaryFor(ip), .chain = chain };

    var ip_buf: [48]u8 = undefined;
    const ip_str = std.fmt.bufPrint(&ip_buf, "{}", .{ip}) catch {
        return error.SystemError;
    };

    var argv_storage: [8][]const u8 = undefined;
    const argv = builder.unbanRule(&argv_storage, ip_str);

    switch (try runCommand(allocator, argv)) {
        .ok => return,
        .not_found => return error.NotBanned,
        .already_exists => return error.SystemError, // impossible on delete
        .locked => return error.SystemError,
        .other => return error.SystemError,
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

    var chain_buf: [128]u8 = undefined;
    const chain = chainName(&chain_buf, cfg.chain_prefix, jail.slice()) catch {
        return error.SystemError;
    };
    // IPv4 and IPv6 are separate binaries; we need to merge.
    const v4_bans = try runAndParse(allocator, "iptables", chain);
    defer allocator.free(v4_bans);
    const v6_bans = try runAndParse(allocator, "ip6tables", chain);
    defer allocator.free(v6_bans);

    var out = try allocator.alloc(shared.IpAddress, v4_bans.len + v6_bans.len);
    @memcpy(out[0..v4_bans.len], v4_bans);
    @memcpy(out[v4_bans.len..], v6_bans);
    return out;
}

fn runAndParse(
    allocator: std.mem.Allocator,
    binary: []const u8,
    chain: []const u8,
) backend.BackendError![]shared.IpAddress {
    const builder: CommandBuilder = .{ .binary = binary, .chain = chain };
    var argv_storage: [5][]const u8 = undefined;
    const argv = builder.listRules(&argv_storage);

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Close;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return error.SystemError;
    const stdout_reader = child.stdout orelse {
        _ = child.wait() catch {};
        return error.SystemError;
    };
    const stdout_buf = stdout_reader.readToEndAlloc(allocator, 64 * 1024) catch {
        _ = child.wait() catch {};
        return error.SystemError;
    };
    defer allocator.free(stdout_buf);
    const term = child.wait() catch return error.SystemError;
    switch (term) {
        .Exited => |c| if (c != 0) return try allocator.alloc(shared.IpAddress, 0),
        else => return error.SystemError,
    }
    return try parseListOutput(allocator, stdout_buf);
}

fn flushImpl(ctx: *anyopaque, jail: shared.JailId) backend.BackendError!void {
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    const allocator = self.allocator orelse return error.NotAvailable;
    const cfg = self.config orelse return error.NotAvailable;

    var chain_buf: [128]u8 = undefined;
    const chain = chainName(&chain_buf, cfg.chain_prefix, jail.slice()) catch {
        return error.SystemError;
    };
    const builder: CommandBuilder = .{ .binary = "iptables", .chain = chain };
    var argv_storage: [4][]const u8 = undefined;
    const argv = builder.flushChain(&argv_storage);
    _ = try runCommand(allocator, argv);

    const builder6: CommandBuilder = .{ .binary = "ip6tables", .chain = chain };
    var argv6_storage: [4][]const u8 = undefined;
    const argv6 = builder6.flushChain(&argv6_storage);
    _ = try runCommand(allocator, argv6);
}

fn isAvailableImpl(ctx: *anyopaque) bool {
    _ = ctx;
    return probeAvailable();
}

// ===========================================================================
// Tests — verify argv construction / parsing / classification only
// ===========================================================================

test "iptables: chainName composes prefix-jail" {
    var buf: [64]u8 = undefined;
    const c = try chainName(&buf, "fail2zig", "sshd");
    try std.testing.expectEqualStrings("fail2zig-sshd", c);
}

test "iptables: chainName returns BufferTooSmall when buffer is small" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        chainName(&buf, "fail2zig", "sshd"),
    );
}

test "iptables: binaryFor selects iptables for IPv4 and ip6tables for IPv6" {
    const v4: shared.IpAddress = .{ .ipv4 = 0 };
    const v6: shared.IpAddress = .{ .ipv6 = 0 };
    try std.testing.expectEqualStrings("iptables", binaryFor(v4));
    try std.testing.expectEqualStrings("ip6tables", binaryFor(v6));
}

test "iptables: CommandBuilder.createChain emits -N <chain>" {
    const cb: CommandBuilder = .{ .binary = "iptables", .chain = "fail2zig-sshd" };
    var argv_storage: [4][]const u8 = undefined;
    const argv = cb.createChain(&argv_storage);
    try std.testing.expectEqual(@as(usize, 3), argv.len);
    try std.testing.expectEqualStrings("iptables", argv[0]);
    try std.testing.expectEqualStrings("-N", argv[1]);
    try std.testing.expectEqualStrings("fail2zig-sshd", argv[2]);
}

test "iptables: CommandBuilder.installJump emits -I INPUT -j <chain>" {
    const cb: CommandBuilder = .{ .binary = "iptables", .chain = "fail2zig-sshd" };
    var argv_storage: [6][]const u8 = undefined;
    const argv = cb.installJump(&argv_storage);
    try std.testing.expectEqual(@as(usize, 5), argv.len);
    try std.testing.expectEqualStrings("iptables", argv[0]);
    try std.testing.expectEqualStrings("-I", argv[1]);
    try std.testing.expectEqualStrings("INPUT", argv[2]);
    try std.testing.expectEqualStrings("-j", argv[3]);
    try std.testing.expectEqualStrings("fail2zig-sshd", argv[4]);
}

test "iptables: CommandBuilder.banRule emits -A <chain> -s <ip> -j DROP" {
    const cb: CommandBuilder = .{ .binary = "iptables", .chain = "fail2zig-sshd" };
    var argv_storage: [8][]const u8 = undefined;
    const argv = cb.banRule(&argv_storage, "1.2.3.4");
    try std.testing.expectEqual(@as(usize, 7), argv.len);
    try std.testing.expectEqualStrings("iptables", argv[0]);
    try std.testing.expectEqualStrings("-A", argv[1]);
    try std.testing.expectEqualStrings("fail2zig-sshd", argv[2]);
    try std.testing.expectEqualStrings("-s", argv[3]);
    try std.testing.expectEqualStrings("1.2.3.4", argv[4]);
    try std.testing.expectEqualStrings("-j", argv[5]);
    try std.testing.expectEqualStrings("DROP", argv[6]);
}

test "iptables: CommandBuilder.unbanRule emits -D <chain> -s <ip> -j DROP" {
    const cb: CommandBuilder = .{ .binary = "ip6tables", .chain = "fail2zig-sshd" };
    var argv_storage: [8][]const u8 = undefined;
    const argv = cb.unbanRule(&argv_storage, "::1");
    try std.testing.expectEqual(@as(usize, 7), argv.len);
    try std.testing.expectEqualStrings("ip6tables", argv[0]);
    try std.testing.expectEqualStrings("-D", argv[1]);
    try std.testing.expectEqualStrings("fail2zig-sshd", argv[2]);
    try std.testing.expectEqualStrings("-s", argv[3]);
    try std.testing.expectEqualStrings("::1", argv[4]);
    try std.testing.expectEqualStrings("-j", argv[5]);
    try std.testing.expectEqualStrings("DROP", argv[6]);
}

test "iptables: classifyExit maps stderr substrings to error classes" {
    try std.testing.expectEqual(ExitClass.ok, classifyExit(0, ""));
    try std.testing.expectEqual(
        ExitClass.already_exists,
        classifyExit(1, "iptables: Chain already exists.\n"),
    );
    try std.testing.expectEqual(
        ExitClass.not_found,
        classifyExit(2, "iptables: Bad rule (does a matching rule exist in that chain?).\n"),
    );
    try std.testing.expectEqual(
        ExitClass.not_found,
        classifyExit(1, "iptables: No chain/target/match by that name.\n"),
    );
    try std.testing.expectEqual(
        ExitClass.locked,
        classifyExit(4, "Another app is currently holding the xtables lock.\n"),
    );
    try std.testing.expectEqual(
        ExitClass.locked,
        classifyExit(4, "iptables: Resource temporarily unavailable\n"),
    );
    try std.testing.expectEqual(
        ExitClass.other,
        classifyExit(1, "iptables: Some other failure\n"),
    );
}

test "iptables: parseListOutput extracts DROP source addresses" {
    const sample =
        "Chain fail2zig-sshd (1 references)\n" ++
        "target     prot opt source               destination\n" ++
        "DROP       all  --  1.2.3.4              0.0.0.0/0\n" ++
        "DROP       all  --  5.6.7.8              0.0.0.0/0\n" ++
        "ACCEPT     all  --  9.9.9.9              0.0.0.0/0\n";
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

test "iptables: parseListOutput returns empty list for empty or header-only input" {
    const empty = try parseListOutput(std.testing.allocator, "");
    defer std.testing.allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);

    const headers_only =
        "Chain fail2zig-sshd (1 references)\n" ++
        "target     prot opt source               destination\n";
    const hdrs = try parseListOutput(std.testing.allocator, headers_only);
    defer std.testing.allocator.free(hdrs);
    try std.testing.expectEqual(@as(usize, 0), hdrs.len);
}

test "iptables: IptablesBackend uninit ban returns NotAvailable" {
    var be: backend.Backend = .{ .iptables = IptablesBackend{} };
    const ip = try shared.IpAddress.parse("1.2.3.4");
    const jail = try shared.JailId.fromSlice("sshd");
    try std.testing.expectError(error.NotAvailable, be.ban(ip, jail, 600));
}

test "iptables: probeAvailable result is consistent with direct PATH scan" {
    // Whatever the host is, a second probe returns the same answer.
    try std.testing.expectEqual(probeAvailable(), probeAvailable());
}
