// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");

pub const nftables = @import("nftables.zig");
pub const iptables = @import("iptables.zig");
pub const ipset = @import("ipset.zig");
pub const netlink = @import("netlink.zig");
pub const inspection = @import("inspection.zig");

pub const BackendError = error{
    SystemError,
    NotAvailable,
    PermissionDenied,
    RuleLimitReached,
    AlreadyBanned,
    NotBanned,
    OutOfMemory,
};

pub const BackendConfig = struct {
    chain_prefix: []const u8 = "fail2zig",
    table_name: []const u8 = "fail2zig",
    priority: i32 = -1,
};

pub const BackendTag = enum { nftables, ipset, iptables };

pub const BackendVTable = struct {
    initFn: *const fn (ctx: *anyopaque, config: BackendConfig, allocator: std.mem.Allocator) BackendError!void,
    deinitFn: *const fn (ctx: *anyopaque) void,
    banFn: *const fn (
        ctx: *anyopaque,
        ip: shared.IpAddress,
        jail: shared.JailId,
        duration: shared.Duration,
    ) BackendError!void,
    unbanFn: *const fn (
        ctx: *anyopaque,
        ip: shared.IpAddress,
        jail: shared.JailId,
    ) BackendError!void,
    listBansFn: *const fn (
        ctx: *anyopaque,
        jail: shared.JailId,
        allocator: std.mem.Allocator,
    ) BackendError![]shared.IpAddress,
    flushFn: *const fn (ctx: *anyopaque, jail: shared.JailId) BackendError!void,
    isAvailableFn: *const fn (ctx: *anyopaque) bool,
};

pub const Backend = union(BackendTag) {
    nftables: nftables.NftablesBackend,
    ipset: ipset.IpsetBackend,
    iptables: iptables.IptablesBackend,

    pub fn tag(self: *const Backend) BackendTag {
        return std.meta.activeTag(self.*);
    }

    fn vtable(self: *const Backend) *const BackendVTable {
        return switch (self.*) {
            .nftables => &nftables.vtable,
            .ipset => &ipset.vtable,
            .iptables => &iptables.vtable,
        };
    }

    fn context(self: *Backend) *anyopaque {
        return switch (self.*) {
            .nftables => |*be| @ptrCast(be),
            .ipset => |*be| @ptrCast(be),
            .iptables => |*be| @ptrCast(be),
        };
    }

    pub fn init(
        self: *Backend,
        config: BackendConfig,
        allocator: std.mem.Allocator,
    ) BackendError!void {
        return self.vtable().initFn(self.context(), config, allocator);
    }

    pub fn deinit(self: *Backend) void {
        self.vtable().deinitFn(self.context());
    }

    pub fn ban(
        self: *Backend,
        ip: shared.IpAddress,
        jail: shared.JailId,
        duration: shared.Duration,
    ) BackendError!void {
        return self.vtable().banFn(self.context(), ip, jail, duration);
    }

    pub fn unban(
        self: *Backend,
        ip: shared.IpAddress,
        jail: shared.JailId,
    ) BackendError!void {
        return self.vtable().unbanFn(self.context(), ip, jail);
    }

    pub fn listBans(
        self: *Backend,
        jail: shared.JailId,
        allocator: std.mem.Allocator,
    ) BackendError![]shared.IpAddress {
        return self.vtable().listBansFn(self.context(), jail, allocator);
    }

    pub fn flush(self: *Backend, jail: shared.JailId) BackendError!void {
        return self.vtable().flushFn(self.context(), jail);
    }

    pub fn isAvailable(self: *Backend) bool {
        return self.vtable().isAvailableFn(self.context());
    }
};

pub const AvailabilityProbes = struct {
    nftablesReason: *const fn () nftables.ProbeResult = defaultNftablesReason,
    ipsetAvailable: *const fn () bool = defaultIpsetAvailable,
    iptablesAvailable: *const fn () bool = defaultIptablesAvailable,
};

/// Why no backend is usable. The nf_tables probe is the only kernel-facing one, so its
/// outcome is the cause; ipset/iptables only fail when their binaries are off PATH.
pub const DetectError = error{
    KernelUnsupported,
    PermissionDenied,
    Transient,
    IpsetUnavailable,
    IptablesUnavailable,
};

pub fn causeName(cause: DetectError) []const u8 {
    return switch (cause) {
        error.KernelUnsupported => "nf_tables not in kernel (module not loaded or not compiled in)",
        error.PermissionDenied => "netlink denied — missing CAP_NET_ADMIN (run as root or setcap cap_net_admin+ep)",
        error.Transient => "netlink probe failed transiently (retry may succeed)",
        error.IpsetUnavailable => "ipset not usable (ipset or iptables binary not found on PATH)",
        error.IptablesUnavailable => "iptables not usable (iptables binary not found on PATH)",
    };
}

pub fn detect(allocator: std.mem.Allocator, forced: ?BackendTag) DetectError!Backend {
    return detectWithProbes(allocator, .{}, forced);
}

pub fn detectWithProbes(
    allocator: std.mem.Allocator,
    probes: AvailabilityProbes,
    forced: ?BackendTag,
) DetectError!Backend {
    _ = allocator;
    if (forced) |tag| return detectForced(probes, tag);
    return detectAuto(probes);
}

fn detectForced(probes: AvailabilityProbes, tag: BackendTag) DetectError!Backend {
    const cause: DetectError = switch (tag) {
        .nftables => switch (probes.nftablesReason()) {
            .available => return selectForced(.{ .nftables = nftables.NftablesBackend{} }),
            .kernel_unsupported => error.KernelUnsupported,
            .transient => error.Transient,
            .permission_denied => error.PermissionDenied,
        },
        .ipset => if (probes.ipsetAvailable())
            return selectForced(.{ .ipset = ipset.IpsetBackend{} })
        else
            error.IpsetUnavailable,
        .iptables => if (probes.iptablesAvailable())
            return selectForced(.{ .iptables = iptables.IptablesBackend{} })
        else
            error.IptablesUnavailable,
    };
    std.log.warn("firewall backend: {s} forced by config but not usable — {s}", .{ @tagName(tag), causeName(cause) });
    return cause;
}

fn selectForced(be: Backend) Backend {
    std.log.info("firewall backend: {s} selected (forced by config)", .{@tagName(be.tag())});
    return be;
}

fn detectAuto(probes: AvailabilityProbes) DetectError!Backend {
    const cause: DetectError = switch (probes.nftablesReason()) {
        .available => {
            std.log.info("firewall backend: nftables selected", .{});
            return .{ .nftables = nftables.NftablesBackend{} };
        },
        .kernel_unsupported => error.KernelUnsupported,
        .transient => error.Transient,
        // ipset/iptables need the same capability, so falling through would only mask the cause.
        .permission_denied => {
            std.log.warn("firewall backend: no backend available — {s}", .{causeName(error.PermissionDenied)});
            return error.PermissionDenied;
        },
    };
    std.log.warn("firewall backend: nftables unavailable — {s}; trying ipset", .{causeName(cause)});

    if (probes.ipsetAvailable()) {
        std.log.info("firewall backend: ipset selected", .{});
        return .{ .ipset = ipset.IpsetBackend{} };
    }
    std.log.debug("firewall backend: ipset unavailable, trying iptables", .{});

    if (probes.iptablesAvailable()) {
        std.log.info("firewall backend: iptables selected", .{});
        return .{ .iptables = iptables.IptablesBackend{} };
    }

    std.log.warn("firewall backend: no backend available — {s}", .{causeName(cause)});
    return cause;
}

fn defaultNftablesReason() nftables.ProbeResult {
    return nftables.probeReason();
}

fn defaultIpsetAvailable() bool {
    return ipset.probeAvailable();
}

fn defaultIptablesAvailable() bool {
    return iptables.probeAvailable();
}

test "backend: tagged union dispatches to nftables vtable" {
    var be: Backend = .{ .nftables = nftables.NftablesBackend{} };
    try std.testing.expectEqual(BackendTag.nftables, be.tag());
    _ = be.isAvailable();
}

test "backend: tagged union dispatches to ipset vtable" {
    var be: Backend = .{ .ipset = ipset.IpsetBackend{} };
    try std.testing.expectEqual(BackendTag.ipset, be.tag());
    _ = be.isAvailable();
}

test "backend: tagged union dispatches to iptables vtable" {
    var be: Backend = .{ .iptables = iptables.IptablesBackend{} };
    try std.testing.expectEqual(BackendTag.iptables, be.tag());
    _ = be.isAvailable();
}

test "backend: detect prefers nftables when all available" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonAvailable,
        .ipsetAvailable = testAlwaysTrue,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes, null);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.nftables, be.tag());
}

test "backend: detect falls back to ipset when nf_tables not in kernel (SYS-014)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonKernelUnsupported,
        .ipsetAvailable = testAlwaysTrue,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes, null);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.ipset, be.tag());
}

test "backend: detect falls back past a transient nftables probe failure (SYS-014)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonTransient,
        .ipsetAvailable = testAlwaysTrue,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes, null);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.ipset, be.tag());
}

test "backend: detect falls back to iptables when only it is available" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonKernelUnsupported,
        .ipsetAvailable = testAlwaysFalse,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes, null);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.iptables, be.tag());
}

test "backend: detect reports PermissionDenied without falling through to ipset/iptables (SYS-022)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonPermissionDenied,
        .ipsetAvailable = testAlwaysTrue,
        .iptablesAvailable = testAlwaysTrue,
    };
    try std.testing.expectError(
        error.PermissionDenied,
        detectWithProbes(std.testing.allocator, probes, null),
    );
}

test "backend: detect reports KernelUnsupported when nf_tables absent and nothing else usable (SYS-014)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonKernelUnsupported,
        .ipsetAvailable = testAlwaysFalse,
        .iptablesAvailable = testAlwaysFalse,
    };
    try std.testing.expectError(
        error.KernelUnsupported,
        detectWithProbes(std.testing.allocator, probes, null),
    );
}

test "backend: detect reports PermissionDenied when netlink is denied and nothing else usable (SYS-014)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonPermissionDenied,
        .ipsetAvailable = testAlwaysFalse,
        .iptablesAvailable = testAlwaysFalse,
    };
    try std.testing.expectError(
        error.PermissionDenied,
        detectWithProbes(std.testing.allocator, probes, null),
    );
}

test "backend: detect reports Transient when the probe failed transiently and nothing else usable (SYS-014)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonTransient,
        .ipsetAvailable = testAlwaysFalse,
        .iptablesAvailable = testAlwaysFalse,
    };
    try std.testing.expectError(
        error.Transient,
        detectWithProbes(std.testing.allocator, probes, null),
    );
}

test "backend: causeName is distinct and non-empty for every DetectError (SYS-014)" {
    const causes = comptime @typeInfo(DetectError).error_set.?;
    inline for (causes, 0..) |c, i| {
        const name = causeName(@field(DetectError, c.name));
        try std.testing.expect(name.len > 0);
        inline for (causes[0..i]) |prev| {
            try std.testing.expect(!std.mem.eql(u8, name, causeName(@field(DetectError, prev.name))));
        }
    }
}

fn testAlwaysTrue() bool {
    return true;
}

fn testAlwaysFalse() bool {
    return false;
}

fn testNftReasonAvailable() nftables.ProbeResult {
    return .available;
}

fn testNftReasonKernelUnsupported() nftables.ProbeResult {
    return .kernel_unsupported;
}

fn testNftReasonTransient() nftables.ProbeResult {
    return .transient;
}

fn testNftReasonPermissionDenied() nftables.ProbeResult {
    return .permission_denied;
}

test "backend: forced nftables is selected when its probe reports available (ENH-007)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonAvailable,
        .ipsetAvailable = testAlwaysFalse,
        .iptablesAvailable = testAlwaysFalse,
    };
    var be = try detectWithProbes(std.testing.allocator, probes, .nftables);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.nftables, be.tag());
}

test "backend: forced nftables unusable returns the probe cause and never probes ipset/iptables (ENH-007)" {
    const Tripwire = struct {
        var invoked: bool = false;
        fn probe() bool {
            invoked = true;
            return true;
        }
    };
    Tripwire.invoked = false;
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonKernelUnsupported,
        .ipsetAvailable = Tripwire.probe,
        .iptablesAvailable = Tripwire.probe,
    };
    try std.testing.expectError(
        error.KernelUnsupported,
        detectWithProbes(std.testing.allocator, probes, .nftables),
    );
    try std.testing.expect(!Tripwire.invoked);
}

test "backend: forced nftables maps transient and permission-denied probe results to their causes (ENH-007)" {
    try std.testing.expectError(
        error.Transient,
        detectWithProbes(std.testing.allocator, .{
            .nftablesReason = testNftReasonTransient,
            .ipsetAvailable = testAlwaysTrue,
            .iptablesAvailable = testAlwaysTrue,
        }, .nftables),
    );
    try std.testing.expectError(
        error.PermissionDenied,
        detectWithProbes(std.testing.allocator, .{
            .nftablesReason = testNftReasonPermissionDenied,
            .ipsetAvailable = testAlwaysTrue,
            .iptablesAvailable = testAlwaysTrue,
        }, .nftables),
    );
}

test "backend: forced ipset is selected even when nftables is available (ENH-007)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonAvailable,
        .ipsetAvailable = testAlwaysTrue,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes, .ipset);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.ipset, be.tag());
}

test "backend: forced ipset unusable returns IpsetUnavailable without falling back (ENH-007)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonAvailable,
        .ipsetAvailable = testAlwaysFalse,
        .iptablesAvailable = testAlwaysTrue,
    };
    try std.testing.expectError(
        error.IpsetUnavailable,
        detectWithProbes(std.testing.allocator, probes, .ipset),
    );
}

test "backend: forced iptables is selected even when nftables and ipset are available (ENH-007)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonAvailable,
        .ipsetAvailable = testAlwaysTrue,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes, .iptables);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.iptables, be.tag());
}

test "backend: forced iptables unusable returns IptablesUnavailable without falling back (ENH-007)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonAvailable,
        .ipsetAvailable = testAlwaysTrue,
        .iptablesAvailable = testAlwaysFalse,
    };
    try std.testing.expectError(
        error.IptablesUnavailable,
        detectWithProbes(std.testing.allocator, probes, .iptables),
    );
}

test "backend: detect with default probes runs without crashing" {
    const result = detect(std.testing.allocator, null);
    if (result) |be_val| {
        var be = be_val;
        defer be.deinit();
        const t = be.tag();
        try std.testing.expect(
            t == .nftables or t == .ipset or t == .iptables,
        );
    } else |err| {
        try std.testing.expect(causeName(err).len > 0);
    }
}
