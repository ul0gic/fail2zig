// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");

pub const nftables = @import("nftables.zig");
pub const iptables = @import("iptables.zig");
pub const ipset = @import("ipset.zig");
pub const netlink = @import("netlink.zig");

pub const BackendError = error{
    SystemError,
    NotAvailable,
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

pub fn detect(allocator: std.mem.Allocator) BackendError!Backend {
    return detectWithProbes(allocator, .{});
}

pub fn detectWithProbes(
    allocator: std.mem.Allocator,
    probes: AvailabilityProbes,
) BackendError!Backend {
    _ = allocator;
    switch (probes.nftablesReason()) {
        .available => {
            std.log.info("firewall backend: nftables selected", .{});
            return .{ .nftables = nftables.NftablesBackend{} };
        },
        .kernel_unsupported => std.log.warn(
            "firewall backend: nftables unavailable — nf_tables not in kernel " ++
                "(module not loaded or not compiled in); trying ipset",
            .{},
        ),
        .transient => std.log.warn(
            "firewall backend: nftables probe failed transiently; trying ipset",
            .{},
        ),
    }

    if (probes.ipsetAvailable()) {
        std.log.info("firewall backend: ipset selected", .{});
        return .{ .ipset = ipset.IpsetBackend{} };
    }
    std.log.debug("firewall backend: ipset unavailable, trying iptables", .{});

    if (probes.iptablesAvailable()) {
        std.log.info("firewall backend: iptables selected", .{});
        return .{ .iptables = iptables.IptablesBackend{} };
    }

    std.log.warn("firewall backend: no backend available", .{});
    return error.NotAvailable;
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
    var be = try detectWithProbes(std.testing.allocator, probes);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.nftables, be.tag());
}

test "backend: detect falls back to ipset when nf_tables not in kernel (SYS-014)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonKernelUnsupported,
        .ipsetAvailable = testAlwaysTrue,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.ipset, be.tag());
}

test "backend: detect falls back past a transient nftables probe failure (SYS-014)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonTransient,
        .ipsetAvailable = testAlwaysTrue,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.ipset, be.tag());
}

test "backend: detect falls back to iptables when only it is available" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonKernelUnsupported,
        .ipsetAvailable = testAlwaysFalse,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.iptables, be.tag());
}

test "backend: detect fails closed (NotAvailable) when nothing available (SYS-014)" {
    const probes: AvailabilityProbes = .{
        .nftablesReason = testNftReasonKernelUnsupported,
        .ipsetAvailable = testAlwaysFalse,
        .iptablesAvailable = testAlwaysFalse,
    };
    try std.testing.expectError(
        error.NotAvailable,
        detectWithProbes(std.testing.allocator, probes),
    );
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

test "backend: detect with default probes runs without crashing" {
    const result = detect(std.testing.allocator);
    if (result) |be_val| {
        var be = be_val;
        defer be.deinit();
        const t = be.tag();
        try std.testing.expect(
            t == .nftables or t == .ipset or t == .iptables,
        );
    } else |err| {
        try std.testing.expectEqual(error.NotAvailable, err);
    }
}
