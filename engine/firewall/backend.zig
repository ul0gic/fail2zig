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

pub fn detectExact(allocator: std.mem.Allocator, tag: BackendTag) DetectError!Backend {
    _ = allocator;
    return probeExact(.{}, tag);
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
    const selected = probeExact(probes, tag) catch |cause| {
        std.log.warn("firewall backend: {s} forced by config but not usable — {s}", .{ @tagName(tag), causeName(cause) });
        return cause;
    };
    return selectForced(selected);
}

fn probeExact(probes: AvailabilityProbes, tag: BackendTag) DetectError!Backend {
    return switch (tag) {
        .nftables => switch (probes.nftablesReason()) {
            .available => .{ .nftables = nftables.NftablesBackend{} },
            .kernel_unsupported => error.KernelUnsupported,
            .transient => error.Transient,
            .permission_denied => error.PermissionDenied,
        },
        .ipset => if (probes.ipsetAvailable())
            .{ .ipset = ipset.IpsetBackend{} }
        else
            error.IpsetUnavailable,
        .iptables => if (probes.iptablesAvailable())
            .{ .iptables = iptables.IptablesBackend{} }
        else
            error.IptablesUnavailable,
    };
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
