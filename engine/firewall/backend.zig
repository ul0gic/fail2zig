//! Firewall backend interface.
//!
//! The engine speaks to the kernel packet filter through this single,
//! backend-agnostic surface. Concrete implementations live in sibling
//! files:
//!
//!   - `nftables.zig` — preferred: direct netlink, atomic, set-based.
//!   - `ipset.zig`    — middle: `ipset` for O(1) membership + one
//!                       `iptables` jump rule per jail.
//!   - `iptables.zig` — fallback: pure CLI fork/exec, per-IP rules.
//!
//! All three implement the same `BackendVTable`. A `Backend` is a
//! tagged union that owns the backend-specific state and exposes a
//! uniform `ban` / `unban` / `listBans` / `flush` surface.
//!
//! Phase 3 scope: interface definition plus a stub for `detect()`.
//! The real detection logic (task 3.6.2) probes the system at runtime
//! and selects the best available backend.

const std = @import("std");
const shared = @import("shared");

pub const nftables = @import("nftables.zig");
pub const iptables = @import("iptables.zig");
pub const ipset = @import("ipset.zig");
pub const netlink = @import("netlink.zig");

/// Errors any backend may return. Concrete backends map their
/// underlying failure modes (syscall errno, CLI exit codes, parse
/// errors) to one of these variants so the caller can stay
/// backend-agnostic.
pub const BackendError = error{
    /// A system call, syscall wrapper, or subprocess failed.
    SystemError,
    /// The backend is not available on this host (kernel module
    /// missing, binary not on PATH, etc.).
    NotAvailable,
    /// The backend's rule/element limit has been reached.
    RuleLimitReached,
    /// The IP is already in the ban set (idempotency failure).
    AlreadyBanned,
    /// The IP is not in the ban set.
    NotBanned,
    /// Allocation failed.
    OutOfMemory,
};

/// Configuration shared by all backends. Individual backends may
/// extend this with backend-specific fields in their own init paths.
pub const BackendConfig = struct {
    /// Prefix used when naming chains, sets, and tables. The
    /// per-jail name is `chain_prefix ++ "-" ++ jail`.
    chain_prefix: []const u8 = "fail2zig",
    /// Table name for nftables. Unused by iptables/ipset backends.
    table_name: []const u8 = "fail2zig",
    /// Chain priority (hook ordering). `-1` runs before conntrack
    /// so dropped packets bypass conntrack overhead.
    priority: i32 = -1,
};

/// Which backend is active. The tag doubles as a human-readable
/// identifier for logging and metrics.
pub const BackendTag = enum { nftables, ipset, iptables };

/// Vtable wired at construction time. Concrete backends expose a
/// `vtable` constant with their function pointers.
///
/// Every entry takes a `*anyopaque` context that concrete backends
/// cast back to their owning struct. Callers never see the raw
/// pointer — they go through `Backend`.
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

/// Tagged union over the three concrete backends. Owns the
/// backend's state inline — the vtable is looked up via the
/// selected variant and the `*anyopaque` context points back at
/// the variant's stored struct.
///
/// Keep the union thin: the engine holds a single `Backend`; the
/// variant determines behaviour but the caller only uses the
/// methods below.
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

/// Availability probe hooks, separated so tests can inject mocks.
/// The defaults call the real system.
pub const AvailabilityProbes = struct {
    nftablesAvailable: *const fn () bool = defaultNftablesAvailable,
    ipsetAvailable: *const fn () bool = defaultIpsetAvailable,
    iptablesAvailable: *const fn () bool = defaultIptablesAvailable,
};

/// Detect the best available backend. Priority: nftables → ipset →
/// iptables. Returns `BackendError.NotAvailable` if nothing works.
///
/// Task 3.6.2 replaces this stub with a real probe. For now the
/// probe delegates to each backend's `isAvailableFn` via module-level
/// helpers so callers can unit-test the detection tree with mocks.
pub fn detect(allocator: std.mem.Allocator) BackendError!Backend {
    return detectWithProbes(allocator, .{});
}

/// Same as `detect` but with pluggable availability checks. Used by
/// the detection tests to exercise every branch without requiring
/// the actual kernel / binaries.
pub fn detectWithProbes(
    allocator: std.mem.Allocator,
    probes: AvailabilityProbes,
) BackendError!Backend {
    _ = allocator;
    if (probes.nftablesAvailable()) {
        std.log.info("firewall backend: nftables selected", .{});
        return .{ .nftables = nftables.NftablesBackend{} };
    }
    std.log.debug("firewall backend: nftables unavailable, trying ipset", .{});

    if (probes.ipsetAvailable()) {
        std.log.info("firewall backend: ipset selected", .{});
        return .{ .ipset = ipset.IpsetBackend{} };
    }
    std.log.debug("firewall backend: ipset unavailable, trying iptables", .{});

    if (probes.iptablesAvailable()) {
        std.log.info("firewall backend: iptables selected", .{});
        return .{ .iptables = iptables.IptablesBackend{} };
    }

    // Don't log at .err here — the caller receives the NotAvailable
    // error and decides whether to log it fatally. Using .err inside a
    // library path also trips the Zig test runner's error-log failure
    // check during negative-path detection tests.
    std.log.warn("firewall backend: no backend available", .{});
    return error.NotAvailable;
}

fn defaultNftablesAvailable() bool {
    return nftables.probeAvailable();
}

fn defaultIpsetAvailable() bool {
    return ipset.probeAvailable();
}

fn defaultIptablesAvailable() bool {
    return iptables.probeAvailable();
}

// ===========================================================================
// Tests
// ===========================================================================

test "backend: tagged union dispatches to nftables vtable" {
    var be: Backend = .{ .nftables = nftables.NftablesBackend{} };
    try std.testing.expectEqual(BackendTag.nftables, be.tag());
    // isAvailable must not crash even without root; the concrete
    // implementation returns false when capabilities are missing.
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
        .nftablesAvailable = testAlwaysTrue,
        .ipsetAvailable = testAlwaysTrue,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.nftables, be.tag());
}

test "backend: detect falls back to ipset when nftables unavailable" {
    const probes: AvailabilityProbes = .{
        .nftablesAvailable = testAlwaysFalse,
        .ipsetAvailable = testAlwaysTrue,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.ipset, be.tag());
}

test "backend: detect falls back to iptables when only it is available" {
    const probes: AvailabilityProbes = .{
        .nftablesAvailable = testAlwaysFalse,
        .ipsetAvailable = testAlwaysFalse,
        .iptablesAvailable = testAlwaysTrue,
    };
    var be = try detectWithProbes(std.testing.allocator, probes);
    defer be.deinit();
    try std.testing.expectEqual(BackendTag.iptables, be.tag());
}

test "backend: detect returns NotAvailable when nothing available" {
    const probes: AvailabilityProbes = .{
        .nftablesAvailable = testAlwaysFalse,
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

test "backend: detect with default probes runs without crashing" {
    // Whatever the host offers, default-probe detection must either
    // succeed with a valid backend tag or fail cleanly with
    // `NotAvailable`. It must never panic or leak file descriptors.
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
