//! Firewall backend interface skeleton. The real interface (tagged union of
//! nftables/iptables/ipset plus vtable) arrives in Phase 3. This stub exists
//! so the engine module graph compiles.

const std = @import("std");
const shared = @import("shared");

pub const BackendError = error{
    NotImplemented,
    NotAvailable,
    SystemError,
    AlreadyBanned,
    NotBanned,
    OutOfMemory,
};

pub const BackendTag = enum { stub, nftables, iptables, ipset };

pub const FirewallBackend = struct {
    tag: BackendTag = .stub,

    pub fn init_backend(self: *FirewallBackend) BackendError!void {
        _ = self;
        return error.NotImplemented;
    }

    pub fn deinit(self: *FirewallBackend) void {
        _ = self;
    }

    pub fn ban(
        self: *FirewallBackend,
        ip: shared.IpAddress,
        jail: shared.JailId,
        duration: shared.Duration,
    ) BackendError!void {
        _ = self;
        _ = ip;
        _ = jail;
        _ = duration;
        return error.NotImplemented;
    }

    pub fn unban(
        self: *FirewallBackend,
        ip: shared.IpAddress,
        jail: shared.JailId,
    ) BackendError!void {
        _ = self;
        _ = ip;
        _ = jail;
        return error.NotImplemented;
    }

    pub fn listBans(
        self: *FirewallBackend,
        jail: shared.JailId,
        allocator: std.mem.Allocator,
    ) BackendError![]shared.IpAddress {
        _ = self;
        _ = jail;
        _ = allocator;
        return error.NotImplemented;
    }

    pub fn flush(self: *FirewallBackend, jail: shared.JailId) BackendError!void {
        _ = self;
        _ = jail;
        return error.NotImplemented;
    }
};

test "firewall_backend: stub instantiates and methods return NotImplemented" {
    var backend = FirewallBackend{};
    defer backend.deinit();
    try std.testing.expectError(error.NotImplemented, backend.init_backend());

    const ip = try shared.IpAddress.parse("1.2.3.4");
    const jail = try shared.JailId.fromSlice("sshd");
    try std.testing.expectError(error.NotImplemented, backend.ban(ip, jail, 600));
    try std.testing.expectError(error.NotImplemented, backend.unban(ip, jail));
    try std.testing.expectError(error.NotImplemented, backend.flush(jail));
    try std.testing.expectError(
        error.NotImplemented,
        backend.listBans(jail, std.testing.allocator),
    );
}
