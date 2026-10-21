// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const shared = @import("shared");
const native = @import("native.zig");
const ban_origin = @import("../core/ban_origin.zig");

const IgnoreEntry = shared.types.IgnoreEntry;
const TimedEntry = shared.types.TimedEntry;
const BanListEntry = ban_origin.BanListEntry;

pub const max_banip_entries = 1024;

pub const BanListConflict = struct {
    jail: []const u8,
    address: [64]u8,
    address_len: u8,
};

pub fn effectiveBanList(cfg: *const native.Config, jail: *const native.JailConfig, out: []BanListEntry) error{ InvalidBanListEntry, BanListLimit }!usize {
    const literals = jail.banip orelse cfg.defaults.banip;
    if (literals.len > max_banip_entries or literals.len > out.len) return error.BanListLimit;
    for (literals, 0..) |literal, index| {
        const parsed = TimedEntry.parse(literal, null) catch return error.InvalidBanListEntry;
        out[index] = .{ .entry = parsed.entry, .jail = jail.name, .duration_s = parsed.duration_s };
    }
    return literals.len;
}

pub fn findConflict(cfg: *const native.Config, out: *BanListConflict) bool {
    for (cfg.jails) |*jail| {
        const banned = jail.banip orelse cfg.defaults.banip;
        const ignored = jail.ignoreip orelse cfg.defaults.ignoreip;
        for (banned) |ban_literal| {
            const ban = IgnoreEntry.parse(TimedEntry.addressText(ban_literal)) catch continue;
            for (ignored) |ignore_literal| {
                const ignore = IgnoreEntry.parse(TimedEntry.addressText(ignore_literal)) catch continue;
                if (!overlaps(ban, ignore)) continue;
                var buffer: [IgnoreEntry.max_text_bytes]u8 = undefined;
                const text = ban.canonical(&buffer);
                out.* = .{ .jail = jail.name, .address = buffer, .address_len = @intCast(text.len) };
                return true;
            }
        }
    }
    return false;
}

fn overlaps(a: IgnoreEntry, b: IgnoreEntry) bool {
    if (a.family != b.family) return false;
    return (a.prefix <= b.prefix and a.contains(b.network())) or (b.prefix <= a.prefix and b.contains(a.network()));
}
