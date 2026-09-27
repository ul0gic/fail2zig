// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const format = @import("client_format");
const testing = std.testing;
const OutputFormat = format.OutputFormat;
const Color = format.Color;
const formatStatus = format.formatStatus;
const formatStatusDetailed = format.formatStatusDetailed;
const formatList = format.formatList;
const formatJails = format.formatJails;
const formatVersion = format.formatVersion;
const formatBan = format.formatBan;
const formatUnban = format.formatUnban;
const formatReload = format.formatReload;
const FirewallRule = format.FirewallRule;
const formatConfig = format.formatConfig;
const formatScopes = format.formatScopes;
const formatHistory = format.formatHistory;
const formatFirewall = format.formatFirewall;
const formatFirewallDetailed = format.formatFirewallDetailed;
const formatStatusForWidth = format.TestAccess.statusForWidth;
const formatStatusForWidthDetailed = format.TestAccess.statusForWidthDetailed;
const diagnostic_max_bytes = format.TestAccess.diagnosticMaxBytes;
const isUnsafeUnicodeControl = format.TestAccess.unsafeUnicodeControl;
const renderDiagnostic = format.TestAccess.diagnostic;
const formatListForWidth = format.TestAccess.listForWidth;
const remainingFromExpiry = format.TestAccess.expiryRemaining;
const formatJailsForWidth = format.TestAccess.jailsForWidth;
const formatJailsForWidthDetailed = format.TestAccess.jailsForWidthDetailed;
const formatFirewallForWidth = format.TestAccess.firewallForWidth;
const formatFirewallForWidthDetailed = format.TestAccess.firewallForWidthDetailed;
const writeFirewallStructureRules = format.TestAccess.firewallStructureRules;
const formatUtc = format.TestAccess.utc;

fn runStatus(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatStatusForWidth(alloc, list.writer(), payload, fmt, .{ .enabled = false }, 160);
    return list.toOwnedSlice();
}

test "format: BUG-059 status memory percentage handles the full u64 range" {
    const cases = .{
        .{ "18446744073709551615", "1", "17592186044416.0 / 0.0 MB (1844674407370955161500%)" },
        .{ "18446744073709551615", "18446744073709551615", "17592186044416.0 / 17592186044416.0 MB (100%)" },
        .{ "1", "18446744073709551615", "0.0 / 17592186044416.0 MB (0%)" },
        .{ "8388608", "67108864", "8.0 / 64.0 MB (12%)" },
        .{ "3", "2", "0.0 / 0.0 MB (150%)" },
        .{ "0", "1", "0.0 / 0.0 MB (0%)" },
        .{ "18446744073709551615", "0", "-" },
    };
    inline for (cases) |case| {
        const payload = "{\"memory_bytes_used\":" ++ case[0] ++ ",\"memory_bytes_limit\":" ++ case[1] ++ "}";
        const out = try runStatus(testing.allocator, payload, .table);
        defer testing.allocator.free(out);
        const start = (std.mem.indexOf(u8, out, "Memory:") orelse return error.MissingMemoryRow) + "Memory:".len;
        const end = std.mem.indexOfScalarPos(u8, out, start, '\n') orelse return error.MissingMemoryRow;
        try testing.expectEqualStrings(case[2], std.mem.trim(u8, out[start..end], " |\r"));
    }

    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var output: [128]u8 = undefined;
    var stream = std.io.fixedBufferStream(&output);
    try formatStatus(failing.allocator(), stream.writer(), "{\"memory_bytes_used\":18446744073709551615,\"memory_bytes_limit\":1}", .table, .{ .enabled = false });
    try testing.expect(std.mem.indexOf(u8, stream.getWritten(), "could not parse status payload (OutOfMemory)") != null);
}

test "format: CP-02 status heading is neutral and narrow output is bounded" {
    const payload = "{\"version\":\"v\\t1\",\"protection\":\"degraded\",\"backend\":\"backend-with-a-very-long-name-that-must-not-overflow-a-narrow-terminal\",\"active_bans\":3}";
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "— status") != null);
    try testing.expect(std.mem.indexOf(u8, table, "running") == null);
    try testing.expect(std.mem.indexOf(u8, table, "v\\t1") != null);

    var narrow = std.ArrayList(u8).init(testing.allocator);
    defer narrow.deinit();
    try formatStatusForWidth(testing.allocator, narrow.writer(), payload, .table, .{ .enabled = false }, 40);
    try testing.expect(std.mem.indexOf(u8, narrow.items, "Protection:") != null);
    var lines = std.mem.splitScalar(u8, narrow.items, '\n');
    while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= 40);
}

test "format: status degraded with protection_cause renders the cause" {
    const payload = "{\"protection\":\"degraded\",\"protection_cause\":\"NftablesUnavailable\",\"backend\":\"none\"}";
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  DEGRADED (NftablesUnavailable)") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Backend:     none") != null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "protection\tdegraded\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "protection_cause\tNftablesUnavailable\n") != null);

    const json = try runStatus(testing.allocator, payload, .json);
    defer testing.allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"protection_cause\":\"NftablesUnavailable\"") != null);
}

test "format: status degraded without protection_cause renders plain DEGRADED (older daemon)" {
    const payload = "{\"protection\":\"degraded\",\"backend\":\"nftables\"}";
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  DEGRADED ") != null);
    try testing.expect(std.mem.indexOf(u8, table, "DEGRADED (") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Cause:       unknown") != null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "protection_cause") == null);
}

test "format: BUG-054 status renders simultaneous scoped degradation details" {
    const payload =
        \\{"protection":"degraded","storage":"paused","cause":"StorageFull","sqlite_code":13,
        \\"next_retry_ms":18446744073709551615,"unhealthy_sources":2,"effects_uncertain":true,
        \\"overdue_effects":3,"effect_backend":"nftables","effect_stage":"dispatch",
        \\"effect_cause":"PermissionDenied","effect_mutation":"not_started",
        \\"worker_busy":true,"worker_stalled":true,"worker_busy_age_ms":6001,
        \\"worker_heartbeat_age_ms":7002,"clock_uncertain":true,"expiry_overdue":true,
        \\"expiry_uncertain":true,"next_committed_expiry_us":-42}
    ;
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  DEGRADED ") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  DEGRADED (") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Storage:     paused") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Cause:       StorageFull") != null);
    try testing.expect(std.mem.indexOf(u8, table, "SQLite code: 13") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Retry at:    18446744073709551615 ms monotonic") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Sources:     2 unhealthy; inspect fail2zig jails") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Effects:     uncertain; 3 overdue") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Effect:      nftables") != null);
    try testing.expect(std.mem.indexOf(u8, table, "  Stage:     dispatch") != null);
    try testing.expect(std.mem.indexOf(u8, table, "  Cause:     PermissionDenied") != null);
    try testing.expect(std.mem.indexOf(u8, table, "  Attempt:   not_started") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Worker:      stalled; busy 6001 ms; heartbeat 7002 ms ago") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Clock:       uncertain") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Expiry:      overdue; view uncertain; next committed -42 us") != null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "storage\tpaused\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "cause\tStorageFull\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "sqlite_code\t13\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "next_retry_ms\t18446744073709551615\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "unhealthy_sources\t2\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_backend\tnftables\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_stage\tdispatch\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_cause\tPermissionDenied\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_mutation\tnot_started\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effects_uncertain\ttrue\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "worker_stalled\ttrue\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "clock_uncertain\ttrue\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "next_committed_expiry_us\t-42\n") != null);
}

test "format: BUG-054 healthy log-only status does not invent fault context" {
    const payload =
        \\{"protection":"log-only","backend":"none","storage":"healthy","cause":"none",
        \\"unhealthy_sources":0,"effects_uncertain":false,"overdue_effects":0,
        \\"worker_busy":false,"worker_stalled":false,"worker_busy_age_ms":0,
        \\"worker_heartbeat_age_ms":7,"clock_uncertain":false,"expiry_overdue":false,
        \\"expiry_uncertain":false}
    ;
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  log-only") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Storage:     healthy") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Cause:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Sources:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Effects:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Effect:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Worker:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Clock:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Expiry:") == null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "cause\tnone\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effects_uncertain\tfalse\n") != null);
}

test "format: BUG-054 diagnostic strings are escaped and capped without splitting UTF-8" {
    const payload =
        \\{"protection":"degraded","protection_cause":"bad\nline\tcol\u001b\\tail",
        \\"storage":"paused\\rstate","cause":"éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé"}
    ;
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.unicode.utf8ValidateSlice(table));
    try testing.expect(std.mem.indexOf(u8, table, "bad\\nline\\tcol\\x1B\\\\tail") != null);
    try testing.expect(std.mem.indexOf(u8, table, "paused\\\\rstate") != null);
    try testing.expect(std.mem.indexOf(u8, table, "...") != null);
    try testing.expect(std.mem.indexOf(u8, table, "\x1b") == null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.unicode.utf8ValidateSlice(plain));
    try testing.expect(std.mem.indexOf(u8, plain, "protection_cause\tbad\\nline\\tcol\\x1B\\\\tail\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "\nline") == null);
}

test "format: BUG-054 diagnostic renderer handles zero and tiny capacities" {
    var empty: [0]u8 = .{};
    try testing.expectEqual(@as(usize, 0), renderDiagnostic(&empty, "hostile\nvalue").len);
    var tiny: [2]u8 = undefined;
    try testing.expectEqualStrings("..", renderDiagnostic(&tiny, "hostile\nvalue"));
}

test "format: diagnostic renderer escapes C1 and bidi controls atomically" {
    const hostile = "oké\u{009b}\u{061c}\u{200e}\u{202e}\u{2066}雪";
    var buffer: [diagnostic_max_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "oké\\xC2\\x9B\\xD8\\x9C\\xE2\\x80\\x8E\\xE2\\x80\\xAE\\xE2\\x81\\xA6雪",
        renderDiagnostic(&buffer, hostile),
    );

    var tight: [11]u8 = undefined;
    try testing.expectEqualStrings("...", renderDiagnostic(&tight, "\u{202e}"));
    try testing.expect(isUnsafeUnicodeControl(0x80));
    try testing.expect(isUnsafeUnicodeControl(0x9f));
    try testing.expect(isUnsafeUnicodeControl(0x202a));
    try testing.expect(isUnsafeUnicodeControl(0x2069));
    try testing.expect(!isUnsafeUnicodeControl(0x200d));
    try testing.expect(!isUnsafeUnicodeControl(0x206a));
}

test "format: status escapes Unicode controls in effect diagnostics" {
    const payload =
        \\{"protection":"degraded","cause":"safe\u009bspoof\u202e",
        \\"effect_backend":"nft\u2066","effect_stage":"verify","effect_cause":"Denied\u061c",
        \\"effect_mutation":"outcome_uncertain"}
    ;
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "safe\\xC2\\x9Bspoof\\xE2\\x80\\xAE") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Effect:      nft\\xE2\\x81\\xA6") != null);
    try testing.expect(std.mem.indexOf(u8, table, "  Cause:     Denied\\xD8\\x9C") != null);
    try testing.expect(std.mem.indexOf(u8, table, "  Attempt:   outcome_uncertain") != null);
    try testing.expect(std.mem.indexOf(u8, table, "\u{009b}") == null);
    try testing.expect(std.mem.indexOf(u8, table, "\u{202e}") == null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_backend\tnft\\xE2\\x81\\xA6\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_mutation\toutcome_uncertain\n") != null);
}

test "format: status reports parser allocation failure without retaining diagnostics" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var output: [128]u8 = undefined;
    var stream = std.io.fixedBufferStream(&output);
    try formatStatus(failing.allocator(), stream.writer(), "{\"cause\":\"StorageFull\"}", .plain, .{ .enabled = false });
    try testing.expect(std.mem.indexOf(u8, stream.getWritten(), "could not parse status payload (OutOfMemory)") != null);
}

fn runList(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatListForWidth(alloc, list.writer(), payload, fmt, .{ .enabled = false }, 160);
    return list.toOwnedSlice();
}

test "format: BUG-040 list preserves network CIDR and ordinary host presentation" {
    const payload = "[{\"ip\":\"192.0.2.0/24\",\"jail\":\"sshd\",\"ban_count\":1},{\"ip\":\"198.51.100.7\",\"jail\":\"sshd\",\"ban_count\":2}]";

    const json = try runList(testing.allocator, payload, .json);
    defer testing.allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"ip\":\"192.0.2.0/24\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"ip\":\"198.51.100.7\"") != null);

    const plain = try runList(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "192.0.2.0/24\tsshd\t") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "198.51.100.7\tsshd\t") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "198.51.100.7/32") == null);

    const table = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "192.0.2.0/24") != null);
    try testing.expect(std.mem.indexOf(u8, table, "198.51.100.7") != null);
    try testing.expect(std.mem.indexOf(u8, table, "198.51.100.7/32") == null);
}

test "format: CP-02 list distinguishes permanent confirmed pending and unknown" {
    const payload = "[{\"ip\":\"192.0.2.1\",\"jail\":\"sshd\",\"ban_count\":1,\"permanent\":true,\"confirmed\":true},{\"ip\":\"192.0.2.2\",\"jail\":\"sshd\",\"ban_count\":2,\"ban_expiry\":9999999999,\"enforced\":false},{\"ip\":\"192.0.2.3\",\"jail\":\"sshd\",\"ban_count\":3}]";
    const table = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "permanent") != null);
    try testing.expect(std.mem.indexOf(u8, table, "confirmed") != null);
    try testing.expect(std.mem.indexOf(u8, table, "pending") != null);
    try testing.expect(std.mem.indexOf(u8, table, "unknown") != null);

    const plain = try runList(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expectEqual(@as(usize, 9), std.mem.count(u8, plain, "\t"));
    try testing.expect(std.mem.indexOf(u8, plain, "permanent") == null);

    const json = try runList(testing.allocator, payload, .json);
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(payload ++ "\n", json);
}

test "format: CP-02 list narrow fallback keeps core meaning" {
    const payload = "[{\"ip\":\"192.0.2.1\",\"jail\":\"ssh\\tadmin\",\"permanent\":true,\"confirmed\":false}]";
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    try formatListForWidth(testing.allocator, out.writer(), payload, .table, .{ .enabled = false }, 40);
    try testing.expect(std.mem.indexOf(u8, out.items, "IP ADDRESS:") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "ssh\\tadmin") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "permanent") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "pending") != null);
    var lines = std.mem.splitScalar(u8, out.items, '\n');
    while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= 40);
}

test "format: CP-02 ban expiry saturates hostile timestamps" {
    const min = std.math.minInt(i64);
    const max = std.math.maxInt(i64);
    try testing.expectEqual(max, remainingFromExpiry(max, min).?);
    try testing.expectEqual(min, remainingFromExpiry(min, max).?);
}

test "format: list rejects object-shape payload (SYS-002 regression)" {
    const payload = "{\"entries\":[]}";
    const out = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "error: could not parse list payload") != null);
}

fn runJails(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatJailsForWidth(alloc, list.writer(), payload, fmt, .{ .enabled = false }, 160);
    return list.toOwnedSlice();
}

test "format: jails rejects object-shape payload (SYS-002 regression)" {
    const payload = "{\"jails\":[]}";
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "error: could not parse jails payload") != null);
}

test "format: CP-02 jails show paused without changing plain columns" {
    const payload = "[{\"name\":\"sshd\",\"enabled\":true,\"paused\":true,\"active_bans\":1,\"action\":\"nftables\",\"source_healthy\":true}]";
    const table = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "paused") != null);

    const plain = try runJails(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expectEqual(@as(usize, 10), std.mem.count(u8, plain, "\t"));
    try testing.expect(std.mem.indexOf(u8, plain, "\tenabled\t") != null);
}

test "format: CP-02 jails keep an absent enabled field unknown in tables" {
    const payload = "[{\"name\":\"sshd\"}]";
    const table = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "sshd unknown") != null);

    const plain = try runJails(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "sshd\tdisabled\t") != null);
}

test "format: CP-02 jails narrow fallback escapes untrusted text" {
    const payload = "[{\"name\":\"ssh\\nadmin\",\"enabled\":true,\"paused\":true,\"active_bans\":1,\"action\":\"nf\\tables\",\"source_healthy\":false,\"cause\":\"bad\"}]";
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    try formatJailsForWidth(testing.allocator, out.writer(), payload, .table, .{ .enabled = false }, 40);
    try testing.expect(std.mem.indexOf(u8, out.items, "ssh\\nadmin") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "nf\\tables") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "paused") != null);
    var lines = std.mem.splitScalar(u8, out.items, '\n');
    while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= 40);
}

test "format: BUG-054 jail cause is bounded in HEALTH while plain stays eleven escaped columns" {
    const payload =
        \\[{"name":"ssh\tadmin\nrow\u2066","enabled":true,"active_bans":1,"maxretry":3,
        \\"findtime":600,"bantime":3600,"action":"log-only","enforcing":false,
        \\"log_source":"journal","source_healthy":false,"lines_seen":9,
        \\"cause":"JournalChildFailed\nnext","source_exit_code":7,"source_signal":9,
        \\"source_stderr_present":true}]
    ;
    const table = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "ssh\\tadmin\\nrow\\xE2\\x81\\xA6") != null);
    try testing.expect(std.mem.indexOf(u8, table, "broken (JournalChildFailed\\nnext; exit=7; signal=9; stderr)") != null);
    try testing.expect(std.mem.indexOf(u8, table, "\nrow") == null);

    const plain = try runJails(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, plain, "\n"));
    try testing.expectEqual(@as(usize, 10), std.mem.count(u8, plain, "\t"));
    try testing.expect(std.mem.startsWith(u8, plain, "ssh\\tadmin\\nrow\\xE2\\x81\\xA6\tenabled\t"));
    try testing.expect(std.mem.indexOf(u8, plain, "JournalChildFailed") == null);
}

test "format: BUG-054 unhealthy jail without a cause reports unknown" {
    const payload = "[{\"name\":\"sshd\",\"source_healthy\":false,\"cause\":\"none\"}]";
    const table = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "broken (unknown)") != null);
}

fn lineLens(out: []const u8) [3]usize {
    var it = std.mem.splitScalar(u8, out, '\n');
    return .{ it.next().?.len, it.next().?.len, it.next().?.len };
}

test "format: jails table SOURCE truncation never splits a UTF-8 sequence (BUG-008)" {
    const payload = "[{\"name\":\"web\",\"enabled\":true,\"log_source\":\"/var/log/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaééééé.log\"}]";
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.unicode.utf8ValidateSlice(out));
    try testing.expect(std.mem.indexOf(u8, out, "aaa...  unknown") != null);
    const lens = lineLens(out);
    try testing.expectEqual(lens[0], lens[1]);
    try testing.expectEqual(lens[0], lens[2]);
}

fn runVersion(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatVersion(alloc, list.writer(), "0.1.0", payload, fmt, .{ .enabled = false });
    return list.toOwnedSlice();
}

test "format: version table rejects malformed payload and escapes terminal data" {
    try testing.expectError(error.UnexpectedEndOfInput, runVersion(testing.allocator, "{", .table));
    const out = try runVersion(testing.allocator, "{\"daemon_version\":\"0.2.0\\u001b[2J\",\"git_commit\":\"a\\nb\"}", .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOfScalar(u8, out, 0x1b) == null);
    try testing.expect(std.mem.indexOf(u8, out, "a\nb") == null);
}

const config_payload =
    \\{"schema_version":1,"generation":"ab12","redacted":false,"jails":[
    \\{"name":"sshd","enabled":true,"filter":"sshd","source":"journal","logpath":["/var/log/auth.log"],
    \\"maxretry":5,"findtime":600,"bantime":3600,"bantime_permanent":false,"banaction":"nftables","ignoreip":["127.0.0.1/8","192.0.2.0/24"]},
    \\{"name":"nginx","enabled":false,"filter":"nginx-http-auth","source":"file","logpath":[],
    \\"maxretry":3,"findtime":60,"bantime":0,"bantime_permanent":true,"banaction":"nftables","ignoreip":[]}],
    \\"global":{"log_level":"info","firewall":"nftables","metrics_enabled":true,"metrics_bind":"127.0.0.1","metrics_port":9101,
    \\"socket_path":"/run/fail2zig/fail2zig.sock","state_file":"/var/lib/fail2zig/state.sqlite","dns_server":null,"timezone_root":null}}
;

const scopes_payload =
    \\{"schema_version":1,"generation":"ab12","items":[
    \\{"jail":"sshd","scope":{"family":"v4","address":"192.0.2.1","prefix":32},"lease":"finite","deadline_us":4102444800000000,"decision_id_hex":"0101010101010101abcd","confirmed":true},
    \\{"jail":"nginx","scope":{"family":"v6","address":"2001:db8::","prefix":64,"protocol":"tcp","port":22},"lease":"permanent","deadline_us":null,"decision_id_hex":null,"confirmed":false}],
    \\"next_cursor":"czoxOjA"}
;

const history_payload =
    \\{"schema_version":1,"generation":"ab12","items":[
    \\{"sequence":7,"event_id_hex":"ee","jail":"sshd","decision_id_hex":"1111111111111111ffff","confirmed_us":1700000000000000,"scope":{"family":"v4","address":"192.0.2.9","prefix":32},"native_retry":true}],
    \\"next_cursor":null}
;

const firewall_payload =
    \\{"schema_version":1,"generation":"ab12","kind":"firewall","available":true,"unavailable_reason":null,
    \\"installation":{"id_hex":"00112233445566778899aabbccddeeff","backend":"nftables","namespace":"daemon-current"},
    \\"observation":{"id":"00112233445566778899aabbccddeeff:7","state":"owned","observed_wall_us":1700000000000000,"age_ms":25,
    \\"observation_complete":true,"observed_total":2,"sample_count":2,"sample_truncated":false,"inventory":"known_entries",
    \\"origin":"normal_readback","comparison":"unavailable","comparison_reason":"intent_revision_not_aligned"},
    \\"last_attempt":{"outcome":"success","cause":null,"stage":null,"age_ms":25},"items":[
    \\{"scope":{"family":"v4","address":"192.0.2.9","prefix":32,"subject_kind":"host","protocols":["tcp","udp"],
    \\"port_ranges":[{"first":53,"last":53},{"first":8000,"last":8010}],"legacy_exact":false,"direction":"input","target":"drop"},
    \\"effect_id_hex":"1111111111111111ffff","remaining_ms_at_observation":3000,"deadline_us":1700000003000000},
    \\{"scope":{"family":"v6","address":"2001:db8::","prefix":64,"subject_kind":"network","protocols":["all"],
    \\"port_ranges":[],"legacy_exact":true,"direction":"input","target":"drop"},"effect_id_hex":null,
    \\"remaining_ms_at_observation":null,"deadline_us":null}],"next_cursor":"fw-token"}
;

fn runFormatter(comptime formatter: anytype, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(testing.allocator);
    errdefer list.deinit();
    try formatter(testing.allocator, list.writer(), payload, fmt, .{ .enabled = false });
    return list.toOwnedSlice();
}

test "format: redacted config table warns and keeps placeholders" {
    const payload = "{\"generation\":\"g\",\"redacted\":true,\"jails\":[{\"name\":\"sshd\",\"enabled\":true,\"logpath\":[\"<redacted>\"],\"ignoreip\":[\"<redacted>\"]}],\"global\":{\"socket_path\":\"<redacted>\"}}";
    const table = try runFormatter(formatConfig, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "redacted for monitor access") != null);
    try testing.expect(std.mem.indexOf(u8, table, "socket_path      <redacted>") != null);
    const plain = try runFormatter(formatConfig, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "jail.sshd.ignoreip\t<redacted>\n") != null);
}

test "format: scopes plain lists indexed items and the next cursor" {
    const out = try runFormatter(formatScopes, scopes_payload, .plain);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "items.0.jail\tsshd\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.0.scope\t192.0.2.1\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.0.match\tany\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.0.deadline_us\t4102444800000000\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.1.scope\t2001:db8::/64\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.1.match\ttcp/22\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.1.deadline_us\t-\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.1.decision_id\t-\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "next_cursor\tczoxOjA\n") != null);
}

test "format: scopes table shows remaining time, confirmation and cursor hint" {
    const out = try runFormatter(formatScopes, scopes_payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "JAIL") != null);
    try testing.expect(std.mem.indexOf(u8, out, "2001:db8::/64") != null);
    try testing.expect(std.mem.indexOf(u8, out, "tcp/22") != null);
    try testing.expect(std.mem.indexOf(u8, out, "never") != null);
    try testing.expect(std.mem.indexOf(u8, out, "m ") != null);
    try testing.expect(std.mem.indexOf(u8, out, "010101010101") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Total: 2 scopes") != null);
    try testing.expect(std.mem.indexOf(u8, out, "--cursor czoxOjA") != null);
    try testing.expect(std.mem.indexOf(u8, out, "generation: ab12") != null);
}

test "format: scopes and history empty pages" {
    const empty = "{\"generation\":\"g\",\"items\":[],\"next_cursor\":null}";
    const scopes = try runFormatter(formatScopes, empty, .table);
    defer testing.allocator.free(scopes);
    try testing.expect(std.mem.indexOf(u8, scopes, "No active scopes.") != null);
    try testing.expect(std.mem.indexOf(u8, scopes, "--cursor") == null);
    const history = try runFormatter(formatHistory, empty, .table);
    defer testing.allocator.free(history);
    try testing.expect(std.mem.indexOf(u8, history, "No confirmed history.") != null);
    const plain = try runFormatter(formatHistory, empty, .plain);
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("generation\tg\nnext_cursor\t-\n", plain);
}

test "format: history empty page with a cursor still tells the operator to keep paging" {
    const payload = "{\"generation\":\"g\",\"items\":[],\"next_cursor\":\"aDoy\"}";
    const table = try runFormatter(formatHistory, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "No confirmed history.") != null);
    try testing.expect(std.mem.indexOf(u8, table, "--cursor aDoy") != null);
    const plain = try runFormatter(formatHistory, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("generation\tg\nnext_cursor\taDoy\n", plain);
}

test "format: history plain and table" {
    const plain = try runFormatter(formatHistory, history_payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.sequence\t7\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.confirmed_us\t1700000000000000\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.native_retry\ttrue\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "next_cursor\t-\n") != null);
    const table = try runFormatter(formatHistory, history_payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "SEQ") != null);
    try testing.expect(std.mem.indexOf(u8, table, "2023-11-14 22:13:20") != null);
    try testing.expect(std.mem.indexOf(u8, table, "192.0.2.9") != null);
    try testing.expect(std.mem.indexOf(u8, table, "111111111111") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Total: 1 events") != null);
    try testing.expect(std.mem.indexOf(u8, table, "--cursor") == null);
}

test "format: canonical scope sets stay exact in scope and history tables" {
    const scope_payload =
        \\{"generation":"g","items":[{"jail":"dns","scope":{"family":"v4","address":"192.0.2.0","prefix":24,
        \\"subject_kind":"network","protocols":["tcp","udp"],"port_ranges":[{"first":53,"last":53},{"first":8000,"last":8010}],
        \\"legacy_exact":false},"lease":"finite","confirmed":true}],"next_cursor":null}
    ;
    const scopes = try runFormatter(formatScopes, scope_payload, .table);
    defer testing.allocator.free(scopes);
    try testing.expect(std.mem.indexOf(u8, scopes, "tcp,udp/53,8000-8010") != null);

    const history =
        \\{"generation":"g","items":[{"sequence":1,"jail":"dns","confirmed_us":1700000000000000,
        \\"scope":{"family":"v4","address":"192.0.2.0","prefix":24,"subject_kind":"network","protocols":["tcp","udp"],
        \\"port_ranges":[{"first":53,"last":53},{"first":8000,"last":8010}],"legacy_exact":false},"native_retry":false}],"next_cursor":null}
    ;
    const table = try runFormatter(formatHistory, history, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "MATCH") != null);
    try testing.expect(std.mem.indexOf(u8, table, "tcp,udp/53,8000-8010") != null);
    const plain = try runFormatter(formatHistory, history, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.scope\t192.0.2.0/24\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.match") == null);
}

test "format: firewall table and plain distinguish observation from intent" {
    const table = try runFormatter(formatFirewall, firewall_payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "owned (clean observation)") != null);
    try testing.expect(std.mem.indexOf(u8, table, "complete readback; 2 observed; 2 retained") != null);
    try testing.expect(std.mem.indexOf(u8, table, "tcp,udp/53,8000-8010") != null);
    try testing.expect(std.mem.indexOf(u8, table, "unknown") != null);
    try testing.expect(std.mem.indexOf(u8, table, "--cursor fw-token") != null);
    try testing.expect(std.mem.indexOf(u8, table, "confirmed") == null);
    try testing.expect(std.mem.indexOf(u8, table, "permanent") == null);

    const plain = try runFormatter(formatFirewall, firewall_payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "observation.id\t00112233445566778899aabbccddeeff:7\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.match\ttcp,udp/53,8000-8010\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "items.1.remaining_ms_at_observation\t-\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "next_cursor\tfw-token\n") != null);
}

test "format: firewall states keep unavailable absent stale and foreign distinct" {
    const unavailable = try runFormatter(formatFirewall, "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":false,\"unavailable_reason\":\"no_manager\",\"installation\":null,\"observation\":null,\"last_attempt\":{\"outcome\":\"none\",\"cause\":null,\"stage\":null,\"age_ms\":null},\"items\":[],\"next_cursor\":null}", .table);
    defer testing.allocator.free(unavailable);
    try testing.expect(std.mem.indexOf(u8, unavailable, "unavailable (no_manager)") != null);
    try testing.expect(std.mem.indexOf(u8, unavailable, "No sample is available") != null);

    const absent = try runFormatter(formatFirewall, "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"installation\":{\"backend\":\"iptables\"},\"observation\":{\"id\":\"n:1\",\"state\":\"absent\",\"observation_complete\":true,\"observed_total\":0,\"sample_count\":0,\"sample_truncated\":false},\"last_attempt\":{\"outcome\":\"success\"},\"items\":[],\"next_cursor\":null}", .table);
    defer testing.allocator.free(absent);
    try testing.expect(std.mem.indexOf(u8, absent, "State:        absent") != null);
    try testing.expect(std.mem.indexOf(u8, absent, "owned installation was absent") != null);

    const foreign = try runFormatter(formatFirewall, "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"installation\":{\"backend\":\"nftables\"},\"observation\":{\"id\":\"n:2\",\"state\":\"owned\",\"observation_complete\":true,\"observed_total\":1,\"sample_count\":1,\"sample_truncated\":false},\"last_attempt\":{\"outcome\":\"failed\",\"cause\":\"ForeignState\",\"stage\":\"readback\",\"age_ms\":4},\"items\":[],\"next_cursor\":null}", .table);
    defer testing.allocator.free(foreign);
    try testing.expect(std.mem.indexOf(u8, foreign, "stale; foreign state on last attempt") != null);
    try testing.expect(std.mem.indexOf(u8, foreign, "cause=ForeignState") != null);
}

test "format: firewall narrow output bounds and escapes diagnostic text" {
    const payload =
        "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"installation\":{\"backend\":\"nf\\ntables-with-a-long-name\",\"namespace\":\"daemon-current\"},\"observation\":{\"id\":\"nonce:1\",\"state\":\"owned\",\"observation_complete\":true,\"observed_total\":0,\"sample_count\":0,\"sample_truncated\":false},\"last_attempt\":{\"outcome\":\"success\"},\"items\":[],\"next_cursor\":null}";
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    try formatFirewallForWidth(testing.allocator, out.writer(), payload, .table, .{ .enabled = false }, 40);
    try testing.expect(std.mem.indexOf(u8, out.items, "nf\\ntables") != null);
    var lines = std.mem.splitScalar(u8, out.items, '\n');
    while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= 40);
}

test "format: firewall item fields escape controls in wide and stacked tables" {
    const payload =
        "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"installation\":{\"backend\":\"nftables\"},\"observation\":{\"id\":\"nonce:3\",\"state\":\"owned\",\"observation_complete\":true,\"observed_total\":2,\"sample_count\":2,\"sample_truncated\":false},\"last_attempt\":{\"outcome\":\"success\"},\"items\":[{\"scope\":{\"family\":\"v4\",\"address\":\"192.0.2.1\\u001b\\nrow\",\"prefix\":32,\"protocols\":[\"tcp\",\"udp\"],\"port_ranges\":[{\"first\":53,\"last\":53},{\"first\":8000,\"last\":8010}]},\"effect_id_hex\":\"abc\\tdef\\u001b\",\"remaining_ms_at_observation\":1,\"deadline_us\":9223372036854775807},{\"scope\":{\"family\":\"v4\",\"address\":\"198.51.100.2\",\"prefix\":32,\"protocol\":\"u\\u001b\\np\\t\",\"port\":53},\"effect_id_hex\":null,\"remaining_ms_at_observation\":null,\"deadline_us\":null}],\"next_cursor\":null}";
    inline for (.{ @as(usize, 200), @as(usize, 40) }) |columns| {
        var out = std.ArrayList(u8).init(testing.allocator);
        defer out.deinit();
        try formatFirewallForWidth(testing.allocator, out.writer(), payload, .table, .{ .enabled = false }, columns);
        try testing.expect(std.mem.indexOfScalar(u8, out.items, 0x1b) == null);
        try testing.expect(std.mem.indexOfScalar(u8, out.items, '\t') == null);
        try testing.expect(std.mem.indexOf(u8, out.items, "192.0.2.1\\x1B\\nrow") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "abc\\tdef\\x1B") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "tcp,udp/53,8000-8010") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "u\\x1B\\np\\t/53") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "out-of-range") != null);
        if (columns == 40) {
            var lines = std.mem.splitScalar(u8, out.items, '\n');
            while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= columns);
        }
    }
}

test "format: firewall coverage preserves missing counts as unknown" {
    const payload =
        "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"installation\":{\"backend\":\"nftables\"},\"observation\":{\"id\":\"nonce:4\",\"state\":\"owned\",\"observation_complete\":true},\"last_attempt\":{\"outcome\":\"success\"},\"items\":[],\"next_cursor\":null}";
    const table = try runFormatter(formatFirewall, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "unknown observed; unknown retained") != null);
    try testing.expect(std.mem.indexOf(u8, table, "0 observed; 0 retained") == null);
}

test "format: UTC rendering bounds hostile microsecond timestamps" {
    var buffer: [32]u8 = undefined;
    try testing.expectEqualStrings("out-of-range", formatUtc(&buffer, std.math.maxInt(i64)));
    try testing.expectEqualStrings("out-of-range", formatUtc(&buffer, -1));
    try testing.expectEqualStrings("9999-12-31 23:59:59", formatUtc(&buffer, 253_402_300_799_000_000));
}

test "format: presentation details retains machine formats and exposes table identifiers" {
    const status = "{\"generation\":\"g\\nunsafe\",\"protection\":\"active\",\"backend\":\"nftables\",\"jails_active\":1,\"active_bans\":2}";
    const plain = try runFormatter(formatStatusDetailed, status, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "generation\tg\\nunsafe") != null);
    const json = try runFormatter(formatStatusDetailed, status, .json);
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(status ++ "\n", json);
    const summary_status = try runFormatter(formatStatus, status, .table);
    defer testing.allocator.free(summary_status);
    try testing.expect(std.mem.indexOf(u8, summary_status, "fail2zig status") != null);
    try testing.expect(std.mem.indexOf(u8, summary_status, "Generation:") == null);

    var status_table = std.ArrayList(u8).init(testing.allocator);
    defer status_table.deinit();
    try formatStatusForWidthDetailed(testing.allocator, status_table.writer(), status, .table, .{ .enabled = false }, 34, true);
    try testing.expect(std.mem.indexOf(u8, status_table.items, "Generation: g\\nunsafe") != null);

    const firewall = "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"generation\":\"g-1\",\"installation\":{\"id_hex\":\"install-1\",\"backend\":\"nftables\"},\"observation\":{\"id\":\"obs-1\",\"state\":\"owned\",\"observation_complete\":true,\"observed_total\":1,\"sample_count\":1,\"sample_truncated\":false},\"last_attempt\":{\"outcome\":\"success\"},\"structure\":{\"proof\":\"exact_v1\",\"tables\":[{\"family\":\"inet\",\"name\":\"f2z\\nowned\"}],\"chains\":[{\"family\":\"inet\",\"table\":\"f2z\\u001bowned\",\"name\":\"input\",\"type\":\"filter\",\"hook\":\"input\",\"priority\":-1,\"policy\":\"accept\"}],\"sets\":[],\"rules\":[]},\"items\":[{\"scope\":{\"family\":\"v4\",\"address\":\"192.0.2.1\",\"prefix\":32},\"effect_id_hex\":\"effect-1\",\"remaining_ms_at_observation\":118000,\"placement\":{\"kind\":\"set_\\u001belement\",\"family\":\"inet\",\"table\":\"f2z\",\"chain\":\"input\",\"set\":\"banned_v4\",\"verdict\":\"drop\"}}],\"next_cursor\":null}";
    var summary = std.ArrayList(u8).init(testing.allocator);
    defer summary.deinit();
    try formatFirewallForWidthDetailed(testing.allocator, summary.writer(), firewall, .table, .{ .enabled = false }, 160, false);
    try testing.expect(std.mem.indexOf(u8, summary.items, "effect-1") == null);
    try testing.expect(std.mem.indexOf(u8, summary.items, "install-1") == null);
    var detailed = std.ArrayList(u8).init(testing.allocator);
    defer detailed.deinit();
    try formatFirewallForWidthDetailed(testing.allocator, detailed.writer(), firewall, .table, .{ .enabled = false }, 160, true);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "effect-1") != null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "install-1") != null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "TABLE") != null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "FAMILY") != null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "f2z\\nowned") != null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "set_\\x1Belement") != null);
    try testing.expect(std.mem.indexOfScalar(u8, detailed.items, 0x1b) == null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "1m 58s") != null);
}

test "format: compact jail summary stacks safely on narrow terminals" {
    const payload = "[{\"name\":\"ssh\\nud\",\"enabled\":true,\"active_bans\":3,\"enforcing\":true,\"log_source\":\"journal\\u001bctl\",\"source_healthy\":false,\"cause\":\"PermissionDenied\"}]";
    var wide = std.ArrayList(u8).init(testing.allocator);
    defer wide.deinit();
    try formatJailsForWidthDetailed(testing.allocator, wide.writer(), payload, .table, .{ .enabled = false }, 160, false);
    try testing.expect(std.mem.indexOf(u8, wide.items, "SOURCE HEALTH") != null);
    try testing.expect(std.mem.indexOf(u8, wide.items, "\\x1B") != null);
    var narrow = std.ArrayList(u8).init(testing.allocator);
    defer narrow.deinit();
    try formatJailsForWidthDetailed(testing.allocator, narrow.writer(), payload, .table, .{ .enabled = false }, 36, false);
    try testing.expect(std.mem.indexOf(u8, narrow.items, "JAIL:") != null);
    try testing.expect(std.mem.indexOf(u8, narrow.items, "SOURCE:") != null);
    try testing.expect(std.mem.indexOf(u8, narrow.items, "ENFORCING:") != null);
    try testing.expect(std.mem.indexOf(u8, narrow.items, "HEALTH:") != null);
    var lines = std.mem.splitScalar(u8, narrow.items, '\n');
    while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= 36);
}

test "format: BUG-068 default summaries retain health and failure context" {
    const jails = "[{\"name\":\"sshd\",\"enabled\":true,\"active_bans\":1,\"enforcing\":false,\"log_source\":\"journal\",\"source_healthy\":false,\"cause\":\"JournalCursorLost\",\"source_exit_code\":125,\"source_signal\":15,\"source_stderr_present\":true}]";
    var jail_output = std.ArrayList(u8).init(testing.allocator);
    defer jail_output.deinit();
    try formatJailsForWidthDetailed(testing.allocator, jail_output.writer(), jails, .table, .{ .enabled = false }, 120, false);
    try testing.expect(std.mem.indexOf(u8, jail_output.items, "broken (JournalCursorLost; exit=125; signal=15; stderr)") != null);
    try testing.expect(std.mem.indexOf(u8, jail_output.items, "false") != null);

    const status = "{\"protection\":\"degraded\",\"sqlite_code\":5,\"next_retry_ms\":1234,\"effect_mutation\":\"retry-17\"}";
    const output = try runFormatter(formatStatus, status, .table);
    defer testing.allocator.free(output);
    try testing.expect(std.mem.indexOf(u8, output, "SQLite code: 5") != null);
    try testing.expect(std.mem.indexOf(u8, output, "Retry at: 1234 ms monotonic") != null);
    try testing.expect(std.mem.indexOf(u8, output, "Effect attempt: retry-17") != null);
}

test "format: verified structural identities fit or stack without clipping" {
    const name = "f2z_0123456789abcdef01234567";
    const set = name ++ "_4";
    const rules = [_]FirewallRule{
        .{ .family = "v4", .table = "filter", .chain = "INPUT", .match = "all", .verdict = name, .position = 1 },
        .{ .family = "v4", .table = "filter", .chain = name, .match = "source in " ++ set, .verdict = "drop" },
    };
    for ([_]usize{ 80, 120 }) |columns| {
        var out = std.ArrayList(u8).init(testing.allocator);
        defer out.deinit();
        try writeFirewallStructureRules(out.writer(), &rules, .{ .enabled = false }, columns);
        try testing.expect(std.mem.indexOf(u8, out.items, "source in " ++ set) != null);
        try testing.expect(std.mem.indexOf(u8, out.items, name) != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "...") == null);
        var lines = std.mem.splitScalar(u8, out.items, '\n');
        while (lines.next()) |line| try testing.expect(line.len <= columns);
    }
    var nft_out = std.ArrayList(u8).init(testing.allocator);
    defer nft_out.deinit();
    try writeFirewallStructureRules(nft_out.writer(), &.{.{ .family = "inet", .table = name, .chain = "input", .match = "ip saddr @banned_ipv4", .verdict = "drop" }}, .{ .enabled = false }, 80);
    try testing.expect(std.mem.indexOf(u8, nft_out.items, "MATCH") != null);
    try testing.expect(std.mem.indexOf(u8, nft_out.items, "MATCH:") == null);
}

test "format: firewall rejects available response without an observation" {
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    try testing.expectError(error.InvalidFirewallPayload, formatFirewallForWidth(
        testing.allocator,
        out.writer(),
        "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"observation\":null}",
        .table,
        .{ .enabled = false },
        80,
    ));
}

test "format: query renderers report unparseable payloads without failing" {
    inline for (.{ formatConfig, formatScopes, formatHistory }) |formatter| {
        const out = try runFormatter(formatter, "nope", .table);
        defer testing.allocator.free(out);
        try testing.expect(std.mem.startsWith(u8, out, "error: could not parse"));
    }
}

test "format: BUG-064 compact jail fallback preserves full source causes at default widths" {
    const payload =
        \\[{"name":"sshd","enabled":true,"source_healthy":false,"cause":"RestoreRequired"},
        \\ {"name":"other","enabled":true,"source_healthy":false,"cause":"InvalidEncoding"}]
    ;
    for ([_]usize{ 74, 80 }) |width| {
        var out = std.ArrayList(u8).init(testing.allocator);
        defer out.deinit();
        try formatJailsForWidth(testing.allocator, out.writer(), payload, .table, .{ .enabled = false }, width);
        try testing.expect(std.mem.indexOf(u8, out.items, "broken (RestoreRequired)") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "broken (InvalidEncoding)") != null);
        var lines = std.mem.splitScalar(u8, out.items, '\n');
        while (lines.next()) |line| try testing.expect(line.len <= width);
    }
}
