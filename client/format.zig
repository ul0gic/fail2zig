// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Re-exports the formatter functions and types that main.zig and args.zig reach as format.<name> from the files under format/.
// Holds: Each name here is an alias of one declaration under client/format/; this file declares no code of its own.

pub const OutputFormat = @import("format/shared.zig").OutputFormat;
pub const Color = @import("format/shared.zig").Color;
pub const shouldColor = @import("format/shared.zig").shouldColor;
pub const diagnostic_max_bytes = @import("format/shared.zig").diagnostic_max_bytes;
pub const escapeArgument = @import("format/shared.zig").escapeArgument;
pub const LossEvent = @import("format/status_sources.zig").LossEvent;
pub const LossReport = @import("format/status_sources.zig").LossReport;
pub const formatStatus = @import("format/status.zig").formatStatus;
pub const formatStatusWithLoss = @import("format/status.zig").formatStatusWithLoss;
pub const formatStats = @import("format/stats.zig").formatStats;
pub const formatStatsDetailed = @import("format/stats.zig").formatStatsDetailed;
pub const formatVersion = @import("format/version.zig").formatVersion;
pub const formatList = @import("format/list.zig").formatList;
pub const formatListDetailed = @import("format/list.zig").formatListDetailed;
pub const formatJails = @import("format/jails.zig").formatJails;
pub const formatJailsDetailed = @import("format/jails.zig").formatJailsDetailed;
pub const formatIgnoreOutcome = @import("format/ignore.zig").formatIgnoreOutcome;
pub const formatIgnoreList = @import("format/ignore.zig").formatIgnoreList;
pub const formatConfig = @import("format/config.zig").formatConfig;
pub const formatHistory = @import("format/history.zig").formatHistory;
pub const formatHistoryDetailed = @import("format/history.zig").formatHistoryDetailed;
pub const formatFirewall = @import("format/firewall.zig").formatFirewall;
pub const formatFirewallDetailed = @import("format/firewall.zig").formatFirewallDetailed;
pub const formatError = @import("format/errors.zig").formatError;
pub const formatUnknownJail = @import("format/errors.zig").formatUnknownJail;
