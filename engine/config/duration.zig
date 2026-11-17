// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Re-exports the shared duration parser for configuration code.
// Holds: Every name here aliases shared.duration, so configuration and shared code cannot parse a duration differently.

const shared_duration = @import("shared").duration;
pub const Error = shared_duration.Error;
pub const Duration = shared_duration.Duration;
pub const parse = shared_duration.parse;
pub const expression = shared_duration.expression;
