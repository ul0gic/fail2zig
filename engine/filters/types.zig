// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const parser = @import("../core/parser.zig");

pub const PatternDef = struct {
    name: []const u8,
    match: parser.MatchFn,
};
