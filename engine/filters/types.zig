// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Defines the named pattern that every built-in filter list is made of.
// Holds: A match gets only the line, with no allocator or context, and its result holds values only, never a slice of the line.

const parser = @import("../detect/parser.zig");

pub const PatternDef = struct {
    name: []const u8,
    match: parser.MatchFn,
};
