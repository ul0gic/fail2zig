//! Shared types for the built-in filter library.
//!
//! Each filter module exports a `pub const patterns = [_]PatternDef{...}`
//! slice. The `registry` module stitches all of these together into a
//! single name → patterns lookup table consumed by the migration tool
//! and (eventually) the daemon's matcher construction.

const parser = @import("../core/parser.zig");

/// One compiled fail2zig pattern. `match` is a comptime-generated
/// zero-allocation match function. `name` is informational only —
/// surfaced in migration reports, diagnostics, and future CLI `--list-filters`.
pub const PatternDef = struct {
    /// Stable identifier for this specific pattern within its filter
    /// (e.g. "failed-password"). Not to be confused with the filter's
    /// registry name (e.g. "sshd").
    name: []const u8,
    /// Zero-allocation matcher. Returns `null` on no match, or a
    /// `ParseResult` populated with at least the offender's IP.
    match: parser.MatchFn,
};
