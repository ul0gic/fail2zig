// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
pub const files = @import("core/durable_file_source.zig");
pub const journal_session = @import("core/journal_session.zig");
pub const journal_policy = @import("core/journal_policy.zig");
pub const journal = @import("core/systemd_reader.zig");
pub const store = @import("core/record_store.zig");
pub const pipeline = @import("core/record_pipeline.zig");
pub const event_time = @import("core/event_time.zig");
pub const duration = @import("config/duration.zig");
pub const source_policy = @import("core/source_policy.zig");
pub const source_processor = @import("core/source_processor.zig");
pub const file_session = @import("core/file_session.zig");
pub const worker = @import("core/compat_worker.zig");
test {
    std.testing.refAllDecls(@This());
}

pub const source_health = @import("source_health_tests.zig");
