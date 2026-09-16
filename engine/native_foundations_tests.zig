// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
pub const files = @import("core/durable_file_source.zig");
pub const journal_policy = @import("core/journal_policy.zig");
pub const store = @import("core/record_store.zig");
pub const pipeline = @import("core/record_pipeline.zig");
pub const storage_health = @import("core/storage_health.zig");
pub const event_time = @import("core/event_time.zig");
pub const line_context = @import("core/line_context.zig");
pub const event_time_pipeline = @import("event_time_pipeline_tests.zig");
pub const native_time = @import("core/native_time.zig");
pub const source_text = @import("core/source_text.zig");
pub const source_time_policy = @import("core/source_time_policy.zig");
pub const time_admission_pipeline = @import("time_admission_pipeline_tests.zig");
pub const future_time_pipeline = @import("future_time_pipeline_tests.zig");
pub const receipt_recovery_pipeline = @import("receipt_recovery_pipeline_tests.zig");
pub const native_source_processor = @import("core/native_source_processor.zig");
pub const native_recovery = @import("core/native_recovery.zig");
pub const clock_recovery_tests = @import("clock_recovery_tests.zig");
pub const native_file_session = @import("core/native_file_session.zig");
pub const native_time_record = @import("core/native_time_record.zig");
pub const native_processor_tests = @import("native_processor_tests.zig");
pub const native_journal_transport = @import("core/native_journal_transport.zig");
pub const native_journal_session = @import("core/native_journal_session.zig");
pub const native_journal_tests = @import("native_journal_tests.zig");
pub const native_source_tests = @import("native_source_tests.zig");
pub const duration = @import("config/duration.zig");
pub const source_policy = @import("core/source_policy.zig");
test {
    std.testing.refAllDecls(@This());
}

pub const source_health = @import("source_health_tests.zig");
