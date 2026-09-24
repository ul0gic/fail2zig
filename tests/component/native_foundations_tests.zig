// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
pub const files = @import("engine_test").core.durable_file_source;
pub const journal_policy = @import("engine_test").core.journal_policy;
pub const store = @import("engine_test").core.record_store;
pub const pipeline = @import("engine_test").core.record_pipeline;
pub const storage_health = @import("engine_test").core.storage_health;
pub const event_time = @import("engine_test").core.event_time;
pub const line_context = @import("engine_test").core.line_context;
pub const event_time_pipeline = @import("event_time_pipeline_tests.zig");
pub const native_time = @import("engine_test").core.native_time;
pub const source_text = @import("engine_test").core.source_text;
pub const source_time_policy = @import("engine_test").core.source_time_policy;
pub const time_admission_pipeline = @import("time_admission_pipeline_tests.zig");
pub const future_time_pipeline = @import("future_time_pipeline_tests.zig");
pub const receipt_recovery_pipeline = @import("receipt_recovery_pipeline_tests.zig");
pub const native_source_processor = @import("engine_test").core.native_source_processor;
pub const native_recovery = @import("engine_test").core.native_recovery;
pub const clock_recovery_tests = @import("clock_recovery_tests.zig");
pub const native_file_session = @import("engine_test").core.native_file_session;
pub const native_time_record = @import("engine_test").core.native_time_record;
pub const native_processor_tests = @import("native_processor_tests.zig");
pub const native_journal_transport = @import("engine_test").core.native_journal_transport;
pub const native_journal_session = @import("engine_test").core.native_journal_session;
pub const native_journal_tests = @import("native_journal_tests.zig");
pub const native_source_tests = @import("native_source_tests.zig");
pub const duration = @import("engine_test").config.duration;
pub const source_policy = @import("engine_test").core.source_policy;
test {
    std.testing.refAllDecls(@This());
}

pub const source_health = @import("source_health_tests.zig");

pub const store_tests = @import("store/tests.zig");
