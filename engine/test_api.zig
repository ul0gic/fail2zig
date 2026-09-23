// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Direct internal imports for isolated component test modules. Not used by the product.
pub const cli = struct {
    pub const rule_test = @import("cli/rule_test.zig");
};
pub const config = struct {
    pub const duration = @import("config/duration.zig");
    pub const native = @import("config/native.zig");
    pub const native_consumer_plan = @import("config/native_consumer_plan.zig");
    pub const native_effective = @import("config/native_effective.zig");
    pub const native_file_detection = @import("config/native_file_detection.zig");
    pub const native_journal_detection = @import("config/native_journal_detection.zig");
    pub const native_journal_profile = @import("config/native_journal_profile.zig");
    pub const native_paths = @import("config/native_paths.zig");
    pub const native_retry_policy = @import("config/native_retry_policy.zig");
};
pub const core = struct {
    pub const durable_file_source = @import("core/durable_file_source.zig");
    pub const event_loop = @import("core/event_loop.zig");
    pub const event_time = @import("core/event_time.zig");
    pub const journal_policy = @import("core/journal_policy.zig");
    pub const line_context = @import("core/line_context.zig");
    pub const log_target = @import("core/log_target.zig");
    pub const native_action_context = @import("core/native_action_context.zig");
    pub const native_action_outcome = @import("core/native_action_outcome.zig");
    pub const native_application_history = @import("core/native_application_history.zig");
    pub const native_builtin_detector = @import("core/native_builtin_detector.zig");
    pub const native_consumer = @import("core/native_consumer.zig");
    pub const native_consumer_coordinator = @import("core/native_consumer_coordinator.zig");
    pub const native_correlation = @import("core/native_correlation.zig");
    pub const native_detection_record = @import("core/native_detection_record.zig");
    pub const native_dns = @import("core/native_dns.zig");
    pub const native_effect = @import("core/native_effect.zig");
    pub const native_effect_history = @import("core/native_effect_history.zig");
    pub const native_file_session = @import("core/native_file_session.zig");
    pub const native_ignore = @import("core/native_ignore.zig");
    pub const native_journal_detector = @import("core/native_journal_detector.zig");
    pub const native_journal_origin = @import("core/native_journal_origin.zig");
    pub const native_journal_session = @import("core/native_journal_session.zig");
    pub const native_journal_transport = @import("core/native_journal_transport.zig");
    pub const native_lease = @import("core/native_lease.zig");
    pub const native_recovery = @import("core/native_recovery.zig");
    pub const native_recurrence = @import("core/native_recurrence.zig");
    pub const native_retry = @import("core/native_retry.zig");
    pub const native_rule_consumer = @import("core/native_rule_consumer.zig");
    pub const native_rules = @import("core/native_rules.zig");
    pub const native_source_processor = @import("core/native_source_processor.zig");
    pub const native_time = @import("core/native_time.zig");
    pub const native_time_record = @import("core/native_time_record.zig");
    pub const native_timezone = @import("core/native_timezone.zig");
    pub const parser = @import("core/parser.zig");
    pub const readiness = @import("core/readiness.zig");
    pub const record_pipeline = @import("core/record_pipeline.zig");
    pub const record_store = @import("core/record_store.zig");
    pub const sd_notify = @import("core/sd_notify.zig");
    pub const source_policy = @import("core/source_policy.zig");
    pub const source_record = @import("core/source_record.zig");
    pub const source_repair = @import("core/source_repair.zig");
    pub const source_text = @import("core/source_text.zig");
    pub const source_time_policy = @import("core/source_time_policy.zig");
    pub const storage_health = @import("core/storage_health.zig");
};
pub const filters = struct {
    pub const portsentry = @import("filters/portsentry.zig");
    pub const registry = @import("filters/registry.zig");
};
pub const firewall = struct {
    pub const command = @import("firewall/command.zig");
    pub const inspection = @import("firewall/inspection.zig");
    pub const netlink = @import("firewall/netlink.zig");
    pub const nftables = @import("firewall/nftables.zig");
    pub const scope = @import("firewall/scope.zig");
};
pub const migration = struct {
    pub const continuity = @import("migration/continuity.zig");
    pub const fail2ban_db = @import("migration/fail2ban_db.zig");
    pub const fail2ban_fixture = @import("migration/fail2ban_fixture.zig");
    pub const import = @import("migration/import.zig");
    pub const inspect = @import("migration/inspect.zig");
    pub const journal = @import("migration/journal.zig");
    pub const plan = @import("migration/plan.zig");
    pub const sqlite_snapshot = @import("migration/sqlite_snapshot.zig");
};
pub const net = struct {
    pub const ipc = @import("net/ipc.zig");
    pub const ipc_auth = @import("net/ipc_auth.zig");
    pub const query_v1 = @import("net/query_v1.zig");
};
pub const runtime = struct {
    pub const native_consumer_runtime = @import("runtime/native_consumer_runtime.zig");
    pub const native_effect_runtime = @import("runtime/native_effect_runtime.zig");
    pub const native_firewall_observation = @import("runtime/native_firewall_observation.zig");
    pub const native_reload = @import("runtime/native_reload.zig");
    pub const native_resource_budget = @import("runtime/native_resource_budget.zig");
};
