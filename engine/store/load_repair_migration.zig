// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const builtin = @import("builtin");
const store_mod = @import("store.zig");
const Error = store_mod.Error;
const latest_schema = store_mod.latest_schema;
pub const target_schema = store_mod.load_repair_schema;
const source_schema: i64 = 23;

// Callback allowance for the one unpageable completion check (unfiltered foreign_key_check
// plus quick_check). Used only by the final migration transaction; every mutating page
// stays under the ordinary 1,000-callback guard. Sized as the measured worst 1.42 callbacks
// per page x the 65,536-page state cap x 1.25.
pub const migration_verify: u32 = 116_400;
// Observations kept per intent; older ones are dropped while the table is rebuilt.
pub const observations_per_intent: i64 = 4;
// Space kept free beyond the backup and the rebuild overlap for WAL and temporary B-trees.
const disk_reserve_bytes: u64 = 32 * 1024 * 1024;
const backup_suffix = ".pre24-backup";
const partial_suffix = ".pre24-backup.partial";

pub const Phase = enum(u8) {
    live_counter = 1,
    detail_columns,
    detail_sequence_index,
    detail_age_index,
    detail_subject_index,
    detail_evidence_index,
    targets_reclaim,
    targets_copy,
    targets_swap,
    observations_copy,
    observations_swap,
    intents_reclaim,
    revisions_reclaim,
    spent_index,
    pending_intent_index,
    events_copy,
    events_swap,
    markers,
    details,
    candidates,
    validate,
    verify,
    complete = 99,
};

pub const Status = enum { earlier_schema, ready, incomplete, complete };

pub const Hooks = if (builtin.is_test) struct {
    context: ?*anyopaque = null,
    before_commit: ?*const fn (?*anyopaque, ?Phase) void = null,
    backup_max_page_count: ?i64 = null,
    window_rows: ?i64 = null,
    verify_allowance: ?u32 = null,
} else struct {};

pub const Options = struct {
    state_path: []const u8,
    now_us: i64,
    history_max_matches: u16,
    hooks: Hooks = .{},
};

pub const Step = struct {
    // Phase that ran; null for the fence transaction that creates the progress row.
    phase: ?Phase,
    next: Phase,
    callbacks: u32,
};

pub const Progress = struct { phase: Phase, cursor: i64 };

const Window = struct {
    rows: i64,
    max_sql: [:0]const u8,
};

extern fn sqlite3_backup_init(dest: *anyopaque, dest_name: [*:0]const u8, source: *anyopaque, source_name: [*:0]const u8) ?*anyopaque;
extern fn sqlite3_backup_step(backup: *anyopaque, pages: c_int) c_int;
extern fn sqlite3_backup_finish(backup: *anyopaque) c_int;
extern fn sqlite3_open_v2(path: [*:0]const u8, db: *?*anyopaque, flags: c_int, vfs: ?[*:0]const u8) c_int;
extern fn sqlite3_close_v2(db: *anyopaque) c_int;
extern fn sqlite3_exec(db: *anyopaque, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*anyopaque) c_int;
extern fn sqlite3_errcode(db: *anyopaque) c_int;
extern fn sqlite3_prepare_v2(db: *anyopaque, sql: [*:0]const u8, bytes: c_int, statement: *?*anyopaque, tail: ?*anyopaque) c_int;
extern fn sqlite3_step(statement: *anyopaque) c_int;
extern fn sqlite3_finalize(statement: *anyopaque) c_int;
extern fn sqlite3_column_int64(statement: *anyopaque, column: c_int) i64;
extern fn sqlite3_column_text(statement: *anyopaque, column: c_int) ?[*:0]const u8;

const Statvfs = extern struct {
    bsize: c_ulong,
    frsize: c_ulong,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    reserved: [128]u8,
};
extern fn fstatvfs(fd: c_int, buffer: *Statvfs) c_int;

// All new structures are created empty in the fence transaction; existing-row work follows
// in bounded pages. Added detail columns carry no CHECK: ADD COLUMN ... CHECK rescans every
// existing row, so triggers enforce the same rules for inserted and updated rows instead.
const fence_ddl =
    \\CREATE TABLE load_repair_migration(id INTEGER PRIMARY KEY CHECK(id=1),phase INTEGER NOT NULL CHECK(phase BETWEEN 1 AND 99),cursor INTEGER NOT NULL CHECK(typeof(cursor)='integer' AND cursor>=0),started_us INTEGER NOT NULL CHECK(typeof(started_us)='integer'),completed_us INTEGER CHECK(completed_us IS NULL OR typeof(completed_us)='integer'),backup_path TEXT NOT NULL CHECK(typeof(backup_path)='text' AND length(backup_path) BETWEEN 1 AND 4096),backup_sha256 BLOB NOT NULL CHECK(typeof(backup_sha256)='blob' AND length(backup_sha256)=32),backup_pages INTEGER NOT NULL CHECK(typeof(backup_pages)='integer' AND backup_pages>0),backup_user_version INTEGER NOT NULL CHECK(backup_user_version=23),backup_quick_check TEXT NOT NULL CHECK(backup_quick_check='ok'),superseded_targets INTEGER NOT NULL CHECK(typeof(superseded_targets)='integer' AND superseded_targets>=0),CHECK((phase=99)=(completed_us IS NOT NULL)));
    \\CREATE TABLE retention_policy(id INTEGER PRIMARY KEY CHECK(id=1),generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation>0),max_matches INTEGER NOT NULL CHECK(typeof(max_matches)='integer' AND max_matches BETWEEN 0 AND 1024),state INTEGER NOT NULL CHECK(state IN(1,2)),sweep_cursor INTEGER NOT NULL CHECK(typeof(sweep_cursor)='integer' AND sweep_cursor>=0));
    \\CREATE TABLE confirmation_markers(scope_key BLOB NOT NULL,jail TEXT NOT NULL,decision_id BLOB NOT NULL CHECK(typeof(decision_id)='blob' AND length(decision_id)=32),event_id BLOB NOT NULL CHECK(typeof(event_id)='blob' AND length(event_id)=32),PRIMARY KEY(scope_key,jail),FOREIGN KEY(scope_key,jail) REFERENCES effect_owners(scope_key,jail));
    \\CREATE TABLE retained_subject_summaries(family INTEGER NOT NULL CHECK(family IN(4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),detail_count INTEGER NOT NULL CHECK(typeof(detail_count)='integer' AND detail_count>0),evidence_bytes INTEGER NOT NULL CHECK(typeof(evidence_bytes)='integer' AND evidence_bytes>=0),earliest_sequence INTEGER NOT NULL CHECK(typeof(earliest_sequence)='integer' AND earliest_sequence>0),earliest_evidence_sequence INTEGER CHECK(earliest_evidence_sequence IS NULL OR earliest_evidence_sequence>=earliest_sequence),evaluated_generation INTEGER NOT NULL CHECK(typeof(evaluated_generation)='integer' AND evaluated_generation>=0),candidate_sequence INTEGER CHECK(candidate_sequence IS NULL OR candidate_sequence>=earliest_sequence),PRIMARY KEY(family,subject));
    \\CREATE INDEX retained_subject_candidates ON retained_subject_summaries(candidate_sequence) WHERE candidate_sequence IS NOT NULL;
    \\DROP INDEX confirmed_effect_events_time;
    \\DROP INDEX confirmed_effect_events_jail_time;
    \\DROP INDEX IF EXISTS confirmed_effect_events_decision;
    \\CREATE TABLE confirmed_effect_events_v24(event_id BLOB PRIMARY KEY NOT NULL CHECK(typeof(event_id)='blob' AND length(event_id)=32),scope_key BLOB NOT NULL CHECK(typeof(scope_key)='blob' AND length(scope_key)=32),jail TEXT NOT NULL,decision_id BLOB NOT NULL CHECK(typeof(decision_id)='blob' AND length(decision_id)=32),confirmed_us INTEGER NOT NULL CHECK(typeof(confirmed_us)='integer'),canonical_scope BLOB NOT NULL CHECK(typeof(canonical_scope)='blob' AND length(canonical_scope)=92),UNIQUE(scope_key,jail,decision_id));
    \\CREATE INDEX confirmed_effect_events_time ON confirmed_effect_events_v24(confirmed_us,event_id);
    \\CREATE INDEX confirmed_effect_events_jail_time ON confirmed_effect_events_v24(jail,confirmed_us,event_id);
    \\CREATE INDEX confirmed_effect_events_decision ON confirmed_effect_events_v24(jail,decision_id);
    \\CREATE TABLE effect_owner_live(id INTEGER PRIMARY KEY CHECK(id=1),live INTEGER NOT NULL CHECK(typeof(live)='integer' AND live>=0),mismatch_streak INTEGER NOT NULL DEFAULT 0 CHECK(typeof(mismatch_streak)='integer' AND mismatch_streak>=0));
    \\CREATE TRIGGER effect_owner_live_insert AFTER INSERT ON effect_owners WHEN NEW.lease_kind<>0 BEGIN UPDATE effect_owner_live SET live=live+1 WHERE id=1; END;
    \\CREATE TRIGGER effect_owner_live_update AFTER UPDATE OF lease_kind ON effect_owners WHEN (OLD.lease_kind<>0)<>(NEW.lease_kind<>0) BEGIN UPDATE effect_owner_live SET live=live+CASE WHEN NEW.lease_kind<>0 THEN 1 ELSE -1 END WHERE id=1; END;
    \\CREATE TRIGGER effect_owner_live_delete AFTER DELETE ON effect_owners WHEN OLD.lease_kind<>0 BEGIN UPDATE effect_owner_live SET live=live-1 WHERE id=1; END;
    \\CREATE TABLE action_targets_v24(action_id BLOB NOT NULL CHECK(typeof(action_id)='blob' AND length(action_id)=32),kind INTEGER NOT NULL CHECK(kind IN(1,2)),scope_key BLOB NOT NULL CHECK(typeof(scope_key)='blob' AND length(scope_key)=32),jail TEXT NOT NULL CHECK(length(jail) BETWEEN 1 AND 64),required INTEGER NOT NULL CHECK(required IN(0,1) AND required=(kind=1)),restored INTEGER NOT NULL CHECK(restored IN(0,1)),status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 7),intent_us INTEGER NOT NULL CHECK(typeof(intent_us)='integer'),dispatch_us INTEGER CHECK(dispatch_us IS NULL OR (typeof(dispatch_us)='integer' AND dispatch_us>=intent_us)),settled_us INTEGER CHECK(settled_us IS NULL OR (typeof(settled_us)='integer' AND settled_us>=dispatch_us)),metadata TEXT CHECK(metadata IS NULL OR (typeof(metadata)='text' AND length(CAST(metadata AS BLOB)) BETWEEN 1 AND 512)),PRIMARY KEY(action_id,kind),CHECK((status=1 AND dispatch_us IS NULL AND settled_us IS NULL) OR (status=2 AND dispatch_us IS NOT NULL AND settled_us IS NULL) OR (status BETWEEN 3 AND 5 AND dispatch_us IS NOT NULL AND settled_us IS NOT NULL) OR (status=6 AND kind=2 AND restored=1 AND dispatch_us IS NULL AND settled_us=intent_us) OR (status=7 AND settled_us IS NOT NULL)),CHECK(kind!=1 OR status!=6),CHECK(kind!=2 OR restored=0 OR status=6));
    \\CREATE INDEX action_targets_unsettled ON action_targets_v24(scope_key) WHERE status IN(1,2,5);
    \\CREATE TABLE effect_observations_v24(observation_id BLOB PRIMARY KEY NOT NULL CHECK(typeof(observation_id)='blob' AND length(observation_id)=32),intent_id BLOB NOT NULL,dispatch_us INTEGER NOT NULL,observed_us INTEGER NOT NULL,fingerprint BLOB NOT NULL CHECK(typeof(fingerprint)='blob' AND length(fingerprint)=32),state_kind INTEGER NOT NULL CHECK(state_kind BETWEEN 0 AND 3),deadline_us INTEGER,outcome INTEGER NOT NULL CHECK(outcome BETWEEN 1 AND 6),FOREIGN KEY(intent_id) REFERENCES effect_intents(intent_id),CHECK(observed_us>=dispatch_us),CHECK((state_kind=1)=(deadline_us IS NOT NULL)));
    \\CREATE INDEX effect_observations_intent ON effect_observations_v24(intent_id,observed_us);
    \\CREATE TABLE source_repairs(token BLOB PRIMARY KEY NOT NULL CHECK(typeof(token)='blob' AND length(token)=32),jail TEXT NOT NULL CHECK(typeof(jail)='text' AND length(jail) BETWEEN 1 AND 64),source TEXT NOT NULL CHECK(typeof(source)='text' AND length(source) BETWEEN 1 AND 16384),generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),prior_cursor_sha256 BLOB NOT NULL CHECK(typeof(prior_cursor_sha256)='blob' AND length(prior_cursor_sha256)=32),prior_checkpoint_revision INTEGER NOT NULL CHECK(typeof(prior_checkpoint_revision)='integer' AND prior_checkpoint_revision>=0),file_device INTEGER NOT NULL CHECK(typeof(file_device)='integer'),file_inode INTEGER NOT NULL CHECK(typeof(file_inode)='integer'),file_size INTEGER NOT NULL CHECK(typeof(file_size)='integer' AND file_size>=0),file_prefix_sha256 BLOB NOT NULL CHECK(typeof(file_prefix_sha256)='blob' AND length(file_prefix_sha256)=32),new_incarnation BLOB NOT NULL CHECK(typeof(new_incarnation)='blob' AND length(new_incarnation)=16),outcome INTEGER NOT NULL CHECK(typeof(outcome)='integer' AND outcome>0),committed_us INTEGER NOT NULL CHECK(typeof(committed_us)='integer'));
    \\CREATE INDEX source_repairs_committed ON source_repairs(committed_us,token);
    \\CREATE TABLE migration_activations(run_id BLOB NOT NULL REFERENCES migration_runs(run_id),seq INTEGER NOT NULL CHECK(typeof(seq)='integer' AND seq>=1),activated_us INTEGER NOT NULL CHECK(typeof(activated_us)='integer' AND activated_us>=0),PRIMARY KEY(run_id,seq)) WITHOUT ROWID;
    \\ALTER TABLE admin_requests ADD COLUMN admission_revision INTEGER;
    \\CREATE TRIGGER admin_request_revision_insert BEFORE INSERT ON admin_requests WHEN NOT (NEW.admission_revision IS NULL OR (typeof(NEW.admission_revision)='integer' AND NEW.admission_revision>=0)) BEGIN SELECT RAISE(ABORT,'invalid admission revision'); END;
    \\CREATE TRIGGER admin_request_revision_update BEFORE UPDATE OF admission_revision ON admin_requests BEGIN SELECT RAISE(ABORT,'admission revision immutable'); END;
;

// A retired decision's settled targets are no longer read by anyone; unsettled ones keep
// their intents, revisions and observations until the runtime disposes of them.
const sql_targets_reclaim = "DELETE FROM action_targets WHERE rowid IN (SELECT a.rowid FROM action_targets a WHERE a.rowid>?1 AND a.rowid<=?2 AND a.status NOT IN(1,2,5) AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.jail=a.jail AND o.decision_id=a.action_id));";
const sql_targets_count = "SELECT count(*) FROM action_targets WHERE rowid>?1 AND rowid<=?2;";
// The runtime only processes the current owner's decision, so an unsettled target of any
// other decision was already abandoned. It becomes terminal `superseded` (7), settled at the
// migration start so resumed runs write identical rows.
const orphaned_target = "a.status IN(1,2,5) AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=a.scope_key AND o.jail=a.jail AND o.decision_id=a.action_id)";
const sql_targets_orphans = "SELECT count(*) FROM action_targets a WHERE a.rowid>?1 AND a.rowid<=?2 AND " ++ orphaned_target ++ ";";
const sql_targets_copy = "INSERT INTO action_targets_v24 SELECT action_id,kind,scope_key,jail,required,restored,CASE WHEN orphaned THEN 7 ELSE status END,intent_us,dispatch_us,CASE WHEN orphaned THEN coalesce(settled_us,max(coalesce(dispatch_us,intent_us),(SELECT started_us FROM load_repair_migration WHERE id=1))) ELSE settled_us END,metadata FROM (SELECT a.*,a.rowid AS source_row," ++ orphaned_target ++ " AS orphaned FROM action_targets a WHERE a.rowid>?1 AND a.rowid<=?2) ORDER BY source_row;";
const obsolete_intent = "i.intent_id IS NOT n.intent_id AND i.status NOT IN(1,2) AND NOT EXISTS(SELECT 1 FROM action_targets a WHERE a.action_id=i.decision_id AND a.scope_key=i.scope_key AND a.status IN(1,2,5))";
const sql_observations_copy = "INSERT INTO effect_observations_v24 SELECT o.* FROM effect_observations o JOIN effect_intents i ON i.intent_id=o.intent_id JOIN native_effects n ON n.scope_key=i.scope_key WHERE o.rowid>?1 AND o.rowid<=?2 AND NOT (" ++ obsolete_intent ++ ") ORDER BY o.rowid;";
const sql_observations_trim = "DELETE FROM effect_observations_v24 WHERE intent_id IN (SELECT DISTINCT intent_id FROM effect_observations WHERE rowid>?1 AND rowid<=?2) AND rowid NOT IN (SELECT k.rowid FROM effect_observations_v24 k INDEXED BY effect_observations_intent WHERE k.intent_id=effect_observations_v24.intent_id ORDER BY k.observed_us DESC,k.rowid DESC LIMIT ?3);";
const sql_intents_reclaim = "DELETE FROM effect_intents WHERE rowid IN (SELECT i.rowid FROM effect_intents i JOIN native_effects n ON n.scope_key=i.scope_key WHERE i.rowid>?1 AND i.rowid<=?2 AND " ++ obsolete_intent ++ ");";
const sql_revisions_reclaim = "DELETE FROM effect_owner_revisions WHERE rowid IN (SELECT h.rowid FROM effect_owner_revisions h WHERE h.rowid>?1 AND h.rowid<=?2 AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=h.scope_key AND o.jail=h.jail AND o.revision=h.revision) AND NOT EXISTS(SELECT 1 FROM action_targets a WHERE a.action_id=h.decision_id AND a.scope_key=h.scope_key AND a.status IN(1,2,5)));";
const sql_events_count = "SELECT count(*) FROM confirmed_effect_events WHERE rowid>?1 AND rowid<=?2;";
const sql_events_copy = "INSERT INTO confirmed_effect_events_v24(event_id,scope_key,jail,decision_id,confirmed_us,canonical_scope) SELECT e.event_id,e.scope_key,e.jail,e.decision_id,e.confirmed_us,n.canonical_scope FROM confirmed_effect_events e JOIN native_effects n ON n.scope_key=e.scope_key WHERE e.rowid>?1 AND e.rowid<=?2 ORDER BY e.rowid;";
const sql_markers = "INSERT INTO confirmation_markers(scope_key,jail,decision_id,event_id) SELECT o.scope_key,o.jail,o.decision_id,e.event_id FROM effect_owners o JOIN confirmed_effect_events e ON e.scope_key=o.scope_key AND e.jail=o.jail AND e.decision_id=o.decision_id WHERE o.rowid>?1 AND o.rowid<=?2 AND o.lease_kind<>0;";
const sql_details_count = "SELECT count(*) FROM confirmed_event_details WHERE rowid>?1 AND rowid<=?2;";
// Legacy details without a joinable retry detail keep a NULL subject and stay age-only.
const sql_details = "UPDATE confirmed_event_details SET family=x.family,subject=x.subject,sequence=x.sequence,confirmed_us=x.confirmed_us,evidence_bytes=x.evidence_bytes FROM (SELECT d.rowid AS rid,r.family AS family,r.subject AS subject,s.sequence AS sequence,e.confirmed_us AS confirmed_us,CASE WHEN d.evidence IS NULL THEN NULL ELSE length(CAST(d.evidence AS BLOB)) END AS evidence_bytes FROM confirmed_event_details d JOIN confirmed_effect_events e ON e.event_id=d.event_id JOIN confirmed_history_sequence s ON s.event_id=d.event_id LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE d.rowid>?1 AND d.rowid<=?2) AS x WHERE confirmed_event_details.rowid=x.rid;";
const sql_summaries = "INSERT INTO retained_subject_summaries(family,subject,detail_count,evidence_bytes,earliest_sequence,earliest_evidence_sequence,evaluated_generation,candidate_sequence) SELECT family,subject,count(*),coalesce(sum(evidence_bytes),0),min(sequence),min(CASE WHEN evidence_bytes IS NOT NULL THEN sequence END),0,NULL FROM confirmed_event_details WHERE rowid>?1 AND rowid<=?2 AND family IS NOT NULL GROUP BY family,subject ON CONFLICT(family,subject) DO UPDATE SET detail_count=detail_count+excluded.detail_count,evidence_bytes=evidence_bytes+excluded.evidence_bytes,earliest_sequence=min(earliest_sequence,excluded.earliest_sequence),earliest_evidence_sequence=CASE WHEN earliest_evidence_sequence IS NULL THEN excluded.earliest_evidence_sequence WHEN excluded.earliest_evidence_sequence IS NULL THEN earliest_evidence_sequence ELSE min(earliest_evidence_sequence,excluded.earliest_evidence_sequence) END;";
const retained_evidence_limit = "16384";
const sql_candidates = "UPDATE retained_subject_summaries SET candidate_sequence=CASE WHEN detail_count>?3 THEN earliest_sequence WHEN evidence_bytes>" ++ retained_evidence_limit ++ " THEN earliest_evidence_sequence END,evaluated_generation=?4 WHERE rowid>?1 AND rowid<=?2;";
// Recomputes each maintained summary from the detail indexes independently of the
// accumulation above; any returned row is a mismatch.
const sql_validate = "SELECT 1 FROM retained_subject_summaries s WHERE s.rowid>?1 AND s.rowid<=?2 AND (s.detail_count IS NOT (SELECT count(*) FROM confirmed_event_details d INDEXED BY confirmed_details_subject WHERE d.family=s.family AND d.subject=s.subject) OR s.evidence_bytes IS NOT (SELECT coalesce(sum(d.evidence_bytes),0) FROM confirmed_event_details d INDEXED BY confirmed_details_subject WHERE d.family=s.family AND d.subject=s.subject) OR s.earliest_sequence IS NOT (SELECT min(d.sequence) FROM confirmed_event_details d INDEXED BY confirmed_details_subject WHERE d.family=s.family AND d.subject=s.subject) OR s.earliest_evidence_sequence IS NOT (SELECT min(d.sequence) FROM confirmed_event_details d INDEXED BY confirmed_details_evidence WHERE d.family=s.family AND d.subject=s.subject AND d.evidence_bytes IS NOT NULL) OR s.candidate_sequence IS NOT (CASE WHEN s.detail_count>?3 THEN s.earliest_sequence WHEN s.evidence_bytes>" ++ retained_evidence_limit ++ " THEN s.earliest_evidence_sequence END) OR s.evaluated_generation<>?4) LIMIT 1;";

const detail_provenance = "typeof(NEW.sequence)='integer' AND NEW.sequence>0 AND typeof(NEW.confirmed_us)='integer' AND ((NEW.family IS NULL AND NEW.subject IS NULL) OR (NEW.family IN(4,6) AND typeof(NEW.subject)='blob' AND length(NEW.subject)=CASE NEW.family WHEN 4 THEN 4 ELSE 16 END)) AND NEW.evidence_bytes IS (CASE WHEN NEW.evidence IS NULL THEN NULL ELSE length(CAST(NEW.evidence AS BLOB)) END)";
const detail_columns_ddl =
    \\ALTER TABLE confirmed_event_details ADD COLUMN family INTEGER;
    \\ALTER TABLE confirmed_event_details ADD COLUMN subject BLOB;
    \\ALTER TABLE confirmed_event_details ADD COLUMN sequence INTEGER;
    \\ALTER TABLE confirmed_event_details ADD COLUMN confirmed_us INTEGER;
    \\ALTER TABLE confirmed_event_details ADD COLUMN evidence_bytes INTEGER;
++ "CREATE TRIGGER confirmed_detail_provenance_insert BEFORE INSERT ON confirmed_event_details WHEN NOT (" ++ detail_provenance ++ ") BEGIN SELECT RAISE(ABORT,'invalid retained detail provenance'); END;" ++
    "CREATE TRIGGER confirmed_detail_provenance_update BEFORE UPDATE OF family,subject,sequence,confirmed_us,evidence_bytes,evidence ON confirmed_event_details WHEN OLD.sequence IS NOT NULL OR NOT (" ++ detail_provenance ++ ") BEGIN SELECT RAISE(ABORT,'retained detail provenance is immutable'); END;";

// Partial indexes over still-NULL columns: each build scans once but inserts nothing, so
// the later backfill pages maintain them incrementally.
const detail_index_ddl = [_][:0]const u8{
    "CREATE UNIQUE INDEX confirmed_details_sequence ON confirmed_event_details(sequence) WHERE sequence IS NOT NULL;",
    "CREATE INDEX confirmed_details_age ON confirmed_event_details(confirmed_us,sequence) WHERE confirmed_us IS NOT NULL;",
    "CREATE INDEX confirmed_details_subject ON confirmed_event_details(family,subject,sequence) WHERE family IS NOT NULL;",
    "CREATE INDEX confirmed_details_evidence ON confirmed_event_details(family,subject,sequence) WHERE family IS NOT NULL AND evidence_bytes IS NOT NULL;",
};

// Runs after the old parent is dropped; the append trigger was dropped with it.
const events_swap_ddl =
    \\ALTER TABLE confirmed_effect_events_v24 RENAME TO confirmed_effect_events;
    \\CREATE TRIGGER confirmed_history_append AFTER INSERT ON confirmed_effect_events BEGIN SELECT CASE WHEN (SELECT count(*) FROM confirmed_history_stream WHERE id=1)!=1 THEN RAISE(ABORT,'missing confirmed history stream') END; UPDATE confirmed_history_stream SET head=head+1,revision=revision+1 WHERE id=1; INSERT INTO confirmed_history_sequence SELECT head,NEW.event_id FROM confirmed_history_stream WHERE id=1; END;
    \\CREATE TRIGGER confirmed_event_provenance_immutable BEFORE UPDATE OF scope_key,jail,decision_id,canonical_scope,confirmed_us ON confirmed_effect_events BEGIN SELECT RAISE(ABORT,'confirmed event provenance immutable'); END;
;

const SchemaObject = struct { kind: []const u8, name: []const u8, table: []const u8 };
fn obj(kind: []const u8, name: []const u8, owner: []const u8) SchemaObject {
    return .{ .kind = kind, .name = name, .table = owner };
}
fn autoindex(comptime owner: []const u8, comptime ordinal: u8) SchemaObject {
    return obj("index", "sqlite_autoindex_" ++ owner ++ "_" ++ [_]u8{'0' + ordinal}, owner);
}
fn table(name: []const u8) SchemaObject {
    return obj("table", name, name);
}

// The complete schema-24 object set. Completion refuses any missing or additional object.
const expected_objects = blk: {
    @setEvalBranchQuota(20_000);
    break :blk [_]SchemaObject{
        obj("index", "action_targets_unsettled", "action_targets"),
        obj("index", "admin_requests_by_revision", "admin_requests"),
        obj("index", "confirmed_details_age", "confirmed_event_details"),
        obj("index", "confirmed_details_evidence", "confirmed_event_details"),
        obj("index", "confirmed_details_sequence", "confirmed_event_details"),
        obj("index", "confirmed_details_subject", "confirmed_event_details"),
        obj("index", "confirmed_effect_events_decision", "confirmed_effect_events"),
        obj("index", "confirmed_effect_events_jail_time", "confirmed_effect_events"),
        obj("index", "confirmed_effect_events_time", "confirmed_effect_events"),
        obj("index", "consumer_requirement_identity", "consumer_requirements"),
        obj("index", "effect_intents_pending", "effect_intents"),
        obj("index", "effect_observations_intent", "effect_observations"),
        obj("index", "effect_owners_decision", "effect_owners"),
        obj("index", "effect_owners_jail", "effect_owners"),
        obj("index", "native_effects_spent", "native_effects"),
        obj("index", "records_source_order", "records"),
        obj("index", "retained_subject_candidates", "retained_subject_summaries"),
        obj("index", "source_repairs_committed", "source_repairs"),
        autoindex("action_intents", 1),
        autoindex("action_targets", 1),
        autoindex("checkpoints", 1),
        autoindex("confirmation_markers", 1),
        autoindex("confirmed_effect_events", 1),
        autoindex("confirmed_effect_events", 2),
        autoindex("confirmed_event_details", 1),
        autoindex("confirmed_history_sequence", 1),
        autoindex("confirmed_policy_summaries", 1),
        autoindex("consumer_checkpoints", 1),
        autoindex("consumer_manifests", 1),
        autoindex("consumer_requirements", 1),
        autoindex("effect_intents", 1),
        autoindex("effect_intents", 2),
        autoindex("effect_observations", 1),
        autoindex("effect_owner_revisions", 1),
        autoindex("effect_owners", 1),
        autoindex("history_reset_watermarks", 1),
        autoindex("native_effects", 1),
        autoindex("pending_receipts", 1),
        autoindex("record_detections", 1),
        autoindex("records", 1),
        autoindex("replay_guards", 1),
        autoindex("replay_guards", 2),
        autoindex("replay_guards", 3),
        autoindex("retained_subject_summaries", 1),
        autoindex("retry_decision_details", 1),
        autoindex("retry_decision_details", 2),
        autoindex("retry_decision_escalations", 1),
        autoindex("retry_decisions", 1),
        autoindex("retry_decisions", 2),
        autoindex("retry_escalation_policies", 1),
        autoindex("retry_policies", 1),
        autoindex("retry_retired", 1),
        autoindex("retry_retired_totals", 1),
        autoindex("retry_states", 1),
        autoindex("shared_checkpoints", 1),
        autoindex("source_cursors", 1),
        autoindex("source_maintenance", 1),
        autoindex("source_repairs", 1),
        table("action_intents"),
        table("action_targets"),
        table("admin_requests"),
        table("admin_revision"),
        table("checkpoints"),
        table("config_generation_jails"),
        table("config_generations"),
        table("confirmation_markers"),
        table("confirmed_effect_events"),
        table("confirmed_event_details"),
        table("confirmed_history_sequence"),
        table("confirmed_history_stream"),
        table("confirmed_policy_summaries"),
        table("consumer_checkpoints"),
        table("consumer_clock"),
        table("consumer_manifests"),
        table("consumer_requirements"),
        table("consumer_revision"),
        table("effect_clock"),
        table("effect_installation"),
        table("effect_intents"),
        table("effect_observations"),
        table("effect_owner_live"),
        table("effect_owner_revisions"),
        table("effect_owners"),
        table("history_reset_watermarks"),
        table("jail_admin_states"),
        table("load_repair_migration"),
        table("maintenance_clock"),
        table("migration_activations"),
        table("migration_deltas"),
        table("migration_runs"),
        table("migration_staged_history"),
        table("migration_staged_owners"),
        table("migration_steps"),
        table("native_effects"),
        table("pending_receipts"),
        table("policy_summary_clock"),
        table("receipt_clock"),
        table("record_detections"),
        table("records"),
        table("replay_guards"),
        table("retained_subject_summaries"),
        table("retention_policy"),
        table("retry_clock"),
        table("retry_decision_details"),
        table("retry_decision_escalations"),
        table("retry_decisions"),
        table("retry_escalation_policies"),
        table("retry_policies"),
        table("retry_retired"),
        table("retry_retired_totals"),
        table("retry_states"),
        table("shared_checkpoints"),
        table("source_cursors"),
        table("source_maintenance"),
        table("source_repairs"),
        obj("trigger", "admin_request_revision_insert", "admin_requests"),
        obj("trigger", "admin_request_revision_update", "admin_requests"),
        obj("trigger", "confirmed_detail_provenance_insert", "confirmed_event_details"),
        obj("trigger", "confirmed_detail_provenance_update", "confirmed_event_details"),
        obj("trigger", "confirmed_event_provenance_immutable", "confirmed_effect_events"),
        obj("trigger", "confirmed_history_append", "confirmed_effect_events"),
        obj("trigger", "effect_owner_insert", "effect_owners"),
        obj("trigger", "effect_owner_live_delete", "effect_owners"),
        obj("trigger", "effect_owner_live_insert", "effect_owners"),
        obj("trigger", "effect_owner_live_update", "effect_owners"),
        obj("trigger", "effect_owner_update", "effect_owners"),
        obj("trigger", "maintenance_source_insert", "source_maintenance"),
        obj("trigger", "maintenance_source_update", "source_maintenance"),
        obj("trigger", "native_effect_scope_v2_insert", "native_effects"),
        obj("trigger", "native_effect_scope_v2_update", "native_effects"),
        obj("trigger", "policy_summary_retired_delete", "retry_retired"),
        obj("trigger", "policy_summary_retired_insert", "retry_retired"),
        obj("trigger", "policy_summary_retired_update", "retry_retired"),
        obj("trigger", "policy_summary_state_delete", "retry_states"),
        obj("trigger", "policy_summary_state_insert", "retry_states"),
        obj("trigger", "policy_summary_state_update", "retry_states"),
        obj("trigger", "records_source_order_insert", "records"),
        obj("trigger", "records_source_order_update", "records"),
        obj("trigger", "zone_provenance_update", "records"),
    };
};

pub fn backupPath(buffer: []u8, state_path: []const u8) Error![:0]u8 {
    return std.fmt.bufPrintZ(buffer, "{s}" ++ backup_suffix, .{state_path}) catch error.StorageLimit;
}

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn loadRepairStatus(self: *Store) Error!Status {
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < source_schema) return .earlier_schema;
            if (schema == source_schema) {
                if (try self.integer("SELECT count(*) FROM sqlite_schema WHERE name='load_repair_migration';") != 0) return error.LoadRepairInvalidState;
                return .ready;
            }
            if (schema != target_schema) return error.UnsupportedSchema;
            const progress = try self.loadRepairProgress();
            return if (progress.phase == .complete) .complete else .incomplete;
        }

        pub fn loadRepairProgress(self: *Store) Error!Progress {
            var row = try self.statement("SELECT phase,cursor,completed_us IS NOT NULL FROM load_repair_migration WHERE id=1;");
            defer row.deinit();
            if (!try row.row()) return error.LoadRepairInvalidState;
            const phase = std.meta.intToEnum(Phase, try row.signed(0)) catch return error.LoadRepairInvalidState;
            const cursor = try row.signed(1);
            if (cursor < 0 or (try row.signed(2) == 1) != (phase == .complete)) return error.LoadRepairInvalidState;
            return .{ .phase = phase, .cursor = cursor };
        }

        // Normal writers do not maintain schema-24 invariants until `latest_schema` is 24,
        // so a migrated file is refused even when its migration completed.
        pub fn requireLoadRepairAdmission(self: *Store) Error!void {
            switch (try self.loadRepairStatus()) {
                .earlier_schema, .ready => {},
                .incomplete => return error.LoadRepairMigrationIncomplete,
                .complete => if (latest_schema < target_schema) return error.LoadRepairWritersPending,
            }
        }

        // Runs every remaining page. Callers hold the state authority lock and call this
        // before startup admission; a failure leaves a resumable, version-fenced state.
        pub fn completeLoadRepairMigration(self: *Store, options: Options) Error!void {
            while (true) {
                switch (try self.loadRepairStatus()) {
                    .earlier_schema, .complete => return,
                    .ready, .incomplete => _ = try self.stepLoadRepairMigration(options),
                }
            }
        }

        // One committed transaction of the migration.
        pub fn stepLoadRepairMigration(self: *Store, options: Options) Error!Step {
            if (options.state_path.len == 0 or options.history_max_matches > 1024) return error.InvalidRecord;
            switch (try self.loadRepairStatus()) {
                .earlier_schema => return error.UnsupportedSchema,
                .complete => return error.LoadRepairInvalidState,
                .ready => return self.startLoadRepair(options),
                .incomplete => {},
            }
            try self.verifyLoadRepairBackup();
            const progress = try self.loadRepairProgress();
            return switch (progress.phase) {
                .live_counter => self.loadRepairPage(options, progress, "INSERT INTO effect_owner_live(id,live) SELECT 1,count(*) FROM effect_owners WHERE lease_kind<>0;" ++
                    // Activation commits a run's whole staged set in one transaction, so every
                    // staged sequence of an activating or complete run has been processed.
                    "INSERT INTO migration_activations SELECT s.run_id,s.seq,r.updated_us FROM migration_staged_owners s JOIN migration_runs r ON r.run_id=s.run_id WHERE r.state IN(6,7);"),
                .detail_columns => self.loadRepairPage(options, progress, detail_columns_ddl),
                .detail_sequence_index, .detail_age_index, .detail_subject_index, .detail_evidence_index => self.loadRepairPage(options, progress, detail_index_ddl[@intFromEnum(progress.phase) - @intFromEnum(Phase.detail_sequence_index)]),
                .targets_swap => self.loadRepairPage(options, progress, "DROP TABLE action_targets; ALTER TABLE action_targets_v24 RENAME TO action_targets;"),
                .observations_swap => self.loadRepairPage(options, progress, "DROP TABLE effect_observations; ALTER TABLE effect_observations_v24 RENAME TO effect_observations;"),
                .spent_index => self.loadRepairPage(options, progress, "CREATE INDEX native_effects_spent ON native_effects(scope_key) WHERE lease_kind=0;"),
                .pending_intent_index => self.loadRepairPage(options, progress, "CREATE INDEX effect_intents_pending ON effect_intents(scope_key) WHERE status IN(1,2);"),
                .events_swap => self.swapLoadRepairEvents(options, progress),
                .verify => self.verifyLoadRepair(options, progress),
                .complete => error.LoadRepairInvalidState,
                else => self.loadRepairWindow(options, progress),
            };
        }

        fn startLoadRepair(self: *Store, options: Options) Error!Step {
            var final_buffer: [std.fs.max_path_bytes]u8 = undefined;
            var partial_buffer: [std.fs.max_path_bytes]u8 = undefined;
            const final_path = try backupPath(&final_buffer, options.state_path);
            const partial_path = std.fmt.bufPrintZ(&partial_buffer, "{s}" ++ partial_suffix, .{options.state_path}) catch return error.StorageLimit;
            // An unrecorded backup may predate writes by another binary; never adopt it.
            if (std.fs.cwd().access(final_path, .{})) |_| {
                std.log.warn("native storage: schema 24 migration refused: backup {s} already exists; keep it if it is the only copy of earlier state, otherwise move it aside and restart", .{final_path});
                return error.LoadRepairBackupExists;
            } else |failure| if (failure != error.FileNotFound) return error.StorageIo;
            const page_size = try self.integer("PRAGMA page_size;");
            const pages = try self.integer("PRAGMA page_count;");
            if (page_size <= 0 or pages <= 0) return error.DatabaseFailure;
            const database_bytes = std.math.mul(u64, @intCast(page_size), @intCast(pages)) catch return error.StorageLimit;
            // Backup copy plus rebuild overlap: the duplicated tables and new indexes are
            // bounded by the existing database size.
            try requireFreeSpace(options.state_path, database_bytes *| 2 +| disk_reserve_bytes);
            const backup = try self.takeLoadRepairBackup(options, final_path, partial_path, pages);
            // Remove the backup only when the fence certainly did not commit.
            errdefer if (!self.reopen_required) std.fs.cwd().deleteFileZ(final_path) catch {};

            try self.beginWrite();
            errdefer self.rollback();
            const budget = self.work_remaining;
            if (try self.integer("PRAGMA user_version;") != source_schema) return error.LoadRepairInvalidState;
            try self.exec(fence_ddl);
            {
                var row = try self.statement("INSERT INTO load_repair_migration VALUES(1,?1,0,?2,NULL,?3,?4,?5,23,'ok',0);");
                defer row.deinit();
                try row.int(1, @intFromEnum(Phase.live_counter));
                try row.int(2, options.now_us);
                try row.text(3, final_path);
                try row.blob(4, &backup.sha256);
                try row.int(5, pages);
                try row.done();
            }
            {
                var row = try self.statement("INSERT INTO retention_policy VALUES(1,1,?1,1,0);");
                defer row.deinit();
                try row.int(1, options.history_max_matches);
                try row.done();
            }
            // The version fence: from this commit on, v0.4.4 and earlier refuse the file.
            try self.exec("PRAGMA user_version=24;");
            return self.commitLoadRepair(options, null, .live_counter, budget);
        }

        const BackupIdentity = struct { sha256: [32]u8 };

        fn takeLoadRepairBackup(self: *Store, options: Options, final_path: [:0]const u8, partial_path: [:0]const u8, pages: i64) Error!BackupIdentity {
            std.fs.cwd().deleteFileZ(partial_path) catch |failure| if (failure != error.FileNotFound) return error.StorageIo;
            const created = std.posix.openZ(partial_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true, .NOFOLLOW = true }, 0o600) catch return error.StorageIo;
            std.posix.close(created);
            errdefer std.fs.cwd().deleteFileZ(partial_path) catch {};
            {
                var handle: ?*anyopaque = null;
                const opened = sqlite3_open_v2(partial_path, &handle, 0x02 | 0x10000 | 0x01000000, null);
                const destination = handle orelse return error.OpenFailed;
                defer _ = sqlite3_close_v2(destination);
                if (opened != 0) return store_mod.sqliteError(opened);
                if (builtin.is_test) if (options.hooks.backup_max_page_count) |maximum| {
                    var sql: [64]u8 = undefined;
                    const pragma = std.fmt.bufPrintZ(&sql, "PRAGMA max_page_count={d};", .{maximum}) catch return error.StorageLimit;
                    if (sqlite3_exec(destination, pragma, null, null, null) != 0) return error.DatabaseFailure;
                };
                const backup = sqlite3_backup_init(destination, "main", @ptrCast(self.db), "main") orelse return store_mod.sqliteError(sqlite3_errcode(destination));
                var rc: c_int = 0;
                while (rc == 0) rc = sqlite3_backup_step(backup, 1024);
                const finished = sqlite3_backup_finish(backup);
                if (rc != 101) return store_mod.sqliteError(rc);
                if (finished != 0) return store_mod.sqliteError(finished);
                // The copied header carries the WAL flag; a rollback-journal backup can be
                // verified read-only without creating sidecar files.
                const journal = sqlite3_exec(destination, "PRAGMA journal_mode=DELETE;", null, null, null);
                if (journal != 0) return store_mod.sqliteError(journal);
            }
            try syncPath(partial_path, false);
            try verifyBackupFile(partial_path, pages);
            std.posix.renameZ(partial_path, final_path) catch return error.StorageIo;
            try syncPath(std.fs.path.dirname(final_path) orelse ".", true);
            return .{ .sha256 = try fileSha256(final_path) };
        }

        fn verifyLoadRepairBackup(self: *Store) Error!void {
            if (self.load_repair_backup_verified) return;
            var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
            var recorded: [32]u8 = undefined;
            {
                var row = try self.statement("SELECT backup_path,backup_sha256 FROM load_repair_migration WHERE id=1;");
                defer row.deinit();
                if (!try row.row()) return error.LoadRepairInvalidState;
                const path = try row.boundedBytes(0, path_buffer.len - 1);
                @memcpy(path_buffer[0..path.len], path);
                path_buffer[path.len] = 0;
                const sha = try row.boundedBytes(1, 32);
                if (sha.len != 32) return error.LoadRepairInvalidState;
                @memcpy(&recorded, sha);
            }
            const path = std.mem.sliceTo(&path_buffer, 0);
            const actual = fileSha256(path) catch return error.LoadRepairBackupInvalid;
            if (!std.mem.eql(u8, &actual, &recorded)) return error.LoadRepairBackupInvalid;
            self.load_repair_backup_verified = true;
        }

        fn loadRepairPage(self: *Store, options: Options, progress: Progress, sql: [:0]const u8) Error!Step {
            try self.beginWrite();
            errdefer self.rollback();
            const budget = self.work_remaining;
            try self.exec(sql);
            const next: Phase = @enumFromInt(@intFromEnum(progress.phase) + 1);
            try self.advanceLoadRepair(progress, next, 0);
            return self.commitLoadRepair(options, progress.phase, next, budget);
        }

        fn window(options: Options, phase: Phase) ?Window {
            const measured: Window = switch (phase) {
                .targets_reclaim, .targets_copy => .{ .rows = 1024, .max_sql = "SELECT coalesce(max(rowid),0) FROM action_targets;" },
                .observations_copy => .{ .rows = 1024, .max_sql = "SELECT coalesce(max(rowid),0) FROM effect_observations;" },
                .intents_reclaim => .{ .rows = 1024, .max_sql = "SELECT coalesce(max(rowid),0) FROM effect_intents;" },
                .revisions_reclaim => .{ .rows = 1024, .max_sql = "SELECT coalesce(max(rowid),0) FROM effect_owner_revisions;" },
                .events_copy => .{ .rows = 1024, .max_sql = "SELECT coalesce(max(rowid),0) FROM confirmed_effect_events;" },
                .markers => .{ .rows = 1024, .max_sql = "SELECT coalesce(max(rowid),0) FROM effect_owners;" },
                .details => .{ .rows = 256, .max_sql = "SELECT coalesce(max(rowid),0) FROM confirmed_event_details;" },
                .candidates => .{ .rows = 1024, .max_sql = "SELECT coalesce(max(rowid),0) FROM retained_subject_summaries;" },
                .validate => .{ .rows = 64, .max_sql = "SELECT coalesce(max(rowid),0) FROM retained_subject_summaries;" },
                else => return null,
            };
            if (builtin.is_test) if (options.hooks.window_rows) |rows| return .{ .rows = rows, .max_sql = measured.max_sql };
            return measured;
        }

        fn loadRepairWindow(self: *Store, options: Options, progress: Progress) Error!Step {
            const shape = window(options, progress.phase) orelse return error.LoadRepairInvalidState;
            try self.beginWrite();
            errdefer self.rollback();
            const budget = self.work_remaining;
            const maximum = try self.integer(shape.max_sql);
            const low = progress.cursor;
            const high = std.math.add(i64, low, shape.rows) catch return error.LoadRepairInvalidState;
            if (low < maximum) switch (progress.phase) {
                .targets_reclaim => try self.windowExec(sql_targets_reclaim, low, high, null),
                .targets_copy => {
                    const superseded = try self.windowCount(sql_targets_orphans, low, high);
                    try self.windowCopy(sql_targets_count, sql_targets_copy, low, high);
                    var total = try self.statement("UPDATE load_repair_migration SET superseded_targets=superseded_targets+?1 WHERE id=1;");
                    defer total.deinit();
                    try total.int(1, superseded);
                    try total.done();
                },
                .observations_copy => {
                    try self.windowExec(sql_observations_copy, low, high, null);
                    try self.windowExec(sql_observations_trim, low, high, .{ observations_per_intent, null });
                },
                .intents_reclaim => try self.windowExec(sql_intents_reclaim, low, high, null),
                .revisions_reclaim => try self.windowExec(sql_revisions_reclaim, low, high, null),
                .events_copy => try self.windowCopy(sql_events_count, sql_events_copy, low, high),
                .markers => try self.windowExec(sql_markers, low, high, null),
                .details => {
                    try self.windowCopy(sql_details_count, sql_details, low, high);
                    try self.windowExec(sql_summaries, low, high, null);
                },
                // The limit fixed by the fence, not the current config: a config edit between
                // resumed pages would otherwise mix limits and fail validation on every start.
                .candidates => try self.windowExec(sql_candidates, low, high, .{ try self.integer("SELECT max_matches FROM retention_policy WHERE id=1;"), 1 }),
                .validate => {
                    const fenced_max_matches = try self.integer("SELECT max_matches FROM retention_policy WHERE id=1;");
                    var row = try self.statement(sql_validate);
                    defer row.deinit();
                    try row.int(1, low);
                    try row.int(2, high);
                    try row.int(3, fenced_max_matches);
                    try row.int(4, 1);
                    if (try row.row()) return error.LoadRepairVerificationFailed;
                },
                else => return error.LoadRepairInvalidState,
            };
            const done = high >= maximum;
            const next: Phase = if (done) @enumFromInt(@intFromEnum(progress.phase) + 1) else progress.phase;
            try self.advanceLoadRepair(progress, next, if (done) 0 else high);
            return self.commitLoadRepair(options, progress.phase, next, budget);
        }

        fn windowExec(self: *Store, sql: [:0]const u8, low: i64, high: i64, extra: ?struct { i64, ?i64 }) Error!void {
            var row = try self.statement(sql);
            defer row.deinit();
            try row.int(1, low);
            try row.int(2, high);
            if (extra) |values| {
                try row.int(3, values[0]);
                if (values[1]) |value| try row.int(4, value);
            }
            try row.done();
        }

        fn windowCount(self: *Store, sql: [:0]const u8, low: i64, high: i64) Error!i64 {
            var count = try self.statement(sql);
            defer count.deinit();
            try count.int(1, low);
            try count.int(2, high);
            if (!try count.row()) return error.DatabaseFailure;
            return count.signed(0);
        }

        // Every source row of the window must be copied; a missing join partner is corruption.
        fn windowCopy(self: *Store, count_sql: [:0]const u8, sql: [:0]const u8, low: i64, high: i64) Error!void {
            const expected = try self.windowCount(count_sql, low, high);
            try self.windowExec(sql, low, high, null);
            if (self.api.changes(self.db) != expected) return error.LoadRepairVerificationFailed;
        }

        // The events table is a foreign-key parent, so its rebuild follows SQLite's
        // documented procedure: enforcement off outside the transaction, a checked swap,
        // then enforcement restored and read back before any later statement.
        fn swapLoadRepairEvents(self: *Store, options: Options, progress: Progress) Error!Step {
            try self.exec("PRAGMA foreign_keys=OFF;");
            if (try self.integer("PRAGMA foreign_keys;") != 0) {
                try self.restoreForeignKeys();
                return error.DatabaseFailure;
            }
            const result = self.swapLoadRepairEventsTx(options, progress);
            const restored = self.restoreForeignKeys();
            const step = result catch |failure| {
                restored catch {};
                return failure;
            };
            try restored;
            return step;
        }

        fn swapLoadRepairEventsTx(self: *Store, options: Options, progress: Progress) Error!Step {
            try self.beginWrite();
            errdefer self.rollback();
            const budget = self.work_remaining;
            if (try self.integer("SELECT count(*) FROM confirmed_effect_events;") != try self.integer("SELECT count(*) FROM confirmed_effect_events_v24;")) return error.LoadRepairVerificationFailed;
            try self.exec("DROP TABLE confirmed_effect_events;");
            try self.fault(.during_load_repair_events_swap);
            try self.exec(events_swap_ddl);
            for ([_][:0]const u8{ "PRAGMA foreign_key_check(confirmed_history_sequence);", "PRAGMA foreign_key_check(confirmed_event_details);" }) |sql| {
                var check = try self.statement(sql);
                defer check.deinit();
                if (try check.row()) return error.LoadRepairVerificationFailed;
            }
            try self.advanceLoadRepair(progress, .markers, 0);
            return self.commitLoadRepair(options, progress.phase, .markers, budget);
        }

        fn restoreForeignKeys(self: *Store) Error!void {
            self.exec("PRAGMA foreign_keys=ON;") catch |failure| {
                self.reopen_required = true;
                return failure;
            };
            if (try self.integer("PRAGMA foreign_keys;") != 1) {
                self.reopen_required = true;
                return error.DatabaseFailure;
            }
        }

        fn verifyLoadRepair(self: *Store, options: Options, progress: Progress) Error!Step {
            try self.beginWrite();
            errdefer self.rollback();
            self.work_remaining = if (builtin.is_test) options.hooks.verify_allowance orelse migration_verify else migration_verify;
            const budget = self.work_remaining;
            for ([_][:0]const u8{
                "SELECT count(*)=0 FROM confirmed_event_details WHERE sequence IS NULL OR confirmed_us IS NULL;",
                "SELECT (SELECT count(*) FROM confirmed_event_details INDEXED BY confirmed_details_subject WHERE family IS NOT NULL)=(SELECT coalesce(sum(detail_count),0) FROM retained_subject_summaries);",
                "SELECT (SELECT live FROM effect_owner_live WHERE id=1) IS (SELECT count(*) FROM effect_owners WHERE lease_kind<>0);",
                "SELECT count(*)=0 FROM confirmation_markers m LEFT JOIN effect_owners o ON o.scope_key=m.scope_key AND o.jail=m.jail WHERE o.decision_id IS NOT m.decision_id OR o.lease_kind=0;",
                "SELECT count(*)=0 FROM effect_owners o WHERE NOT EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision);",
                "SELECT count(*)=0 FROM native_effects n WHERE n.intent_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM effect_intents i WHERE i.intent_id=n.intent_id);",
            }) |sql| if (try self.integer(sql) != 1) return error.LoadRepairVerificationFailed;
            try self.verifyLoadRepairObjects();
            {
                var check = try self.statement("PRAGMA foreign_key_check;");
                defer check.deinit();
                if (try check.row()) return error.LoadRepairVerificationFailed;
            }
            {
                var check = try self.statement("PRAGMA quick_check;");
                defer check.deinit();
                if (!try check.row() or !std.mem.eql(u8, try check.bytes(0), "ok") or try check.row()) return error.LoadRepairVerificationFailed;
            }
            try self.exec("UPDATE retention_policy SET state=2,sweep_cursor=0 WHERE id=1 AND generation=1 AND state=1;");
            if (self.api.changes(self.db) != 1) return error.LoadRepairInvalidState;
            {
                var row = try self.statement("UPDATE load_repair_migration SET phase=99,cursor=0,completed_us=?1 WHERE id=1 AND phase=?2 AND completed_us IS NULL;");
                defer row.deinit();
                try row.int(1, options.now_us);
                try row.int(2, @intFromEnum(progress.phase));
                try row.done();
                if (self.api.changes(self.db) != 1) return error.LoadRepairInvalidState;
            }
            return self.commitLoadRepair(options, progress.phase, .complete, budget);
        }

        fn verifyLoadRepairObjects(self: *Store) Error!void {
            var rows = try self.statement("SELECT type,name,tbl_name FROM sqlite_schema;");
            defer rows.deinit();
            var seen = [_]bool{false} ** expected_objects.len;
            while (try rows.row()) {
                const kind = try rows.bytes(0);
                const name = try rows.bytes(1);
                const owner = try rows.bytes(2);
                const index = for (expected_objects, 0..) |expected, i| {
                    if (std.mem.eql(u8, expected.name, name) and std.mem.eql(u8, expected.kind, kind) and std.mem.eql(u8, expected.table, owner)) break i;
                } else return error.LoadRepairVerificationFailed;
                if (seen[index]) return error.LoadRepairVerificationFailed;
                seen[index] = true;
            }
            for (seen) |present| if (!present) return error.LoadRepairVerificationFailed;
        }

        fn advanceLoadRepair(self: *Store, progress: Progress, next: Phase, cursor: i64) Error!void {
            var row = try self.statement("UPDATE load_repair_migration SET phase=?1,cursor=?2 WHERE id=1 AND phase=?3 AND cursor=?4 AND completed_us IS NULL;");
            defer row.deinit();
            try row.int(1, @intFromEnum(next));
            try row.int(2, cursor);
            try row.int(3, @intFromEnum(progress.phase));
            try row.int(4, progress.cursor);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.LoadRepairInvalidState;
        }

        fn commitLoadRepair(self: *Store, options: Options, phase: ?Phase, next: Phase, budget: u32) Error!Step {
            if (builtin.is_test) if (options.hooks.before_commit) |hook| hook(options.hooks.context, phase);
            try self.commitTransaction();
            return .{ .phase = phase, .next = next, .callbacks = if (self.runtime_limits) budget - self.work_remaining else 0 };
        }
    };
}

fn requireFreeSpace(state_path: []const u8, required: u64) Error!void {
    var directory = std.fs.cwd().openDir(std.fs.path.dirname(state_path) orelse ".", .{}) catch return error.StorageIo;
    defer directory.close();
    var info: Statvfs = undefined;
    if (fstatvfs(directory.fd, &info) != 0) return error.StorageIo;
    const available = std.math.mul(u64, info.bavail, @as(u64, info.frsize)) catch std.math.maxInt(u64);
    if (available < required) return error.LoadRepairDiskSpace;
}

fn syncPath(path: []const u8, directory: bool) Error!void {
    const fd = std.posix.open(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = directory, .CLOEXEC = true, .NOFOLLOW = !directory }, 0) catch return error.StorageIo;
    defer std.posix.close(fd);
    std.posix.fsync(fd) catch return error.StorageIo;
}

fn fileSha256(path: []const u8) Error![32]u8 {
    var file = std.fs.cwd().openFile(path, .{}) catch return error.StorageIo;
    defer file.close();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const count = file.read(&buffer) catch return error.StorageIo;
        if (count == 0) break;
        hash.update(buffer[0..count]);
    }
    return hash.finalResult();
}

fn backupInteger(db: *anyopaque, sql: [:0]const u8) Error!i64 {
    var statement: ?*anyopaque = null;
    if (sqlite3_prepare_v2(db, sql, -1, &statement, null) != 0) return error.LoadRepairBackupInvalid;
    const prepared = statement orelse return error.LoadRepairBackupInvalid;
    defer _ = sqlite3_finalize(prepared);
    if (sqlite3_step(prepared) != 100) return error.LoadRepairBackupInvalid;
    return sqlite3_column_int64(prepared, 0);
}

fn verifyBackupFile(path: [:0]const u8, pages: i64) Error!void {
    var handle: ?*anyopaque = null;
    const opened = sqlite3_open_v2(path, &handle, 0x01 | 0x10000 | 0x01000000, null);
    const db = handle orelse return error.LoadRepairBackupInvalid;
    defer _ = sqlite3_close_v2(db);
    if (opened != 0) return error.LoadRepairBackupInvalid;
    if (try backupInteger(db, "PRAGMA user_version;") != source_schema) return error.LoadRepairBackupInvalid;
    if (try backupInteger(db, "PRAGMA page_count;") != pages) return error.LoadRepairBackupInvalid;
    var statement: ?*anyopaque = null;
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check;", -1, &statement, null) != 0) return error.LoadRepairBackupInvalid;
    const prepared = statement orelse return error.LoadRepairBackupInvalid;
    defer _ = sqlite3_finalize(prepared);
    if (sqlite3_step(prepared) != 100) return error.LoadRepairBackupInvalid;
    const text = sqlite3_column_text(prepared, 0) orelse return error.LoadRepairBackupInvalid;
    if (!std.mem.eql(u8, std.mem.span(text), "ok") or sqlite3_step(prepared) != 101) return error.LoadRepairBackupInvalid;
}
