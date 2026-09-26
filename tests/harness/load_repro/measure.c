// Measures SQLite VM steps of fail2zig per-tick queries against a real state file, and
// populates synthetic confirmed history to test retention-query bounds at scale.
// Build: gcc -O1 -DSQLITE_OMIT_LOAD_EXTENSION=1 -I vendor/sqlite -o .zig-cache/load-repro/measure tests/harness/load_repro/measure.c vendor/sqlite/sqlite3.c -lpthread -lm
// Modes:
//   measure <state.sqlite> [now_us|-] [setup-sql|@file]   per-tick queries (read-only unless setup given)
//   synth <copy.sqlite> S D M E J                          add S subjects x D decisions, last M with details,
//                                                          evidence E bytes (0 = NULL), spread over J jails
//   retention <copy.sqlite> max_matches [window_start] [page]  retention candidate variants V0..V4 with plans
//   exec-measure <copy.sqlite> "SQL"                       run one statement read-write under the step counter
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "sqlite3.h"

static long long callbacks;
static int progress(void *ctx) { (void)ctx; callbacks++; return 0; }
static double now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e3 + t.tv_nsec / 1e6; }

typedef struct { const char *name; const char *sql; int nparam; sqlite3_int64 p[5]; const char *text1; int null1; } Q;

static void explain(sqlite3 *db, const char *sql) {
  char *eq = sqlite3_mprintf("EXPLAIN QUERY PLAN %s", sql);
  sqlite3_stmt *st;
  if (sqlite3_prepare_v2(db, eq, -1, &st, NULL) != SQLITE_OK) { printf("    plan: prepare failed: %s\n", sqlite3_errmsg(db)); sqlite3_free(eq); return; }
  while (sqlite3_step(st) == SQLITE_ROW) printf("    plan: %s\n", sqlite3_column_text(st, 3));
  sqlite3_finalize(st); sqlite3_free(eq);
}

static void run(sqlite3 *db, Q *q, int show_plan) {
  sqlite3_stmt *st;
  if (sqlite3_prepare_v2(db, q->sql, -1, &st, NULL) != SQLITE_OK) { printf("%s: prepare failed: %s\n", q->name, sqlite3_errmsg(db)); return; }
  if (q->text1) sqlite3_bind_text(st, 1, q->text1, -1, SQLITE_STATIC);
  else if (q->null1) sqlite3_bind_null(st, 1);
  else if (q->nparam >= 1) sqlite3_bind_int64(st, 1, q->p[0]);
  for (int i = 2; i <= q->nparam && i <= 5; i++) sqlite3_bind_int64(st, i, q->p[i - 1]);
  callbacks = 0;
  double t0 = now_ms();
  int rows = 0, rc;
  while ((rc = sqlite3_step(st)) == SQLITE_ROW) rows++;
  double t1 = now_ms();
  long long steps = sqlite3_stmt_status(st, SQLITE_STMTSTATUS_VM_STEP, 0);
  long long fullscan = sqlite3_stmt_status(st, SQLITE_STMTSTATUS_FULLSCAN_STEP, 0);
  long long autoidx = sqlite3_stmt_status(st, SQLITE_STMTSTATUS_AUTOINDEX, 0);
  printf("%-30s rc=%d rows=%d vm_steps=%lld callbacks(1000)=%lld fullscan_steps=%lld autoindex=%lld wall=%.2fms %s\n",
         q->name, rc == SQLITE_DONE ? 0 : rc, rows, steps, callbacks, fullscan, autoidx, t1 - t0,
         steps > 1000000 ? "  <== EXCEEDS 1,000,000-step transaction budget" : "");
  if (show_plan) explain(db, q->sql);
  sqlite3_finalize(st);
}

static void count(sqlite3 *db, const char *table) {
  char *sql = sqlite3_mprintf("SELECT count(*) FROM %s", table);
  sqlite3_stmt *st; if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) printf("  %-30s %lld\n", table, sqlite3_column_int64(st, 0));
  sqlite3_finalize(st); sqlite3_free(sql);
}

static char *read_file(const char *path) {
  FILE *f = fopen(path, "rb"); if (!f) return NULL;
  fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
  char *buf = malloc(n + 1); if (fread(buf, 1, n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }
  buf[n] = 0; fclose(f); return buf;
}

// ---- retention candidate variants ----
#define OUTER_HEAD "SELECT d.event_id FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN confirmed_history_sequence s USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE s.sequence<=?1 "
#define OUTER_TAIL " ORDER BY s.sequence LIMIT 1;"
// V0/V1: shipped v0.4.4 text (V1 differs only by the A1 index existing in the file)
static const char *V0 = OUTER_HEAD "AND (e.confirmed_us<=?2 OR (r.effect_decision_id IS NOT NULL AND ((SELECT count(*) FROM confirmed_event_details d2 JOIN confirmed_effect_events e2 USING(event_id) JOIN retry_decision_details r2 ON r2.jail=e2.jail AND r2.effect_decision_id=e2.decision_id WHERE r2.family=r.family AND r2.subject=r.subject)>?3 OR (d.evidence IS NOT NULL AND (SELECT coalesce(sum(length(CAST(d3.evidence AS BLOB))),0) FROM confirmed_event_details d3 JOIN confirmed_effect_events e3 USING(event_id) JOIN retry_decision_details r3 ON r3.jail=e3.jail AND r3.effect_decision_id=e3.decision_id WHERE r3.family=r.family AND r3.subject=r.subject)>16384))))" OUTER_TAIL;
// V2: inner aggregates keyed by the event's scope_key (host scope of the same subject), count bounded by LIMIT ?3+1, evidence running sum stops at the cap
static const char *V2 = OUTER_HEAD "AND (e.confirmed_us<=?2 OR (r.effect_decision_id IS NOT NULL AND ((SELECT count(*) FROM (SELECT 1 FROM confirmed_effect_events e2 JOIN confirmed_event_details d2 USING(event_id) WHERE e2.scope_key=e.scope_key LIMIT ?3+1))>?3 OR (d.evidence IS NOT NULL AND EXISTS(SELECT 1 FROM (SELECT sum(length(CAST(d3.evidence AS BLOB))) OVER (ORDER BY e3.confirmed_us,e3.event_id ROWS UNBOUNDED PRECEDING) AS running FROM confirmed_effect_events e3 JOIN confirmed_event_details d3 USING(event_id) WHERE e3.scope_key=e.scope_key) WHERE running>16384 LIMIT 1)))))" OUTER_TAIL;
// V3: V2 plus a bounded outer window [?4, ?4+page)
static const char *V3 = "SELECT d.event_id FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN confirmed_history_sequence s USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE s.sequence<=?1 AND s.sequence>=?4 AND s.sequence<?4+?5 AND (e.confirmed_us<=?2 OR (r.effect_decision_id IS NOT NULL AND ((SELECT count(*) FROM (SELECT 1 FROM confirmed_effect_events e2 JOIN confirmed_event_details d2 USING(event_id) WHERE e2.scope_key=e.scope_key LIMIT ?3+1))>?3 OR (d.evidence IS NOT NULL AND EXISTS(SELECT 1 FROM (SELECT sum(length(CAST(d3.evidence AS BLOB))) OVER (ORDER BY e3.confirmed_us,e3.event_id ROWS UNBOUNDED PRECEDING) AS running FROM confirmed_effect_events e3 JOIN confirmed_event_details d3 USING(event_id) WHERE e3.scope_key=e.scope_key) WHERE running>16384 LIMIT 1))))) ORDER BY s.sequence LIMIT 1;";

// V4: shipped inner text, window drives the join (CROSS JOIN fixes the outer loop order in SQLite)
static const char *V4 = "SELECT d.event_id FROM confirmed_history_sequence s CROSS JOIN confirmed_effect_events e ON e.event_id=s.event_id CROSS JOIN confirmed_event_details d ON d.event_id=s.event_id LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE s.sequence<=?1 AND s.sequence>=?4 AND s.sequence<?4+?5 AND (e.confirmed_us<=?2 OR (r.effect_decision_id IS NOT NULL AND ((SELECT count(*) FROM confirmed_event_details d2 JOIN confirmed_effect_events e2 USING(event_id) JOIN retry_decision_details r2 ON r2.jail=e2.jail AND r2.effect_decision_id=e2.decision_id WHERE r2.family=r.family AND r2.subject=r.subject)>?3 OR (d.evidence IS NOT NULL AND (SELECT coalesce(sum(length(CAST(d3.evidence AS BLOB))),0) FROM confirmed_event_details d3 JOIN confirmed_effect_events e3 USING(event_id) JOIN retry_decision_details r3 ON r3.jail=e3.jail AND r3.effect_decision_id=e3.decision_id WHERE r3.family=r.family AND r3.subject=r.subject)>16384)))) ORDER BY s.sequence LIMIT 1;";
// V5: V4 with an explicit inclusive window end parameter (?5 = last sequence of the window), no redundant upper bound
static const char *V5 = "SELECT d.event_id FROM confirmed_history_sequence s CROSS JOIN confirmed_effect_events e ON e.event_id=s.event_id CROSS JOIN confirmed_event_details d ON d.event_id=s.event_id LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE s.sequence BETWEEN ?4 AND ?5 AND (e.confirmed_us<=?2 OR (r.effect_decision_id IS NOT NULL AND ((SELECT count(*) FROM confirmed_event_details d2 JOIN confirmed_effect_events e2 USING(event_id) JOIN retry_decision_details r2 ON r2.jail=e2.jail AND r2.effect_decision_id=e2.decision_id WHERE r2.family=r.family AND r2.subject=r.subject)>?3 OR (d.evidence IS NOT NULL AND (SELECT coalesce(sum(length(CAST(d3.evidence AS BLOB))),0) FROM confirmed_event_details d3 JOIN confirmed_effect_events e3 USING(event_id) JOIN retry_decision_details r3 ON r3.jail=e3.jail AND r3.effect_decision_id=e3.decision_id WHERE r3.family=r.family AND r3.subject=r.subject)>16384)))) ORDER BY s.sequence LIMIT 1;";
static int retention(sqlite3 *db, sqlite3_int64 max_matches, sqlite3_int64 page_start, sqlite3_int64 page) {
  sqlite3_int64 now_us = (sqlite3_int64)time(NULL) * 1000000LL;
  sqlite3_int64 cutoff = now_us - 86400LL * 1000000LL;
  count(db, "confirmed_effect_events"); count(db, "confirmed_event_details"); count(db, "retry_decision_details");
  printf("max_matches=%lld window_start=%lld page=%lld\n", (long long)max_matches, (long long)page_start, (long long)page);
  Q v0 = { "V0/V1 shipped text", V0, 3, { (sqlite3_int64)1 << 62, cutoff, max_matches, 0 }, NULL, 0 };
  Q v2 = { "V2 scope_key bounded inner", V2, 3, { (sqlite3_int64)1 << 62, cutoff, max_matches, 0 }, NULL, 0 };
  Q v3 = { "V3 V2 + window", V3, 5, { (sqlite3_int64)1 << 62, cutoff, max_matches, page_start, page }, NULL, 0 };
  Q v4 = { "V4 shipped inner + CROSS window", V4, 5, { (sqlite3_int64)1 << 62, cutoff, max_matches, page_start, page }, NULL, 0 };
  Q v5 = { "V5 CROSS + BETWEEN window", V5, 5, { (sqlite3_int64)1 << 62, cutoff, max_matches, page_start, page_start + page - 1 }, NULL, 0 };
  if (getenv("SKIP_UNBOUNDED") == NULL) { run(db, &v0, 0); run(db, &v2, 0); }
  run(db, &v3, 1); run(db, &v4, 1); run(db, &v5, 1);
  return 0;
}

static void fill32(unsigned char *out, unsigned char tag, uint32_t a, uint32_t b) {
  memset(out, 0, 32); out[0] = tag; memcpy(out + 1, &a, 4); memcpy(out + 5, &b, 4);
}

static int synth(sqlite3 *db, long S, long D, long M, long E, long J) {
  char *err = NULL;
  if (sqlite3_exec(db, "PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE;", NULL, NULL, &err) != SQLITE_OK) { fprintf(stderr, "begin: %s\n", err); return 1; }
  sqlite3_stmt *ins_r, *ins_e, *ins_d;
  const char *sql_r = "INSERT INTO retry_decision_details(jail,source,occurrence,family,subject,ordinal,decided_us,effect_decision_id,evidence) VALUES(?1,'synth',?2,4,?3,?4,?5,?6,?7);";
  const char *sql_e = "INSERT INTO confirmed_effect_events(event_id,scope_key,jail,decision_id,confirmed_us) VALUES(?1,?2,?3,?4,?5);";
  const char *sql_d = "INSERT INTO confirmed_event_details(event_id,source,occurrence,decided_us,ordinal,evidence) VALUES(?1,'synth',?2,?3,?4,?5);";
  if (sqlite3_prepare_v2(db, sql_r, -1, &ins_r, NULL) || sqlite3_prepare_v2(db, sql_e, -1, &ins_e, NULL) || sqlite3_prepare_v2(db, sql_d, -1, &ins_d, NULL)) { fprintf(stderr, "prepare: %s\n", sqlite3_errmsg(db)); return 1; }
  char *evidence = NULL;
  if (E > 0) { evidence = malloc(E + 1); memset(evidence, 'x', E); evidence[E] = 0; }
  sqlite3_int64 now_us = (sqlite3_int64)time(NULL) * 1000000LL;
  unsigned char dec[32], ev[32], sk[32], subj[4];
  char jail[32], occ[64];
  long rows = 0;
  for (long s = 0; s < S; s++) {
    uint32_t sid = 0x10000000u + (uint32_t)s;
    memcpy(subj, &sid, 4);
    fill32(sk, 0x5C, sid, 0);
    snprintf(jail, sizeof jail, "synth%ld", s % (J > 0 ? J : 1));
    for (long i = 0; i < D; i++) {
      fill32(dec, 0xD1, sid, (uint32_t)i); fill32(ev, 0xE1, sid, (uint32_t)i);
      snprintf(occ, sizeof occ, "s%ld-d%ld", s, i);
      sqlite3_int64 t = now_us - (D - i) * 1000;
      sqlite3_reset(ins_r); sqlite3_bind_text(ins_r, 1, jail, -1, SQLITE_STATIC); sqlite3_bind_text(ins_r, 2, occ, -1, SQLITE_STATIC);
      sqlite3_bind_blob(ins_r, 3, subj, 4, SQLITE_STATIC); sqlite3_bind_int64(ins_r, 4, i + 1); sqlite3_bind_int64(ins_r, 5, t);
      sqlite3_bind_blob(ins_r, 6, dec, 32, SQLITE_STATIC);
      if (evidence) sqlite3_bind_text(ins_r, 7, evidence, -1, SQLITE_STATIC); else sqlite3_bind_null(ins_r, 7);
      if (sqlite3_step(ins_r) != SQLITE_DONE) { fprintf(stderr, "r: %s\n", sqlite3_errmsg(db)); return 1; }
      sqlite3_reset(ins_e); sqlite3_bind_blob(ins_e, 1, ev, 32, SQLITE_STATIC); sqlite3_bind_blob(ins_e, 2, sk, 32, SQLITE_STATIC);
      sqlite3_bind_text(ins_e, 3, jail, -1, SQLITE_STATIC); sqlite3_bind_blob(ins_e, 4, dec, 32, SQLITE_STATIC); sqlite3_bind_int64(ins_e, 5, t);
      if (sqlite3_step(ins_e) != SQLITE_DONE) { fprintf(stderr, "e: %s\n", sqlite3_errmsg(db)); return 1; }
      if (i >= D - M) {
        sqlite3_reset(ins_d); sqlite3_bind_blob(ins_d, 1, ev, 32, SQLITE_STATIC); sqlite3_bind_text(ins_d, 2, occ, -1, SQLITE_STATIC);
        sqlite3_bind_int64(ins_d, 3, t); sqlite3_bind_int64(ins_d, 4, i + 1);
        if (evidence) sqlite3_bind_text(ins_d, 5, evidence, -1, SQLITE_STATIC); else sqlite3_bind_null(ins_d, 5);
        if (sqlite3_step(ins_d) != SQLITE_DONE) { fprintf(stderr, "d: %s\n", sqlite3_errmsg(db)); return 1; }
      }
      rows++;
    }
  }
  sqlite3_finalize(ins_r); sqlite3_finalize(ins_e); sqlite3_finalize(ins_d);
  if (sqlite3_exec(db, "COMMIT;", NULL, NULL, &err) != SQLITE_OK) { fprintf(stderr, "commit: %s\n", err); return 1; }
  printf("synth: %ld subjects x %ld decisions (%ld with details, evidence %ld bytes, %ld jails) = %ld decisions\n", S, D, M, E, J, rows);
  free(evidence);
  return 0;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "synth") == 0) {
    if (argc < 8) { fprintf(stderr, "usage: measure synth <copy.sqlite> S D M E J\n"); return 2; }
    sqlite3 *db; if (sqlite3_open_v2(argv[2], &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) { fprintf(stderr, "open: %s\n", sqlite3_errmsg(db)); return 1; }
    int rc = synth(db, atol(argv[3]), atol(argv[4]), atol(argv[5]), atol(argv[6]), atol(argv[7]));
    sqlite3_close(db); return rc;
  }
  if (argc >= 2 && strcmp(argv[1], "exec-measure") == 0) {
    if (argc < 4) { fprintf(stderr, "usage: measure exec-measure <copy.sqlite> \"SQL\"\n"); return 2; }
    sqlite3 *db; if (sqlite3_open_v2(argv[2], &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) { fprintf(stderr, "open: %s\n", sqlite3_errmsg(db)); return 1; }
    sqlite3_progress_handler(db, 1000, progress, NULL);
    Q q = { "exec-measure", argv[3], 0, {0}, NULL, 0 };
    run(db, &q, 0);
    sqlite3_close(db); return 0;
  }
  if (argc >= 2 && strcmp(argv[1], "retention") == 0) {
    if (argc < 4) { fprintf(stderr, "usage: measure retention <copy.sqlite> max_matches [window_start]\n"); return 2; }
    sqlite3 *db; if (sqlite3_open_v2(argv[2], &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) { fprintf(stderr, "open: %s\n", sqlite3_errmsg(db)); return 1; }
    sqlite3_progress_handler(db, 1000, progress, NULL);
    printf("sqlite %s\n", sqlite3_libversion());
    int rc = retention(db, atoll(argv[3]), argc > 4 ? atoll(argv[4]) : 1, argc > 5 ? atoll(argv[5]) : 256);
    sqlite3_close(db); return rc;
  }
  if (argc < 2) { fprintf(stderr, "usage: measure <state.sqlite> [now_us|-] [setup-sql|@file]\n"); return 2; }
  sqlite3 *db;
  const char *setup = argc > 3 ? argv[3] : NULL;
  char *setup_text = NULL;
  if (setup && setup[0] == '@') { setup_text = read_file(setup + 1); if (!setup_text) { fprintf(stderr, "cannot read %s\n", setup + 1); return 1; } setup = setup_text; }
  if (sqlite3_open_v2(argv[1], &db, setup ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) { fprintf(stderr, "open: %s\n", sqlite3_errmsg(db)); return 1; }
  if (setup) { char *err = NULL; if (sqlite3_exec(db, setup, NULL, NULL, &err) != SQLITE_OK) { fprintf(stderr, "setup: %s\n", err); return 1; } printf("setup applied (%zu bytes)\n", strlen(setup)); }
  sqlite3_progress_handler(db, 1000, progress, NULL);
  sqlite3_int64 now_us = (argc > 2 && strcmp(argv[2], "-") != 0) ? atoll(argv[2]) : (sqlite3_int64)time(NULL) * 1000000LL;
  sqlite3_int64 cutoff = now_us - 86400LL * 1000000LL;
  printf("sqlite %s  now_us=%lld\n", sqlite3_libversion(), (long long)now_us);
  const char *tables[] = { "records", "record_detections", "retry_states", "retry_decisions", "retry_decision_details", "retry_decision_escalations",
    "native_effects", "effect_owners", "effect_owner_revisions", "effect_intents", "effect_observations", "confirmed_effect_events",
    "confirmed_event_details", "confirmed_history_sequence", "confirmed_policy_summaries", "action_targets", "replay_guards", NULL };
  for (int i = 0; tables[i]; i++) count(db, tables[i]);
  Q qs[] = {
    { "history_detail_candidate", V0, 3, { (sqlite3_int64)1 << 62, 0, 10, 0 }, NULL, 0 },
    { "history_retained_candidate", "SELECT s.sequence,e.event_id,e.scope_key,e.jail,e.decision_id,e.confirmed_us FROM confirmed_history_sequence s JOIN confirmed_effect_events e USING(event_id) WHERE s.sequence=(SELECT retained_from FROM confirmed_history_stream WHERE id=1);", 0, {0}, NULL, 0 },
    { "prune_spent_effect_candidate", "SELECT n.scope_key,n.intent_id FROM native_effects n JOIN effect_intents i ON i.intent_id=n.intent_id WHERE n.lease_kind=0 AND i.status=4 AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=n.scope_key AND o.lease_kind<>0) AND NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.scope_key=n.scope_key) AND NOT EXISTS(SELECT 1 FROM action_targets a WHERE a.scope_key=n.scope_key AND a.status IN(1,2,5)) AND NOT EXISTS(SELECT 1 FROM effect_intents p WHERE p.scope_key=n.scope_key AND p.status IN(1,2)) ORDER BY n.scope_key LIMIT 1;", 0, {0}, NULL, 0 },
    { "prune_retry_details", "SELECT d.rowid,length(CAST(d.jail AS BLOB))+length(CAST(d.source AS BLOB))+length(CAST(d.occurrence AS BLOB))+length(d.subject)+coalesce(length(d.effect_decision_id),0)+coalesce(length(CAST(d.evidence AS BLOB)),0)+24 FROM retry_decision_details d WHERE d.effect_decision_id IS NULL OR (NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.jail=d.jail AND o.decision_id=d.effect_decision_id) AND NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.jail=d.jail AND e.decision_id=d.effect_decision_id) AND NOT EXISTS(SELECT 1 FROM action_targets a WHERE a.action_id=d.effect_decision_id AND a.status IN(1,2,5))) ORDER BY d.rowid LIMIT 32;", 0, {0}, NULL, 0 },
    { "operator_owners", "SELECT o.scope_key,n.canonical_scope,o.jail,o.decision_id,o.lease_kind,o.deadline_us,o.decided_us,d.ordinal,EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.generation=o.generation AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind AND h.deadline_us IS o.deadline_us AND h.decided_us=o.decided_us) FROM effect_owners o JOIN native_effects n USING(scope_key) LEFT JOIN retry_decision_details d ON d.jail=o.jail AND d.effect_decision_id=o.decision_id WHERE o.lease_kind=2 OR (o.lease_kind=1 AND o.deadline_us>?1) ORDER BY o.jail,o.scope_key LIMIT ?2;", 2, { 0, 16385, 0, 0 }, NULL, 0 },
    { "retry_summary_portsentry", "SELECT last_processed_us,lease_kind,deadline_us,decisions,attempts,family,subject FROM retry_states WHERE jail=?1 ORDER BY family,subject;", 1, {0}, "portsentry", 0 },
    { "unsettled_action_scope", "SELECT a.scope_key FROM action_targets a JOIN effect_owners o ON o.scope_key=a.scope_key AND o.decision_id=a.action_id WHERE a.status IN(1,2,5) LIMIT 1;", 0, {0}, NULL, 0 },
    { "effect_page_first", "SELECT e.scope_key,e.canonical_scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id WHERE (?1 IS NULL OR e.scope_key>?1) ORDER BY e.scope_key LIMIT ?2;", 2, { 0, 65, 0, 0 }, NULL, 1 },
  };
  qs[0].p[1] = cutoff; qs[4].p[0] = now_us;
  for (size_t i = 0; i < sizeof(qs) / sizeof(qs[0]); i++) run(db, &qs[i], 1);
  sqlite3_close(db);
  free(setup_text);
  return 0;
}
