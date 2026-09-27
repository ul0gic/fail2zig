// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Offline retention oracle and non-resetting measurement wrapper for fail2zig state copies.
// Build: gcc -O1 -DSQLITE_OMIT_LOAD_EXTENSION=1 -I vendor/sqlite -o ORACLE tests/harness/load_repro/oracle.c vendor/sqlite/sqlite3.c -lpthread -lm
// Modes:
//   vector <db> (cutoff=US | now=US age=US) [fence=db|N] [max_matches=N] [limit=N]
//   steps <step>...     step = db=PATH,(cutoff=US|now=US,age=US)[,fence=db|N][,max_matches=N][,count=N]
//   measure <db> <script>   one line per statement; optional "@rows=N" / "@changes=N" prefixes;
//                           a line "@budget=N" sets the transaction's callback allowance (default 1000)
// Every mode reads the database read-only and works on an in-memory copy made with the backup API.
// vector/steps run offline without a work guard: they establish the order the shipped query
// would produce, not whether production could afford it. Negative controls:
//   F2Z_ORACLE_NC1=1  measure with a zero-callback budget (expects SQLITE_INTERRUPT, exit 1)
//   F2Z_ORACLE_NC2=1  measure makes the final write fail after an earlier change (exit 1)
//   F2Z_ORACLE_NC3=1  off-by-one count limit in the C evaluator (expects disagreement, exit 3)
// Exit: 0 agreement/success, 1 SQLite or state failure, 2 usage, 3 evaluator disagreement.
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

// Copied verbatim from engine/store/maintenance.zig:1140 (cleanupConfirmedHistoryOne detail branch).
static const char shipped_detail_sql[] =
    "SELECT d.event_id FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN confirmed_history_sequence s USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE s.sequence<=?1 AND (e.confirmed_us<=?2 OR (r.effect_decision_id IS NOT NULL AND ((SELECT count(*) FROM confirmed_event_details d2 JOIN confirmed_effect_events e2 USING(event_id) JOIN retry_decision_details r2 ON r2.jail=e2.jail AND r2.effect_decision_id=e2.decision_id WHERE r2.family=r.family AND r2.subject=r.subject)>?3 OR (d.evidence IS NOT NULL AND (SELECT coalesce(sum(length(CAST(d3.evidence AS BLOB))),0) FROM confirmed_event_details d3 JOIN confirmed_effect_events e3 USING(event_id) JOIN retry_decision_details r3 ON r3.jail=e3.jail AND r3.effect_decision_id=e3.decision_id WHERE r3.family=r.family AND r3.subject=r.subject)>16384)))) ORDER BY s.sequence LIMIT 1;";
// engine/store/maintenance.zig:1148; the shipped code requires exactly one changed row.
static const char shipped_delete_sql[] = "DELETE FROM confirmed_event_details WHERE event_id=?1;";

#define SUBJECT_EVIDENCE_LIMIT 16384
#define MAX_MATCHES_LIMIT 1024
#define MAX_ROWS 1048576
#define MAX_CARRIED 1048576
#define PROGRESS_OPS 1000
#define PROGRESS_BUDGET 1000

static int env_flag(const char *name) {
  const char *value = getenv(name);
  return value != NULL && strcmp(value, "1") == 0;
}

static int parse_i64(const char *text, int64_t *out) {
  char *end = NULL;
  errno = 0;
  long long value = strtoll(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0') return 0;
  *out = (int64_t)value;
  return 1;
}

static void print_hex(const unsigned char *bytes, int length) {
  for (int i = 0; i < length; i++) printf("%02x", bytes[i]);
}

static sqlite3 *load_copy(const char *path) {
  sqlite3 *source = NULL;
  sqlite3 *copy = NULL;
  if (sqlite3_open_v2(path, &source, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
    fprintf(stderr, "oracle: open %s: %s\n", path, source ? sqlite3_errmsg(source) : "out of memory");
    sqlite3_close(source);
    return NULL;
  }
  if (sqlite3_open(":memory:", &copy) != SQLITE_OK) {
    fprintf(stderr, "oracle: open memory copy failed\n");
    sqlite3_close(copy);
    sqlite3_close(source);
    return NULL;
  }
  sqlite3_backup *backup = sqlite3_backup_init(copy, "main", source, "main");
  int rc = backup ? sqlite3_backup_step(backup, -1) : SQLITE_ERROR;
  int finish = backup ? sqlite3_backup_finish(backup) : SQLITE_ERROR;
  if (rc != SQLITE_DONE || finish != SQLITE_OK) {
    fprintf(stderr, "oracle: backup of %s failed: %s\n", path, sqlite3_errmsg(copy));
    sqlite3_close(copy);
    sqlite3_close(source);
    return NULL;
  }
  sqlite3_close(source);
  if (sqlite3_exec(copy, "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;", NULL, NULL, NULL) != SQLITE_OK) {
    fprintf(stderr, "oracle: connection setup failed: %s\n", sqlite3_errmsg(copy));
    sqlite3_close(copy);
    return NULL;
  }
  return copy;
}

static int single_int(sqlite3 *db, const char *sql, int64_t *out) {
  sqlite3_stmt *stmt = NULL;
  int ok = 0;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW &&
      sqlite3_column_type(stmt, 0) == SQLITE_INTEGER) {
    *out = sqlite3_column_int64(stmt, 0);
    ok = sqlite3_step(stmt) == SQLITE_DONE;
  }
  if (!ok) fprintf(stderr, "oracle: %s: %s\n", sql, sqlite3_errmsg(db));
  sqlite3_finalize(stmt);
  return ok;
}

// The shipped transaction's fence: the history consumer's last consumed sequence.
// Returns 1 with *present=0 when no checkpoint exists (the shipped code then deletes nothing).
static int history_fence(sqlite3 *db, int64_t *fence, int *present) {
  int64_t schema = 0;
  if (!single_int(db, "PRAGMA user_version;", &schema)) return 0;
  if (schema < 18 || schema > 23) {
    fprintf(stderr, "oracle: unsupported schema %" PRId64 "\n", schema);
    return 0;
  }
  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2(db, "SELECT payload FROM consumer_checkpoints WHERE kind=5 AND jail='@history' AND source='confirmed-effects' AND rule='checkpoint';", -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "oracle: checkpoint query: %s\n", sqlite3_errmsg(db));
    return 0;
  }
  int rc = sqlite3_step(stmt);
  if (rc == SQLITE_DONE) {
    *present = 0;
    sqlite3_finalize(stmt);
    return 1;
  }
  const unsigned char *payload = sqlite3_column_blob(stmt, 0);
  int length = sqlite3_column_bytes(stmt, 0);
  if (rc != SQLITE_ROW || payload == NULL || length != 112 || memcmp(payload, "F2ZHIST1", 8) != 0) {
    fprintf(stderr, "oracle: invalid history checkpoint\n");
    sqlite3_finalize(stmt);
    return 0;
  }
  uint64_t last = 0, total = 0;
  for (int i = 7; i >= 0; i--) last = (last << 8) | payload[56 + i];
  for (int i = 7; i >= 0; i--) total = (total << 8) | payload[64 + i];
  unsigned char installation[16];
  memcpy(installation, payload + 40, 16);
  int extra = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (extra != SQLITE_DONE || last != total || last > (uint64_t)INT64_MAX) {
    fprintf(stderr, "oracle: invalid history checkpoint\n");
    return 0;
  }
  if (sqlite3_prepare_v2(db, "SELECT identity FROM effect_installation WHERE singleton=1;", -1, &stmt, NULL) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_ROW || sqlite3_column_bytes(stmt, 0) != 16 ||
      memcmp(sqlite3_column_blob(stmt, 0), installation, 16) != 0) {
    fprintf(stderr, "oracle: history checkpoint installation mismatch\n");
    sqlite3_finalize(stmt);
    return 0;
  }
  sqlite3_finalize(stmt);
  *fence = (int64_t)last;
  *present = 1;
  return 1;
}

typedef struct {
  unsigned char event_id[32];
  int64_t sequence;
  int has_sequence;
  int64_t confirmed_us;
  int linked;
  int subject;
  int has_evidence;
  int64_t evidence_bytes;
  int deleted;
} Detail;

typedef struct {
  int family;
  int length;
  unsigned char bytes[16];
  int64_t count;
  int64_t evidence_bytes;
} Subject;

typedef struct {
  Detail *rows;
  size_t count;
  Subject *subjects;
  size_t subject_count;
  int *slots;
  size_t slot_mask;
  Detail **by_id;
} Model;

static void model_free(Model *model) {
  free(model->rows);
  free(model->subjects);
  free(model->slots);
  free(model->by_id);
  memset(model, 0, sizeof(*model));
}

static int compare_detail(const void *left, const void *right) {
  const Detail *a = left, *b = right;
  if (a->has_sequence != b->has_sequence) return a->has_sequence ? -1 : 1;
  if (a->sequence != b->sequence) return a->sequence < b->sequence ? -1 : 1;
  return memcmp(a->event_id, b->event_id, 32);
}

static int compare_id(const void *left, const void *right) {
  return memcmp((*(Detail *const *)left)->event_id, (*(Detail *const *)right)->event_id, 32);
}

// Open addressing over at least twice as many slots as rows, so probing terminates.
static int subject_index(Model *model, int family, const unsigned char *bytes, int length) {
  uint64_t hash = 1469598103934665603ULL ^ (uint64_t)family;
  for (int i = 0; i < length; i++) hash = (hash ^ bytes[i]) * 1099511628211ULL;
  size_t slot = (size_t)hash & model->slot_mask;
  for (; model->slots[slot] >= 0; slot = (slot + 1) & model->slot_mask) {
    Subject *s = &model->subjects[model->slots[slot]];
    if (s->family == family && s->length == length && memcmp(s->bytes, bytes, (size_t)length) == 0) return model->slots[slot];
  }
  model->slots[slot] = (int)model->subject_count;
  Subject *s = &model->subjects[model->subject_count];
  memset(s, 0, sizeof(*s));
  s->family = family;
  s->length = length;
  memcpy(s->bytes, bytes, (size_t)length);
  return (int)model->subject_count++;
}

// Independent evaluator: rows are loaded with plain joins; eligibility, aggregates and
// ordering are computed here, not by the shipped SQL.
static int model_load(sqlite3 *db, Model *model) {
  memset(model, 0, sizeof(*model));
  int64_t total = 0;
  if (!single_int(db, "SELECT count(*) FROM confirmed_event_details;", &total)) return 0;
  if (total < 0 || total > MAX_ROWS) {
    fprintf(stderr, "oracle: %" PRId64 " details exceed the oracle bound\n", total);
    return 0;
  }
  size_t capacity = total == 0 ? 1 : (size_t)total;
  model->rows = calloc(capacity, sizeof(Detail));
  model->subjects = calloc(capacity, sizeof(Subject));
  size_t slots = 2;
  while (slots < 2 * capacity) slots <<= 1;
  model->slots = malloc(slots * sizeof(int));
  model->slot_mask = slots - 1;
  model->by_id = calloc(capacity, sizeof(Detail *));
  if (!model->rows || !model->subjects || !model->slots || !model->by_id) {
    fprintf(stderr, "oracle: out of memory\n");
    model_free(model);
    return 0;
  }
  memset(model->slots, 0xff, slots * sizeof(int));
  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2(db, "SELECT d.event_id,s.sequence,e.confirmed_us,r.family,r.subject,d.evidence FROM confirmed_event_details d JOIN confirmed_effect_events e ON e.event_id=d.event_id LEFT JOIN confirmed_history_sequence s ON s.event_id=d.event_id LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id;", -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "oracle: load: %s\n", sqlite3_errmsg(db));
    model_free(model);
    return 0;
  }
  int rc;
  while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    if (model->count == capacity) {
      fprintf(stderr, "oracle: detail rows changed while loading\n");
      rc = SQLITE_ERROR;
      break;
    }
    Detail *row = &model->rows[model->count];
    if (sqlite3_column_bytes(stmt, 0) != 32 || sqlite3_column_type(stmt, 2) != SQLITE_INTEGER) {
      fprintf(stderr, "oracle: malformed detail row\n");
      rc = SQLITE_ERROR;
      break;
    }
    memcpy(row->event_id, sqlite3_column_blob(stmt, 0), 32);
    row->has_sequence = sqlite3_column_type(stmt, 1) == SQLITE_INTEGER;
    row->sequence = row->has_sequence ? sqlite3_column_int64(stmt, 1) : 0;
    row->confirmed_us = sqlite3_column_int64(stmt, 2);
    row->linked = sqlite3_column_type(stmt, 3) != SQLITE_NULL;
    row->subject = -1;
    if (row->linked) {
      int family = sqlite3_column_int(stmt, 3);
      int length = sqlite3_column_bytes(stmt, 4);
      const unsigned char *subject = sqlite3_column_blob(stmt, 4);
      if ((family != 4 && family != 6) || subject == NULL || length != (family == 4 ? 4 : 16)) {
        fprintf(stderr, "oracle: malformed retry subject\n");
        rc = SQLITE_ERROR;
        break;
      }
      row->subject = subject_index(model, family, subject, length);
    }
    row->has_evidence = sqlite3_column_type(stmt, 5) != SQLITE_NULL;
    if (row->has_evidence) {
      (void)sqlite3_column_blob(stmt, 5);
      row->evidence_bytes = sqlite3_column_bytes(stmt, 5);
    }
    model->count++;
  }
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) {
    if (rc != SQLITE_ERROR) fprintf(stderr, "oracle: load: %s\n", sqlite3_errmsg(db));
    model_free(model);
    return 0;
  }
  qsort(model->rows, model->count, sizeof(Detail), compare_detail);
  for (size_t i = 0; i < model->count; i++) model->by_id[i] = &model->rows[i];
  qsort(model->by_id, model->count, sizeof(Detail *), compare_id);
  for (size_t i = 1; i < model->count; i++) {
    if (memcmp(model->by_id[i]->event_id, model->by_id[i - 1]->event_id, 32) == 0) {
      fprintf(stderr, "oracle: duplicate detail row\n");
      model_free(model);
      return 0;
    }
  }
  for (size_t i = 0; i < model->count; i++) {
    Detail *row = &model->rows[i];
    if (row->subject >= 0) {
      model->subjects[row->subject].count++;
      if (row->has_evidence) model->subjects[row->subject].evidence_bytes += row->evidence_bytes;
    }
  }
  return 1;
}

static void model_delete(Model *model, Detail *row) {
  row->deleted = 1;
  if (row->subject < 0) return;
  Subject *s = &model->subjects[row->subject];
  s->count--;
  if (row->has_evidence) s->evidence_bytes -= row->evidence_bytes;
}

static Detail *model_find(Model *model, const unsigned char *event_id) {
  size_t low = 0, high = model->count;
  while (low < high) {
    size_t middle = low + (high - low) / 2;
    int order = memcmp(model->by_id[middle]->event_id, event_id, 32);
    if (order == 0) return model->by_id[middle]->deleted ? NULL : model->by_id[middle];
    if (order < 0) low = middle + 1;
    else high = middle;
  }
  return NULL;
}

static Detail *model_choose(Model *model, int64_t cutoff, int64_t fence, int64_t max_matches, int off_by_one) {
  int64_t count_limit = off_by_one ? max_matches + 1 : max_matches;
  for (size_t i = 0; i < model->count; i++) {
    Detail *row = &model->rows[i];
    if (row->deleted || !row->has_sequence) continue;
    if (row->sequence > fence) return NULL;
    if (row->confirmed_us <= cutoff) return row;
    if (row->subject < 0) continue;
    const Subject *s = &model->subjects[row->subject];
    if (s->count > count_limit) return row;
    if (row->has_evidence && s->evidence_bytes > SUBJECT_EVIDENCE_LIMIT) return row;
  }
  return NULL;
}

typedef struct {
  sqlite3 *db;
  sqlite3_stmt *select;
  sqlite3_stmt *remove;
  int64_t vm_total;
  int64_t vm_max;
  int64_t vm_last;
} Shipped;

static int shipped_init(Shipped *shipped, sqlite3 *db) {
  memset(shipped, 0, sizeof(*shipped));
  shipped->db = db;
  if (sqlite3_prepare_v2(db, shipped_detail_sql, -1, &shipped->select, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(db, shipped_delete_sql, -1, &shipped->remove, NULL) != SQLITE_OK) {
    fprintf(stderr, "oracle: prepare shipped statements: %s\n", sqlite3_errmsg(db));
    return 0;
  }
  return 1;
}

static void shipped_free(Shipped *shipped) {
  sqlite3_finalize(shipped->select);
  sqlite3_finalize(shipped->remove);
}

// One shipped decision. Returns 1 with *found set, 0 on failure. Statement counters are
// read as non-resetting deltas.
static int shipped_choose(Shipped *shipped, int64_t cutoff, int64_t fence, int64_t max_matches, unsigned char *event_id, int *found) {
  sqlite3_stmt *stmt = shipped->select;
  int64_t before = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_VM_STEP, 0);
  if (sqlite3_reset(stmt) != SQLITE_OK || sqlite3_bind_int64(stmt, 1, fence) != SQLITE_OK ||
      sqlite3_bind_int64(stmt, 2, cutoff) != SQLITE_OK || sqlite3_bind_int64(stmt, 3, max_matches) != SQLITE_OK) {
    fprintf(stderr, "oracle: bind shipped query: %s\n", sqlite3_errmsg(shipped->db));
    return 0;
  }
  int rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    if (sqlite3_column_bytes(stmt, 0) != 32) {
      fprintf(stderr, "oracle: shipped query returned a malformed event id\n");
      return 0;
    }
    memcpy(event_id, sqlite3_column_blob(stmt, 0), 32);
    *found = 1;
  } else if (rc == SQLITE_DONE) {
    *found = 0;
  } else {
    fprintf(stderr, "oracle: shipped query: %s\n", sqlite3_errmsg(shipped->db));
    return 0;
  }
  int64_t steps = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_VM_STEP, 0) - before;
  if (sqlite3_reset(stmt) != SQLITE_OK) return 0;
  shipped->vm_last = steps;
  shipped->vm_total += steps;
  if (steps > shipped->vm_max) shipped->vm_max = steps;
  return 1;
}

static int shipped_delete(Shipped *shipped, const unsigned char *event_id) {
  sqlite3_stmt *stmt = shipped->remove;
  if (sqlite3_reset(stmt) != SQLITE_OK || sqlite3_bind_blob(stmt, 1, event_id, 32, SQLITE_TRANSIENT) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "oracle: delete detail: %s\n", sqlite3_errmsg(shipped->db));
    return 0;
  }
  if (sqlite3_changes(shipped->db) != 1) {
    fprintf(stderr, "oracle: delete detail changed %d rows\n", sqlite3_changes(shipped->db));
    return 0;
  }
  return sqlite3_reset(stmt) == SQLITE_OK;
}

typedef struct {
  const char *db;
  int64_t cutoff;
  int has_cutoff;
  int64_t now;
  int has_now;
  int64_t age;
  int has_age;
  int64_t fence;
  int fence_from_db;
  int64_t max_matches;
  int64_t limit;
} Params;

static int set_param(Params *params, const char *key, const char *value) {
  if (strcmp(key, "db") == 0) {
    params->db = value;
    return 1;
  }
  if (strcmp(key, "fence") == 0 && strcmp(value, "db") == 0) {
    params->fence_from_db = 1;
    return 1;
  }
  int64_t number = 0;
  if (!parse_i64(value, &number)) return 0;
  if (strcmp(key, "cutoff") == 0) params->cutoff = number, params->has_cutoff = 1;
  else if (strcmp(key, "now") == 0) params->now = number, params->has_now = 1;
  else if (strcmp(key, "age") == 0) params->age = number, params->has_age = 1;
  else if (strcmp(key, "fence") == 0) params->fence = number, params->fence_from_db = 0;
  else if (strcmp(key, "max_matches") == 0) params->max_matches = number;
  else if (strcmp(key, "limit") == 0 || strcmp(key, "count") == 0) params->limit = number;
  else return 0;
  return 1;
}

// cutoff mirrors the shipped `now - age`, saturating at the minimum like std.math.sub's catch.
static int resolve_cutoff(Params *params) {
  if (params->has_cutoff == (params->has_now || params->has_age)) return 0;
  if (params->has_cutoff) return 1;
  if (!params->has_now || !params->has_age || params->age < 0) return 0;
  if (params->age > 0 && params->now < INT64_MIN + params->age) params->cutoff = INT64_MIN;
  else params->cutoff = params->now - params->age;
  return 1;
}

static int valid_params(Params *params) {
  return params->db != NULL && resolve_cutoff(params) && params->max_matches >= 0 && params->max_matches <= MAX_MATCHES_LIMIT &&
         params->limit >= 0 && (params->fence_from_db || params->fence >= 0);
}

typedef struct {
  unsigned char (*ids)[32];
  size_t count;
} Carried;

// Runs up to `limit` repeated one-row decisions at one cutoff/fence/policy on `db`, with
// both evaluators; prints the ascending deletion vector as JSON. Returns the exit code.
static int run_decisions(sqlite3 *db, Params *params, Carried *carried, int first) {
  int present = 1;
  int64_t fence = params->fence;
  if (!history_fence(db, &fence, &present)) return 1;
  if (!params->fence_from_db) fence = params->fence;
  Model model;
  if (!model_load(db, &model)) return 1;
  Shipped shipped;
  if (!shipped_init(&shipped, db)) {
    shipped_free(&shipped);
    model_free(&model);
    return 1;
  }
  int off_by_one = env_flag("F2Z_ORACLE_NC3");
  int status = 0;
  size_t made = 0;
  printf("%s{\"db\":\"%s\",\"cutoff\":%" PRId64 ",\"fence\":%" PRId64 ",\"fence_source\":\"%s\",\"max_matches\":%" PRId64 ",\"details_loaded\":%zu,\"deleted\":[",
         first ? "" : ",", params->db, params->cutoff, fence, params->fence_from_db ? (present ? "history-checkpoint" : "no-checkpoint") : "argument",
         params->max_matches, model.count);
  if (params->fence_from_db && !present) {
    // The shipped transaction commits without deleting when no checkpoint exists.
  } else {
    for (size_t n = 0; params->limit == 0 || n < (size_t)params->limit; n++) {
      unsigned char chosen[32];
      int found = 0;
      if (!shipped_choose(&shipped, params->cutoff, fence, params->max_matches, chosen, &found)) {
        status = 1;
        break;
      }
      Detail *expected = model_choose(&model, params->cutoff, fence, params->max_matches, off_by_one);
      if ((expected == NULL) != (found == 0) || (expected && memcmp(expected->event_id, chosen, 32) != 0)) {
        fprintf(stderr, "oracle: evaluators disagree at decision %zu: sql=%s c=%s\n", n + 1, found ? "row" : "none", expected ? "row" : "none");
        status = 3;
        break;
      }
      if (!found) break;
      Detail *row = model_find(&model, chosen);
      if (row == NULL || !shipped_delete(&shipped, chosen)) {
        status = 1;
        break;
      }
      model_delete(&model, row);
      if (carried) {
        if (carried->count == MAX_CARRIED) {
          status = 1;
          break;
        }
        memcpy(carried->ids[carried->count++], chosen, 32);
      }
      printf("%s{\"sequence\":%" PRId64 ",\"event_id\":\"", made ? "," : "", row->sequence);
      print_hex(chosen, 32);
      printf("\",\"vm_steps\":%" PRId64 "}", shipped.vm_last);
      made++;
    }
  }
  printf("],\"count\":%zu,\"shipped_vm_steps_total\":%" PRId64 ",\"shipped_vm_steps_max_decision\":%" PRId64 ",\"agree\":%s}",
         made, shipped.vm_total, shipped.vm_max, status == 0 ? "true" : "false");
  shipped_free(&shipped);
  model_free(&model);
  return status;
}

static int mode_vector(int argc, char **argv) {
  Params params = {.db = argv[2], .fence_from_db = 1, .max_matches = 10};
  for (int i = 3; i < argc; i++) {
    char *eq = strchr(argv[i], '=');
    if (!eq) return 2;
    *eq = '\0';
    if (strcmp(argv[i], "db") == 0 || !set_param(&params, argv[i], eq + 1)) return 2;
  }
  if (!valid_params(&params)) return 2;
  sqlite3 *db = load_copy(params.db);
  if (!db) return 1;
  printf("{\"mode\":\"vector\",\"offline_allowance\":\"no work guard\",\"nc3\":%s,\"results\":[", env_flag("F2Z_ORACLE_NC3") ? "true" : "false");
  int status = run_decisions(db, &params, NULL, 1);
  printf("],\"status\":%d}\n", status);
  sqlite3_close(db);
  return status;
}

// Each step reloads its snapshot and first re-applies every earlier deletion by event id,
// so a later snapshot that gained rows (a live insert) still sees the prior deletions.
static int mode_steps(int argc, char **argv) {
  Carried carried = {.ids = calloc(MAX_CARRIED, 32), .count = 0};
  if (!carried.ids) return 1;
  int status = 0;
  printf("{\"mode\":\"steps\",\"offline_allowance\":\"no work guard\",\"nc3\":%s,\"results\":[", env_flag("F2Z_ORACLE_NC3") ? "true" : "false");
  for (int i = 2; i < argc && status == 0; i++) {
    Params params = {.fence_from_db = 1, .max_matches = 10, .limit = 1};
    char *spec = argv[i];
    for (char *part = strtok(spec, ","); part; part = strtok(NULL, ",")) {
      char *eq = strchr(part, '=');
      if (!eq) {
        status = 2;
        break;
      }
      *eq = '\0';
      if (!set_param(&params, part, eq + 1)) status = 2;
    }
    if (status != 0 || !valid_params(&params)) {
      status = 2;
      break;
    }
    sqlite3 *db = load_copy(params.db);
    if (!db) {
      status = 1;
      break;
    }
    Shipped replay;
    if (!shipped_init(&replay, db)) status = 1;
    for (size_t n = 0; status == 0 && n < carried.count; n++)
      if (!shipped_delete(&replay, carried.ids[n])) status = 1;
    shipped_free(&replay);
    if (status == 0) status = run_decisions(db, &params, &carried, i == 2);
    sqlite3_close(db);
  }
  printf("],\"status\":%d}\n", status);
  free(carried.ids);
  return status;
}

typedef struct {
  int64_t remaining;
  int64_t invoked;
} Guard;

// Same shape as Store.workProgress: interrupt once the per-transaction budget is spent.
static int guard_progress(void *context) {
  Guard *guard = context;
  guard->invoked++;
  if (guard->remaining == 0) return 1;
  guard->remaining--;
  return 0;
}

typedef struct {
  int line;
  int64_t expect_rows;
  int64_t expect_changes;
  const char *sql;
} Line;

static char *read_script(const char *path) {
  FILE *file = fopen(path, "rb");
  if (!file) return NULL;
  char *buffer = malloc(1 << 20);
  size_t length = buffer ? fread(buffer, 1, (1 << 20) - 1, file) : 0;
  int overflow = buffer && !feof(file);
  fclose(file);
  if (!buffer || overflow) {
    free(buffer);
    return NULL;
  }
  buffer[length] = '\0';
  return buffer;
}

static int parse_directive(char **cursor, const char *name, int64_t *out) {
  size_t length = strlen(name);
  if (strncmp(*cursor, name, length) != 0) return 0;
  char *end = *cursor + length;
  while (*end && *end != ' ' && *end != '\t') end++;
  char saved = *end;
  *end = '\0';
  int ok = parse_i64(*cursor + length, out) && *out >= 0;
  *end = saved;
  if (!ok) return -1;
  *cursor = end;
  while (**cursor == ' ' || **cursor == '\t') (*cursor)++;
  return 1;
}

static int run_statement(sqlite3 *db, const char *sql, int line, int64_t *vm_total, int64_t expect_rows, int64_t expect_changes, int report) {
  sqlite3_stmt *stmt = NULL;
  const char *tail = NULL;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail) != SQLITE_OK || stmt == NULL) {
    fprintf(stderr, "oracle: line %d prepare: %s\n", line, sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return 0;
  }
  while (tail && (*tail == ' ' || *tail == '\t' || *tail == '\r')) tail++;
  if (tail && *tail != '\0') {
    fprintf(stderr, "oracle: line %d holds more than one statement\n", line);
    sqlite3_finalize(stmt);
    return 0;
  }
  int64_t rows = 0;
  int rc;
  while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) rows++;
  int64_t steps = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_VM_STEP, 0);
  *vm_total += steps;
  int ok = rc == SQLITE_DONE;
  int changes = sqlite3_changes(db);
  int readonly = sqlite3_stmt_readonly(stmt);
  if (!ok) fprintf(stderr, "oracle: line %d step: %s (rc=%d)\n", line, sqlite3_errmsg(db), rc);
  if (ok && expect_rows >= 0 && rows != expect_rows) {
    fprintf(stderr, "oracle: line %d returned %" PRId64 " rows, expected %" PRId64 "\n", line, rows, expect_rows);
    ok = 0;
  }
  if (ok && expect_changes >= 0 && (readonly || changes != expect_changes)) {
    fprintf(stderr, "oracle: line %d changed %d rows, expected %" PRId64 "\n", line, changes, expect_changes);
    ok = 0;
  }
  if (report)
    printf(",{\"line\":%d,\"vm_steps\":%" PRId64 ",\"rows\":%" PRId64 ",\"changes\":%d,\"ok\":%s}", line, steps, rows, readonly ? 0 : changes, ok ? "true" : "false");
  sqlite3_finalize(stmt);
  return ok;
}

static int mode_measure(const char *path, const char *script_path) {
  char *script = read_script(script_path);
  if (!script) {
    fprintf(stderr, "oracle: cannot read script %s (limit 1 MiB)\n", script_path);
    return 1;
  }
  Line lines[4096];
  int count = 0;
  int64_t script_budget = PROGRESS_BUDGET;
  int line_number = 0;
  for (char *line = strtok(script, "\n"); line; line = strtok(NULL, "\n")) {
    line_number++;
    while (*line == ' ' || *line == '\t') line++;
    size_t length = strlen(line);
    while (length && (line[length - 1] == '\r' || line[length - 1] == ' ')) line[--length] = '\0';
    if (length == 0 || strncmp(line, "--", 2) == 0) continue;
    if (strncmp(line, "@budget=", 8) == 0) {
      if (count != 0 || !parse_i64(line + 8, &script_budget) || script_budget < 0 || script_budget > 1000000) {
        free(script);
        return 2;
      }
      continue;
    }
    if (count == 4096) {
      free(script);
      return 2;
    }
    Line *entry = &lines[count++];
    entry->line = line_number;
    entry->expect_rows = -1;
    entry->expect_changes = -1;
    for (;;) {
      int rows = parse_directive(&line, "@rows=", &entry->expect_rows);
      int changes = rows ? 0 : parse_directive(&line, "@changes=", &entry->expect_changes);
      if (rows < 0 || changes < 0) {
        free(script);
        return 2;
      }
      if (!rows && !changes) break;
    }
    entry->sql = line;
  }
  if (count == 0) {
    free(script);
    return 2;
  }
  sqlite3 *db = load_copy(path);
  if (!db) {
    free(script);
    return 1;
  }
  int nc1 = env_flag("F2Z_ORACLE_NC1");
  int nc2 = env_flag("F2Z_ORACLE_NC2");
  Guard guard = {.remaining = nc1 ? 0 : script_budget, .invoked = 0};
  int64_t budget = guard.remaining;
  sqlite3_progress_handler(db, PROGRESS_OPS, guard_progress, &guard);
  int64_t vm_total = 0;
  int status = 0;
  int64_t changed_before_final = 0;
  printf("{\"mode\":\"measure\",\"db\":\"%s\",\"script\":\"%s\",\"progress_ops\":%d,\"budget\":%" PRId64 ",\"nc1\":%s,\"nc2\":%s,\"statements\":[{\"line\":0,\"sql\":\"BEGIN IMMEDIATE\"}",
         path, script_path, PROGRESS_OPS, budget, nc1 ? "true" : "false", nc2 ? "true" : "false");
  if (!run_statement(db, "BEGIN IMMEDIATE;", 0, &vm_total, -1, -1, 0)) status = 1;
  for (int i = 0; status == 0 && i < count; i++) {
    if (nc2 && i == count - 1) {
      sqlite3_stmt *probe = NULL;
      int is_write = sqlite3_prepare_v2(db, lines[i].sql, -1, &probe, NULL) == SQLITE_OK && probe && !sqlite3_stmt_readonly(probe);
      sqlite3_finalize(probe);
      if (!is_write || changed_before_final == 0) {
        fprintf(stderr, "oracle: the final-write control needs an earlier change and a final write statement\n");
        status = 2;
        break;
      }
      if (sqlite3_exec(db, "PRAGMA query_only=1;", NULL, NULL, NULL) != SQLITE_OK) {
        status = 1;
        break;
      }
    }
    int64_t before = sqlite3_total_changes64(db);
    if (!run_statement(db, lines[i].sql, lines[i].line, &vm_total, lines[i].expect_rows, lines[i].expect_changes, 1)) status = 1;
    changed_before_final += sqlite3_total_changes64(db) - before;
  }
  if (status == 0 && !run_statement(db, "COMMIT;", -1, &vm_total, -1, -1, 0)) status = 1;
  printf("],\"vm_steps_total\":%" PRId64 ",\"callbacks_invoked\":%" PRId64 ",\"callbacks_consumed\":%" PRId64 ",\"committed\":%s,\"status\":%d}\n",
         vm_total, guard.invoked, budget - guard.remaining, status == 0 ? "true" : "false", status);
  sqlite3_close(db);
  free(script);
  return status;
}

int main(int argc, char **argv) {
  int status = 2;
  if (argc >= 3 && strcmp(argv[1], "vector") == 0) status = mode_vector(argc, argv);
  else if (argc >= 3 && strcmp(argv[1], "steps") == 0) status = mode_steps(argc, argv);
  else if (argc == 4 && strcmp(argv[1], "measure") == 0) status = mode_measure(argv[2], argv[3]);
  if (status == 2) fprintf(stderr, "usage: see the header of tests/harness/load_repro/oracle.c\n");
  return status;
}
