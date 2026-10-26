// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const detection = @import("../core/native_detection_record.zig");
const store = @import("store.zig");
const Error = store.Error;

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn releaseRetryDecision(self: *Store, jail: []const u8, subject: detection.Subject, now_us: i64) Error!bool {
            try self.beginWrite();
            errdefer self.rollback();
            try self.requireRetryProjectionMutationTx();
            if (self.schema_version < 16) return error.RetryStorageRequired;
            const releasable = blk: {
                var row = try self.statement("SELECT lease_kind,deadline_us,length(attempts) FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
                defer row.deinit();
                try row.text(1, jail);
                try Store.bindSubject(&row, &subject);
                if (!try row.row()) break :blk false;
                const deadline = try row.optionalSigned(1);
                const leased = switch (try row.signed(0)) {
                    0 => false,
                    1 => (deadline orelse return error.InvalidRetryState) > now_us,
                    2 => true,
                    else => return error.InvalidRetryState,
                };
                break :blk leased or try row.signed(2) != 0;
            };
            if (releasable) {
                var update = try self.statement("UPDATE retry_states SET lease_kind=0,deadline_us=NULL,attempts=x'' WHERE jail=?1 AND family=?2 AND subject=?3;");
                defer update.deinit();
                try update.text(1, jail);
                try Store.bindSubject(&update, &subject);
                try update.done();
                if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
                try self.syncRetryProjectionRowTx(jail, &subject);
                try self.changeRetryJailSummaryTx(jail, 0, 0);
            }
            try self.commitTransaction();
            return releasable;
        }
    };
}
