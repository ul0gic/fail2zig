// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const store = @import("store.zig");
const Error = store.Error;

pub const max_batch_records = 64;

pub const Frame = struct {
    records: u16 = 0,
    effect_changed: bool = false,
    broken: bool = false,
    open: ?struct { noted_count: u8, noted_ambiguous: bool } = null,
};

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn beginBatch(self: *Store) Error!Frame {
            try self.beginWrite();
            return .{};
        }

        pub fn openBatchRecord(self: *Store, frame: *Frame) Error!void {
            if (frame.broken or frame.open != null or frame.records >= max_batch_records) return error.InvalidRecord;
            try self.exec("SAVEPOINT batch_record;");
            frame.open = .{ .noted_count = self.noted_count, .noted_ambiguous = self.noted_ambiguous };
        }

        pub fn closeBatchRecord(self: *Store, frame: *Frame, record: store.Record) Error!store.CommitResult {
            if (frame.open == null) return error.InvalidRecord;
            const detections = try Store.validateRecord(&record);
            const step = try self.commitRecordStep(&record, detections);
            if (step.result == .already_committed) return .already_committed;
            try self.exec("RELEASE batch_record;");
            frame.open = null;
            frame.records += 1;
            frame.effect_changed = frame.effect_changed or step.effect_changed;
            return .committed;
        }

        pub fn dropBatchRecord(self: *Store, frame: *Frame) void {
            const saved = frame.open orelse return;
            frame.open = null;
            self.row_tallies = .{};
            self.noted_count = saved.noted_count;
            self.noted_ambiguous = saved.noted_ambiguous;
            self.exec("ROLLBACK TO batch_record;") catch {
                frame.broken = true;
                return;
            };
            self.exec("RELEASE batch_record;") catch {
                frame.broken = true;
            };
        }

        pub fn commitBatch(self: *Store, frame: *Frame) Error!void {
            errdefer self.rollback();
            if (frame.broken or frame.open != null) return error.DatabaseFailure;
            try self.commitEffectTransaction(frame.effect_changed);
        }
    };
}
