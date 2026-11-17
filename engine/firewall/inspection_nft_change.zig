// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Creates the nftables installation, changes its set elements and scoped rules over netlink and applies set events to a snapshot.
// Holds: Each change goes to the kernel as one netlink batch, and progress is marked requested only just before that batch is sent.

const std = @import("std");
const shared = @import("shared");
const nl = @import("netlink.zig");
const nft = @import("nftables.zig");
const linux = @import("std").os.linux;
const mem = @import("std").mem;
const ClockSample = @import("inspection.zig").ClockSample;
const DispatchToken = @import("inspection.zig").DispatchToken;
const Entry = @import("inspection.zig").Entry;
const Error = @import("inspection.zig").Error;
const EventDelta = @import("inspection.zig").EventDelta;
const EventSink = @import("inspection.zig").EventSink;
const MutationProgress = @import("inspection.zig").MutationProgress;
const ScopedRuleMetadata = @import("inspection.zig").ScopedRuleMetadata;
const Snapshot = @import("inspection.zig").Snapshot;
const hostScope = @import("inspection.zig").hostScope;
const legacyAddress = @import("inspection.zig").legacyAddress;
const max_install_messages = @import("inspection.zig").max_install_messages;
const max_withdraw_messages = @import("inspection.zig").max_withdraw_messages;
const install_batch_bytes = @import("inspection.zig").install_batch_bytes;
const withdraw_batch_bytes = @import("inspection.zig").withdraw_batch_bytes;
const findEntry = @import("inspection_entries.zig").findEntry;
const leaseDeadline = @import("inspection_entries.zig").leaseDeadline;
const timingTransport = @import("inspection_entries.zig").timingTransport;
const decodeSetElement = @import("inspection_nft_read.zig").decodeSetElement;
const dump = @import("inspection_nft_read.zig").dump;
const netlinkError = @import("inspection_nft_read.zig").netlinkError;
const payloadAttrs = @import("inspection_nft_read.zig").payloadAttrs;
const rejectedBatch = @import("inspection_nft_read.zig").rejectedBatch;
const scopeBuildError = @import("inspection_nft_read.zig").scopeBuildError;
const validateScopedDropRule = @import("inspection_nft_read.zig").validateScopedDropRule;

fn nftSetKey(address: shared.IpAddress, buf: *[16]u8) []const u8 {
    switch (address) {
        .ipv4 => |v| {
            mem.writeInt(u32, buf[0..4], v, .big);
            return buf[0..4];
        },
        .ipv6 => |v| {
            mem.writeInt(u128, buf, v, .big);
            return buf;
        },
    }
}

pub fn Methods(comptime Inspector: type) type {
    return struct {
        pub fn installSocket(self: *Inspector) nl.Error!*nl.NetlinkSocket {
            if (self.install == null) {
                var sock = try nl.NetlinkSocket.init(linux.NETLINK.NETFILTER);
                errdefer sock.close();
                try sock.setSendBuffer(install_batch_bytes * 2);
                self.install = sock;
            }
            self.last_install_port = self.install.?.port_id;
            return &self.install.?;
        }
        pub fn drainEvents(self: *Inspector, sink: EventSink, max_datagrams: usize) Error!usize {
            const sock = &(self.events orelse return 0);
            var bytes: [16384]u8 = undefined;
            var datagrams: usize = 0;
            while (datagrams < max_datagrams) : (datagrams += 1) {
                const data = (nl.recvEvents(sock, &bytes) catch |err| return switch (err) {
                    error.EventsOverflowed => error.EventsLost,
                    else => netlinkError(err),
                }) orelse break;
                var messages = nl.StrictMessages{ .bytes = data };
                while (messages.next() catch return error.Incomplete) |item| {
                    const event = nft.decodeEvent(item) catch |err| return netlinkError(err);
                    try sink.apply(sink.context, event);
                }
            }
            return datagrams;
        }
        pub fn applyEvent(self: *Inspector, snapshot: *Snapshot, event: nft.ElementEvent, offset_ms: i64) Error!?EventDelta {
            var name_buf: [28]u8 = undefined;
            if (!mem.eql(u8, event.table, self.installation.name(&name_buf))) return null;
            const index: usize = if (mem.eql(u8, event.set, "banned_ipv4")) 0 else if (mem.eql(u8, event.set, "banned_ipv6")) 1 else return error.ForeignState;
            const capacity = self.limits.max_bytes / @sizeOf(Entry);
            var delta = EventDelta{};
            var items = nl.Attributes{ .bytes = event.elements };
            while (items.next() catch return error.Incomplete) |item| {
                if (item.kind != 1 or (item.flags & 0x4000) != 0) return error.UnknownState;
                var entry = try decodeSetElement(item.value, index);
                if (entry.remaining_ms) |remaining| entry.remaining_ms = @intCast(@max(0, @as(i64, @intCast(remaining)) + offset_ms));
                if (event.removed) {
                    if (try snapshot.removeHost(entry)) delta.removed += 1 else delta.missing += 1;
                } else {
                    if (snapshot.entries.len >= capacity) return error.LimitExceeded;
                    if (try snapshot.upsertHost(entry)) delta.added += 1 else delta.replaced += 1;
                }
            }
            self.retained_bytes = snapshot.entries.len * @sizeOf(Entry);
            return delta;
        }
        pub fn withdrawNft(self: *Inspector, present: []const DispatchToken, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
            var name_buf: [28]u8 = undefined;
            const name = self.installation.name(&name_buf);
            var sock = nl.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| return netlinkError(err);
            defer sock.close();
            var host_count: usize = 0;
            var scoped_count: usize = 0;
            for (present) |token| {
                if (hostScope(token.scope)) host_count += 1 else scoped_count += 1;
            }
            var handles: [max_withdraw_messages]u64 = undefined;
            var handle_count: usize = 0;
            if (scoped_count != 0) {
                var request_buf: [256]u8 align(4) = undefined;
                const request = nft.buildTablePayload(&request_buf, nl.NFPROTO.INET, name) catch |err| return netlinkError(err);
                var rules = try dump(self, &sock, nft.NFT_MSG.GETRULE, nft.NFT_MSG.NEWRULE, request, timer, 0);
                defer rules.deinit();
                var per_token = [_]usize{0} ** max_withdraw_messages;
                var collected: usize = 0;
                for (rules.values.items) |payload| {
                    const attributes = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 6, 7, 8 });
                    if (!mem.eql(u8, try attributes.text(1), name) or !mem.eql(u8, try attributes.text(2), "input") or attributes.values[7] == null) continue;
                    const metadata = try ScopedRuleMetadata.decode(try attributes.get(7));
                    const owner = for (present, 0..) |token, index| {
                        if (mem.eql(u8, &metadata.effect_id, &token.effect_id) and !hostScope(token.scope)) break index;
                    } else continue;
                    if (!std.meta.eql(metadata.scope, present[owner].scope)) return error.ForeignState;
                    try validateScopedDropRule(name, attributes, metadata);
                    const handle = try attributes.number(u64, 3);
                    if (handle == 0) return error.UnknownState;
                    if (per_token[owner] == nft.max_scope_rule_parts) continue;
                    per_token[owner] += 1;
                    collected += 1;
                    if (collected <= handles.len) {
                        handles[handle_count] = handle;
                        handle_count += 1;
                    }
                }
                if (host_count + collected > max_withdraw_messages) return error.LimitExceeded;
            }
            var payloads: [max_withdraw_messages][128]u8 align(4) = undefined;
            var batch_bytes: [withdraw_batch_bytes]u8 align(4) = undefined;
            var related: [max_withdraw_messages + 2]u32 = undefined;
            var batch = nl.Batch.init(&batch_bytes);
            related[0] = sock.nextSeq();
            batch.begin(related[0], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
            var count: usize = 1;
            for (present) |token| {
                const address = legacyAddress(token.scope) catch continue;
                var key_buf: [16]u8 = undefined;
                const payload = nft.buildSetElemDelPayload(
                    &payloads[count - 1],
                    nl.NFPROTO.INET,
                    name,
                    if (address == .ipv4) "banned_ipv4" else "banned_ipv6",
                    nftSetKey(address, &key_buf),
                ) catch |err| return netlinkError(err);
                related[count] = sock.nextSeq();
                batch.add(
                    nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.DELSETELEM),
                    linux.NLM_F_REQUEST | linux.NLM_F_ACK,
                    related[count],
                    sock.port_id,
                    payload,
                ) catch |err| return netlinkError(err);
                count += 1;
            }
            for (handles[0..handle_count]) |handle| {
                const payload = nft.buildRuleDeletePayload(&payloads[count - 1], name, "input", handle) catch |err| return netlinkError(err);
                related[count] = sock.nextSeq();
                batch.add(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.DELRULE), linux.NLM_F_REQUEST | linux.NLM_F_ACK, related[count], sock.port_id, payload) catch |err| return netlinkError(err);
                count += 1;
            }
            if (count == 1) return error.Changed;
            related[count] = sock.nextSeq();
            const bytes = batch.commit(related[count], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
            const send_timeout = @min(try self.remainingMs(timer), 2000);
            progress.requested = true;
            nl.sendKernel(&sock, bytes, send_timeout) catch |err| return netlinkError(err);
            nl.receiveAcknowledgments(&sock, related[count .. count + 1], related[0 .. count + 1], @min(try self.remainingMs(timer), 2000)) catch |err| return rejectedBatch(err, progress);
            try self.afterMutation(1);
        }
        // Why: NLM_F_EXCL refuses an element already present, so one found in the baseline is deleted first in the same batch.
        pub fn installNft(self: *Inspector, tokens: []const DispatchToken, clock: ClockSample, baseline: *const Snapshot, elapsed: *std.time.Timer, timer: *std.time.Timer, progress: *MutationProgress) Error!usize {
            var name_buf: [28]u8 = undefined;
            const name = self.installation.name(&name_buf);
            const sock = self.installSocket() catch |err| return netlinkError(err);
            const batch_bytes = self.allocator.alignedAlloc(u8, 4, install_batch_bytes) catch return error.OutOfMemory;
            defer self.allocator.free(batch_bytes);
            const related = self.allocator.alloc(u32, 2 * max_install_messages + 2) catch return error.OutOfMemory;
            defer self.allocator.free(related);
            var payload_buf: [512]u8 align(4) = undefined;
            var batch = nl.Batch.init(batch_bytes);
            related[0] = sock.nextSeq();
            batch.begin(related[0], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
            const now = try self.clockAt(clock, elapsed);
            var count: usize = 1;
            var consumed: usize = 0;
            for (tokens) |token| {
                const address = try legacyAddress(token.scope);
                const existed = (try findEntry(baseline.entries, token.scope, token.effect_id)) != null;
                const units = try self.kernelUnits(token.operation, timingTransport(.nftables, token.scope), now);
                var key_buf: [16]u8 = undefined;
                const key = nftSetKey(address, &key_buf);
                const set = if (address == .ipv4) "banned_ipv4" else "banned_ipv6";
                const messages: usize = if (existed) 2 else 1;
                if (batch.builder.offset + messages * payload_buf.len > batch_bytes.len) break;
                if (existed) {
                    const payload = nft.buildSetElemDelPayload(&payload_buf, nl.NFPROTO.INET, name, set, key) catch |err| return netlinkError(err);
                    related[count] = sock.nextSeq();
                    batch.add(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.DELSETELEM), linux.NLM_F_REQUEST, related[count], sock.port_id, payload) catch |err| return netlinkError(err);
                    count += 1;
                }
                const payload = nft.buildSetElemAddPayload(&payload_buf, nl.NFPROTO.INET, name, set, key, units) catch |err| return netlinkError(err);
                related[count] = sock.nextSeq();
                batch.add(
                    nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.NEWSETELEM),
                    linux.NLM_F_REQUEST | linux.NLM_F_CREATE | linux.NLM_F_EXCL,
                    related[count],
                    sock.port_id,
                    payload,
                ) catch |err| return netlinkError(err);
                count += 1;
                consumed += 1;
            }
            if (consumed == 0) return error.LimitExceeded;
            related[count] = sock.nextSeq();
            const bytes = batch.commit(related[count], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
            const send_timeout = @min(try self.remainingMs(timer), 2000);
            progress.requested = true;
            nl.sendKernel(sock, bytes, send_timeout) catch |err| {
                self.dropInstallSocket();
                return netlinkError(err);
            };
            nl.receiveAcknowledgments(sock, related[count .. count + 1], related[0 .. count + 1], @min(try self.remainingMs(timer), 2000)) catch |err| {
                self.dropInstallSocket();
                return rejectedBatch(err, progress);
            };
            try self.afterMutation(1);
            return consumed;
        }
        pub fn mutateNft(self: *Inspector, token: DispatchToken, name: []const u8, existed: bool, timeout_ms: u64, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
            if (legacyAddress(token.scope)) |_| return self.mutateLegacyNft(token, name, existed, timeout_ms, timer, progress) else |_| {}
            return self.mutateScopedNft(token, name, timer, progress);
        }
        pub fn mutateLegacyNft(self: *Inspector, token: DispatchToken, name: []const u8, existed: bool, timeout_ms: u64, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
            var sock = nl.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| return netlinkError(err);
            defer sock.close();
            var key_buf: [16]u8 = undefined;
            const scoped_address = try legacyAddress(token.scope);
            const key = nftSetKey(scoped_address, &key_buf);
            const set = if (scoped_address == .ipv4) "banned_ipv4" else "banned_ipv6";
            var payloads: [2][512]u8 align(4) = undefined;
            var batch_buf: [2048]u8 align(4) = undefined;
            var batch = nl.Batch.init(&batch_buf);
            var related: [4]u32 = undefined;
            related[0] = sock.nextSeq();
            batch.begin(related[0], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
            var count: usize = 1;
            if (existed) {
                const payload = nft.buildSetElemDelPayload(&payloads[0], nl.NFPROTO.INET, name, set, key) catch |err| return netlinkError(err);
                related[count] = sock.nextSeq();
                count += 1;
                batch.add(
                    nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.DELSETELEM),
                    linux.NLM_F_REQUEST | linux.NLM_F_ACK,
                    related[count - 1],
                    sock.port_id,
                    payload,
                ) catch |err| return netlinkError(err);
            }
            if (token.operation == .ensure_present) {
                const payload = nft.buildSetElemAddPayload(&payloads[1], nl.NFPROTO.INET, name, set, key, timeout_ms) catch |err| return netlinkError(err);
                related[count] = sock.nextSeq();
                count += 1;
                batch.add(
                    nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.NEWSETELEM),
                    linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL,
                    related[count - 1],
                    sock.port_id,
                    payload,
                ) catch |err| return netlinkError(err);
            }
            related[count] = sock.nextSeq();
            const bytes = batch.commit(related[count], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
            const send_timeout = @min(try self.remainingMs(timer), 2000);
            progress.requested = true;
            nl.sendKernel(&sock, bytes, send_timeout) catch |err| return netlinkError(err);
            nl.receiveAcknowledgments(&sock, related[count .. count + 1], related[0 .. count + 1], @min(try self.remainingMs(timer), 2000)) catch |err| return rejectedBatch(err, progress);
        }

        pub fn mutateScopedNft(self: *Inspector, token: DispatchToken, name: []const u8, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
            const part_count = nft.scopeRulePartCount(token.scope) catch |err| return scopeBuildError(err);
            if (part_count > nft.max_scope_rule_parts) return error.LimitExceeded;
            var sock = nl.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| return netlinkError(err);
            defer sock.close();

            var request_buf: [256]u8 align(4) = undefined;
            const request = nft.buildTablePayload(&request_buf, nl.NFPROTO.INET, name) catch |err| return netlinkError(err);
            var rules = try dump(self, &sock, nft.NFT_MSG.GETRULE, nft.NFT_MSG.NEWRULE, request, timer, 0);
            defer rules.deinit();
            var handles: [nft.max_scope_rule_parts]u64 = undefined;
            var handle_count: usize = 0;
            for (rules.values.items) |payload| {
                const attributes = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 6, 7, 8 });
                if (!mem.eql(u8, try attributes.text(1), name) or !mem.eql(u8, try attributes.text(2), "input") or attributes.values[7] == null) continue;
                const metadata = try ScopedRuleMetadata.decode(try attributes.get(7));
                if (!mem.eql(u8, &metadata.effect_id, &token.effect_id)) continue;
                if (!std.meta.eql(metadata.scope, token.scope)) return error.ForeignState;
                try validateScopedDropRule(name, attributes, metadata);
                const handle = try attributes.number(u64, 3);
                if (handle == 0) return error.UnknownState;
                if (handle_count == handles.len) continue;
                handles[handle_count] = handle;
                handle_count += 1;
            }

            var payloads: [nft.max_scope_rule_parts * 2][2048]u8 align(4) = undefined;
            var batch_bytes: [128 * 1024]u8 align(4) = undefined;
            var related: [nft.max_scope_rule_parts * 2 + 2]u32 = undefined;
            var batch = nl.Batch.init(&batch_bytes);
            related[0] = sock.nextSeq();
            batch.begin(related[0], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
            var count: usize = 1;
            for (handles[0..handle_count], 0..) |handle, index| {
                const payload = nft.buildRuleDeletePayload(&payloads[index], name, "input", handle) catch |err| return netlinkError(err);
                related[count] = sock.nextSeq();
                batch.add(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.DELRULE), linux.NLM_F_REQUEST | linux.NLM_F_ACK, related[count], sock.port_id, payload) catch |err| return netlinkError(err);
                count += 1;
            }
            if (token.operation == .ensure_present) {
                const deadline = leaseDeadline(token.operation.ensure_present);
                for (0..part_count) |part| {
                    const metadata = ScopedRuleMetadata{ .effect_id = token.effect_id, .part = @intCast(part), .count = @intCast(part_count), .deadline_us = deadline, .scope = token.scope };
                    const userdata = try metadata.encode();
                    const payload = nft.buildScopedDropRulePayload(&payloads[handle_count + part], name, "input", token.scope, part, &userdata) catch |err| return scopeBuildError(err);
                    related[count] = sock.nextSeq();
                    // Why: 0x800 is NLM_F_APPEND (include/uapi/linux/netlink.h), which adds each rule at the end of the chain.
                    batch.add(
                        nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.NEWRULE),
                        linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL | 0x800,
                        related[count],
                        sock.port_id,
                        payload,
                    ) catch |err| return netlinkError(err);
                    count += 1;
                }
            }
            if (count == 1) return error.Changed;
            related[count] = sock.nextSeq();
            const bytes = batch.commit(related[count], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
            const send_timeout = @min(try self.remainingMs(timer), 2000);
            progress.requested = true;
            nl.sendKernel(&sock, bytes, send_timeout) catch |err| return netlinkError(err);
            nl.receiveAcknowledgments(&sock, related[count .. count + 1], related[0 .. count + 1], @min(try self.remainingMs(timer), 2000)) catch |err| return rejectedBatch(err, progress);
        }
        // Holds: readNft accepts only these values (hook 1 NF_INET_LOCAL_IN, priority -1, policy 1 NF_ACCEPT), so the two change together.
        pub fn createNft(self: *Inspector, name: []const u8, marker: []const u8, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
            var sock = nl.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| return netlinkError(err);
            defer sock.close();
            var payloads: [6][1024]u8 align(4) = undefined;
            const data = [_][]const u8{
                nft.buildOwnedTablePayload(&payloads[0], name, marker) catch |err| return netlinkError(err),
                nft.buildSetPayload(&payloads[1], nl.NFPROTO.INET, name, "banned_ipv4", 1, nft.NFT_TYPE.IPV4_ADDR, 4, 0) catch |err| return netlinkError(err),
                nft.buildSetPayload(&payloads[2], nl.NFPROTO.INET, name, "banned_ipv6", 2, nft.NFT_TYPE.IPV6_ADDR, 16, 0) catch |err| return netlinkError(err),
                nft.buildChainPayload(&payloads[3], nl.NFPROTO.INET, name, "input", 1, -1, "filter", 1) catch |err| return netlinkError(err),
                nft.buildDropRulePayload(&payloads[4], nl.NFPROTO.INET, name, "input", "banned_ipv4", nl.NFPROTO.IPV4, 12, 4) catch |err| return netlinkError(err),
                nft.buildDropRulePayload(&payloads[5], nl.NFPROTO.INET, name, "input", "banned_ipv6", nl.NFPROTO.IPV6, 8, 16) catch |err| return netlinkError(err),
            };
            var batch_bytes: [8192]u8 align(4) = undefined;
            var batch = nl.Batch.init(&batch_bytes);
            var related: [8]u32 = undefined;
            related[0] = sock.nextSeq();
            batch.begin(related[0], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
            const kinds = [_]u16{ nft.NFT_MSG.NEWTABLE, nft.NFT_MSG.NEWSET, nft.NFT_MSG.NEWSET, nft.NFT_MSG.NEWCHAIN, nft.NFT_MSG.NEWRULE, nft.NFT_MSG.NEWRULE };
            for (data, kinds, 1..) |payload, kind, index| {
                related[index] = sock.nextSeq();
                batch.add(
                    nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, kind),
                    linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL,
                    related[index],
                    sock.port_id,
                    payload,
                ) catch |err| return netlinkError(err);
            }
            related[7] = sock.nextSeq();
            const bytes = batch.commit(related[7], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
            const send_timeout = @min(try self.remainingMs(timer), 2000);
            progress.requested = true;
            nl.sendKernel(&sock, bytes, send_timeout) catch |err| return netlinkError(err);
            nl.receiveAcknowledgments(&sock, related[7..8], &related, @min(try self.remainingMs(timer), 2000)) catch |err| return netlinkError(err);
        }
    };
}
