/**
 * fail2zig demo event schema.
 *
 * Mirrors the four event types emitted by the engine's WebSocket
 * broadcaster (see `engine/net/ws.zig`).  This file is the only place
 * the wire shapes are described — TerminalPane, NftSetPane,
 * MetricsPane, and the event stream module all import from here so a
 * wire-schema change causes a single compile error, not a scavenger
 * hunt.
 *
 * All four variants share `type` and `ts` (engine emits ISO-8601
 * strings).  Payload shapes differ per variant and live on `payload`.
 */

export type JailName = string;

/** Attacker match before a ban threshold trips. */
export interface AttackDetectedPayload {
  readonly ip: string;
  readonly jail: JailName;
  readonly pattern_name: string;
}

/** An attacker has been added to the nftables drop set. */
export interface IpBannedPayload {
  readonly ip: string;
  readonly jail: JailName;
  readonly bantime_s: number;
}

/** A ban has expired and been removed from the set. */
export interface IpUnbannedPayload {
  readonly ip: string;
  readonly jail: JailName;
}

/** Point-in-time counter snapshot broadcast alongside the ban feed. */
export interface MetricsPayload {
  readonly lines_parsed: number;
  readonly lines_matched: number;
  readonly bans_total: number;
  readonly active_bans: number;
  readonly memory_bytes_used: number;
  readonly uptime_s: number;
}

interface EventBase<TType extends string, TPayload> {
  readonly type: TType;
  readonly ts: string;
  readonly payload: TPayload;
}

export type AttackDetectedEvent = EventBase<'attack_detected', AttackDetectedPayload>;
export type IpBannedEvent = EventBase<'ip_banned', IpBannedPayload>;
export type IpUnbannedEvent = EventBase<'ip_unbanned', IpUnbannedPayload>;
export type MetricsEvent = EventBase<'metrics', MetricsPayload>;

export type DemoEvent = AttackDetectedEvent | IpBannedEvent | IpUnbannedEvent | MetricsEvent;

export type EventType = DemoEvent['type'];

/**
 * Single ban row in `/api/bans` — matches the JSON emitted by the
 * engine (`engine/net/http.zig`, Phase 9B.1).
 *
 * `seconds_remaining` is pre-computed server-side so the UI never has
 * to do its own clock arithmetic.  The API already caps responses to
 * 200 rows; the UI caps again defensively.
 */
export interface BanRow {
  readonly ip: string;
  readonly jail: JailName;
  readonly banned_at: string;
  readonly seconds_remaining: number;
}

export interface BansSnapshot {
  readonly total: number;
  readonly entries: readonly BanRow[];
}

/**
 * Best-effort runtime validation of a decoded JSON value from the WS.
 *
 * This runs on every frame, so it has to be cheap — we validate
 * enough to keep downstream code sound (narrowed discriminated
 * union) without trying to be a full JSON schema validator.  A
 * malformed frame is dropped silently, preserving stream continuity.
 */
export function parseDemoEvent(raw: unknown): DemoEvent | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const obj = raw as Record<string, unknown>;
  if (typeof obj.type !== 'string' || typeof obj.ts !== 'string') return null;
  const payload = obj.payload;
  if (typeof payload !== 'object' || payload === null) return null;
  const p = payload as Record<string, unknown>;

  switch (obj.type) {
    case 'attack_detected':
      if (
        typeof p.ip !== 'string' ||
        typeof p.jail !== 'string' ||
        typeof p.pattern_name !== 'string'
      ) {
        return null;
      }
      return {
        type: 'attack_detected',
        ts: obj.ts,
        payload: { ip: p.ip, jail: p.jail, pattern_name: p.pattern_name },
      };
    case 'ip_banned':
      if (
        typeof p.ip !== 'string' ||
        typeof p.jail !== 'string' ||
        typeof p.bantime_s !== 'number'
      ) {
        return null;
      }
      return {
        type: 'ip_banned',
        ts: obj.ts,
        payload: { ip: p.ip, jail: p.jail, bantime_s: p.bantime_s },
      };
    case 'ip_unbanned':
      if (typeof p.ip !== 'string' || typeof p.jail !== 'string') return null;
      return {
        type: 'ip_unbanned',
        ts: obj.ts,
        payload: { ip: p.ip, jail: p.jail },
      };
    case 'metrics': {
      if (
        typeof p.lines_parsed !== 'number' ||
        typeof p.lines_matched !== 'number' ||
        typeof p.bans_total !== 'number' ||
        typeof p.active_bans !== 'number' ||
        typeof p.memory_bytes_used !== 'number' ||
        typeof p.uptime_s !== 'number'
      ) {
        return null;
      }
      return {
        type: 'metrics',
        ts: obj.ts,
        payload: {
          lines_parsed: p.lines_parsed,
          lines_matched: p.lines_matched,
          bans_total: p.bans_total,
          active_bans: p.active_bans,
          memory_bytes_used: p.memory_bytes_used,
          uptime_s: p.uptime_s,
        },
      };
    }
    default:
      return null;
  }
}

/**
 * Runtime validator for `/api/bans`.  Same cheap-but-sound posture
 * as `parseDemoEvent` — enough to narrow for downstream consumers,
 * no more.
 */
export function parseBansSnapshot(raw: unknown): BansSnapshot | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const obj = raw as Record<string, unknown>;
  if (typeof obj.total !== 'number' || !Array.isArray(obj.entries)) return null;
  const entries: BanRow[] = [];
  for (const entry of obj.entries) {
    if (typeof entry !== 'object' || entry === null) continue;
    const e = entry as Record<string, unknown>;
    if (
      typeof e.ip !== 'string' ||
      typeof e.jail !== 'string' ||
      typeof e.banned_at !== 'string' ||
      typeof e.seconds_remaining !== 'number'
    ) {
      continue;
    }
    entries.push({
      ip: e.ip,
      jail: e.jail,
      banned_at: e.banned_at,
      seconds_remaining: e.seconds_remaining,
    });
  }
  return { total: obj.total, entries };
}
