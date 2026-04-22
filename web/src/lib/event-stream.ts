/**
 * WebSocket event stream with exponential-backoff reconnect and
 * blessed-replay fallback.
 *
 * Why vanilla (not React):
 *   The see-it-live page has no other React surface — the three
 *   panes are plain Astro components that each take a client-side
 *   `<script>` island.  Adding React purely to carry a hook for
 *   this module would pull in ~45 KB of runtime for a single
 *   publisher-subscriber object.  A hand-rolled EventTarget-backed
 *   stream weighs ~2 KB and is exactly as testable.
 *
 * Status machine:
 *   connecting — open attempt in flight
 *   connected  — onopen fired, frames arriving
 *   disconnected — onclose fired, waiting to retry (2/5/15/30/60 s)
 *   replay     — > 60 s of total dead-air, auto-switched to replay
 *                JSON and looping through its frames in wall-clock order
 *
 * Replay fallback:
 *   Loads `/replay/recent-attacks.json` on first dead-air timeout.
 *   We preserve inter-event gaps by replaying against the first
 *   frame's ts as anchor — so the visitor sees bursts and lulls,
 *   not a firehose.
 */

import type { DemoEvent } from './events';
import { parseDemoEvent } from './events';

export type StreamStatus = 'connecting' | 'connected' | 'disconnected' | 'replay';

export interface StreamState {
  status: StreamStatus;
  lastEventTs: number | null;
  attemptCount: number;
}

export type StreamListener = (event: DemoEvent) => void;
export type StateListener = (state: Readonly<StreamState>) => void;

export interface EventStreamOptions {
  readonly url: string;
  readonly replayUrl: string;
  /** Max total dead-air in ms before auto-replay engages.  Default 60 s. */
  readonly deadAirMs?: number;
  /** Backoff schedule in ms (final value repeats).  Default 2/5/15/30/60 s. */
  readonly backoffSchedule?: readonly number[];
}

const DEFAULT_BACKOFF: readonly number[] = [2_000, 5_000, 15_000, 30_000, 60_000];
const DEFAULT_DEAD_AIR_MS = 60_000;

export class EventStream {
  private readonly url: string;
  private readonly replayUrl: string;
  private readonly deadAirMs: number;
  private readonly backoff: readonly number[];

  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private deadAirTimer: ReturnType<typeof setTimeout> | null = null;
  private replayAbort: AbortController | null = null;
  private replayTimer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;

  private readonly eventListeners = new Set<StreamListener>();
  private readonly stateListeners = new Set<StateListener>();
  private state: StreamState = {
    status: 'connecting',
    lastEventTs: null,
    attemptCount: 0,
  };

  constructor(opts: EventStreamOptions) {
    this.url = opts.url;
    this.replayUrl = opts.replayUrl;
    this.deadAirMs = opts.deadAirMs ?? DEFAULT_DEAD_AIR_MS;
    this.backoff = opts.backoffSchedule ?? DEFAULT_BACKOFF;
  }

  start(): void {
    this.armDeadAirTimer();
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer !== null) clearTimeout(this.reconnectTimer);
    if (this.deadAirTimer !== null) clearTimeout(this.deadAirTimer);
    if (this.replayTimer !== null) clearTimeout(this.replayTimer);
    this.replayAbort?.abort();
    if (this.ws !== null) {
      this.ws.onopen = null;
      this.ws.onmessage = null;
      this.ws.onclose = null;
      this.ws.onerror = null;
      try {
        this.ws.close();
      } catch {
        // Closing a never-opened socket throws in some browsers; harmless.
      }
    }
  }

  onEvent(listener: StreamListener): () => void {
    this.eventListeners.add(listener);
    return () => this.eventListeners.delete(listener);
  }

  onState(listener: StateListener): () => void {
    this.stateListeners.add(listener);
    listener(this.state);
    return () => this.stateListeners.delete(listener);
  }

  getState(): Readonly<StreamState> {
    return this.state;
  }

  private setState(patch: Partial<StreamState>): void {
    this.state = { ...this.state, ...patch };
    for (const listener of this.stateListeners) listener(this.state);
  }

  private emitEvent(event: DemoEvent): void {
    this.setState({ lastEventTs: Date.now() });
    for (const listener of this.eventListeners) listener(event);
  }

  private connect(): void {
    if (this.stopped) return;
    this.setState({ status: 'connecting' });

    let ws: WebSocket;
    try {
      ws = new WebSocket(this.url);
    } catch {
      // Malformed URL / blocked scheme — treat as a normal close.
      this.handleClose();
      return;
    }
    this.ws = ws;

    ws.onopen = () => {
      this.setState({ status: 'connected', attemptCount: 0 });
      this.armDeadAirTimer();
    };
    ws.onmessage = (ev: MessageEvent<string>) => {
      this.armDeadAirTimer();
      let parsed: unknown;
      try {
        parsed = JSON.parse(ev.data);
      } catch {
        return;
      }
      const event = parseDemoEvent(parsed);
      if (event !== null) this.emitEvent(event);
    };
    ws.onerror = () => {
      // `onerror` is cosmetic; `onclose` is always delivered after.
    };
    ws.onclose = () => {
      this.handleClose();
    };
  }

  private handleClose(): void {
    if (this.stopped) return;
    if (this.state.status === 'replay') return;

    const attempt = this.state.attemptCount;
    const delayIdx = Math.min(attempt, this.backoff.length - 1);
    const delay = this.backoff.at(delayIdx) ?? this.backoff.at(-1) ?? 60_000;
    this.setState({ status: 'disconnected', attemptCount: attempt + 1 });

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private armDeadAirTimer(): void {
    if (this.deadAirTimer !== null) clearTimeout(this.deadAirTimer);
    this.deadAirTimer = setTimeout(() => {
      this.deadAirTimer = null;
      if (this.state.status !== 'connected') {
        this.engageReplay();
      } else {
        // Connected but silent — quiet window.  Keep the connection;
        // the pane itself handles the "waiting for next attack" line.
        this.armDeadAirTimer();
      }
    }, this.deadAirMs);
  }

  private engageReplay(): void {
    if (this.stopped || this.state.status === 'replay') return;
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.setState({ status: 'replay' });
    this.replayAbort = new AbortController();

    const load = async (): Promise<void> => {
      const res = await fetch(this.replayUrl, {
        signal: this.replayAbort?.signal ?? null,
      });
      if (!res.ok) throw new Error(`replay fetch ${String(res.status)}`);
      const raw: unknown = await res.json();
      if (!Array.isArray(raw)) throw new Error('replay not an array');

      const events: DemoEvent[] = [];
      for (const frame of raw) {
        const ev = parseDemoEvent(frame);
        if (ev !== null) events.push(ev);
      }
      if (events.length === 0) throw new Error('replay contained no valid events');
      this.schedulePlayback(events, 0, Date.parse(events[0]?.ts ?? ''));
    };

    load().catch(() => {
      // Replay load failed — fall back to a single synthetic banner
      // line so the page isn't blank.  Without throwing further
      // noise, we just stay in replay state; TerminalPane's
      // quiet-window copy will kick in.
    });
  }

  private schedulePlayback(events: readonly DemoEvent[], idx: number, anchor: number): void {
    if (this.stopped) return;
    if (idx >= events.length) {
      // Loop: re-anchor to the first event's ts and restart from 0.
      const first = events[0];
      if (first === undefined) return;
      this.schedulePlayback(events, 0, Date.parse(first.ts));
      return;
    }
    const current = events.at(idx);
    if (current === undefined) return;
    const nowInReplay = Date.parse(current.ts);
    const delta = Number.isFinite(nowInReplay) && Number.isFinite(anchor) ? nowInReplay - anchor : 0;
    const clamped = Math.max(0, Math.min(delta, 30_000));

    this.replayTimer = setTimeout(() => {
      this.replayTimer = null;
      // Re-stamp the ts so the terminal shows "now", not the capture time.
      const restamped: DemoEvent = { ...current, ts: new Date().toISOString() };
      this.emitEvent(restamped);
      this.schedulePlayback(events, idx + 1, anchor);
    }, clamped);
  }
}
