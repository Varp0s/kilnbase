import type { AuthClient } from "./auth.js";

export type ChangeEvent<T> =
  | { op: "INSERT" | "UPDATE"; event_id: number; table: string; record: T }
  | { op: "DELETE"; event_id: number; table: string; old_pk: Record<string, unknown> };

export interface RealtimeError {
  code: string;
  message: string;
}

/** Everyone currently tracked on a channel, keyed by connection. */
export type PresenceState = Record<string, { user: string | null; state: unknown }>;

export interface ChannelOptions {
  onBroadcast?: (event: string, payload: unknown) => void;
  /** Called with the full, current presence state whenever it changes. */
  onPresence?: (state: PresenceState) => void;
  onError?: (error: RealtimeError) => void;
}

export interface Channel {
  /** Sends to every other member (and to yourself with `{ self: true }`). */
  send(event: string, payload?: unknown, options?: { self?: boolean }): void;
  /** Publishes (or replaces) your presence state; it is restored after reconnects. */
  track(state: unknown): void;
  untrack(): void;
  leave(): void;
}

interface Subscription {
  table: string;
  onChange: (event: ChangeEvent<never>) => void;
  onError?: (error: RealtimeError) => void;
  /** Newest event received, sent as `since` on resubscribe so missed changes are replayed. */
  last?: number;
  /** Recently delivered ids: a resume can repeat events that also arrive live. */
  recent: Set<number>;
}

interface ChannelEntry {
  options: ChannelOptions;
  tracked: unknown;
  presence: PresenceState;
}

const MAX_BACKOFF_MS = 30_000;
const RECENT_IDS = 1000;
const joinId = (name: string) => `ch:${name}`;

/**
 * One shared WebSocket per client. It opens on the first subscription or channel, re-subscribes and
 * re-joins everything after reconnects, and reconnects with a fresh token when the session changes
 * or expires. Subscriptions resume where they left off; on a `resync_required` error, refetch over REST.
 */
export class RealtimeClient {
  #ws: WebSocket | null = null;
  #connecting = false;
  #subs = new Map<string, Subscription>();
  #channels = new Map<string, ChannelEntry>();
  #counter = 0;
  #attempt = 0;

  constructor(
    private readonly url: string,
    private readonly apiKey: string,
    private readonly auth: AuthClient,
  ) {
    auth.onAuthStateChange(() => this.#ws?.close());
  }

  /** Row changes for a table enabled with `kilnbase.enable_realtime`. Returns a function that cancels it. */
  subscribe<T>(
    table: string,
    onChange: (event: ChangeEvent<T>) => void,
    onError?: (error: RealtimeError) => void,
  ): () => void {
    const id = `s${++this.#counter}`;
    this.#subs.set(id, { table, onChange: onChange as Subscription["onChange"], onError, recent: new Set() });
    if (this.#open()) this.#send({ type: "subscribe", id, table });
    else void this.#connect();
    return () => {
      this.#subs.delete(id);
      this.#send({ type: "unsubscribe", id });
      this.#closeIfIdle();
    };
  }

  /** Joins a broadcast/presence channel; access is decided by `realtime.authorize()` on the server. */
  channel(name: string, options: ChannelOptions = {}): Channel {
    const entry: ChannelEntry = { options, tracked: undefined, presence: {} };
    this.#channels.set(name, entry);
    if (this.#open()) this.#send({ type: "join", id: joinId(name), channel: name });
    else void this.#connect();
    return {
      send: (event, payload = {}, { self = false } = {}) =>
        this.#send({ type: "broadcast", channel: name, event, payload, self }),
      track: (state) => {
        entry.tracked = state;
        this.#send({ type: "presence", channel: name, state });
      },
      untrack: () => {
        entry.tracked = undefined;
        this.#send({ type: "presence", channel: name, state: null });
      },
      leave: () => {
        this.#channels.delete(name);
        this.#send({ type: "leave", channel: name });
        this.#closeIfIdle();
      },
    };
  }

  #open(): boolean {
    return this.#ws?.readyState === WebSocket.OPEN;
  }

  #idle(): boolean {
    return this.#subs.size === 0 && this.#channels.size === 0;
  }

  #closeIfIdle(): void {
    if (this.#idle()) this.#ws?.close();
  }

  async #connect(): Promise<void> {
    if (this.#ws || this.#connecting || this.#idle()) return;
    this.#connecting = true;
    try {
      const params = new URLSearchParams({ apikey: this.apiKey });
      const token = await this.auth.accessToken();
      if (token) params.set("access_token", token);
      const ws = new WebSocket(`${this.url.replace(/^http/, "ws")}/realtime/v1/websocket?${params}`);
      this.#ws = ws;
      ws.onopen = () => {
        this.#attempt = 0;
        for (const [id, sub] of this.#subs) this.#send({ type: "subscribe", id, table: sub.table, since: sub.last });
        for (const name of this.#channels.keys()) this.#send({ type: "join", id: joinId(name), channel: name });
      };
      ws.onmessage = (e) => this.#receive(String(e.data));
      ws.onclose = () => {
        this.#ws = null;
        if (this.#idle()) return;
        const delay = Math.min(MAX_BACKOFF_MS, 500 * 2 ** this.#attempt++);
        setTimeout(() => void this.#connect(), delay);
      };
    } finally {
      this.#connecting = false;
    }
  }

  #receive(raw: string): void {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return;
    }
    const channelName = typeof msg.channel === "string" ? msg.channel : undefined;
    const entry = channelName === undefined ? undefined : this.#channels.get(channelName);

    switch (msg.type) {
      case "change": {
        const sub = this.#subs.get(String(msg.id));
        const eventId = Number(msg.event_id);
        if (!sub || sub.recent.has(eventId)) return;
        sub.recent.add(eventId);
        if (sub.recent.size > RECENT_IDS) sub.recent.delete(sub.recent.values().next().value as number);
        sub.last = Math.max(sub.last ?? eventId, eventId);
        sub.onChange(msg as unknown as ChangeEvent<never>);
        return;
      }
      case "joined":
        // Presence is per connection, so it has to be re-published after every (re)join.
        if (entry && entry.tracked !== undefined) {
          this.#send({ type: "presence", channel: channelName, state: entry.tracked });
        }
        return;
      case "broadcast":
        entry?.options.onBroadcast?.(String(msg.event), msg.payload);
        return;
      case "presence_state":
        if (entry) {
          entry.presence = { ...(msg.state as PresenceState) };
          entry.options.onPresence?.(entry.presence);
        }
        return;
      case "presence_diff":
        if (entry) {
          for (const key of Object.keys(msg.leaves as PresenceState)) delete entry.presence[key];
          Object.assign(entry.presence, msg.joins as PresenceState);
          entry.options.onPresence?.({ ...entry.presence });
        }
        return;
      case "error": {
        const error = { code: String(msg.code), message: String(msg.message) };
        const id = typeof msg.id === "string" ? msg.id : undefined;
        const sub = id ? this.#subs.get(id) : undefined;
        const channel = id?.startsWith("ch:") ? this.#channels.get(id.slice(3)) : undefined;
        if (sub) sub.onError?.(error);
        else if (channel) channel.options.onError?.(error);
        else {
          // Errors without an id concern the whole connection.
          for (const s of this.#subs.values()) s.onError?.(error);
          for (const c of this.#channels.values()) c.options.onError?.(error);
        }
        return;
      }
    }
  }

  #send(message: object): void {
    if (this.#open()) this.#ws!.send(JSON.stringify(message));
  }
}
