import type { AuthClient } from "./auth.js";

export type ChangeEvent<T> =
  | { op: "INSERT" | "UPDATE"; table: string; record: T }
  | { op: "DELETE"; table: string; old_pk: Record<string, unknown> };

export interface RealtimeError {
  code: string;
  message: string;
}

interface Subscription {
  table: string;
  onChange: (event: ChangeEvent<never>) => void;
  onError?: (error: RealtimeError) => void;
}

const MAX_BACKOFF_MS = 30_000;

/**
 * One shared WebSocket per client. It opens on the first subscription, re-subscribes everything
 * after reconnects, and reconnects with a fresh token when the session changes or expires.
 * Delivery is at-most-once: refetch over REST after a reconnect if you need full consistency.
 */
export class RealtimeClient {
  #ws: WebSocket | null = null;
  #connecting = false;
  #subs = new Map<string, Subscription>();
  #counter = 0;
  #attempt = 0;

  constructor(
    private readonly url: string,
    private readonly apiKey: string,
    private readonly auth: AuthClient,
  ) {
    auth.onAuthStateChange(() => this.#ws?.close());
  }

  /** Returns a function that cancels the subscription. */
  subscribe<T>(
    table: string,
    onChange: (event: ChangeEvent<T>) => void,
    onError?: (error: RealtimeError) => void,
  ): () => void {
    const id = `s${++this.#counter}`;
    this.#subs.set(id, { table, onChange: onChange as Subscription["onChange"], onError });
    if (this.#ws?.readyState === WebSocket.OPEN) this.#send({ type: "subscribe", id, table });
    else void this.#connect();
    return () => {
      this.#subs.delete(id);
      this.#send({ type: "unsubscribe", id });
      if (this.#subs.size === 0) this.#ws?.close();
    };
  }

  async #connect(): Promise<void> {
    if (this.#ws || this.#connecting || this.#subs.size === 0) return;
    this.#connecting = true;
    try {
      const params = new URLSearchParams({ apikey: this.apiKey });
      const token = await this.auth.accessToken();
      if (token) params.set("access_token", token);
      const ws = new WebSocket(`${this.url.replace(/^http/, "ws")}/realtime/v1/websocket?${params}`);
      this.#ws = ws;
      ws.onopen = () => {
        this.#attempt = 0;
        for (const [id, sub] of this.#subs) this.#send({ type: "subscribe", id, table: sub.table });
      };
      ws.onmessage = (e) => this.#receive(String(e.data));
      ws.onclose = () => {
        this.#ws = null;
        if (this.#subs.size === 0) return;
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
    const sub = typeof msg.id === "string" ? this.#subs.get(msg.id) : undefined;
    if (msg.type === "change" && sub) {
      sub.onChange(msg as unknown as ChangeEvent<never>);
    } else if (msg.type === "error") {
      const error = { code: String(msg.code), message: String(msg.message) };
      // Errors without an id concern the whole connection.
      const targets = sub ? [sub] : [...this.#subs.values()];
      for (const s of targets) s.onError?.(error);
    }
  }

  #send(message: object): void {
    if (this.#ws?.readyState === WebSocket.OPEN) this.#ws.send(JSON.stringify(message));
  }
}
