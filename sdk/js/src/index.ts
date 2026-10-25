import { AuthClient, type StorageAdapter } from "./auth.js";
import { RealtimeClient } from "./realtime.js";
import { Query } from "./rest.js";
import { StorageClient } from "./storage.js";

export type { AuthEvent, AuthListener, Credentials, Factor, Session, StorageAdapter, User } from "./auth.js";
export type { KilnbaseError, Result } from "./http.js";
export type { Channel, ChannelOptions, ChangeEvent, PresenceState, RealtimeError } from "./realtime.js";
export type { Query } from "./rest.js";
export type { BucketClient, StoredObject, UploadOptions } from "./storage.js";

export interface ClientOptions {
  /**
   * Where the session is kept between page loads. Defaults to `localStorage` when available,
   * otherwise memory only. Pass `null` to never persist tokens.
   */
  storage?: StorageAdapter | null;
  storageKey?: string;
}

export interface KilnbaseClient {
  auth: AuthClient;
  storage: StorageClient;
  realtime: RealtimeClient;
  /** Query a table in the `public` schema. */
  from<T = Record<string, unknown>>(table: string): Query<T>;
}

/**
 * @param url Base URL of the Kilnbase gateway, e.g. `http://localhost:8000`.
 * @param apiKey The **anon** key. Never ship the service_role key to browsers.
 */
export function createClient(url: string, apiKey: string, options: ClientOptions = {}): KilnbaseClient {
  const base = url.replace(/\/+$/, "");
  const storage =
    options.storage !== undefined
      ? options.storage
      : ((globalThis as { localStorage?: StorageAdapter }).localStorage ?? null);
  const auth = new AuthClient(base, apiKey, storage, options.storageKey ?? "kilnbase.session");

  const headers = async (): Promise<Record<string, string>> => {
    const token = await auth.accessToken();
    return token ? { apikey: apiKey, Authorization: `Bearer ${token}` } : { apikey: apiKey };
  };

  return {
    auth,
    storage: new StorageClient(base, headers),
    realtime: new RealtimeClient(base, apiKey, auth),
    from: <T = Record<string, unknown>>(table: string) => new Query<T>(base, table, headers),
  };
}
