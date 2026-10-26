import { AuthClient, type StorageAdapter } from "./auth.js";
import { RealtimeClient } from "./realtime.js";
import { Query } from "./rest.js";
import { StorageClient } from "./storage.js";

export type { AuthEvent, AuthListener, Credentials, Factor, Session, StorageAdapter, User } from "./auth.js";
export type { KilnbaseError, Result } from "./http.js";
export type { Channel, ChannelOptions, ChangeEvent, PresenceState, RealtimeError } from "./realtime.js";
export type { Query } from "./rest.js";
export type { BucketClient, StoredObject, TransformOptions, UploadOptions } from "./storage.js";

export interface ClientOptions {
  /**
   * Where the session is kept between page loads. Defaults to `localStorage` when available,
   * otherwise memory only. Pass `null` to never persist tokens.
   */
  storage?: StorageAdapter | null;
  storageKey?: string;
}

/** Shape of the `Database` type written by `kilnbase gen types`. */
type PublicRelations<DB> = DB extends { public: { Tables: infer T; Views: infer V } } ? T & V : never;
type Field<R, K extends string, Fallback> = R extends Record<K, infer F> ? F : Fallback;
type TypedQuery<R> = Query<
  Field<R, "Row", never>,
  Field<R, "Insert", Partial<Field<R, "Row", never>>>,
  Field<R, "Update", Partial<Field<R, "Row", never>>>
>;

export interface KilnbaseClient<DB = unknown> {
  auth: AuthClient;
  storage: StorageClient;
  realtime: RealtimeClient;
  /** Query a table in the `public` schema. */
  from: [PublicRelations<DB>] extends [never]
    ? <T = Record<string, unknown>>(table: string) => Query<T>
    : <K extends keyof PublicRelations<DB> & string>(table: K) => TypedQuery<PublicRelations<DB>[K]>;
}

/**
 * @param url Base URL of the Kilnbase gateway, e.g. `http://localhost:8000`.
 * @param apiKey The **anon** key. Never ship the service_role key to browsers.
 * @typeParam DB The `Database` type from `kilnbase gen types`, to type `from()` per table.
 */
export function createClient<DB = unknown>(
  url: string,
  apiKey: string,
  options: ClientOptions = {},
): KilnbaseClient<DB> {
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
    from: ((table: string) => new Query(base, table, headers)) as KilnbaseClient<DB>["from"],
  };
}
