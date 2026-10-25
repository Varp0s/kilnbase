import { type KilnbaseError, type Result, fail, isError, ok, request, toError } from "./http.js";

export interface User {
  id: string;
  /** null for anonymous users until they add one. */
  email: string | null;
  is_anonymous: boolean;
  email_confirmed_at: string | null;
  created_at: string;
  last_sign_in_at: string | null;
}

export interface Session {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  expires_in: number;
  /** Unix seconds. */
  expires_at: number;
  user: User;
  /** True when the user has MFA enrolled and this session still needs `mfa.verify()`. */
  mfa_required: boolean;
}

export interface Factor {
  id: string;
  type: "totp";
  /** Base32 secret and `otpauth://` URI to show as a QR code; only returned on enrolment. */
  secret: string;
  uri: string;
}

export interface Credentials {
  email: string;
  password: string;
}

/** Anything shaped like `localStorage`; may be async. */
export interface StorageAdapter {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

export type AuthEvent = "SIGNED_IN" | "SIGNED_OUT" | "TOKEN_REFRESHED";
export type AuthListener = (event: AuthEvent, session: Session | null) => void;

/** Refresh this many seconds before expiry so in-flight requests never carry a dead token. */
const REFRESH_MARGIN = 60;

const now = () => Math.floor(Date.now() / 1000);

const base64url = (bytes: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

export class AuthClient {
  #session: Session | null = null;
  #loaded = false;
  #refreshing: Promise<Result<Session>> | null = null;
  #listeners = new Set<AuthListener>();
  #verifier: string | null = null;

  constructor(
    private readonly url: string,
    private readonly apiKey: string,
    private readonly storage: StorageAdapter | null,
    private readonly storageKey: string,
  ) {}

  signUp(credentials: Credentials): Promise<Result<Session>> {
    return this.#obtain("/auth/v1/signup", credentials, "SIGNED_IN");
  }

  /** A guest account (must be enabled on the server); keep it later with `updateUser({ email, password })`. */
  signInAnonymously(): Promise<Result<Session>> {
    return this.#obtain("/auth/v1/anonymous", {}, "SIGNED_IN");
  }

  /**
   * Changes the password (send `currentPassword`, unless signed in through a password reset), or turns an
   * anonymous user into a permanent one when `email` is given. Other sessions are signed out.
   */
  async updateUser(changes: { password: string; currentPassword?: string; email?: string }): Promise<Result<null>> {
    const res = await this.#authed("/auth/v1/user", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: changes.password, current_password: changes.currentPassword, email: changes.email }),
    });
    if ("error" in res) return { data: null, error: res.error };
    if (!res.ok) return toError(res);
    // An upgrade returns a fresh session (the anonymous flag is gone from the token).
    if (res.status === 200) await this.#set((await res.json()) as Session, "TOKEN_REFRESHED");
    return ok(null);
  }

  signInWithPassword(credentials: Credentials): Promise<Result<Session>> {
    return this.#obtain("/auth/v1/token?grant_type=password", credentials, "SIGNED_IN");
  }

  /**
   * Starts a provider sign-in. Send the browser to the returned URL; the provider sends it back to
   * `redirectTo` with `?code=...`, which `exchangeCodeForSession` turns into a session. The PKCE
   * verifier never leaves this client, so an intercepted code is useless.
   */
  async signInWithOAuth(provider: string, { redirectTo }: { redirectTo: string }): Promise<Result<{ url: string }>> {
    const verifier = base64url(crypto.getRandomValues(new Uint8Array(48)));
    const challenge = base64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
    // Survives the full-page redirect when storage is available.
    this.#verifier = verifier;
    await this.storage?.setItem(`${this.storageKey}:pkce`, verifier);
    const params = new URLSearchParams({ provider, redirect_to: redirectTo, code_challenge: challenge });
    return ok({ url: `${this.url}/auth/v1/authorize?${params}` });
  }

  /**
   * Emails a 6-digit code, plus a magic link to `redirectTo` when given. The response is identical
   * whether or not the address has an account.
   */
  async signInWithOtp({
    email,
    redirectTo,
    createUser = true,
  }: {
    email: string;
    redirectTo?: string;
    createUser?: boolean;
  }): Promise<Result<null>> {
    const res = await request(`${this.url}/auth/v1/otp`, {
      method: "POST",
      headers: { apikey: this.apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ email, redirect_to: redirectTo, create_user: createUser }),
    });
    if (isError(res)) return { data: null, error: res };
    return res.ok ? ok(null) : toError(res);
  }

  /** `type: "email"` with the emailed code, or `type: "magiclink"` with the `token` from the link. */
  verifyOtp(params: { type: "email"; email: string; token: string } | { type: "magiclink"; token: string }) {
    return this.#obtain("/auth/v1/verify", params, "SIGNED_IN");
  }

  async exchangeCodeForSession(code: string): Promise<Result<Session>> {
    const verifier = this.#verifier ?? (await this.storage?.getItem(`${this.storageKey}:pkce`)) ?? null;
    if (!verifier) return fail(400, "missing_verifier", "call signInWithOAuth in this browser first");
    this.#verifier = null;
    await this.storage?.removeItem(`${this.storageKey}:pkce`);
    return this.#obtain("/auth/v1/token?grant_type=authorization_code", { code, code_verifier: verifier }, "SIGNED_IN");
  }

  /** Ends the session on the server too, so its refresh token stops working everywhere. */
  async signOut(): Promise<Result<null>> {
    const session = await this.#current();
    if (session) {
      await request(`${this.url}/auth/v1/logout`, {
        method: "POST",
        headers: { apikey: this.apiKey, Authorization: `Bearer ${session.access_token}` },
      });
    }
    await this.#set(null, "SIGNED_OUT");
    return ok(null);
  }

  /** The current session, refreshed first if it is about to expire. */
  async getSession(): Promise<Session | null> {
    const session = await this.#current();
    if (session && session.expires_at - REFRESH_MARGIN <= now()) {
      const refreshed = await this.refreshSession();
      return refreshed.data;
    }
    return session;
  }

  async getUser(): Promise<Result<User>> {
    const session = await this.getSession();
    if (!session) return fail(401, "not_signed_in", "no active session");
    const res = await request(`${this.url}/auth/v1/user`, {
      headers: { apikey: this.apiKey, Authorization: `Bearer ${session.access_token}` },
    });
    if (isError(res)) return { data: null, error: res };
    return res.ok ? ok((await res.json()) as User) : toError(res);
  }

  /**
   * Refresh tokens are single-use and replaying one ends the session, so concurrent refreshes are
   * collapsed into one — within this client, and across tabs via the Web Locks API when present.
   */
  refreshSession(): Promise<Result<Session>> {
    const seen = this.#session?.refresh_token;
    this.#refreshing ??= this.#withLock(() => this.#refresh(seen)).finally(() => {
      this.#refreshing = null;
    });
    return this.#refreshing;
  }

  /** TOTP second factor. Once a factor is verified, sign-ins need `verify()` before the API accepts them. */
  readonly mfa = {
    enroll: async (): Promise<Result<Factor>> => {
      const res = await this.#authed("/auth/v1/factors", { method: "POST" });
      if ("error" in res) return { data: null, error: res.error };
      return res.ok ? ok((await res.json()) as Factor) : toError(res);
    },
    /** Confirms an enrolment or completes a pending sign-in; the session is upgraded on success. */
    verify: async (factorId: string, code: string): Promise<Result<Session>> => {
      const res = await this.#authed(`/auth/v1/factors/${encodeURIComponent(factorId)}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      if ("error" in res) return { data: null, error: res.error };
      if (!res.ok) return toError(res);
      const session = (await res.json()) as Session;
      await this.#set(session, "SIGNED_IN");
      return ok(session);
    },
    unenroll: async (factorId: string): Promise<Result<null>> => {
      const res = await this.#authed(`/auth/v1/factors/${encodeURIComponent(factorId)}`, { method: "DELETE" });
      if ("error" in res) return { data: null, error: res.error };
      return res.ok ? ok(null) : toError(res);
    },
  };

  async #authed(path: string, init: RequestInit): Promise<Response | { error: KilnbaseError }> {
    const session = await this.getSession();
    if (!session) return { error: { status: 401, code: "not_signed_in", message: "no active session" } };
    const res = await request(`${this.url}${path}`, {
      ...init,
      headers: { ...(init.headers as Record<string, string>), apikey: this.apiKey, Authorization: `Bearer ${session.access_token}` },
    });
    return isError(res) ? { error: res } : res;
  }

  onAuthStateChange(listener: AuthListener): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  /** @internal Token for outgoing requests; null means "use the API key". */
  async accessToken(): Promise<string | null> {
    return (await this.getSession())?.access_token ?? null;
  }

  async #refresh(seen: string | undefined): Promise<Result<Session>> {
    // Another tab may have rotated the token while we waited for the lock; reuse its result
    // instead of replaying a token that is already spent.
    this.#loaded = false;
    const session = await this.#current();
    if (!session) return fail(401, "not_signed_in", "no active session");
    if (seen !== undefined && session.refresh_token !== seen) return ok(session);

    const res = await request(`${this.url}/auth/v1/token?grant_type=refresh_token`, {
      method: "POST",
      headers: { apikey: this.apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: session.refresh_token }),
    });
    if (isError(res)) return { data: null, error: res };
    if (!res.ok) {
      const error = await toError<Session>(res);
      if (res.status === 401) await this.#set(null, "SIGNED_OUT");
      return error;
    }
    const fresh = (await res.json()) as Session;
    await this.#set(fresh, "TOKEN_REFRESHED");
    return ok(fresh);
  }

  async #obtain(path: string, credentials: object, event: AuthEvent): Promise<Result<Session>> {
    const res = await request(`${this.url}${path}`, {
      method: "POST",
      headers: { apikey: this.apiKey, "Content-Type": "application/json" },
      body: JSON.stringify(credentials),
    });
    if (isError(res)) return { data: null, error: res };
    if (!res.ok) return toError(res);
    const session = (await res.json()) as Session;
    await this.#set(session, event);
    return ok(session);
  }

  async #current(): Promise<Session | null> {
    if (!this.#loaded && this.storage) {
      const raw = await this.storage.getItem(this.storageKey);
      try {
        this.#session = raw ? (JSON.parse(raw) as Session) : null;
      } catch {
        this.#session = null;
      }
    }
    this.#loaded = true;
    return this.#session;
  }

  async #set(session: Session | null, event: AuthEvent): Promise<void> {
    this.#session = session;
    this.#loaded = true;
    if (this.storage) {
      if (session) await this.storage.setItem(this.storageKey, JSON.stringify(session));
      else await this.storage.removeItem(this.storageKey);
    }
    for (const listener of this.#listeners) listener(event, session);
  }

  #withLock<T>(fn: () => Promise<T>): Promise<T> {
    const locks = (globalThis.navigator as { locks?: LockManager } | undefined)?.locks;
    return locks ? locks.request(`${this.storageKey}:refresh`, fn) : fn();
  }
}
