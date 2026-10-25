// End-to-end against a running stack: `docker compose up` at the repo root, then `npm run test:e2e`.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { before, test } from "node:test";
import { createHmac, randomUUID } from "node:crypto";

import { createClient } from "../dist/index.js";

const ROOT = new URL("../../../", import.meta.url);
const URL_ = process.env.KILNBASE_URL ?? "http://localhost:8000";
const env = Object.fromEntries(
  readFileSync(new URL(".env", ROOT), "utf8")
    .split("\n")
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => {
      const i = l.indexOf("=");
      return [l.slice(0, i), l.slice(i + 1).replace(/^'|'$/g, "")];
    }),
);
const ANON = env.KILNBASE_ANON_KEY as string;
const SERVICE = env.KILNBASE_SERVICE_ROLE_KEY as string;

const client = () => createClient(URL_, ANON, { storage: null });
const credentials = () => ({ email: `sdk-${randomUUID().slice(0, 8)}@example.com`, password: "a long passphrase" });

before(async () => {
  execFileSync("docker", ["compose", "exec", "-T", "db", "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1"], {
    cwd: ROOT,
    input: `
      drop table if exists public.e2e_sdk;
      create table public.e2e_sdk (
        id bigint generated always as identity primary key,
        owner uuid not null default auth.uid(),
        title text not null
      );
      alter table public.e2e_sdk enable row level security;
      create policy own_sdk on public.e2e_sdk for all to authenticated
        using (owner = auth.uid()) with check (owner = auth.uid());
      select kilnbase.enable_realtime('public.e2e_sdk');
      drop policy if exists e2e_sdk_files on storage.objects;
      create policy e2e_sdk_files on storage.objects for all to authenticated
        using (bucket_id = 'e2e-sdk' and owner = auth.uid())
        with check (bucket_id = 'e2e-sdk' and owner = auth.uid());
      delete from storage.objects where bucket_id = 'e2e-sdk';
      delete from storage.buckets where id = 'e2e-sdk';
      insert into storage.buckets (id) values ('e2e-sdk');
      notify pgrst, 'reload schema';
    `,
  });
  // Wait for PostgREST to reload its schema cache.
  for (let i = 0; i < 50; i++) {
    const res = await fetch(`${URL_}/rest/v1/e2e_sdk`, { headers: { apikey: SERVICE } });
    if (res.ok) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("e2e_sdk never appeared");
});

test("auth + REST respect row level security", async () => {
  const a = client();
  const b = client();
  const signedUp = await a.auth.signUp(credentials());
  assert.equal(signedUp.error, null);
  await b.auth.signUp(credentials());

  const inserted = await a.from<{ id: number; title: string; owner: string }>("e2e_sdk").insert({ title: "mine" });
  assert.equal(inserted.error, null);
  assert.equal(inserted.data?.[0]?.owner, signedUp.data?.user.id);

  const mine = await a.from("e2e_sdk").select().eq("title", "mine");
  assert.equal(mine.data?.length, 1);
  const theirs = await b.from("e2e_sdk").select();
  assert.deepEqual(theirs.data, []);

  const one = await a.from("e2e_sdk").select("title").eq("title", "mine").single();
  assert.deepEqual(one.data, { title: "mine" });
});

test("errors are returned, not thrown", async () => {
  const c = client();
  const bad = await c.auth.signInWithPassword({ email: "nobody@example.com", password: "wrong password" });
  assert.equal(bad.data, null);
  assert.equal(bad.error?.code, "invalid_credentials");
  const missing = await c.from("no_such_table").select();
  assert.equal(missing.data, null);
  assert.ok(missing.error);
});

test("concurrent refreshes collapse into one rotation", async () => {
  const c = client();
  const first = (await c.auth.signUp(credentials())).data!;
  const results = await Promise.all([c.auth.refreshSession(), c.auth.refreshSession(), c.auth.refreshSession()]);
  for (const r of results) assert.equal(r.error, null);
  const rotated = results.map((r) => r.data!.refresh_token);
  assert.notEqual(rotated[0], first.refresh_token);
  assert.equal(new Set(rotated).size, 1);
  // Session would have been revoked if the same refresh token had been sent twice.
  const user = await c.auth.getUser();
  assert.equal(user.error, null);
});

test("two clients sharing storage do not replay a spent refresh token", async () => {
  // Simulates two tabs over one localStorage.
  const shared = new Map<string, string>();
  const storage = {
    getItem: (k: string) => shared.get(k) ?? null,
    setItem: (k: string, v: string) => void shared.set(k, v),
    removeItem: (k: string) => void shared.delete(k),
  };
  const tab1 = createClient(URL_, ANON, { storage });
  const tab2 = createClient(URL_, ANON, { storage });
  await tab1.auth.signUp(credentials());
  assert.equal((await tab2.auth.getUser()).error, null);
  assert.equal((await tab1.auth.refreshSession()).error, null);
  // tab2 still holds the old token in memory, but re-reads storage before refreshing.
  assert.equal((await tab2.auth.refreshSession()).error, null);
  assert.equal((await tab1.auth.getUser()).error, null);
});

test("sign out ends the session", async () => {
  const c = client();
  const events: string[] = [];
  c.auth.onAuthStateChange((e) => events.push(e));
  await c.auth.signUp(credentials());
  await c.auth.signOut();
  assert.deepEqual(events, ["SIGNED_IN", "SIGNED_OUT"]);
  assert.equal((await c.auth.getUser()).error?.code, "not_signed_in");
});

test("storage round trip and signed URLs", async () => {
  const c = client();
  await c.auth.signUp(credentials());
  const bucket = c.storage.from("e2e-sdk");
  const path = `notes/${randomUUID()}.txt`;

  const up = await bucket.upload(path, "hello sdk", { contentType: "text/plain" });
  assert.equal(up.error, null);
  assert.equal(up.data?.size, 9);
  assert.equal((await bucket.upload(path, "again")).error?.code, "already_exists");
  assert.equal((await bucket.upload(path, "replaced", { upsert: true })).error, null);

  const down = await bucket.download(path);
  assert.equal(await down.data?.text(), "replaced");

  const signed = await bucket.createSignedUrl(path, 60);
  assert.equal(await (await fetch(signed.data!.signedUrl)).text(), "replaced");

  assert.equal((await bucket.remove(path)).error, null);
  assert.equal((await bucket.download(path)).error?.status, 404);
});

test("realtime delivers own inserts only", async () => {
  const a = client();
  const b = client();
  await a.auth.signUp(credentials());
  await b.auth.signUp(credentials());

  const seenByA: unknown[] = [];
  const seenByB: unknown[] = [];
  const ready = (c: ReturnType<typeof client>, sink: unknown[]) =>
    new Promise<() => void>((resolve, reject) => {
      const stop = c.realtime.subscribe("e2e_sdk", (e) => sink.push(e), reject);
      // The server confirms asynchronously; give it a moment before writing.
      setTimeout(() => resolve(stop), 500);
    });
  const stopA = await ready(a, seenByA);
  const stopB = await ready(b, seenByB);

  await a.from("e2e_sdk").insert({ title: "live" });
  for (let i = 0; i < 50 && seenByA.length === 0; i++) await new Promise((r) => setTimeout(r, 100));
  await new Promise((r) => setTimeout(r, 500));
  stopA();
  stopB();

  assert.equal(seenByA.length, 1);
  assert.equal((seenByA[0] as { record: { title: string } }).record.title, "live");
  assert.deepEqual(seenByB, []);
});

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s) for tests, without a dependency. */
function totp(secretBase32: string, at = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secretBase32.replace(/=+$/, "")) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const h = createHmac("sha1", key).update(counter).digest();
  const offset = h[h.length - 1]! & 0xf;
  return String((h.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

test("MFA: enrolled users need a code before the API accepts them", async () => {
  const c = client();
  const creds = credentials();
  await c.auth.signUp(creds);
  const factor = (await c.auth.mfa.enroll()).data!;
  // Distinct time steps, since each code is single-use.
  const enrolled = await c.auth.mfa.verify(factor.id, totp(factor.secret, Date.now() - 30_000));
  assert.equal(enrolled.error, null);

  const pending = await c.auth.signInWithPassword(creds);
  assert.equal(pending.data?.mfa_required, true);
  assert.equal((await c.from("e2e_sdk").select()).error?.status, 401);

  const done = await c.auth.mfa.verify(factor.id, totp(factor.secret));
  assert.equal(done.data?.mfa_required, false);
  assert.equal((await c.from("e2e_sdk").select()).error, null);
  assert.equal((await c.auth.mfa.unenroll(factor.id)).error, null);
});

test("OAuth: provider sign-in with PKCE", async (t) => {
  const mock = "http://localhost:9100";
  try {
    await fetch(`${mock}/healthz`);
  } catch {
    t.skip("mock provider not running (docker-compose.test.yml)");
    return;
  }
  const email = `sdk-oauth-${randomUUID().slice(0, 8)}@example.com`;
  await fetch(`${mock}/next`, {
    method: "POST",
    body: JSON.stringify({ sub: randomUUID(), email, email_verified: true }),
  });
  const c = client();
  const { url } = (await c.auth.signInWithOAuth("mock", { redirectTo: "http://localhost:3000/callback" })).data!;
  // Follow the browser's redirects by hand: gateway -> provider -> gateway callback -> app.
  let location = url;
  for (let hop = 0; hop < 3; hop++) {
    const res = await fetch(location, { redirect: "manual" });
    location = new URL(res.headers.get("location")!, location).toString();
  }
  const code = new URL(location).searchParams.get("code")!;
  const session = await c.auth.exchangeCodeForSession(code);
  assert.equal(session.error, null);
  assert.equal(session.data?.user.email, email);
  assert.equal((await c.from("e2e_sdk").select()).error, null);
});

test("passwordless email code", async (t) => {
  const mailpit = "http://localhost:8025";
  try {
    await fetch(`${mailpit}/api/v1/info`);
  } catch {
    t.skip("mail server not running (docker-compose.test.yml)");
    return;
  }
  const c = client();
  const email = `sdk-otp-${randomUUID().slice(0, 8)}@example.com`;
  assert.equal((await c.auth.signInWithOtp({ email })).error, null);
  let text = "";
  for (let i = 0; i < 50 && !text; i++) {
    const found = (await (await fetch(`${mailpit}/api/v1/search?query=to:${encodeURIComponent(email)}`)).json()) as {
      messages: { ID: string }[];
    };
    if (found.messages.length) {
      text = ((await (await fetch(`${mailpit}/api/v1/message/${found.messages[0]!.ID}`)).json()) as { Text: string }).Text;
    } else await new Promise((r) => setTimeout(r, 100));
  }
  const token = /code is (\d{6})/.exec(text)![1]!;
  const session = await c.auth.verifyOtp({ type: "email", email, token });
  assert.equal(session.data?.user.email, email);
});

test("anonymous user upgrades to a permanent account", async () => {
  const c = client();
  const guest = await c.auth.signInAnonymously();
  assert.equal(guest.data?.user.is_anonymous, true);
  const id = guest.data!.user.id;
  const creds = credentials();
  assert.equal((await c.auth.updateUser({ email: creds.email, password: creds.password })).error, null);
  const user = (await c.auth.getUser()).data!;
  assert.equal(user.is_anonymous, false);
  const again = await client().auth.signInWithPassword(creds);
  assert.equal(again.data?.user.id, id);
});

test("channels: broadcast and presence", async () => {
  execFileSync("docker", ["compose", "exec", "-T", "db", "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1"], {
    cwd: ROOT,
    input: `create or replace function realtime.authorize(channel text, action text) returns boolean
      language sql stable as $$ select channel like 'sdk-room:%' and auth.role() = 'authenticated' $$;`,
  });
  try {
    const a = client();
    const b = client();
    await a.auth.signUp(credentials());
    await b.auth.signUp(credentials());
    const room = `sdk-room:${randomUUID()}`;
    const received: unknown[] = [];
    let presence: Record<string, unknown> = {};
    const chA = a.realtime.channel(room, { onPresence: (s) => (presence = s) });
    const chB = b.realtime.channel(room, { onBroadcast: (event, payload) => received.push({ event, payload }) });
    await new Promise((r) => setTimeout(r, 500));
    chA.track({ name: "ada" });
    chA.send("hello", { n: 1 });
    for (let i = 0; i < 50 && (received.length === 0 || Object.keys(presence).length === 0); i++) {
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.deepEqual(received, [{ event: "hello", payload: { n: 1 } }]);
    assert.deepEqual(Object.values(presence).map((p) => (p as { state: unknown }).state), [{ name: "ada" }]);
    // Leaving every channel closes the sockets, so the test process can exit.
    chA.leave();
    chB.leave();
  } finally {
    execFileSync("docker", ["compose", "exec", "-T", "db", "psql", "-U", "postgres"], {
      cwd: ROOT,
      input: "create or replace function realtime.authorize(channel text, action text) returns boolean language sql stable as $$ select false $$;",
    });
  }
});
