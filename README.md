# Kilnbase

Open-source, self-hosted backend: Postgres, Auth, REST, Realtime and Storage — secure by default, fast, and simple to run.

> **Status:** early development (pre-0.1). Not ready for production.

## Quick start

Requirements: Docker and [uv](https://docs.astral.sh/uv/).

```sh
uv run kilnbase init        # generates .env with fresh keys and passwords
docker compose up -d
curl localhost:8000/health
```

`kilnbase init` refuses to overwrite an existing `.env`, and every service refuses to start with missing or example secrets.

### Security check

```sh
uv run kilnbase doctor
```

Audits `.env` (missing or example secrets, weak passwords, file permissions) and the running database:
tables reachable without RLS (for example after a manual `GRANT`), views that bypass RLS, unconditional write
policies for `anon`, `SECURITY DEFINER` functions callable from the API, and public buckets. Exits non-zero on
anything blocking, so it fits in CI.

### Rotating keys

```sh
uv run kilnbase rotate-keys && docker compose up -d            # new signing key, old one still accepted
# ...hand the new KILNBASE_ANON_KEY / KILNBASE_SERVICE_ROLE_KEY to your apps, wait at least 1 hour...
uv run kilnbase rotate-keys --retire && docker compose up -d   # stop accepting the old key
```

Rotation never logs anyone out: the JWKS keeps the previous public keys, so existing sessions and the old API
keys stay valid until `--retire`. `.env` is rewritten atomically and keeps its file permissions.

`uv run kilnbase rotate-keys --s3` replaces only the S3 key pair (and adds one to an older `.env`). Core accepts a
single pair, so there is no overlap: the old pair stops working on the next `docker compose up -d`.

### Backup and restore

```sh
uv run kilnbase backup -o kilnbase.tar     # database (pg_dump) + stored files, one file
uv run kilnbase restore kilnbase.tar       # asks first; --yes for scripts
```

No local Postgres tools are needed: the dump runs inside the `db` container. `restore` refuses a backup whose
migrations differ from the running version, stops the other services while it runs, and only replaces the
database once the dump has restored cleanly into a scratch copy. The archive holds password hashes and all user
data, so treat it like a secret; it does not contain `.env`, which you must keep separately (without the same
keys, restored sessions and API keys are invalid). Only the local storage volume is included.

### TypeScript types

```sh
uv run kilnbase gen types -o src/database.ts   # stdout without -o; --schema to pick another schema
```

Writes a `Database` type (Row / Insert / Update per table, enums as unions) for every relation the API can
read. Pass it to the client to type `from()`: `createClient<Database>(url, ANON_KEY)`.

### JavaScript / TypeScript client

```js
import { createClient } from "kilnbase";

const kb = createClient("http://localhost:8000", ANON_KEY);

await kb.auth.signUp({ email: "ada@example.com", password: "a long passphrase" });

const { data, error } = await kb.from("todos").select().eq("done", false).order("id");
await kb.from("todos").insert({ title: "write docs" });

await kb.storage.from("avatars").upload("ada/me.png", file, { upsert: true });

const stop = kb.realtime.subscribe("todos", (change) => console.log(change.op, change));
```

Calls resolve to `{ data, error }` and never throw on HTTP errors. Sessions refresh themselves before they
expire, and concurrent refreshes — including from other tabs — are collapsed so a refresh token is never
replayed. The package has no runtime dependencies.

### REST API

Every table in `public` is served at `/rest/v1/<table>`, but **only while row level security protects it** —
tables without RLS, views without `security_invoker`, and materialized views are hidden automatically.

```sql
create table todos (
  id bigint generated always as identity primary key,
  owner uuid not null default auth.uid(),
  title text not null
);
alter table todos enable row level security;
create policy own_todos on todos for all to authenticated
  using (owner = auth.uid()) with check (owner = auth.uid());
```

```sh
curl localhost:8000/rest/v1/todos \
  -H "apikey: $KILNBASE_ANON_KEY" \
  -H "Authorization: Bearer <user access token>"
```

### Auth

```sh
# sign up (or sign in with grant_type=password) — returns access_token + refresh_token
curl -X POST localhost:8000/auth/v1/signup -H "apikey: $KILNBASE_ANON_KEY" \
  -H "Content-Type: application/json" -d '{"email":"ada@example.com","password":"a long passphrase"}'

curl -X POST "localhost:8000/auth/v1/token?grant_type=refresh_token" -H "apikey: $KILNBASE_ANON_KEY" \
  -H "Content-Type: application/json" -d '{"refresh_token":"..."}'

curl localhost:8000/auth/v1/user -H "apikey: $KILNBASE_ANON_KEY" -H "Authorization: Bearer <access_token>"
curl -X POST localhost:8000/auth/v1/logout -H "apikey: $KILNBASE_ANON_KEY" -H "Authorization: Bearer <access_token>"
```

- Passwords are hashed with argon2id; access tokens are ES256 JWTs valid for one hour.
- Refresh tokens are single-use. Presenting a used one again is treated as theft and ends the whole session.
- Failed sign-ins are rate limited per email and per client IP.

**Sign in with GitHub, Google or any OIDC provider.** Set `KILNBASE_OAUTH_GITHUB_CLIENT_ID` /
`_CLIENT_SECRET` (or `GOOGLE`; other names also need `_AUTHORIZE_URL`, `_TOKEN_URL`, `_USERINFO_URL`), register
`<KILNBASE_PUBLIC_URL>/auth/v1/callback` with the provider, and list your app in `KILNBASE_AUTH_REDIRECT_URLS`.

```js
const { data } = await kb.auth.signInWithOAuth("github", { redirectTo: "https://app.example.com/callback" });
location.href = data.url;
// on /callback:
await kb.auth.exchangeCodeForSession(new URLSearchParams(location.search).get("code"));
```

The flow uses PKCE twice (with the provider, and between your app and Kilnbase), so tokens never travel in
URLs and an intercepted code is useless. Redirects only go to allow-listed URLs, and a provider account is only
linked to an existing user when the provider reports the email as verified.

**Passwordless email.** `POST /auth/v1/otp {"email", "redirect_to"?}` mails a 6-digit code (and a magic link when
`redirect_to` is allow-listed); `POST /auth/v1/verify` with `{"type":"email","email","token"}` or
`{"type":"magiclink","token"}` returns a session. Codes are single-use, expire after 10 minutes and die after
5 wrong tries; sending is limited per address and per client, and the answer never reveals whether an account
exists. Set `KILNBASE_SMTP_URL` (`smtps://user:pass@host` or `smtp://` with STARTTLS); without it, mail is printed
to the auth log for local development. JS: `kb.auth.signInWithOtp({ email })`, `kb.auth.verifyOtp(...)`.

**Email confirmation and password reset.** With SMTP configured, password sign-ups get a confirmation mail
(`POST /auth/v1/verify {"type":"signup", ...}`); access tokens carry `email_verified`, so a policy can require it:
`using ((auth.jwt() ->> 'email_verified')::boolean and owner = auth.uid())`. `POST /auth/v1/recover {"email"}`
mails a reset code/link; verifying it (`"type":"recovery"`) yields a session that may call
`PUT /auth/v1/user {"password"}` once without the current password. Ordinary sessions must send
`current_password`. Any password change signs out every other session. A reset never bypasses MFA.

**Changing the email.** `PUT /auth/v1/user {"email", "current_password"}` mails a code to the new address and a
heads-up to the old one; `POST /auth/v1/user/email/verify {"token"}` from the same user's session applies it and
signs out every other session.

**Anonymous users.** With `KILNBASE_AUTH_ANONYMOUS=true`, `POST /auth/v1/anonymous` creates a guest user (rate
limited per IP) whose token carries `is_anonymous: true`, so policies can treat guests differently. Sending
`PUT /auth/v1/user {"email", "password"}` later turns the guest into a permanent account with the same id and
data. JS: `kb.auth.signInAnonymously()`, `kb.auth.updateUser({ email, password })`.

**Two-factor (TOTP).** `POST /auth/v1/factors` returns a secret and an `otpauth://` URI for any authenticator
app; `POST /auth/v1/factors/<id>/verify {"code": "123456"}` confirms it. From then on a password sign-in returns
`"mfa_required": true` and a token the REST, storage and realtime APIs reject until the code is verified — MFA is
enforced for every enrolled user without extra configuration. Set `KILNBASE_AUTH_MFA_REQUIRED=true` to require
it of everyone: users without a factor then get the same restricted token, which can only enrol and verify one
(guest users are exempt). Codes are single-use and wrong codes are rate
limited. In the JS client: `kb.auth.mfa.enroll()`, `kb.auth.mfa.verify(id, code)`, `kb.auth.mfa.unenroll(id)`.

### Storage

```sh
# create a bucket (service_role only); public buckets are readable without credentials
curl -X POST localhost:8000/storage/v1/bucket -H "apikey: $KILNBASE_SERVICE_ROLE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"id":"avatars","public":false,"file_size_limit":1048576,"allowed_mime_types":["image/*"]}'

# upload (POST creates, PUT creates or replaces), download, delete
curl -X POST localhost:8000/storage/v1/object/avatars/ada/me.png -H "apikey: $KILNBASE_ANON_KEY" \
  -H "Authorization: Bearer <access_token>" -H "Content-Type: image/png" --data-binary @me.png
curl localhost:8000/storage/v1/object/avatars/ada/me.png -H "apikey: $KILNBASE_ANON_KEY" -H "Authorization: Bearer <access_token>"

# time-limited link anyone can open
curl -X POST localhost:8000/storage/v1/object/sign/avatars/ada/me.png -H "apikey: $KILNBASE_ANON_KEY" \
  -H "Authorization: Bearer <access_token>" -H "Content-Type: application/json" -d '{"expires_in":3600}'
```

Large files can be uploaded resumably with any [tus 1.0](https://tus.io/protocols/resumable-upload) client:
endpoint `/storage/v1/upload/resumable`, metadata `bucketName`, `objectName` and `contentType`, plus the usual
`apikey` and `Authorization` headers. Unfinished uploads are deleted after 24 hours.

Images can be resized and converted on the fly once the optional imgproxy service is on
(`COMPOSE_PROFILES=images` and `KILNBASE_IMGPROXY_URL=http://imgproxy:8080` in `.env`):

```bash
# width/height 1-2500, resize=cover|contain|fill, quality 1-100, format=origin|webp|avif|jpeg|png
curl "localhost:8000/storage/v1/render/image/authenticated/avatars/ada/me.png?width=200&format=webp" \
  -H "apikey: $KILNBASE_ANON_KEY" -H "Authorization: Bearer <access_token>"
# public buckets: /storage/v1/render/image/public/<bucket>/<name>
```

From the JS client: `download(path, { transform: { width: 200 } })` or `getPublicUrl(path, { transform })`.

The same RLS check as a download decides access; imgproxy only reads stored files and is reachable from `core` alone.

Existing S3 tools and SDKs work against `http://localhost:8000/storage/v1/s3` (path-style addressing,
SigV4, region `us-east-1` unless `KILNBASE_S3_REGION` says otherwise). Two kinds of credentials:

- **Servers:** `KILNBASE_S3_ACCESS_KEY_ID` and `KILNBASE_S3_SECRET_ACCESS_KEY` (32+ characters, generated by
  `kilnbase init`); that pair acts as `service_role`, so never ship it to clients.
- **Users:** any access key id, with the user's access token as both the secret key and the session token;
  RLS decides exactly as for the native API.

```python
s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:8000/storage/v1/s3",
    region_name="us-east-1",
    aws_access_key_id="user",
    aws_secret_access_key=access_token,
    aws_session_token=access_token,
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)
```

Supported: ListBuckets, ListObjectsV2, Head/Get (with ranges)/Put/DeleteObject, multipart uploads and SigV4
presigned URLs. Copies, batch deletes, ACLs and tagging answer `NotImplemented`. A TLS proxy in front must
keep the `Host` header, which is part of the signature.

Access to a file is access to its row in `storage.objects`, so sharing rules are ordinary RLS policies:

```sql
create policy own_avatars on storage.objects for all to authenticated
  using (bucket_id = 'avatars' and owner = auth.uid())
  with check (bucket_id = 'avatars' and owner = auth.uid());
```

Uploads stream to disk with the size limit enforced while bytes arrive. Files are stored under their database ID, never under the client-supplied name, and are served with `nosniff` and a sandboxing CSP so uploaded HTML cannot run on your API's origin.

### Realtime

```sql
select kilnbase.enable_realtime('public.todos');
```

```js
const ws = new WebSocket(`ws://localhost:8000/realtime/v1/websocket?apikey=${anonKey}&access_token=${accessToken}`);
ws.onopen = () => ws.send(JSON.stringify({ type: "subscribe", id: "todos", table: "todos" }));
ws.onmessage = (e) => console.log(JSON.parse(e.data)); // {type:"change", op:"INSERT", record:{...}}
```

Every insert and update is re-read as the subscriber, so clients only receive rows their RLS policies allow.
**Broadcast and presence channels** carry messages between clients (cursors, typing, who is online). They are
closed until you replace `realtime.authorize(channel, action)`, which runs as the calling user:

```js
const room = kb.realtime.channel("room:42", {
  onBroadcast: (event, payload) => console.log(event, payload),
  onPresence: (state) => console.log(Object.values(state)), // [{ user, state }]
});
room.track({ name: "Ada" });
room.send("cursor", { x: 10 });
```

See [docs/realtime-protocol.md](docs/realtime-protocol.md).

## Architecture

| Service | Language | Role |
|---|---|---|
| `core` | Rust | Gateway (API keys, JWT verification, rate limiting), storage, realtime |
| `auth` | Python | Sign-up, sign-in, tokens; the only holder of the signing key |
| `postgrest` | PostgREST | Auto-generated REST API, reachable only through `core` |
| `db` | PostgreSQL 18 | Data, row level security |

API keys are ES256 JWTs. `KILNBASE_ANON_KEY` is safe for clients; `KILNBASE_SERVICE_ROLE_KEY` bypasses row level security and must never leave your servers.

## Development

```sh
uv sync && uv run pytest              # Python unit tests (auth, cli)
# end-to-end, needs the stack plus the test-only mock OAuth provider:
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
KILNBASE_E2E=1 uv run pytest tests/e2e
cd core && cargo test                 # Rust (core)
cd sdk/js && npm ci && npm test       # SDK unit tests; npm run test:e2e needs the stack
```

## License

[Apache-2.0](LICENSE)
