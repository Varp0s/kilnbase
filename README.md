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
KILNBASE_E2E=1 uv run pytest tests/e2e  # end-to-end, needs the stack running
cd core && cargo test                 # Rust (core)
cd sdk/js && npm ci && npm test       # SDK unit tests; npm run test:e2e needs the stack
```

## License

[Apache-2.0](LICENSE)
