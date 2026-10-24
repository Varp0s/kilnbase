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
```

## License

[Apache-2.0](LICENSE)
