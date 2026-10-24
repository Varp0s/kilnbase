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

## Architecture

| Service | Language | Role |
|---|---|---|
| `core` | Rust | Gateway (API keys, JWT verification, rate limiting), storage, realtime |
| `auth` | Python | Sign-up, sign-in, tokens; the only holder of the signing key |
| `db` | PostgreSQL 18 | Data, row level security |

API keys are ES256 JWTs. `KILNBASE_ANON_KEY` is safe for clients; `KILNBASE_SERVICE_ROLE_KEY` bypasses row level security and must never leave your servers.

## Development

```sh
uv sync && uv run pytest              # Python (auth, cli)
cd core && cargo test                 # Rust (core)
```

## License

[Apache-2.0](LICENSE)
