# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/);
until 1.0, minor releases may contain breaking changes, always called out below.

## [Unreleased]

First release candidate (planned as 0.1.0).

### Added
- **Stack**: Postgres 18, PostgREST, a Rust gateway (`core`) and a Python auth service, started with
  `kilnbase init` + `docker compose up`. Services refuse to start with missing or example secrets.
- **REST**: every table in `public` is served at `/rest/v1`, but only while row level security protects it;
  tables without RLS, views without `security_invoker` and materialized views are hidden automatically.
- **Auth**: email/password sign-up and sign-in, ES256 access tokens, single-use refresh tokens with reuse
  detection that revokes the whole session, argon2id hashing, per-email and per-IP rate limits.
- **Storage**: buckets with size and MIME limits, uploads streamed to disk, RLS-decided access, public
  buckets, HMAC-signed links; downloads are served with `nosniff` and a sandboxing CSP.
- **Realtime**: WebSocket change feed where every insert and update is re-read as the subscriber, so RLS
  decides who receives it. Protocol in `docs/realtime-protocol.md`.
- **JS/TS client** (`kilnbase` on npm, no runtime dependencies): auth with cross-tab-safe refresh, query
  builder, storage and realtime.
- **MFA (TOTP)**: enrolment, single-use codes with ±30 s drift, rate-limited verification; enrolled users'
  password-only sessions get a token the APIs reject until the second factor is verified; refresh tokens issued
  before the upgrade are revoked.
- **CLI**: `kilnbase init` (keys and secrets) and `kilnbase doctor` (secret and database security audit).
- **CORS**: any origin by default (header-based auth, no cookies) or an explicit allow-list.
- **Migrations** are checksummed; edited or unknown applied migrations stop the auth service.
- **Release gate** that keeps third-party platform code and dependencies out of shipped artifacts;
  multi-arch GHCR images with SBOM, provenance and cosign signatures.
- Example todo app, k6 benchmark (`docs/benchmarks.md`).

### Known limitations
- Realtime delivery is at-most-once; changes during a reconnect are lost. `DELETE` events carry only the
  primary key and reach every subscriber of the table.
- Auth rate limits are kept in memory per auth replica.
- An access token stays valid at the REST API until it expires (at most one hour) after sign-out.
