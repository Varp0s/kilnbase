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
- **CLI**: `kilnbase init` also generates the S3 key pair, `kilnbase doctor` checks it (both or neither, length,
  reuse of another secret) and `kilnbase rotate-keys --s3` replaces it.
- **CLI**: `kilnbase backup` / `kilnbase restore` archive the database and stored files into one file and
  restore it after checking that its migrations match the running version.
- **CLI**: `kilnbase rotate-keys` switches to a new ES256 signing key without downtime (old keys stay in the
  JWKS until `--retire`) and reissues the anon and service_role keys.
- **CLI**: `kilnbase gen types` writes a TypeScript `Database` type for the tables the API exposes;
  `createClient<Database>()` types `from()` per table.
- **Storage**: buckets with size and MIME limits, uploads streamed to disk, RLS-decided access, public
  buckets, HMAC-signed links; downloads are served with `nosniff` and a sandboxing CSP.
- **Image transformations** (optional imgproxy service): resize, quality and format conversion at
  `/storage/v1/render/image/{authenticated,public}/…`, with the same access rules as downloads.
- **S3-compatible API** at `/storage/v1/s3` (path-style, SigV4 headers and presigned URLs): list, head,
  get with ranges, put (including `aws-chunked` bodies), multipart uploads and delete, with RLS applied to users who sign with
  their access token; an optional server key pair acts as service_role.
- **Resumable uploads** (tus 1.0 with creation and termination) at `/storage/v1/upload/resumable`: the
  policy and size limit are checked before any bytes arrive, uploads are private to their creator, and
  unfinished ones are removed after 24 hours.
- **Realtime**: WebSocket change feed where every insert and update is re-read as the subscriber, so RLS
  decides who receives it. Protocol in `docs/realtime-protocol.md`.
- **Realtime channels**: broadcast and presence, closed by default and opened per channel/action by
  `realtime.authorize()` (evaluated as the caller); per-connection rate and size limits.
- **Realtime resume**: changes go through a 10-minute outbox, so events committed while the server's
  database connection was down are replayed, and clients resume with `since` (the JS client does this
  automatically); gaps that are too old or too long answer `resync_required`.
- **JS/TS client** (`kilnbase` on npm, no runtime dependencies): auth with cross-tab-safe refresh, query
  builder, storage and realtime.
- **OAuth / OIDC sign-in**: GitHub, Google and generic OIDC providers; PKCE with the provider and with the
  app, single-use state and codes, redirect allow-list, verified-email-only account linking.
- **Passwordless email**: 6-digit codes and magic links over SMTP (implicit TLS or required STARTTLS),
  single-use, 10-minute expiry, burned after 5 wrong tries, send limits, no account enumeration.
- **Email confirmation and password reset**: per-purpose codes and links, `email_verified` claim for RLS,
  password changes require the current password or a reset session and sign out all other sessions.
- **Email change** confirmed by a code sent to the new address, with a notice to the old one.
- **Anonymous users** (opt-in): guest accounts with an `is_anonymous` claim that can later be upgraded in place.
- **MFA (TOTP)**: enrolment, single-use codes with ±30 s drift, rate-limited verification; enrolled users'
  password-only sessions get a token the APIs reject until the second factor is verified; refresh tokens issued
  before the upgrade are revoked. `KILNBASE_AUTH_MFA_REQUIRED=true` makes a second factor mandatory for every
  non-guest user.
- **Python SDK** (`sdk/python`): sync client with the same auth (passwordless, OAuth, MFA, anonymous), query and
  storage features as the JS client, including image transforms, and realtime (table changes with resume,
  broadcast and presence) on a background thread that reconnects as the current user after sign-in/out.
- **CLI**: `kilnbase init` (keys and secrets) and `kilnbase doctor` (secret and database security audit).
- **CORS**: any origin by default (header-based auth, no cookies) or an explicit allow-list.
- **Migrations** are checksummed; edited or unknown applied migrations stop the auth service.
- **Release gate** that keeps third-party platform code and dependencies out of shipped artifacts;
  multi-arch GHCR images with SBOM, provenance and cosign signatures.
- Example todo app, k6 benchmark (`docs/benchmarks.md`).

### Known limitations
- Realtime replays missed changes for up to 10 minutes; longer gaps answer `resync_required`. `DELETE` events
  carry only the primary key and reach every subscriber of the table.
- The S3 API does not verify `aws-chunked` chunk signatures or checksum trailers, and has no copy, batch
  delete, ACL or tagging operations.
- Auth rate limits are kept in memory per auth replica.
- An access token stays valid at the REST API until it expires (at most one hour) after sign-out.
