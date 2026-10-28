# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/);
until 1.0, minor releases may contain breaking changes, always called out below.

## [Unreleased]

### Added
- **Auth**: phone sign-in with texted 6-digit codes, sent through a signed HTTP hook of your own
  (`KILNBASE_SMS_URL`, `KILNBASE_SMS_SECRET`), so any SMS provider works. Access tokens and the user carry the
  verified `phone`; Studio shows it and finds users by it. The JS and Python clients accept `phone` in
  `signInWithOtp` / `verifyOtp`. Signed-in users add or change their number with a texted code
  (`PUT /auth/v1/user {"phone"}`, then `POST /auth/v1/user/phone/verify`), which also lets an anonymous user
  keep their account with just a phone.
- **Clients**: the JS and Python clients change a user's email or phone (`updateUser({ email | phone })`, then
  `confirmEmailChange` / `confirmPhoneChange`); `password` is no longer required by `updateUser`.
- **Auth**: password sign-in with a verified phone number instead of an email, once the user set a password.
- **Studio**: table editor (browse rows a page at a time; insert, edit and delete rows of tables with a primary
  key, as service_role).
- **Studio**: SQL editor (runs as the database superuser in one transaction, optionally rolled back; first
  500 rows shown).
- **Studio**: create users (with or without a password), confirm their email, end all their sessions and delete
  them; the user list shows sign-in and session details.
- **Studio**: storage browser (create buckets; browse files by folder; upload, download and delete).
- **Studio**: webhook management (create, enable, disable, delete; retry failed deliveries). Only the URL's host
  is shown, since chat webhooks carry their secret in the path.
- **Studio**: database overview (version, size, connections) and extensions, enabled into the `extensions`
  schema where they allow it.
- **Studio**: Connect page (API URL, anon key, client snippets) and "Enable RLS" / "Add policy" shortcuts that
  open the SQL editor with a statement to review.
- **Studio**: queues page (create, purge and delete pgmq queues; send a message; peek at messages without
  consuming them).
- **Studio**: cron jobs page (schedule SQL with pg_cron, enable, disable, delete; the newest runs). A name that
  is taken is refused rather than silently replaced.
- **Logs**: core, auth, functions and Studio also write their JSON log lines to a per-service volume (10 MB,
  one rotation); Studio reads them read-only. Postgres, PostgREST and imgproxy still log to stderr only.
- **Functions**: TypeScript functions (`functions/<name>/main.ts`) on Node 24, in the same per-call sandbox as
  Python ones, returning a body or a `Response`.
- **S3 API**: CopyObject and UploadPartCopy (within or across buckets, metadata `COPY` or `REPLACE`, ETag
  preconditions), so boto3's managed `copy()` works at any size, and DeleteObjects (up to 1000 keys). RLS
  decides as the caller: a copy needs read access to the source and write access to the target.

### Changed
- **Releases**: an `edge` image channel, built from `main` every night once CI has passed on that commit (also
  tagged `edge-<commit>`).
- **Studio**: new look: a sidebar with grouped sections, a sign-in card, light and dark themes that follow the
  system, consistent tables, badges and forms, and a layout that works on phones. The open page is kept in the
  URL. The UI is built with Vite (still no framework: about 11 KB gzipped); `npm run dev` in `studio/web` serves
  it with live reload against a running Studio.
- **Studio**: an Overview home page (counts, health checks for tables without RLS, failed webhook deliveries and
  recent errors), confirmation dialogs and toasts instead of browser prompts, loading placeholders and empty
  states, a light / dark / system theme switch, and the Inter typeface served by Studio itself.

### Security
- **S3 API**: streamed (`aws-chunked`) uploads are verified: every chunk signature and a signed trailer must chain
  from the request signature, and `x-amz-checksum-*` values (CRC32, CRC32C, CRC64/NVME, SHA-1, SHA-256, sent as a
  header or trailer) must match the stored bytes. A failed check stores nothing. SigV4a (ECDSA) streaming answers
  `NotImplemented`.

### Fixed
- **Studio**: the sign-in form no longer stays visible after signing in.
- **S3 API**: multipart completion bodies are now checked against `x-amz-content-sha256`.

## [0.8.0] - 2026-10-27

First tagged release.

### Added
- **Stack**: Postgres 18, PostgREST, a Rust gateway (`core`) and a Python auth service, started with
  `kilnbase init` + `docker compose up`. Services refuse to start with missing or example secrets.
- **REST**: every table in `public` is served at `/rest/v1`, but only while row level security protects it;
  tables without RLS, views without `security_invoker` and materialized views are hidden automatically.
- **Auth**: email/password sign-up and sign-in, ES256 access tokens, single-use refresh tokens with reuse
  detection that revokes the whole session, argon2id hashing, per-email and per-IP rate limits.
- **CLI**: `kilnbase init` also generates the S3 key pair, `kilnbase doctor` checks it (both or neither, length,
  reuse of another secret) and `kilnbase rotate-keys --s3` replaces it.
- **Auth**: SAML 2.0 single sign-on (SP-initiated) next to OAuth, configured per IdP with
  `KILNBASE_SAML_<NAME>_*`; each IdP may only sign in emails in its own domains.
- **GraphQL** (optional, `graphql` profile): PostGraphile at `/graphql/v1` over the tables `/rest/v1` serves,
  with tokens verified by the service itself and every request run as the caller under row level security.
- **Point-in-time recovery** (`kilnbase pitr enable|backup|list|restore`) with pgBackRest in the `db` image;
  restores are validated before anything stops and print an undo command. `kilnbase restore` and `pitr restore`
  keep realtime and webhook event ids increasing so clients' deduplication never drops new events.
- **CLI**: `kilnbase upgrade` backs up with writes stopped, starts the new version and, if a migration or a
  service fails, restores the data and the previous images automatically.
- **CLI**: `kilnbase migrate` applies the project's SQL files from `db/migrations` (one transaction each,
  checksummed, refuses edited or out-of-order history); `kilnbase migrate new <name>` creates one.
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
- **Postgres image** (`ghcr.io/varp0s/kilnbase-postgres`) with pgvector, pg_cron and pgmq available (not
  enabled), plus an `extensions` schema that keeps extension functions out of the REST API.
- **Functions** (optional, `COMPOSE_PROFILES=functions`): Python handlers at `/functions/v1/<name>`, each call in
  its own nsjail sandbox (namespaces, read-only root, syscall filter, time/memory/process limits) on a network
  that cannot reach the database; caller tokens are verified again inside the runner. `functions/requirements.txt`
  is installed at start-up from wheels only; `functions/.secrets` gives each function only its own variables.
- **Studio** (optional, `COMPOSE_PROFILES=studio`): tables with their RLS state and policies, users, webhook
  deliveries, and "view as user", which shows exactly the rows the REST API returns to a given user or to anon.
- **Webhooks**: `kilnbase.create_webhook()` sends table changes as signed (HMAC-SHA256) POSTs, queued in the
  writing transaction, retried with backoff and logged in `kilnbase.webhook_deliveries`.
- **Logs**: `core` and `auth` write JSON lines in one shape (`ts`, `level`, `service`, `msg`), including a
  request log without query strings, so tokens in links never reach the logs.
- **CORS**: any origin by default (header-based auth, no cookies) or an explicit allow-list.
- **Migrations** are checksummed; edited or unknown applied migrations stop the auth service.
- Multi-arch GHCR images with SBOM and provenance attestations.
- Example todo app, k6 benchmark (`docs/benchmarks.md`).

### Known limitations
- Realtime replays missed changes for up to 10 minutes; longer gaps answer `resync_required`. `DELETE` events
  carry only the primary key and reach every subscriber of the table.
- The S3 API does not verify `aws-chunked` chunk signatures or checksum trailers, and has no copy, batch
  delete, ACL or tagging operations.
- Auth rate limits are kept in memory per auth replica.
- An access token stays valid at the REST API until it expires (at most one hour) after sign-out.
