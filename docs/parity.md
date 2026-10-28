# Feature status

What Kilnbase has, what is planned, and what it leaves out on purpose. The README shows how to use each
feature; `CHANGELOG.md` says when it arrived and lists known limitations.

**Status:** ✅ available · 🟡 partial (see the note) · 🗓 planned · ⛔ out of scope

## Database

| Feature | Status | Notes |
|---|---|---|
| Postgres 18 | ✅ | Own image with pgBackRest; pgvector, pg_cron and pgmq available, none enabled by default |
| Row level security by default | ✅ | Tables without RLS (and views without `security_invoker`) are hidden from the API automatically |
| Schema migrations | ✅ | `kilnbase migrate`: checksummed, one transaction per file, refuses edited history |
| Vector search | ✅ | pgvector, in the `extensions` schema |
| Scheduled jobs | ✅ | pg_cron; managed in SQL or on Studio's Cron jobs page |
| Queues | ✅ | pgmq; managed in SQL or on Studio's Queues page. Not exposed as an HTTP API |
| Database webhooks | ✅ | Signed POSTs from a queue table that doubles as the delivery log; rolled-back writes are never sent |
| Backup and restore | ✅ | `kilnbase backup` / `restore`: database and stored files in one archive |
| Point-in-time recovery | ✅ | `kilnbase pitr` with pgBackRest |
| Branching | ⛔ | Hosted-platform feature; one install is one database |

## APIs

| Feature | Status | Notes |
|---|---|---|
| REST | ✅ | PostgREST behind the Rust gateway |
| GraphQL | ✅ | Optional PostGraphile at `/graphql/v1`, same RLS as REST |
| Database functions as RPC | ✅ | `public` functions via PostgREST; extension functions are not served |
| Generated TypeScript types | ✅ | `kilnbase gen types` |

## Auth

| Feature | Status | Notes |
|---|---|---|
| Email and password | ✅ | argon2id, per-email and per-IP rate limits |
| Single-use refresh tokens | ✅ | Reuse revokes the whole session family |
| Email confirmation, password reset, email change | ✅ | Over your own SMTP server |
| Magic links and one-time codes (email) | ✅ | |
| OAuth / OIDC | ✅ | GitHub, Google, any OIDC provider |
| SAML 2.0 SSO | ✅ | SP-initiated, each IdP limited to its own email domains |
| MFA (TOTP) | ✅ | Can be required for every user |
| Anonymous sign-in | ✅ | Opt-in; guests can be upgraded in place |
| Phone / SMS sign-in | ✅ | Codes through your own signed SMS hook; adding or changing a number is confirmed by a code; phone + password once a password is set |
| Key rotation without downtime | ✅ | `kilnbase rotate-keys` |

## Storage

| Feature | Status | Notes |
|---|---|---|
| Buckets, RLS-decided access, signed URLs | ✅ | Size and MIME limits per bucket |
| Resumable uploads (tus 1.0) | ✅ | |
| S3-compatible API | 🟡 | No ACL, tagging or versioning |
| Image transformations | ✅ | Optional imgproxy service |

## Realtime

| Feature | Status | Notes |
|---|---|---|
| Database changes | 🟡 | Filtered by RLS per subscriber; `DELETE` events carry only the primary key |
| Broadcast and presence | ✅ | Closed by default, opened per channel and action by policy |
| Resume after a disconnect | 🟡 | Up to 10 minutes; longer gaps answer `resync_required` |

## Functions

| Feature | Status | Notes |
|---|---|---|
| Python functions | ✅ | One nsjail sandbox per call, per-function secrets, wheels-only dependencies |
| TypeScript functions | 🟡 | Node 24 in the same sandbox; npm packages are not installed yet |

## Tools

| Feature | Status | Notes |
|---|---|---|
| Studio | ✅ | Tables and policies, table editor, SQL, users, view as user, storage, webhooks, queues, cron, logs |
| JS / TS client | ✅ | `kilnbase` on npm, no runtime dependencies |
| Python client | ✅ | `sdk/python` |
| Security audit | ✅ | `kilnbase doctor` |
| One-command upgrade with rollback | ✅ | `kilnbase upgrade` |
| Logs | ✅ | JSON lines per service, read in Studio; no separate log stack |
| Multi-tenant hosting, organizations, billing | ⛔ | Kilnbase is self-hosted, one project per install |
