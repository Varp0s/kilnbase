import hmac
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

import asyncpg
import httpx2 as httpx
from argon2 import PasswordHasher
from fastapi import Depends, FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from kilnbase_auth.app import MIN_PASSWORD_LENGTH, normalize_email
from kilnbase_auth.tokens import ACCESS_TOKEN_LIFETIME, user_claims
from pydantic import BaseModel, Field

from .config import Config
from .rows import COLUMNS_SQL, BadRequest, Table

WEB = Path(__file__).parent / "web"
NO_SESSION = "00000000-0000-0000-0000-000000000000"
# Studio shows rows that end users wrote, on a page that holds the service_role key: nothing may
# run except our own script, and the page may not be framed.
HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

TABLES_SQL = """
select c.relname as name, c.relrowsecurity as rls,
       coalesce((select json_agg(json_build_object(
                    'name', p.policyname, 'command', p.cmd, 'roles', p.roles,
                    'using', p.qual, 'check', p.with_check) order by p.policyname)
                   from pg_policies p
                  where p.schemaname = 'public' and p.tablename = c.relname), '[]')::text
           as policies
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relkind in ('r', 'p')
 order by c.relname
"""
# Explicit columns only: auth tables also hold password hashes, MFA secrets and token hashes.
USERS_SQL = """
select id, email, phone, created_at, is_anonymous, email_confirmed_at, last_sign_in_at,
       (select count(*) from auth.sessions s
         where s.user_id = u.id and s.revoked_at is null) as active_sessions
  from auth.users u
 where $1 = '' or strpos(lower(email), lower($1)) > 0 or strpos(phone, $1) > 0
 order by created_at desc limit 50
"""
# Neither the URL (chat webhooks carry their secret in it) nor the signing secret.
DELIVERIES_SQL = """
select d.id, w.name as webhook, d.status, d.attempts, d.last_status, d.last_error,
       d.created_at, d.delivered_at
  from kilnbase.webhook_deliveries d join kilnbase.webhooks w on w.id = d.webhook_id
 order by d.id desc limit 50
"""
RELATION_SQL = """
select quote_ident(c.relname) from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relname = $1 and c.relkind in ('r', 'p', 'v')
"""
USER_SQL = """
select u.id, u.email, u.phone, u.email_confirmed_at is not null as email_verified,
       u.is_anonymous,
       s.id as session_id, s.aal, s.recovery
  from auth.users u
  left join lateral (select id, aal, recovery from auth.sessions
                      where user_id = u.id and revoked_at is null
                      order by created_at desc limit 1) s on true
 where u.id = $1
"""


class ViewAs(BaseModel):
    table: str = Field(min_length=1, max_length=63)
    # None means anon (the anon key without a user token).
    user_id: UUID | None = None
    limit: int = Field(default=50, ge=1, le=100)


SQL_MAX_ROWS = 500
SQL_MAX_CELL = 10_000


class SqlRun(BaseModel):
    query: str = Field(min_length=1, max_length=100_000)
    # Run it, show the result, then roll back: a safe way to try a change.
    rollback: bool = False


def cell(value):
    """JSON-safe, size-capped: timestamps, UUIDs, decimals and the like become their text."""
    if value is None or isinstance(value, bool | int | float):
        return value
    text = value if isinstance(value, str) else str(value)
    return text if len(text) <= SQL_MAX_CELL else text[:SQL_MAX_CELL] + "…"


BUCKETS_SQL = """
select b.id, b.public, b.file_size_limit, b.allowed_mime_types, b.created_at,
       count(o.id) as objects, coalesce(sum(o.size), 0) as bytes
  from storage.buckets b left join storage.objects o on o.bucket_id = b.id
 group by b.id order by b.id
"""
# One level of a "folder": files directly under the prefix, and the next path segments as folders.
OBJECTS_SQL = """
with under as (
    select substr(name, length($2) + 1) as rest, name, size, mime_type, updated_at
      from storage.objects
     where bucket_id = $1 and starts_with(name, $2)
)
select split_part(rest, '/', 1) || '/' as name, null::bigint as size, null as mime_type,
       max(updated_at) as updated_at, true as folder
  from under where strpos(rest, '/') > 0 group by 1
union all
select rest, size, mime_type, updated_at, false from under where strpos(rest, '/') = 0
 order by folder desc, name limit 500
"""


# The URL's host only: chat webhooks carry their secret in the path. Never the signing secret.
WEBHOOKS_SQL = """
select w.id, w.name, w.table_name::text as table, w.events, w.enabled, w.max_attempts, w.created_at,
       substring(w.url from '^https?://[^/?#]+') as host,
       count(d.id) filter (where d.status = 'pending') as pending,
       count(d.id) filter (where d.status = 'failed') as failed
  from kilnbase.webhooks w left join kilnbase.webhook_deliveries d on d.webhook_id = w.id
 group by w.id order by w.name
"""
WEBHOOK_ACTIONS = {
    "enable": "update kilnbase.webhooks set enabled = true where name = $1 returning id",
    "disable": "update kilnbase.webhooks set enabled = false where name = $1 returning id",
    # drop_webhook also removes the table's trigger once no webhook uses it.
    "delete": "select w.id from (select id from kilnbase.webhooks where name = $1) w,"
    " lateral (select kilnbase.drop_webhook($1)) d",
}


DATABASE_SQL = """
select current_setting('server_version') as version,
       pg_database_size(current_database()) as bytes,
       (select count(*) from pg_stat_activity where datname = current_database()) as connections,
       current_setting('max_connections')::int as max_connections,
       (select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'public' and c.relkind in ('r', 'p')) as tables,
       pg_postmaster_start_time() as started_at
"""
EXTENSIONS_SQL = """
select a.name, a.default_version, a.installed_version, a.comment, n.nspname as schema
  from pg_available_extensions a
  left join pg_extension e on e.extname = a.name
  left join pg_namespace n on n.oid = e.extnamespace
 order by a.installed_version is null, a.name
"""


LOG_DIR = Path("/logs")
# Fixed names only: a path is never built from the request.
LOG_FILES = {s: LOG_DIR / s / f"{s}.log" for s in ("core", "auth", "functions", "studio")}
LOG_TAIL_BYTES = 2 * 1024 * 1024
LEVELS = ("debug", "info", "warning", "error", "critical")


def read_log(path: Path) -> list[dict]:
    """The last LOG_TAIL_BYTES of the rotated and the current file, oldest first."""
    entries = []
    for file in (path.with_name(path.name + ".1"), path):
        try:
            with file.open("rb") as f:
                f.seek(max(0, f.seek(0, 2) - LOG_TAIL_BYTES))
                data = f.read()
        except OSError:
            continue
        for raw in data.splitlines():
            try:
                entry = json.loads(raw)
            except ValueError:
                continue  # a line cut by the tail offset, or one written mid-rotation
            if isinstance(entry, dict):
                entries.append(entry)
    return entries


OVERVIEW_SQL = """
select (select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'public' and c.relkind in ('r', 'p')) as tables,
       (select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'public' and c.relkind in ('r', 'p') and not c.relrowsecurity)
           as tables_without_rls,
       (select count(*) from auth.users) as users,
       (select count(*) from auth.users where created_at > now() - interval '7 days') as new_users,
       (select count(*) from auth.sessions where revoked_at is null) as sessions,
       (select count(*) from storage.buckets) as buckets,
       (select count(*) from storage.objects) as files,
       (select coalesce(sum(size), 0) from storage.objects) as file_bytes,
       (select count(*) from kilnbase.webhooks) as webhooks,
       (select count(*) from kilnbase.webhook_deliveries where status = 'failed')
           as failed_deliveries,
       pg_database_size(current_database()) as database_bytes,
       current_setting('server_version') as version
"""


class NewWebhook(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    table: str = Field(min_length=1, max_length=130)
    events: list[str] = Field(min_length=1)
    url: str = Field(pattern=r"^https?://", max_length=2048)


CRON_ENABLED_SQL = "select exists (select from pg_extension where extname = 'pg_cron')"
CRON_JOBS_SQL = """
select j.jobid, j.jobname as name, j.schedule, j.command, j.active, j.username,
       r.status as last_status, r.start_time as last_run
  from cron.job j
  left join lateral (select status, start_time from cron.job_run_details
                      where jobid = j.jobid order by runid desc limit 1) r on true
 order by j.jobname nulls last, j.jobid
"""
CRON_RUNS_SQL = """
select r.runid, coalesce(j.jobname, r.jobid::text) as job, r.status, r.return_message,
       r.start_time, r.end_time
  from cron.job_run_details r left join cron.job j on j.jobid = r.jobid
 order by r.runid desc limit 50
"""
CRON_ACTIONS = {
    "enable": "select cron.alter_job(jobid, active := true) from cron.job where jobname = $1",
    "disable": "select cron.alter_job(jobid, active := false) from cron.job where jobname = $1",
    # By id: unschedule(name) only finds jobs owned by the calling role.
    "delete": "select cron.unschedule(jobid) from cron.job where jobname = $1",
}

QUEUES_ENABLED_SQL = "select exists (select from pg_extension where extname = 'pgmq')"
QUEUES_SQL = """
select q.queue_name as name, q.created_at, q.is_unlogged,
       m.queue_length, m.total_messages, m.oldest_msg_age_sec
  from pgmq.list_queues() q join pgmq.metrics_all() m using (queue_name)
 order by q.queue_name
"""
QUEUE_ACTIONS = {
    "purge": "select pgmq.purge_queue($1)",
    "delete": "select pgmq.drop_queue($1)",
}


class NewQueue(BaseModel):
    # pgmq prefixes q_ / a_ to the name for its tables, which caps it at 47 characters.
    name: str = Field(pattern=r"^[a-z0-9_]{1,47}$")


class NewCronJob(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    # Five cron fields, or pg_cron's '<n> seconds'; pg_cron itself rejects a bad one.
    schedule: str = Field(min_length=1, max_length=100)
    command: str = Field(min_length=1, max_length=100_000)


class NewBucket(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,62}$")
    public: bool = False


class NewUser(BaseModel):
    email: str = Field(max_length=254)
    # None creates a user who signs in with a link, code or provider only.
    password: str | None = Field(default=None, max_length=1024)
    email_confirmed: bool = True


class RowWrite(BaseModel):
    # The primary key of the row to change or delete; absent for an insert.
    key: dict | None = None
    values: dict | None = None


def error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"code": code, "message": message}, status_code=status, headers=HEADERS)


class Unauthorized(Exception):
    pass


def create_app(config: Config) -> FastAPI:
    expected = config.service_role_key.encode()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.pool = await asyncpg.create_pool(config.database_url, min_size=1, max_size=4)
        app.state.http = httpx.AsyncClient(base_url=config.core_url, timeout=60)
        try:
            yield
        finally:
            await app.state.http.aclose()
            await app.state.pool.close()

    app = FastAPI(title="Kilnbase Studio", docs_url=None, redoc_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update(HEADERS)
        return response

    @app.exception_handler(Unauthorized)
    async def unauthorized(_request: Request, _exc: Unauthorized) -> JSONResponse:
        return error(401, "unauthorized", "sign in with the service_role key")

    def admin(request: Request) -> None:
        """The service_role key, compared in constant time; no cookies, so no CSRF."""
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(token.encode(), expected):
            raise Unauthorized

    @app.get("/api/tables", dependencies=[Depends(admin)])
    async def tables() -> list[dict]:
        rows = await app.state.pool.fetch(TABLES_SQL)
        return [{**r, "policies": json.loads(r["policies"])} for r in rows]

    @app.get("/api/users", dependencies=[Depends(admin)])
    async def users(search: str = "") -> list[dict]:
        return [dict(r) for r in await app.state.pool.fetch(USERS_SQL, search[:200])]

    hasher = PasswordHasher()

    @app.post("/api/users", dependencies=[Depends(admin)])
    async def create_user(body: NewUser):
        email = normalize_email(body.email)
        if email is None:
            return error(422, "invalid_email", "email address is not valid")
        password_hash = None
        if body.password is not None:
            if len(body.password) < MIN_PASSWORD_LENGTH:
                message = f"password must be at least {MIN_PASSWORD_LENGTH} characters"
                return error(422, "weak_password", message)
            password_hash = await run_in_threadpool(hasher.hash, body.password)
        try:
            row = await app.state.pool.fetchrow(
                "insert into auth.users (email, password_hash, email_confirmed_at)"
                " values ($1, $2, case when $3 then now() end) returning id, email",
                email,
                password_hash,
                body.email_confirmed,
            )
        except asyncpg.UniqueViolationError:
            return error(422, "email_taken", "a user with this email already exists")
        return dict(row)

    @app.post("/api/users/{user_id}/{action}", dependencies=[Depends(admin)])
    async def user_action(user_id: UUID, action: str):
        """delete, confirm-email or sign-out (revokes every session's refresh tokens)."""
        sql = {
            "delete": "delete from auth.users where id = $1 returning id",
            "confirm-email": "update auth.users set email_confirmed_at = coalesce("
            "email_confirmed_at, now()) where id = $1 returning id",
            "sign-out": "with u as (select id from auth.users where id = $1),"
            " s as (update auth.sessions set revoked_at = now()"
            " where user_id = $1 and revoked_at is null) select id from u",
        }.get(action)
        if sql is None:
            return error(400, "invalid_request", "action is delete, confirm-email or sign-out")
        if await app.state.pool.fetchval(sql, user_id) is None:
            return error(404, "not_found", "no such user")
        return {"ok": True}

    @app.get("/api/buckets", dependencies=[Depends(admin)])
    async def buckets() -> list[dict]:
        return [dict(r) for r in await app.state.pool.fetch(BUCKETS_SQL)]

    @app.post("/api/buckets", dependencies=[Depends(admin)])
    async def create_bucket(body: NewBucket):
        try:
            await app.state.pool.execute(
                "insert into storage.buckets (id, public) values ($1, $2)", body.id, body.public
            )
        except asyncpg.PostgresError as e:
            return error(400, "database_error", str(e))
        return {"id": body.id}

    @app.get("/api/buckets/{bucket}/objects", dependencies=[Depends(admin)])
    async def objects(bucket: str, prefix: str = "") -> list[dict]:
        return [dict(r) for r in await app.state.pool.fetch(OBJECTS_SQL, bucket, prefix)]

    def object_path(bucket: str, name: str) -> str:
        return f"/storage/v1/object/{quote(bucket, safe='')}/{quote(name, safe='/')}"

    async def core(method: str, path: str, **kwargs) -> httpx.Response:
        headers = kwargs.pop("headers", {}) | {
            "apikey": config.service_role_key,
            "Authorization": f"Bearer {config.service_role_key}",
        }
        return await app.state.http.request(method, path, headers=headers, **kwargs)

    def relay(r: httpx.Response) -> Response:
        """Core's answer as is, minus anything that would let a stored file act on this page."""
        return Response(
            r.content,
            status_code=r.status_code,
            media_type="application/octet-stream" if r.is_success else "application/json",
        )

    @app.get("/api/buckets/{bucket}/object", dependencies=[Depends(admin)])
    async def download(bucket: str, name: str):
        return relay(await core("GET", object_path(bucket, name)))

    @app.post("/api/buckets/{bucket}/object", dependencies=[Depends(admin)])
    async def upload(bucket: str, name: str, request: Request):
        content_type = request.headers.get("content-type", "application/octet-stream")
        r = await core(
            "POST",
            object_path(bucket, name),
            content=request.stream(),
            headers={"Content-Type": content_type},
        )
        return relay(r)

    @app.post("/api/buckets/{bucket}/object/delete", dependencies=[Depends(admin)])
    async def delete_object(bucket: str, name: str):
        return relay(await core("DELETE", object_path(bucket, name)))

    @app.get("/api/overview", dependencies=[Depends(admin)])
    async def overview():
        info = dict(await app.state.pool.fetchrow(OVERVIEW_SQL))
        entries = []
        for path in LOG_FILES.values():
            entries += await run_in_threadpool(read_log, path)
        day_ago = time.time() - 86400
        errors = [
            e
            for e in entries
            if e.get("level") in ("error", "critical") and (e.get("ts") or 0) > day_ago
        ]
        errors.sort(key=lambda e: e.get("ts") or 0, reverse=True)
        return info | {"errors_24h": len(errors), "recent_errors": errors[:5]}

    @app.get("/api/connect", dependencies=[Depends(admin)])
    async def connect():
        return {"url": config.public_url, "anon_key": config.anon_key}

    @app.get("/api/logs", dependencies=[Depends(admin)])
    async def logs(service: str = "", level: str = "", q: str = "", limit: int = 200):
        if service and service not in LOG_FILES:
            return error(400, "invalid_request", f"service is one of {', '.join(LOG_FILES)}")
        if level and level not in LEVELS:
            return error(400, "invalid_request", f"level is one of {', '.join(LEVELS)}")
        limit = max(1, min(limit, 1000))
        names = [service] if service else list(LOG_FILES)
        entries = []
        for name in names:
            entries += await run_in_threadpool(read_log, LOG_FILES[name])
        floor = LEVELS.index(level) if level else 0
        needle = q.lower()[:200]
        picked = [
            e
            for e in entries
            if e.get("level") in LEVELS
            if LEVELS.index(e["level"]) >= floor
            if not needle or needle in json.dumps(e).lower()
        ]
        picked.sort(key=lambda e: e.get("ts") or 0, reverse=True)
        available = [n for n, p in LOG_FILES.items() if p.exists()]
        return {"entries": picked[:limit], "services": available}

    @app.get("/api/database", dependencies=[Depends(admin)])
    async def database():
        async with app.state.pool.acquire() as conn:
            info = dict(await conn.fetchrow(DATABASE_SQL))
            info["extensions"] = [dict(r) for r in await conn.fetch(EXTENSIONS_SQL)]
        return info

    @app.post("/api/extensions/{name}/{action}", dependencies=[Depends(admin)])
    async def extension(name: str, action: str):
        """Relocatable extensions go to the extensions schema (README); others pick their own."""
        async with app.state.pool.acquire() as conn:
            relocatable = await conn.fetchval(
                "select bool_or(relocatable) from pg_available_extension_versions where name = $1",
                name,
            )
            if relocatable is None:
                return error(404, "not_found", "no such extension in this image")
            ident = await conn.fetchval("select quote_ident($1)", name)
            if action == "enable":
                schema = " with schema extensions" if relocatable else ""
                sql = f"create extension if not exists {ident}{schema}"
            elif action == "disable":
                sql = f"drop extension if exists {ident}"
            else:
                return error(400, "invalid_request", "action is enable or disable")
            try:
                await conn.execute(sql)
            except asyncpg.PostgresError as e:
                return error(400, "database_error", str(e))
        return {"ok": True}

    @app.get("/api/webhooks", dependencies=[Depends(admin)])
    async def webhooks() -> list[dict]:
        return [dict(r) for r in await app.state.pool.fetch(WEBHOOKS_SQL)]

    @app.post("/api/webhooks", dependencies=[Depends(admin)])
    async def create_webhook(body: NewWebhook):
        try:
            row = await app.state.pool.fetchrow(
                "select name, secret from kilnbase.create_webhook($1, $2::regclass, $3, $4)",
                body.name,
                body.table,
                body.events,
                body.url,
            )
        except asyncpg.PostgresError as e:
            return error(400, "database_error", str(e))
        # The only time the signing secret is shown.
        return dict(row)

    @app.post("/api/webhooks/{name}/{action}", dependencies=[Depends(admin)])
    async def webhook_action(name: str, action: str):
        sql = WEBHOOK_ACTIONS.get(action)
        if sql is None:
            return error(400, "invalid_request", "action is enable, disable or delete")
        if await app.state.pool.fetchval(sql, name) is None:
            return error(404, "not_found", "no such webhook")
        return {"ok": True}

    @app.post("/api/webhook-deliveries/{delivery_id}/retry", dependencies=[Depends(admin)])
    async def retry_delivery(delivery_id: int):
        done = await app.state.pool.fetchval(
            "update kilnbase.webhook_deliveries set status = 'pending', attempts = 0,"
            " next_attempt_at = now() where id = $1 and status = 'failed' returning id",
            delivery_id,
        )
        if done is None:
            return error(404, "not_found", "no failed delivery with that id")
        return {"ok": True}

    @app.get("/api/webhook-deliveries", dependencies=[Depends(admin)])
    async def deliveries() -> list[dict]:
        return [dict(r) for r in await app.state.pool.fetch(DELIVERIES_SQL)]

    @app.get("/api/cron", dependencies=[Depends(admin)])
    async def cron():
        async with app.state.pool.acquire() as conn:
            if not await conn.fetchval(CRON_ENABLED_SQL):
                return {"enabled": False, "jobs": [], "runs": []}
            jobs = [
                dict(r) | {"command": cell(r["command"])} for r in await conn.fetch(CRON_JOBS_SQL)
            ]
            runs = [
                dict(r) | {"return_message": cell(r["return_message"])}
                for r in await conn.fetch(CRON_RUNS_SQL)
            ]
        return {"enabled": True, "jobs": jobs, "runs": runs}

    @app.post("/api/cron", dependencies=[Depends(admin)])
    async def create_cron_job(body: NewCronJob):
        async with app.state.pool.acquire() as conn:
            if not await conn.fetchval(CRON_ENABLED_SQL):
                return error(409, "conflict", "enable the pg_cron extension first")
            # cron.schedule replaces a job of the same name; here that has to be asked for.
            if await conn.fetchval("select 1 from cron.job where jobname = $1", body.name):
                return error(409, "conflict", "a job with that name exists")
            try:
                await conn.execute(
                    "select cron.schedule($1, $2, $3)", body.name, body.schedule, body.command
                )
            except asyncpg.PostgresError as e:
                return error(400, "database_error", str(e))
        return {"ok": True}

    @app.post("/api/cron/{name}/{action}", dependencies=[Depends(admin)])
    async def cron_action(name: str, action: str):
        sql = CRON_ACTIONS.get(action)
        if sql is None:
            return error(400, "invalid_request", "action is enable, disable or delete")
        async with app.state.pool.acquire() as conn:
            if not await conn.fetchval(CRON_ENABLED_SQL):
                return error(404, "not_found", "no such job")
            if not await conn.fetch(sql, name):
                return error(404, "not_found", "no such job")
        return {"ok": True}

    async def queue_exists(conn, name: str) -> bool:
        return bool(
            await conn.fetchval(QUEUES_ENABLED_SQL)
            and await conn.fetchval("select 1 from pgmq.list_queues() where queue_name = $1", name)
        )

    @app.get("/api/queues", dependencies=[Depends(admin)])
    async def queues():
        async with app.state.pool.acquire() as conn:
            if not await conn.fetchval(QUEUES_ENABLED_SQL):
                return {"enabled": False, "queues": []}
            return {"enabled": True, "queues": [dict(r) for r in await conn.fetch(QUEUES_SQL)]}

    @app.post("/api/queues", dependencies=[Depends(admin)])
    async def create_queue(body: NewQueue):
        async with app.state.pool.acquire() as conn:
            if not await conn.fetchval(QUEUES_ENABLED_SQL):
                return error(409, "conflict", "enable the pgmq extension first")
            if await queue_exists(conn, body.name):
                return error(409, "conflict", "a queue with that name exists")
            try:
                await conn.execute("select pgmq.create($1)", body.name)
            except asyncpg.PostgresError as e:
                return error(400, "database_error", str(e))
        return {"ok": True}

    @app.get("/api/queues/{name}/messages", dependencies=[Depends(admin)])
    async def queue_messages(name: str):
        """A peek at the table: unlike pgmq.read, it neither hides messages nor counts a read."""
        async with app.state.pool.acquire() as conn:
            if not await queue_exists(conn, name):
                return error(404, "not_found", "no such queue")
            table = await conn.fetchval("select quote_ident('q_' || $1)", name)
            rows = await conn.fetch(
                # The name is an existing queue's, quoted by Postgres.
                "select msg_id, read_ct, enqueued_at, vt, message::text as message"  # noqa: S608
                f" from pgmq.{table} order by msg_id limit 50"
            )
        return [dict(r) | {"message": cell(r["message"])} for r in rows]

    @app.post("/api/queues/{name}/messages", dependencies=[Depends(admin)])
    async def send_message(name: str, request: Request):
        try:
            message = await request.json()
        except ValueError:
            return error(400, "invalid_request", "the body is the message, as JSON")
        async with app.state.pool.acquire() as conn:
            if not await queue_exists(conn, name):
                return error(404, "not_found", "no such queue")
            msg_id = await conn.fetchval(
                "select pgmq.send($1, $2::jsonb)", name, json.dumps(message)
            )
        return {"msg_id": msg_id}

    @app.post("/api/queues/{name}/{action}", dependencies=[Depends(admin)])
    async def queue_action(name: str, action: str):
        sql = QUEUE_ACTIONS.get(action)
        if sql is None:
            return error(400, "invalid_request", "action is purge or delete")
        async with app.state.pool.acquire() as conn:
            if not await queue_exists(conn, name):
                return error(404, "not_found", "no such queue")
            await conn.execute(sql, name)
        return {"ok": True}

    @app.post("/api/view-as", dependencies=[Depends(admin)])
    async def view_as(body: ViewAs):
        """
        The rows `body.user_id` (or anon) gets from the REST API: the same role and the same
        request.jwt.claims as PostgREST sets for their token, in a transaction that is rolled back.
        """
        async with app.state.pool.acquire() as conn:
            relation = await conn.fetchval(RELATION_SQL, body.table)
            if relation is None:
                return error(404, "not_found", "no such table or view in public")
            if body.user_id is None:
                role, claims = "anon", config.anon_claims
            else:
                user = await conn.fetchrow(USER_SQL, body.user_id)
                if user is None:
                    return error(404, "not_found", "no such user")
                now = int(time.time())
                role = "authenticated"
                claims = user_claims(
                    str(user["id"]),
                    user["email"],
                    str(user["session_id"] or NO_SESSION),
                    user["aal"] or "aal1",
                    mfa_pending=False,
                    email_verified=user["email_verified"],
                    recovery=bool(user["recovery"]),
                    is_anonymous=user["is_anonymous"],
                    phone=user["phone"],
                ) | {"iat": now, "exp": now + ACCESS_TOKEN_LIFETIME}
            tx = conn.transaction()
            await tx.start()
            try:
                # `role` comes from the two literals above, `relation` from quote_ident().
                await conn.execute(f"set local role {role}")
                await conn.execute("set local statement_timeout = '5s'")
                await conn.execute(
                    "select set_config('request.jwt.claims', $1, true)", json.dumps(claims)
                )
                rows = await conn.fetch(
                    f"select to_json(t)::text as row from public.{relation} t limit $1",  # noqa: S608
                    body.limit,
                )
            except asyncpg.InsufficientPrivilegeError:
                return {"role": role, "claims": claims, "denied": True, "rows": []}
            finally:
                await tx.rollback()
        rows = [json.loads(r["row"]) for r in rows]
        return {"role": role, "claims": claims, "denied": False, "rows": rows}

    async def load_table(conn, name: str) -> Table | None:
        columns = [dict(r) for r in await conn.fetch(COLUMNS_SQL, name)]
        return Table(name, columns) if columns else None

    async def as_service_role(conn) -> None:
        # Studio connects as postgres; edits go through the role the API's server keys use.
        await conn.execute("set local role service_role")
        await conn.execute("set local statement_timeout = '5s'")

    @app.get("/api/tables/{name}/rows", dependencies=[Depends(admin)])
    async def rows(name: str, offset: int = 0, limit: int = 50):
        if not (0 <= offset and 1 <= limit <= 200):
            return error(400, "invalid_request", "offset >= 0 and 1 <= limit <= 200")
        async with app.state.pool.acquire() as conn, conn.transaction():
            table = await load_table(conn, name)
            if table is None:
                return error(404, "not_found", "no such table in public")
            await as_service_role(conn)
            fetched = await conn.fetch(table.select(), limit, offset)
        return {
            "columns": list(table.columns.values()),
            "key": table.key,
            "rows": [json.loads(r["row"]) for r in fetched],
        }

    @app.post("/api/tables/{name}/rows", dependencies=[Depends(admin)])
    async def write_row(name: str, body: RowWrite, action: str = "insert"):
        async with app.state.pool.acquire() as conn, conn.transaction():
            table = await load_table(conn, name)
            if table is None:
                return error(404, "not_found", "no such table in public")
            try:
                if action == "insert":
                    sql, args = table.insert(body.values), [json.dumps(body.values)]
                elif action == "update":
                    sql = table.update(body.key, body.values)
                    args = [json.dumps(body.values), json.dumps(body.key)]
                elif action == "delete":
                    sql, args = table.delete(body.key), [json.dumps(body.key)]
                else:
                    raise BadRequest("action is insert, update or delete")
            except BadRequest as e:
                return error(400, "invalid_request", str(e))
            await as_service_role(conn)
            try:
                row = await conn.fetchval(sql, *args)
            except asyncpg.PostgresError as e:
                # The database's own message (constraint, type, permission) is what the admin needs.
                return error(400, "database_error", str(e))
        if row is None:
            return error(404, "not_found", "no row has that primary key")
        return {"row": json.loads(row)}

    @app.post("/api/sql", dependencies=[Depends(admin)])
    async def run_sql(body: SqlRun):
        """Runs as the database superuser, in one transaction; DDL here bypasses db/migrations."""
        async with app.state.pool.acquire() as conn:
            tx = conn.transaction()
            await tx.start()
            try:
                await conn.execute("set local statement_timeout = '15s'")
                try:
                    async with conn.transaction():  # a savepoint: a failed prepare is undone
                        stmt = await conn.prepare(body.query)
                except asyncpg.PostgresError as e:
                    # Several statements cannot be prepared; run them as a script, without rows.
                    if "multiple commands" not in str(e):
                        raise
                    status = await conn.execute(body.query)
                    columns, rows, truncated = [], [], False
                else:
                    columns = [a.name for a in stmt.get_attributes()]
                    records = await stmt.fetch() if not columns else []
                    if columns:
                        cursor = await stmt.cursor()
                        records = await cursor.fetch(SQL_MAX_ROWS + 1)
                    truncated = len(records) > SQL_MAX_ROWS
                    rows = [[cell(v) for v in r] for r in records[:SQL_MAX_ROWS]]
                    status = stmt.get_statusmsg() or f"{len(rows)} row(s)"
            except asyncpg.PostgresError as e:
                await tx.rollback()
                return error(400, "database_error", str(e))
            if body.rollback:
                await tx.rollback()
            else:
                await tx.commit()
        return {
            "columns": columns,
            "rows": rows,
            "truncated": truncated,
            "status": status,
            "committed": not body.rollback,
        }

    app.mount("/", StaticFiles(directory=WEB, html=True), name="web")
    return app
