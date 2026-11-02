"""Functions, realtime, GraphQL, reports and project settings."""

import asyncio
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

import jwt
from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from websockets.asyncio.client import connect

from .common import LOG_FILES, error, read_log, rows

# The project's functions directory, mounted read-only (docker-compose.yml); the runner has the
# same mount, so what is listed here is what /functions/v1 serves.
FUNCTIONS_DIR = Path("/functions")
NAME = re.compile(r"[a-z0-9_-]{1,63}")
SOURCE_LIMIT = 200_000
BODY_LIMIT = 100_000
LISTEN_SECONDS = 300

REALTIME_TABLES_SQL = """
select c.relname as name,
       exists (select 1 from pg_trigger t
                where t.tgrelid = c.oid and t.tgname = 'kilnbase_realtime') as enabled,
       exists (select 1 from pg_index i where i.indrelid = c.oid and i.indisprimary) as has_key
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relkind in ('r', 'p') order by c.relname
"""
SIGNUPS_SQL = """
select to_char(d, 'YYYY-MM-DD') as day,
       (select count(*) from auth.users u where u.created_at::date = d) as sign_ups,
       (select count(*) from auth.sessions s where s.created_at::date = d) as sign_ins
  from generate_series(current_date - 13, current_date, interval '1 day') d order by d
"""
BUCKET_USAGE_SQL = """
select b.id as bucket, count(o.id) as files, coalesce(sum(o.size), 0) as bytes
  from storage.buckets b left join storage.objects o on o.bucket_id = b.id
 group by b.id order by 3 desc
"""
TOP_TABLES_SQL = """
select relname as name, n_live_tup as live_rows, pg_total_relation_size(relid) as bytes
  from pg_stat_user_tables where schemaname = 'public'
 order by pg_total_relation_size(relid) desc limit 10
"""
SETTINGS_SQL = """
select name, setting, unit from pg_settings
 where name in ('max_connections', 'shared_buffers', 'work_mem', 'maintenance_work_mem',
                'effective_cache_size', 'TimeZone', 'wal_level', 'archive_mode',
                'statement_timeout', 'idle_in_transaction_session_timeout',
                'log_min_duration_statement', 'shared_preload_libraries')
 order by name
"""
ARCHIVER_SQL = """
select archived_count, last_archived_wal, last_archived_time, failed_count, last_failed_time,
       stats_reset from pg_stat_archiver
"""
SERVICES = {"rest", "auth", "storage", "functions", "realtime", "graphql"}


class Invoke(BaseModel):
    method: str = Field(default="POST", pattern=r"^(GET|POST|PUT|PATCH|DELETE)$")
    query: str = Field(default="", max_length=2000)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=BODY_LIMIT)
    # anon: the apikey alone, as a visitor; service_role: as a trusted server.
    caller: str = Field(default="anon", pattern=r"^(anon|service_role)$")


class GraphQL(BaseModel):
    query: str = Field(min_length=1, max_length=BODY_LIMIT)
    variables: dict | None = None
    caller: str = Field(default="anon", pattern=r"^(anon|service_role)$")


class Broadcast(BaseModel):
    channel: str = Field(min_length=1, max_length=255)
    event: str = Field(min_length=1, max_length=255)
    payload: dict | list | str | int | float | bool | None = None


def list_functions() -> dict:
    """The functions directory as the page shows it; run in a thread (it touches the disk)."""
    if not FUNCTIONS_DIR.is_dir():
        return {"mounted": False, "functions": [], "requirements": False, "package": False}
    out = []
    for directory in sorted(FUNCTIONS_DIR.iterdir()):
        if not directory.is_dir() or not NAME.fullmatch(directory.name):
            continue
        entries = [e for e in ("main.py", "main.ts") if (directory / e).is_file()]
        if not entries:
            continue
        stat = (directory / entries[0]).stat()
        files = sorted(p.name for p in directory.iterdir() if p.is_file())
        out.append(
            {
                "name": directory.name,
                "entry": entries[0],
                "language": "python" if entries[0].endswith(".py") else "typescript",
                "bytes": stat.st_size,
                "updated_at": stat.st_mtime,
                "files": files[:50],
                "conflict": len(entries) > 1,
            }
        )
    return {
        "mounted": True,
        "functions": out,
        "requirements": (FUNCTIONS_DIR / "requirements.txt").is_file(),
        "package": (FUNCTIONS_DIR / "package.json").is_file(),
    }


def log_sizes() -> dict:
    return {n: p.stat().st_size if p.exists() else None for n, p in LOG_FILES.items()}


def read_source(directory: Path, file: str) -> tuple[Path, bytes] | None:
    if not directory.is_dir():
        return None
    entry = next((e for e in ("main.py", "main.ts") if (directory / e).is_file()), None)
    path = directory / (file or entry or "main.py")
    return (path, path.read_bytes()) if path.is_file() else None


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p))]


def request_report(entries: list[dict]) -> dict:
    """Requests per hour (last 24 h) and per service, from core's access log lines."""
    now = time.time()
    start = now - 24 * 3600
    hours = [
        {"hour": int(start + i * 3600), "ok": 0, "client_error": 0, "server_error": 0}
        for i in range(25)
    ]
    services: dict[str, dict] = {}
    for e in entries:
        ts = e.get("ts") or 0
        if e.get("msg") != "request" or ts < start or not isinstance(e.get("status"), int):
            continue
        status, ms = e["status"], e.get("ms")
        bucket = hours[min(24, int((ts - start) // 3600))]
        bucket["server_error" if status >= 500 else "client_error" if status >= 400 else "ok"] += 1
        parts = str(e.get("path", "")).split("/")
        name = parts[1] if len(parts) > 1 and parts[1] in SERVICES else "other"
        svc = services.setdefault(name, {"service": name, "requests": 0, "errors": 0, "ms": []})
        svc["requests"] += 1
        svc["errors"] += status >= 500
        if isinstance(ms, int | float):
            svc["ms"].append(ms)
    return {
        "hours": hours,
        "services": sorted(
            (
                {k: v for k, v in s.items() if k != "ms"}
                | {"p50_ms": percentile(s["ms"], 0.5), "p95_ms": percentile(s["ms"], 0.95)}
                for s in services.values()
            ),
            key=lambda s: -s["requests"],
        ),
    }


def router(admin, config, core) -> APIRouter:
    r = APIRouter(prefix="/api", dependencies=[Depends(admin)])
    ws_url = (
        re.sub("^http", "ws", config.core_url)
        + "/realtime/v1/websocket?apikey="
        + config.service_role_key
    )

    def caller_headers(caller: str) -> dict:
        key = config.service_role_key if caller == "service_role" else config.anon_key
        return {"apikey": config.anon_key, "Authorization": f"Bearer {key}"}

    @r.get("/functions")
    async def functions() -> dict:
        return await run_in_threadpool(list_functions)

    @r.get("/functions/{name}/source")
    async def function_source(name: str, file: str = ""):
        # A plain file name inside the function's directory; never a path.
        if not NAME.fullmatch(name):
            return error(404, "not_found", "no such function")
        if file and (not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", file) or file.startswith(".")):
            return error(400, "invalid_request", "file is a plain file name")
        found = await run_in_threadpool(read_source, FUNCTIONS_DIR / name, file)
        if found is None:
            return error(404, "not_found", "no such function or file")
        path, data = found
        return {
            "name": name,
            "file": path.name,
            "source": data[:SOURCE_LIMIT].decode("utf-8", "replace"),
            "truncated": len(data) > SOURCE_LIMIT,
        }

    @r.post("/functions/{name}/invoke")
    async def invoke(name: str, body: Invoke, request: Request):
        """Calls the function through core, as a visitor or as a server, and shows the answer."""
        if not NAME.fullmatch(name):
            return error(404, "not_found", "no such function")
        headers = {
            k: v
            for k, v in list(body.headers.items())[:20]
            if re.fullmatch(r"[A-Za-z0-9-]{1,64}", k)
            if k.lower() not in ("apikey", "authorization", "host")
        } | caller_headers(body.caller)
        query = body.query.lstrip("?")
        started = time.monotonic()
        res = await request.app.state.http.request(
            body.method,
            f"/functions/v1/{name}" + (f"?{query}" if query else ""),
            headers=headers,
            content=body.body.encode(),
        )
        return {
            "status": res.status_code,
            "headers": {k: v for k, v in res.headers.items() if k.lower() not in ("set-cookie",)},
            "body": res.text[:BODY_LIMIT],
            "truncated": len(res.content) > BODY_LIMIT,
            "ms": round((time.monotonic() - started) * 1000, 1),
        }

    @r.get("/realtime")
    async def realtime(request: Request) -> dict:
        async with request.app.state.pool.acquire() as conn:
            return {
                "tables": rows(await conn.fetch(REALTIME_TABLES_SQL)),
                "authorize": await conn.fetchval(
                    "select pg_get_functiondef('realtime.authorize(text, text)'::regprocedure)"
                ),
                "events": await conn.fetchval("select count(*) from kilnbase.realtime_events"),
            }

    @r.get("/realtime/listen")
    async def listen(table: str = "", channel: str = ""):
        """Server-sent events relaying one table's changes and/or one channel, as service_role,
        for up to five minutes. The page cannot open the socket itself (the CSP allows no other
        origin), and this way the service_role key never leaves the server."""
        if not table and not channel:
            return error(400, "invalid_request", "give table and/or channel")
        if table and not re.fullmatch(r"[A-Za-z0-9_]{1,63}", table):
            return error(400, "invalid_request", "table is a plain name in public")
        if len(channel) > 255:
            return error(400, "invalid_request", "channel names are 1-255 characters")

        async def stream():
            async with connect(ws_url, max_size=2**20) as ws:
                if table:
                    await ws.send(json.dumps({"type": "subscribe", "id": "table", "table": table}))
                if channel:
                    await ws.send(json.dumps({"type": "join", "id": "channel", "channel": channel}))
                deadline = time.monotonic() + LISTEN_SECONDS
                while time.monotonic() < deadline:
                    try:
                        message = await asyncio.wait_for(ws.recv(), timeout=15)
                    except TimeoutError:
                        yield ": keep-alive\n\n"
                        continue
                    yield f"data: {message}\n\n"
                yield 'data: {"type": "closed", "reason": "time limit"}\n\n'

        return StreamingResponse(stream(), media_type="text/event-stream")

    @r.post("/realtime/broadcast")
    async def broadcast(body: Broadcast):
        """Sends one broadcast message on a channel, as service_role (which skips authorize)."""
        async with connect(ws_url, max_size=2**20) as ws:
            await ws.send(json.dumps({"type": "join", "id": "studio", "channel": body.channel}))
            answer = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
            if answer.get("type") == "error":
                return error(400, answer.get("code", "error"), answer.get("message", ""))
            await ws.send(
                json.dumps(
                    {
                        "type": "broadcast",
                        "channel": body.channel,
                        "event": body.event,
                        "payload": body.payload,
                    }
                )
            )
        return {"ok": True}

    @r.post("/graphql")
    async def graphql(body: GraphQL, request: Request):
        res = await request.app.state.http.post(
            "/graphql/v1",
            headers=caller_headers(body.caller),
            json={"query": body.query, "variables": body.variables},
        )
        return Response(res.content, status_code=res.status_code, media_type="application/json")

    @r.get("/reports")
    async def reports(request: Request) -> dict:
        entries = await run_in_threadpool(read_log, LOG_FILES["core"])
        async with request.app.state.pool.acquire() as conn:
            report = request_report(entries) | {
                "days": rows(await conn.fetch(SIGNUPS_SQL)),
                "buckets": rows(await conn.fetch(BUCKET_USAGE_SQL)),
                "tables": rows(await conn.fetch(TOP_TABLES_SQL)),
            }
        return report

    async def probe(method: str, path: str, **kwargs) -> bool:
        try:
            res = await core(method, path, timeout=3, **kwargs)
        except Exception:  # noqa: BLE001 - a service that is down is a report, not an error
            return False
        return res.is_success

    @r.get("/settings")
    async def settings(request: Request) -> dict:
        url = urlsplit(config.database_url)
        async with request.app.state.pool.acquire() as conn:
            version = await conn.fetchval("select version()")
            pg_settings = rows(await conn.fetch(SETTINGS_SQL))
            archiver = rows([await conn.fetchrow(ARCHIVER_SQL)])[0]
        health = await asyncio.gather(
            probe("GET", "/health"),
            probe("GET", "/auth/v1/health"),
            probe("POST", "/graphql/v1", json={"query": "{ __typename }"}),
        )
        return {
            "public_url": config.public_url,
            "anon_key": config.anon_key,
            "jwt": jwt.get_unverified_header(config.service_role_key)
            | {"issuer": config.anon_claims.get("iss")},
            "database": {
                "host": url.hostname,
                "port": url.port or 5432,
                "name": url.path.lstrip("/"),
                "user": url.username,
                "version": version,
                "settings": pg_settings,
            },
            "archiver": archiver,
            "services": dict(zip(("core", "auth", "graphql"), health, strict=True)),
            "logs": await run_in_threadpool(log_sizes),
            "functions_mounted": (await run_in_threadpool(list_functions))["mounted"],
        }

    return r
