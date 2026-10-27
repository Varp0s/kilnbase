import hmac
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID

import asyncpg
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from kilnbase_auth.tokens import ACCESS_TOKEN_LIFETIME, user_claims
from pydantic import BaseModel, Field

from .config import Config

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
select id, email, created_at, is_anonymous from auth.users
 where $1 = '' or strpos(lower(email), lower($1)) > 0
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
select u.id, u.email, u.email_confirmed_at is not null as email_verified, u.is_anonymous,
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


def error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"code": code, "message": message}, status_code=status, headers=HEADERS)


class Unauthorized(Exception):
    pass


def create_app(config: Config) -> FastAPI:
    expected = config.service_role_key.encode()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.pool = await asyncpg.create_pool(config.database_url, min_size=1, max_size=4)
        try:
            yield
        finally:
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

    @app.get("/api/webhook-deliveries", dependencies=[Depends(admin)])
    async def deliveries() -> list[dict]:
        return [dict(r) for r in await app.state.pool.fetch(DELIVERIES_SQL)]

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

    app.mount("/", StaticFiles(directory=WEB, html=True), name="web")
    return app
