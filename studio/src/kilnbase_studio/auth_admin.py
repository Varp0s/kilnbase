"""Auth pages beyond the user list: one user's identities, factors and sessions; every active
session; password-reset and magic-link mails; the auth service's effective settings.

Explicit columns only: the auth tables also hold password hashes, TOTP secrets and token hashes.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from .common import error, rows

USER_SQL = """
select id, email, phone, created_at, updated_at, is_anonymous, email_confirmed_at,
       last_sign_in_at, password_hash is not null as has_password
  from auth.users where id = $1
"""
IDENTITIES_SQL = """
select provider, provider_user_id, email, created_at from auth.identities
 where user_id = $1 order by created_at
"""
FACTORS_SQL = "select id, verified, created_at from auth.mfa_factors where user_id = $1 order by 3"
USER_SESSIONS_SQL = """
select s.id, s.created_at, s.revoked_at, s.aal, s.recovery,
       (select max(created_at) from auth.refresh_tokens t where t.session_id = s.id) as refreshed_at
  from auth.sessions s where s.user_id = $1 order by s.created_at desc limit 50
"""
SESSIONS_SQL = """
select s.id, s.user_id, u.email, u.phone, s.created_at, s.aal, s.recovery,
       (select max(created_at) from auth.refresh_tokens t where t.session_id = s.id) as refreshed_at
  from auth.sessions s join auth.users u on u.id = s.user_id
 where s.revoked_at is null
   and ($1 = '' or strpos(lower(coalesce(u.email, '')), lower($1)) > 0
        or strpos(coalesce(u.phone, ''), $1) > 0)
 order by s.created_at desc limit 100
"""
# Sent through the public auth API, as the app would, so the same templates and limits apply.
MAILS = {
    "recover": ("/auth/v1/recover", {}),
    "magic-link": ("/auth/v1/otp", {"create_user": False}),
}


def router(admin, _config, core) -> APIRouter:
    r = APIRouter(prefix="/api", dependencies=[Depends(admin)])

    @r.get("/users/{user_id}")
    async def user(user_id: UUID, request: Request):
        async with request.app.state.pool.acquire() as conn:
            row = await conn.fetchrow(USER_SQL, user_id)
            if row is None:
                return error(404, "not_found", "no such user")
            return rows([row])[0] | {
                "identities": rows(await conn.fetch(IDENTITIES_SQL, user_id)),
                "factors": rows(await conn.fetch(FACTORS_SQL, user_id)),
                "sessions": rows(await conn.fetch(USER_SESSIONS_SQL, user_id)),
            }

    @r.post("/users/{user_id}/send/{kind}")
    async def send_mail(user_id: UUID, kind: str, request: Request):
        """A password-reset or magic-link mail; the answer is the auth service's."""
        if kind not in MAILS:
            return error(400, "invalid_request", "kind is recover or magic-link")
        email = await request.app.state.pool.fetchval(
            "select email from auth.users where id = $1", user_id
        )
        if email is None:
            return error(404, "not_found", "no such user, or the user has no email")
        path, extra = MAILS[kind]
        res = await core("POST", path, json={"email": email} | extra)
        return Response(res.content, status_code=res.status_code, media_type="application/json")

    @r.post("/users/{user_id}/factors/{factor_id}/delete")
    async def delete_factor(user_id: UUID, factor_id: UUID, request: Request):
        """Unenrols a TOTP factor, for a user who lost their authenticator."""
        done = await request.app.state.pool.fetchval(
            "delete from auth.mfa_factors where id = $1 and user_id = $2 returning id",
            factor_id,
            user_id,
        )
        if done is None:
            return error(404, "not_found", "no such factor")
        return {"ok": True}

    @r.get("/sessions")
    async def sessions(request: Request, search: str = "") -> list[dict]:
        return rows(await request.app.state.pool.fetch(SESSIONS_SQL, search[:200]))

    @r.post("/sessions/{session_id}/revoke")
    async def revoke_session(session_id: UUID, request: Request):
        done = await request.app.state.pool.fetchval(
            "update auth.sessions set revoked_at = now()"
            " where id = $1 and revoked_at is null returning id",
            session_id,
        )
        if done is None:
            return error(404, "not_found", "no such active session")
        return {"ok": True}

    @r.get("/auth/settings")
    async def auth_settings():
        res = await core("GET", "/auth/v1/settings")
        return Response(res.content, status_code=res.status_code, media_type="application/json")

    return r
