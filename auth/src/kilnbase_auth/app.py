from contextlib import asynccontextmanager

import asyncpg
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from .config import Config
from .ratelimit import FailureLimiter
from .tokens import (
    ACCESS_TOKEN_LIFETIME,
    REFRESH_TOKEN_LIFETIME,
    Signer,
    hash_refresh_token,
    new_refresh_token,
)

MIN_PASSWORD_LENGTH = 8


class Credentials(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=1024)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(max_length=256)


def error(status: int, code: str, message: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"code": code, "message": message}, status_code=status, headers=headers)


def normalize_email(raw: str) -> str | None:
    email = raw.strip().lower()
    local, sep, domain = email.partition("@")
    if not sep or not local or "@" in domain or "." not in domain.strip("."):
        return None
    if any(c.isspace() for c in email):
        return None
    return email


def user_json(row) -> dict:
    return {
        "id": str(row["id"]),
        "email": row["email"],
        "created_at": row["created_at"].isoformat(),
        "last_sign_in_at": row["last_sign_in_at"] and row["last_sign_in_at"].isoformat(),
    }


def bearer(request: Request) -> str | None:
    value = request.headers.get("authorization", "")
    return value.removeprefix("Bearer ") if value.startswith("Bearer ") else None


def client_ip(request: Request) -> str:
    # The gateway overwrites X-Forwarded-For and auth is not reachable around it.
    return request.headers.get("x-forwarded-for") or (request.client.host if request.client else "")


def create_app(config: Config) -> FastAPI:
    signer = Signer(config.private_jwk)
    hasher = PasswordHasher()
    # Verifying against a dummy hash keeps unknown-email logins as slow as wrong-password ones.
    dummy_hash = hasher.hash("timing-equaliser")
    email_limiter = FailureLimiter(limit=10, window=900)
    ip_limiter = FailureLimiter(limit=100, window=900)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.pool = await asyncpg.create_pool(config.database_url, min_size=1, max_size=10)
        try:
            yield
        finally:
            await app.state.pool.close()

    app = FastAPI(title="Kilnbase Auth", docs_url=None, redoc_url=None, lifespan=lifespan)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, exc: RequestValidationError) -> JSONResponse:
        return error(422, "invalid_request", "request body is missing fields or has invalid ones")

    async def issue_session(conn, user_id, email: str, session_id=None) -> dict:
        if session_id is None:
            session_id = await conn.fetchval(
                "insert into auth.sessions (user_id) values ($1) returning id", user_id
            )
        refresh_token, refresh_hash = new_refresh_token()
        await conn.execute(
            "insert into auth.refresh_tokens (token_hash, session_id) values ($1, $2)",
            refresh_hash,
            session_id,
        )
        user = await conn.fetchrow(
            "update auth.users set last_sign_in_at = now() where id = $1"
            " returning id, email, created_at, last_sign_in_at",
            user_id,
        )
        access_token, expires_at = signer.access_token(str(user_id), email, str(session_id))
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_LIFETIME,
            "expires_at": expires_at,
            "refresh_token": refresh_token,
            "user": user_json(user),
        }

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.post("/signup")
    async def signup(body: Credentials):
        email = normalize_email(body.email)
        if email is None:
            return error(422, "invalid_email", "email address is not valid")
        if len(body.password) < MIN_PASSWORD_LENGTH:
            return error(
                422, "weak_password", f"password must be at least {MIN_PASSWORD_LENGTH} characters"
            )
        # argon2 is deliberately CPU-heavy; keep it off the event loop.
        password_hash = await run_in_threadpool(hasher.hash, body.password)
        async with app.state.pool.acquire() as conn, conn.transaction():
            try:
                user_id = await conn.fetchval(
                    "insert into auth.users (email, password_hash) values ($1, $2) returning id",
                    email,
                    password_hash,
                )
            except asyncpg.UniqueViolationError:
                return error(422, "email_taken", "a user with this email already exists")
            return await issue_session(conn, user_id, email)

    @app.post("/token")
    async def token(request: Request, grant_type: str):
        if grant_type == "password":
            return await password_grant(request)
        if grant_type == "refresh_token":
            return await refresh_grant(request)
        return error(400, "unsupported_grant_type", "grant_type must be password or refresh_token")

    async def password_grant(request: Request):
        try:
            body = Credentials.model_validate(await request.json())
        except ValueError:
            return error(
                422, "invalid_request", "request body is missing fields or has invalid ones"
            )
        email = normalize_email(body.email) or body.email.strip().lower()
        keys = [(email_limiter, f"email:{email}"), (ip_limiter, f"ip:{client_ip(request)}")]
        for limiter, key in keys:
            if wait := limiter.retry_after(key):
                return error(
                    429,
                    "too_many_attempts",
                    "too many failed sign-in attempts",
                    headers={"Retry-After": str(wait)},
                )

        async with app.state.pool.acquire() as conn:
            row = await conn.fetchrow(
                "select id, email, password_hash from auth.users where lower(email) = $1", email
            )
            try:
                ok = await run_in_threadpool(
                    hasher.verify, row["password_hash"] if row else dummy_hash, body.password
                )
            except VerificationError, InvalidHashError:
                ok = False
            if not (row and ok):
                for limiter, key in keys:
                    limiter.fail(key)
                return error(400, "invalid_credentials", "invalid email or password")

            email_limiter.reset(keys[0][1])
            async with conn.transaction():
                if hasher.check_needs_rehash(row["password_hash"]):
                    new_hash = await run_in_threadpool(hasher.hash, body.password)
                    await conn.execute(
                        "update auth.users set password_hash = $2, updated_at = now()"
                        " where id = $1",
                        row["id"],
                        new_hash,
                    )
                return await issue_session(conn, row["id"], row["email"])

    async def refresh_grant(request: Request):
        try:
            body = RefreshRequest.model_validate(await request.json())
        except ValueError:
            return error(
                422, "invalid_request", "request body is missing fields or has invalid ones"
            )
        token_hash = hash_refresh_token(body.refresh_token)
        async with app.state.pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                """
                update auth.refresh_tokens rt set used_at = now()
                  from auth.sessions s join auth.users u on u.id = s.user_id
                 where rt.token_hash = $1
                   and rt.used_at is null
                   and rt.session_id = s.id
                   and s.revoked_at is null
                   and rt.created_at > now() - make_interval(secs => $2)
                returning s.id as session_id, u.id as user_id, u.email
                """,
                token_hash,
                REFRESH_TOKEN_LIFETIME,
            )
            if row is None:
                # A rotated token presented again means it leaked: end the whole session.
                # shortcut: no grace window, so two tabs refreshing at the same instant also log
                # out; add a few-second reuse window if that bites real clients.
                await conn.execute(
                    "update auth.sessions set revoked_at = now()"
                    " where revoked_at is null and id = (select session_id from auth.refresh_tokens"
                    " where token_hash = $1 and used_at is not null)",
                    token_hash,
                )
                return error(401, "invalid_refresh_token", "refresh token is invalid or expired")
            return await issue_session(conn, row["user_id"], row["email"], row["session_id"])

    async def current_session(request: Request) -> dict | None:
        token = bearer(request)
        if token is None:
            return None
        try:
            claims = signer.verify(token)
        except jwt.InvalidTokenError:
            return None
        revoked = await app.state.pool.fetchval(
            "select revoked_at is not null from auth.sessions where id = $1::uuid", claims["sid"]
        )
        return None if revoked in (None, True) else claims

    @app.post("/logout")
    async def logout(request: Request):
        claims = await current_session(request)
        if claims is None:
            return error(401, "unauthorized", "a valid access token is required")
        await app.state.pool.execute(
            "update auth.sessions set revoked_at = now()"
            " where id = $1::uuid and revoked_at is null",
            claims["sid"],
        )
        return Response(status_code=204)

    @app.get("/user")
    async def user(request: Request):
        claims = await current_session(request)
        if claims is None:
            return error(401, "unauthorized", "a valid access token is required")
        row = await app.state.pool.fetchrow(
            "select id, email, created_at, last_sign_in_at from auth.users where id = $1::uuid",
            claims["sub"],
        )
        if row is None:
            return error(401, "unauthorized", "a valid access token is required")
        return user_json(row)

    return app
