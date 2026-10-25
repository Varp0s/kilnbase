import hmac
import re
import secrets
import smtplib
import sys
import uuid
from contextlib import asynccontextmanager
from typing import Literal
from urllib.parse import urlencode

import asyncpg
import httpx2 as httpx
import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import FastAPI, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from .config import Config
from .mailer import Mailer
from .mfa import matching_step
from .oauth import (
    CODE_LIFETIME,
    STATE_LIFETIME,
    authorize_redirect,
    digest,
    fetch_user,
    new_secret,
    pkce_challenge,
    redirect_allowed,
)
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
    # Sign-up only: where the confirmation link should lead.
    redirect_to: str | None = Field(default=None, max_length=2048)


class RecoverRequest(BaseModel):
    email: str = Field(max_length=254)
    redirect_to: str | None = Field(default=None, max_length=2048)


class PasswordChange(BaseModel):
    password: str = Field(max_length=1024)
    current_password: str | None = Field(default=None, max_length=1024)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(max_length=256)


class CodeExchange(BaseModel):
    code: str = Field(max_length=256)
    # RFC 7636: verifiers are 43-128 characters.
    code_verifier: str = Field(min_length=43, max_length=128)


class OtpRequest(BaseModel):
    email: str = Field(max_length=254)
    create_user: bool = True
    redirect_to: str | None = Field(default=None, max_length=2048)


class VerifyRequest(BaseModel):
    type: Literal["email", "magiclink", "signup", "recovery"]
    email: str | None = Field(default=None, max_length=254)
    token: str = Field(max_length=256)


OTP_LIFETIME = 600
OTP_MAX_ATTEMPTS = 5

# purpose -> (subject, sentence before the code, sentence before the link, link `type`)
MAIL_TEXT = {
    "signin": (
        "Your sign-in code",
        "Your sign-in code is",
        "Or sign in with this link:",
        "magiclink",
    ),
    "confirm": ("Confirm your email", "Your confirmation code is", "Or confirm here:", "signup"),
    "recovery": (
        "Reset your password",
        "Your password reset code is",
        "Or reset it here:",
        "recovery",
    ),
}
VERIFY_PURPOSE = {
    "email": "signin",
    "magiclink": "signin",
    "signup": "confirm",
    "recovery": "recovery",
}


class CodeRequest(BaseModel):
    code: str = Field(pattern=r"^[0-9]{6}$")


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
    confirmed = row.get("email_confirmed_at")
    return {
        "id": str(row["id"]),
        "email": row["email"],
        "email_confirmed_at": confirmed and confirmed.isoformat(),
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
    # A 6-digit code has 10^6 values; 5 tries per 5 minutes keeps guessing hopeless.
    code_limiter = FailureLimiter(limit=5, window=300)
    # Every send counts: caps mail bombing of one address and bulk sending from one client.
    otp_email_limiter = FailureLimiter(limit=5, window=3600)
    otp_ip_limiter = FailureLimiter(limit=config.mails_per_ip_hour, window=3600)
    mailer = Mailer(config.smtp_url, config.smtp_from)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.pool = await asyncpg.create_pool(config.database_url, min_size=1, max_size=10)
        app.state.http = httpx.AsyncClient(timeout=10)
        try:
            yield
        finally:
            await app.state.http.aclose()
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
            " returning id, email, created_at, last_sign_in_at, email_confirmed_at",
            user_id,
        )
        aal, recovery = await conn.fetchrow(
            "select aal, recovery from auth.sessions where id = $1", session_id
        )
        has_factor = await conn.fetchval(
            "select exists (select 1 from auth.mfa_factors where user_id = $1 and verified)",
            user_id,
        )
        # Enrolled users get an API-usable token only after proving the second factor.
        mfa_pending = has_factor and aal != "aal2"
        access_token, expires_at = signer.access_token(
            str(user_id),
            email,
            str(session_id),
            aal,
            mfa_pending,
            email_verified=user["email_confirmed_at"] is not None,
            recovery=recovery,
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_LIFETIME,
            "expires_at": expires_at,
            "refresh_token": refresh_token,
            "user": user_json(user),
            "mfa_required": mfa_pending,
        }

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.post("/signup")
    async def signup(body: Credentials, request: Request):
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
            session = await issue_session(conn, user_id, email)
        sent = False
        if config.smtp_url and (body.redirect_to is None or redirect_ok(body.redirect_to)):
            sent = (
                await send_code(email, "confirm", body.redirect_to, False, client_ip(request))
                is None
            )
        return session | {"confirmation_sent": sent}

    @app.post("/token")
    async def token(request: Request, grant_type: str):
        if grant_type == "password":
            return await password_grant(request)
        if grant_type == "refresh_token":
            return await refresh_grant(request)
        if grant_type == "authorization_code":
            return await code_grant(request)
        return error(
            400,
            "unsupported_grant_type",
            "grant_type must be password, refresh_token or authorization_code",
        )

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
                    hasher.verify,
                    (row and row["password_hash"]) or dummy_hash,
                    body.password,
                )
            except VerificationError, InvalidHashError:
                ok = False
            if not (row and row["password_hash"] and ok):
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

    providers = config.providers or {}
    callback_url = f"{config.public_url}/auth/v1/callback"

    @app.get("/authorize")
    async def authorize(
        provider: str, redirect_to: str, code_challenge: str, code_challenge_method: str = "S256"
    ):
        """Browser entry point for provider sign-in; reached without an API key."""
        selected = providers.get(provider)
        if selected is None:
            return error(400, "unknown_provider", "this provider is not enabled")
        if code_challenge_method != "S256" or not re.fullmatch(
            r"[A-Za-z0-9_-]{43}", code_challenge
        ):
            return error(400, "invalid_request", "an S256 code_challenge is required")
        if not redirect_allowed(redirect_to, [config.public_url, *config.redirect_urls]):
            return error(400, "redirect_not_allowed", "add this URL to KILNBASE_AUTH_REDIRECT_URLS")
        state, verifier = new_secret(), new_secret()
        async with app.state.pool.acquire() as conn:
            await conn.execute(
                "delete from auth.oauth_states"
                " where created_at < now() - make_interval(secs => $1)",
                STATE_LIFETIME,
            )
            await conn.execute(
                "insert into auth.oauth_states"
                " (state_hash, provider, redirect_to, provider_verifier, client_challenge)"
                " values ($1, $2, $3, $4, $5)",
                digest(state),
                provider,
                redirect_to,
                verifier,
                code_challenge,
            )
        return RedirectResponse(authorize_redirect(selected, callback_url, state, verifier), 302)

    @app.get("/callback")
    async def callback(state: str = "", code: str = "", error_: str = Query("", alias="error")):
        async with app.state.pool.acquire() as conn:
            flow = await conn.fetchrow(
                "delete from auth.oauth_states where state_hash = $1"
                " and created_at > now() - make_interval(secs => $2) returning *",
                digest(state),
                STATE_LIFETIME,
            )
        if flow is None:
            return error(400, "invalid_state", "sign-in link expired or was already used")
        target = flow["redirect_to"]

        def back(**params: str) -> RedirectResponse:
            separator = "&" if "?" in target else "?"
            return RedirectResponse(f"{target}{separator}{urlencode(params)}", 302)

        if error_ or not code:
            return back(error="access_denied")
        try:
            external = await fetch_user(
                app.state.http,
                providers[flow["provider"]],
                code,
                callback_url,
                flow["provider_verifier"],
            )
        except httpx.HTTPError, KeyError, ValueError, TypeError:
            return back(error="provider_error")

        async with app.state.pool.acquire() as conn, conn.transaction():
            user_id = await conn.fetchval(
                "select user_id from auth.identities where provider = $1 and provider_user_id = $2",
                flow["provider"],
                external.id,
            )
            if user_id is None:
                # Only a provider-verified email may claim an account; otherwise anyone could
                # register "victim@example.com" at a provider and take over the victim's account.
                if not (external.email and external.email_verified):
                    return back(error="email_not_verified")
                user_id = await conn.fetchval(
                    "select id from auth.users where lower(email) = $1", external.email
                )
                if user_id is None:
                    user_id = await conn.fetchval(
                        "insert into auth.users (email, email_confirmed_at) values ($1, now())"
                        " returning id",
                        external.email,
                    )
                await conn.execute(
                    "insert into auth.identities (provider, provider_user_id, user_id, email)"
                    " values ($1, $2, $3, $4)",
                    flow["provider"],
                    external.id,
                    user_id,
                    external.email,
                )
            one_time = new_secret()
            await conn.execute(
                "insert into auth.auth_codes (code_hash, user_id, client_challenge)"
                " values ($1, $2, $3)",
                digest(one_time),
                user_id,
                flow["client_challenge"],
            )
        return back(code=one_time)

    async def code_grant(request: Request):
        try:
            body = CodeExchange.model_validate(await request.json())
        except ValueError:
            return error(
                422, "invalid_request", "request body is missing fields or has invalid ones"
            )
        async with app.state.pool.acquire() as conn, conn.transaction():
            # Deleted on first presentation, so a wrong verifier also burns the code.
            row = await conn.fetchrow(
                "delete from auth.auth_codes where code_hash = $1"
                " and created_at > now() - make_interval(secs => $2)"
                " returning user_id, client_challenge",
                digest(body.code),
                CODE_LIFETIME,
            )
            if row is None or not hmac.compare_digest(
                pkce_challenge(body.code_verifier), row["client_challenge"]
            ):
                return error(400, "invalid_grant", "code is invalid, expired or already used")
            email = await conn.fetchval(
                "select email from auth.users where id = $1", row["user_id"]
            )
            return await issue_session(conn, row["user_id"], email)

    def redirect_ok(url: str) -> bool:
        return redirect_allowed(url, [config.public_url, *config.redirect_urls])

    async def send_code(
        email: str, purpose: str, redirect_to: str | None, create_user: bool, ip: str | None
    ) -> JSONResponse | None:
        """Stores a fresh code + link for (email, purpose) and mails them; None on success."""
        keys = [(otp_email_limiter, f"otp:{email}")]
        if ip is not None:
            keys.append((otp_ip_limiter, ip))
        for limiter, key in keys:
            if wait := limiter.retry_after(key):
                return error(
                    429,
                    "too_many_requests",
                    "too many codes requested",
                    headers={"Retry-After": str(wait)},
                )
            limiter.fail(key)
        code = f"{secrets.randbelow(10**6):06d}"
        link = new_secret()
        await app.state.pool.execute(
            "insert into auth.one_time_tokens (email, purpose, code_hash, link_hash, create_user)"
            " values ($1, $2, $3, $4, $5)"
            " on conflict (email, purpose) do update set code_hash = excluded.code_hash,"
            " link_hash = excluded.link_hash, create_user = excluded.create_user,"
            " attempts = 0, created_at = now()",
            email,
            purpose,
            digest(f"{email}:{purpose}:{code}"),
            digest(link),
            create_user,
        )
        subject, code_line, link_line, link_type = MAIL_TEXT[purpose]
        text = f"{code_line} {code}. It expires in {OTP_LIFETIME // 60} minutes.\n"
        if redirect_to:
            separator = "&" if "?" in redirect_to else "?"
            query = urlencode({"type": link_type, "token": link})
            text += f"\n{link_line}\n{redirect_to}{separator}{query}\n"
        text += "\nIf you did not ask for this, you can ignore this email.\n"
        try:
            await run_in_threadpool(mailer.send, email, subject, text)
        except (OSError, smtplib.SMTPException) as e:
            print(f"kilnbase-auth: sending mail failed: {e}", file=sys.stderr)
            await app.state.pool.execute(
                "delete from auth.one_time_tokens where email = $1 and purpose = $2", email, purpose
            )
            return error(503, "mail_unavailable", "could not send the email, try again later")
        return None

    @app.post("/otp")
    async def request_otp(body: OtpRequest, request: Request):
        """Emails a 6-digit code (and a magic link when redirect_to is given).

        The answer is the same whether or not an account exists, so it cannot probe for emails.
        """
        email = normalize_email(body.email)
        if email is None:
            return error(422, "invalid_email", "email address is not valid")
        if body.redirect_to and not redirect_ok(body.redirect_to):
            return error(400, "redirect_not_allowed", "add this URL to KILNBASE_AUTH_REDIRECT_URLS")
        if not body.create_user:
            exists = await app.state.pool.fetchval(
                "select exists (select 1 from auth.users where lower(email) = $1)", email
            )
            if not exists:
                return {"sent": True}
        failed = await send_code(
            email, "signin", body.redirect_to, body.create_user, client_ip(request)
        )
        return failed or {"sent": True}

    @app.post("/recover")
    async def recover(body: RecoverRequest, request: Request):
        """Starts a password reset; like /otp, the answer never reveals if an account exists."""
        email = normalize_email(body.email)
        if email is None:
            return error(422, "invalid_email", "email address is not valid")
        if body.redirect_to and not redirect_ok(body.redirect_to):
            return error(400, "redirect_not_allowed", "add this URL to KILNBASE_AUTH_REDIRECT_URLS")
        exists = await app.state.pool.fetchval(
            "select exists (select 1 from auth.users where lower(email) = $1)", email
        )
        if not exists:
            return {"sent": True}
        failed = await send_code(email, "recovery", body.redirect_to, False, client_ip(request))
        return failed or {"sent": True}

    @app.post("/verify")
    async def verify_otp(body: VerifyRequest):
        invalid = error(400, "invalid_otp", "code or link is wrong, expired or already used")
        purpose = VERIFY_PURPOSE[body.type]
        # "email" is always a code; "magiclink" always a link; the others accept either.
        use_code = body.type == "email" or (body.type != "magiclink" and body.email is not None)
        async with app.state.pool.acquire() as conn, conn.transaction():
            if use_code:
                email = normalize_email(body.email or "")
                if email is None:
                    return invalid
                row = await conn.fetchrow(
                    "select code_hash, create_user, attempts,"
                    " created_at > now() - make_interval(secs => $3) as fresh"
                    " from auth.one_time_tokens where email = $1 and purpose = $2 for update",
                    email,
                    purpose,
                    OTP_LIFETIME,
                )
                if row is None:
                    return invalid
                expected = digest(f"{email}:{purpose}:{body.token}")
                if not (
                    row["fresh"]
                    and row["attempts"] < OTP_MAX_ATTEMPTS
                    and hmac.compare_digest(expected, row["code_hash"])
                ):
                    # Too many wrong tries kills the code, so 6 digits cannot be brute forced.
                    await conn.execute(
                        "update auth.one_time_tokens set attempts = attempts + 1"
                        " where email = $1 and purpose = $2",
                        email,
                        purpose,
                    )
                    return invalid
                await conn.execute(
                    "delete from auth.one_time_tokens where email = $1 and purpose = $2",
                    email,
                    purpose,
                )
                create_user = row["create_user"]
            else:
                row = await conn.fetchrow(
                    "delete from auth.one_time_tokens where link_hash = $1 and purpose = $2"
                    " and created_at > now() - make_interval(secs => $3)"
                    " returning email, create_user",
                    digest(body.token),
                    purpose,
                    OTP_LIFETIME,
                )
                if row is None:
                    return invalid
                email, create_user = row["email"], row["create_user"]

            user_id = await conn.fetchval(
                "select id from auth.users where lower(email) = $1", email
            )
            if user_id is None:
                if not create_user:
                    return invalid
                user_id = await conn.fetchval(
                    "insert into auth.users (email) values ($1) returning id", email
                )
            # Receiving the code proves the address.
            await conn.execute(
                "update auth.users set email_confirmed_at = coalesce(email_confirmed_at, now())"
                " where id = $1",
                user_id,
            )
            session_id = await conn.fetchval(
                "insert into auth.sessions (user_id, recovery) values ($1, $2) returning id",
                user_id,
                purpose == "recovery",
            )
            return await issue_session(conn, user_id, email, session_id)

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
            "select id, email, created_at, last_sign_in_at, email_confirmed_at"
            " from auth.users where id = $1::uuid",
            claims["sub"],
        )
        if row is None:
            return error(401, "unauthorized", "a valid access token is required")
        factors = await app.state.pool.fetch(
            "select id, verified, created_at from auth.mfa_factors where user_id = $1 order by 3",
            row["id"],
        )
        return user_json(row) | {
            "factors": [
                {"id": str(f["id"]), "type": "totp", "verified": f["verified"]} for f in factors
            ]
        }

    @app.put("/user")
    async def change_password(body: PasswordChange, request: Request):
        """Sets a new password. Needs the current one, unless this is a password-reset session.

        Every other session of the user is signed out, since a password change often follows a leak.
        """
        claims = await current_session(request)
        if claims is None or claims["role"] != "authenticated":
            return error(401, "unauthorized", "a fully signed-in session is required")
        if len(body.password) < MIN_PASSWORD_LENGTH:
            return error(
                422, "weak_password", f"password must be at least {MIN_PASSWORD_LENGTH} characters"
            )
        async with app.state.pool.acquire() as conn:
            row = await conn.fetchrow(
                "select u.email, u.password_hash, s.recovery from auth.users u"
                " join auth.sessions s on s.user_id = u.id"
                " where u.id = $1::uuid and s.id = $2::uuid",
                claims["sub"],
                claims["sid"],
            )
            if row is None:
                return error(401, "unauthorized", "a valid access token is required")
            if not row["recovery"] and row["password_hash"]:
                key = f"email:{row['email']}"
                if wait := email_limiter.retry_after(key):
                    return error(
                        429,
                        "too_many_attempts",
                        "too many failed attempts",
                        headers={"Retry-After": str(wait)},
                    )
                try:
                    ok = await run_in_threadpool(
                        hasher.verify, row["password_hash"], body.current_password or ""
                    )
                except VerificationError, InvalidHashError:
                    ok = False
                if not ok:
                    email_limiter.fail(key)
                    return error(400, "invalid_credentials", "current password is wrong")
            new_hash = await run_in_threadpool(hasher.hash, body.password)
            async with conn.transaction():
                await conn.execute(
                    "update auth.users set password_hash = $2, updated_at = now()"
                    " where id = $1::uuid",
                    claims["sub"],
                    new_hash,
                )
                await conn.execute(
                    "update auth.sessions set recovery = false where id = $1::uuid", claims["sid"]
                )
                await conn.execute(
                    "update auth.sessions set revoked_at = now()"
                    " where user_id = $1::uuid and id <> $2::uuid and revoked_at is null",
                    claims["sub"],
                    claims["sid"],
                )
                await conn.execute(
                    "delete from auth.one_time_tokens where email = $1 and purpose = 'recovery'",
                    row["email"],
                )
        return Response(status_code=204)

    @app.post("/factors")
    async def enroll_factor(request: Request):
        claims = await current_session(request)
        if claims is None or claims["role"] != "authenticated":
            return error(401, "unauthorized", "a fully signed-in session is required")
        secret = pyotp.random_base32()
        async with app.state.pool.acquire() as conn, conn.transaction():
            enrolled = await conn.fetchval(
                "select exists (select 1 from auth.mfa_factors"
                " where user_id = $1::uuid and verified)",
                claims["sub"],
            )
            if enrolled:
                return error(409, "mfa_already_enrolled", "remove the existing factor first")
            # Abandoned enrolments are replaced rather than piling up.
            await conn.execute(
                "delete from auth.mfa_factors where user_id = $1::uuid and not verified",
                claims["sub"],
            )
            factor_id = await conn.fetchval(
                "insert into auth.mfa_factors (user_id, secret) values ($1::uuid, $2) returning id",
                claims["sub"],
                secret,
            )
        uri = pyotp.TOTP(secret).provisioning_uri(name=claims["email"], issuer_name="Kilnbase")
        return {"id": str(factor_id), "type": "totp", "secret": secret, "uri": uri}

    @app.post("/factors/{factor_id}/verify")
    async def verify_factor(factor_id: uuid.UUID, body: CodeRequest, request: Request):
        """Confirms an enrolment, or completes sign-in for an enrolled user; returns aal2 tokens."""
        claims = await current_session(request)
        if claims is None:
            return error(401, "unauthorized", "a valid access token is required")
        key = f"factor:{factor_id}"
        if wait := code_limiter.retry_after(key):
            return error(
                429,
                "too_many_attempts",
                "too many wrong codes",
                headers={"Retry-After": str(wait)},
            )
        async with app.state.pool.acquire() as conn, conn.transaction():
            factor = await conn.fetchrow(
                "select secret, last_step from auth.mfa_factors"
                " where id = $1 and user_id = $2::uuid for update",
                factor_id,
                claims["sub"],
            )
            if factor is None:
                return error(404, "factor_not_found", "no such factor")
            step = matching_step(factor["secret"], body.code, factor["last_step"])
            if step is None:
                code_limiter.fail(key)
                return error(400, "invalid_code", "code is wrong, expired or already used")
            code_limiter.reset(key)
            await conn.execute(
                "update auth.mfa_factors set verified = true, last_step = $2 where id = $1",
                factor_id,
                step,
            )
            await conn.execute(
                "update auth.sessions set aal = 'aal2' where id = $1::uuid", claims["sid"]
            )
            # Refresh tokens minted before the upgrade must not inherit aal2.
            await conn.execute(
                "update auth.refresh_tokens set used_at = now()"
                " where session_id = $1::uuid and used_at is null",
                claims["sid"],
            )
            return await issue_session(
                conn, uuid.UUID(claims["sub"]), claims["email"], uuid.UUID(claims["sid"])
            )

    @app.delete("/factors/{factor_id}")
    async def remove_factor(factor_id: uuid.UUID, request: Request):
        claims = await current_session(request)
        if claims is None or claims.get("aal") != "aal2":
            return error(403, "aal2_required", "verify your second factor before removing it")
        deleted = await app.state.pool.fetchval(
            "delete from auth.mfa_factors where id = $1 and user_id = $2::uuid returning id",
            factor_id,
            claims["sub"],
        )
        if deleted is None:
            return error(404, "factor_not_found", "no such factor")
        return Response(status_code=204)

    return app
