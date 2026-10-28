import asyncio
import hmac
import re
import secrets
import smtplib
import uuid
from contextlib import asynccontextmanager, suppress
from typing import Literal
from urllib.parse import parse_qs, urlencode

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

from . import webhooks
from .config import Config
from .log import log
from .mailer import Mailer
from .mfa import matching_step
from .oauth import (
    CODE_LIFETIME,
    STATE_LIFETIME,
    ExternalUser,
    authorize_redirect,
    digest,
    fetch_user,
    new_secret,
    pkce_challenge,
    redirect_allowed,
)
from .ratelimit import FailureLimiter
from .saml import MAX_RESPONSE_BYTES, SamlError, authn_redirect, new_request_id, verify_response
from .sms import SmsSender, normalize_phone
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


class PhoneCredentials(BaseModel):
    phone: str = Field(max_length=32)
    password: str = Field(max_length=1024)


class RecoverRequest(BaseModel):
    email: str = Field(max_length=254)
    redirect_to: str | None = Field(default=None, max_length=2048)


class PasswordChange(BaseModel):
    password: str | None = Field(default=None, max_length=1024)
    current_password: str | None = Field(default=None, max_length=1024)
    email: str | None = Field(default=None, max_length=254)
    phone: str | None = Field(default=None, max_length=32)


class EmailChangeVerify(BaseModel):
    token: str = Field(pattern=r"^[0-9]{6}$")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(max_length=256)


class CodeExchange(BaseModel):
    code: str = Field(max_length=256)
    # RFC 7636: verifiers are 43-128 characters.
    code_verifier: str = Field(min_length=43, max_length=128)


class OtpRequest(BaseModel):
    # Exactly one of the two.
    email: str | None = Field(default=None, max_length=254)
    phone: str | None = Field(default=None, max_length=32)
    create_user: bool = True
    redirect_to: str | None = Field(default=None, max_length=2048)


class VerifyRequest(BaseModel):
    type: Literal["email", "magiclink", "signup", "recovery", "sms"]
    email: str | None = Field(default=None, max_length=254)
    phone: str | None = Field(default=None, max_length=32)
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
    "sms": "sms",
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
        "phone": row.get("phone"),
        "is_anonymous": row.get("is_anonymous", False),
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
    sms = SmsSender(config.sms_url, config.sms_secret)
    # Every text costs the operator money: 5 per number and hour, and the per-IP mail budget.
    otp_phone_limiter = FailureLimiter(limit=5, window=3600)
    anonymous_ip_limiter = FailureLimiter(limit=30, window=3600)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.pool = await asyncpg.create_pool(config.database_url, min_size=1, max_size=10)
        app.state.http = httpx.AsyncClient(timeout=10)
        worker = asyncio.create_task(webhooks.run(app.state.pool, app.state.http))
        try:
            yield
        finally:
            worker.cancel()
            with suppress(asyncio.CancelledError):
                await worker
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
            " returning id, email, phone, created_at, last_sign_in_at, email_confirmed_at,"
            " is_anonymous",
            user_id,
        )
        aal, recovery = await conn.fetchrow(
            "select aal, recovery from auth.sessions where id = $1", session_id
        )
        has_factor = await conn.fetchval(
            "select exists (select 1 from auth.mfa_factors where user_id = $1 and verified)",
            user_id,
        )
        # Enrolled users get an API-usable token only after proving the second factor; with
        # MFA required, so do users who have not enrolled yet (guests have nothing to protect).
        must_verify = has_factor or (config.mfa_required and not user["is_anonymous"])
        mfa_pending = must_verify and aal != "aal2"
        access_token, expires_at = signer.access_token(
            str(user_id),
            email,
            str(session_id),
            aal,
            mfa_pending,
            email_verified=user["email_confirmed_at"] is not None,
            recovery=recovery,
            is_anonymous=user["is_anonymous"],
            phone=user["phone"],
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

    @app.post("/anonymous")
    async def anonymous(request: Request):
        """Creates a user without credentials; it can become permanent later via PUT /user."""
        if not config.anonymous_sign_in:
            return error(
                403, "anonymous_disabled", "set KILNBASE_AUTH_ANONYMOUS=true to allow this"
            )
        key = client_ip(request)
        if wait := anonymous_ip_limiter.retry_after(key):
            return error(
                429,
                "too_many_requests",
                "too many anonymous sign-ups",
                headers={"Retry-After": str(wait)},
            )
        anonymous_ip_limiter.fail(key)
        async with app.state.pool.acquire() as conn, conn.transaction():
            user_id = await conn.fetchval(
                "insert into auth.users (is_anonymous) values (true) returning id"
            )
            return await issue_session(conn, user_id, None)

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
        """With email and password, or with a verified phone number and a password set later."""
        try:
            raw = await request.json()
            by_phone = isinstance(raw, dict) and "phone" in raw and "email" not in raw
            body = (PhoneCredentials if by_phone else Credentials).model_validate(raw)
        except ValueError:
            return error(
                422, "invalid_request", "request body is missing fields or has invalid ones"
            )
        if isinstance(body, PhoneCredentials):
            login = normalize_phone(body.phone) or body.phone.strip()
            lookup = "select id, email, password_hash from auth.users where phone = $1"
        else:
            login = normalize_email(body.email) or body.email.strip().lower()
            lookup = "select id, email, password_hash from auth.users where lower(email) = $1"
        # Same key as check_current_password, so both count against one budget per account.
        keys = [(email_limiter, f"email:{login}"), (ip_limiter, f"ip:{client_ip(request)}")]
        for limiter, key in keys:
            if wait := limiter.retry_after(key):
                return error(
                    429,
                    "too_many_attempts",
                    "too many failed sign-in attempts",
                    headers={"Retry-After": str(wait)},
                )

        async with app.state.pool.acquire() as conn:
            row = await conn.fetchrow(lookup, login)
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
                return error(400, "invalid_credentials", "invalid login or password")

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
    identity_providers = config.identity_providers or {}
    callback_url = f"{config.public_url}/auth/v1/callback"
    # SAML responses are posted to the same callback; this names us to the IdP.
    sp_entity_id = f"{config.public_url}/auth/v1/saml"

    @app.get("/authorize")
    async def authorize(
        provider: str, redirect_to: str, code_challenge: str, code_challenge_method: str = "S256"
    ):
        """Browser entry point for provider sign-in; reached without an API key."""
        selected = providers.get(provider)
        idp = identity_providers.get(provider)
        if selected is None and idp is None:
            return error(400, "unknown_provider", "this provider is not enabled")
        if code_challenge_method != "S256" or not re.fullmatch(
            r"[A-Za-z0-9_-]{43}", code_challenge
        ):
            return error(400, "invalid_request", "an S256 code_challenge is required")
        if not redirect_allowed(redirect_to, [config.public_url, *config.redirect_urls]):
            return error(400, "redirect_not_allowed", "add this URL to KILNBASE_AUTH_REDIRECT_URLS")
        state = new_secret()
        # For SAML the "verifier" is the AuthnRequest ID the response must answer.
        verifier = new_request_id() if idp else new_secret()
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
        if idp:
            url = authn_redirect(idp, sp_entity_id, callback_url, verifier, state)
        else:
            url = authorize_redirect(selected, callback_url, state, verifier)
        return RedirectResponse(url, 302)

    async def take_flow(state: str):
        async with app.state.pool.acquire() as conn:
            return await conn.fetchrow(
                "delete from auth.oauth_states where state_hash = $1"
                " and created_at > now() - make_interval(secs => $2) returning *",
                digest(state),
                STATE_LIFETIME,
            )

    def back_to(target: str, **params: str) -> RedirectResponse:
        separator = "&" if "?" in target else "?"
        return RedirectResponse(f"{target}{separator}{urlencode(params)}", 302)

    @app.post("/callback")
    async def saml_callback(request: Request):
        """The IdP's HTTP-POST binding: a form with SAMLResponse and RelayState (our state)."""
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_RESPONSE_BYTES * 2:
                return error(413, "too_large", "SAML response is too large")
        form = {k: v[0] for k, v in parse_qs(body.decode("latin-1")).items()}
        flow = await take_flow(form.get("RelayState", ""))
        if flow is None or flow["provider"] not in identity_providers:
            return error(400, "invalid_state", "sign-in link expired or was already used")
        try:
            external = verify_response(
                form.get("SAMLResponse", ""),
                identity_providers[flow["provider"]],
                sp_entity_id=sp_entity_id,
                acs_url=callback_url,
                request_id=flow["provider_verifier"],
            )
        except SamlError as e:
            log.warning("SAML response from %s rejected: %s", flow["provider"], e)
            return back_to(flow["redirect_to"], error="provider_error")
        return await finish_sign_in(flow, f"saml:{flow['provider']}", external)

    @app.get("/callback")
    async def callback(state: str = "", code: str = "", error_: str = Query("", alias="error")):
        flow = await take_flow(state)
        if flow is None or flow["provider"] not in providers:
            return error(400, "invalid_state", "sign-in link expired or was already used")
        if error_ or not code:
            return back_to(flow["redirect_to"], error="access_denied")
        try:
            external = await fetch_user(
                app.state.http,
                providers[flow["provider"]],
                code,
                callback_url,
                flow["provider_verifier"],
            )
        except httpx.HTTPError, KeyError, ValueError, TypeError:
            return back_to(flow["redirect_to"], error="provider_error")
        return await finish_sign_in(flow, flow["provider"], external)

    async def finish_sign_in(flow, identity_provider: str, external: ExternalUser):
        """Finds or links the user, then hands the app a one-time code for its PKCE verifier."""

        def back(**params: str) -> RedirectResponse:
            return back_to(flow["redirect_to"], **params)

        async with app.state.pool.acquire() as conn, conn.transaction():
            user_id = await conn.fetchval(
                "select user_id from auth.identities where provider = $1 and provider_user_id = $2",
                identity_provider,
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
                    identity_provider,
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
            log.error("sending mail failed: %s", e)
            await app.state.pool.execute(
                "delete from auth.one_time_tokens where email = $1 and purpose = $2", email, purpose
            )
            return error(503, "mail_unavailable", "could not send the email, try again later")
        return None

    def sms_limited(phone: str, ip: str) -> JSONResponse | None:
        for limiter, key in [(otp_phone_limiter, phone), (otp_ip_limiter, ip)]:
            if wait := limiter.retry_after(key):
                return error(
                    429,
                    "too_many_requests",
                    "too many codes requested",
                    headers={"Retry-After": str(wait)},
                )
            limiter.fail(key)
        return None

    async def send_sms_code(phone: str, create_user: bool, ip: str) -> JSONResponse | None:
        """Stores a fresh code for the number and texts it; None on success."""
        if failed := sms_limited(phone, ip):
            return failed
        code = f"{secrets.randbelow(10**6):06d}"
        await app.state.pool.execute(
            "insert into auth.phone_codes (phone, code_hash, create_user) values ($1, $2, $3)"
            " on conflict (phone) do update set code_hash = excluded.code_hash,"
            " create_user = excluded.create_user, attempts = 0, created_at = now()",
            phone,
            digest(f"{phone}:sms:{code}"),
            create_user,
        )
        text = f"Your sign-in code is {code}. It expires in {OTP_LIFETIME // 60} minutes."
        try:
            await sms.send(app.state.http, phone, text)
        except httpx.HTTPError as e:
            # The type only: the hook URL may carry a secret.
            log.error("sending SMS failed: %s", type(e).__name__)
            await app.state.pool.execute("delete from auth.phone_codes where phone = $1", phone)
            return error(503, "sms_unavailable", "could not send the text message, try again later")
        return None

    @app.post("/otp")
    async def request_otp(body: OtpRequest, request: Request):
        """Emails a 6-digit code (and a magic link when redirect_to is given), or texts one.

        The answer is the same whether or not an account exists, so it cannot probe for accounts.
        """
        if (body.email is None) == (body.phone is None):
            return error(422, "invalid_request", "give either email or phone")
        if body.phone is not None:
            phone = normalize_phone(body.phone)
            if phone is None:
                return error(422, "invalid_phone", "phone number must be in E.164 form")
            if not body.create_user:
                exists = await app.state.pool.fetchval(
                    "select exists (select 1 from auth.users where phone = $1)", phone
                )
                if not exists:
                    return {"sent": True}
            failed = await send_sms_code(phone, body.create_user, client_ip(request))
            return failed or {"sent": True}
        email = normalize_email(body.email or "")
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
        if body.type == "sms":
            return await verify_sms(body)
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

    async def verify_sms(body: VerifyRequest):
        invalid = error(400, "invalid_otp", "code is wrong, expired or already used")
        phone = normalize_phone(body.phone or "")
        if phone is None:
            return invalid
        async with app.state.pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                "select code_hash, create_user, attempts,"
                " created_at > now() - make_interval(secs => $2) as fresh"
                " from auth.phone_codes where phone = $1 for update",
                phone,
                OTP_LIFETIME,
            )
            if row is None:
                return invalid
            if not (
                row["fresh"]
                and row["attempts"] < OTP_MAX_ATTEMPTS
                and hmac.compare_digest(digest(f"{phone}:sms:{body.token}"), row["code_hash"])
            ):
                # Too many wrong tries kills the code, so 6 digits cannot be brute forced.
                await conn.execute(
                    "update auth.phone_codes set attempts = attempts + 1 where phone = $1", phone
                )
                return invalid
            await conn.execute("delete from auth.phone_codes where phone = $1", phone)
            user = await conn.fetchrow("select id, email from auth.users where phone = $1", phone)
            if user is None:
                if not row["create_user"]:
                    return invalid
                user = await conn.fetchrow(
                    "insert into auth.users (phone) values ($1) returning id, email", phone
                )
            return await issue_session(conn, user["id"], user["email"])

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
            "select id, email, phone, is_anonymous, created_at, last_sign_in_at, email_confirmed_at"
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

    async def check_current_password(row, current: str | None) -> JSONResponse | None:
        """Re-authentication for sensitive changes; rate limited like sign-in."""
        # Phone-only users have no email; keyed by email alone they would share one budget.
        key = f"email:{row['email'] or row['phone']}"
        if wait := email_limiter.retry_after(key):
            return error(
                429,
                "too_many_attempts",
                "too many failed attempts",
                headers={"Retry-After": str(wait)},
            )
        try:
            ok = await run_in_threadpool(hasher.verify, row["password_hash"], current or "")
        except VerificationError, InvalidHashError:
            ok = False
        if not ok:
            email_limiter.fail(key)
            return error(400, "invalid_credentials", "current password is wrong")
        return None

    async def own_row(conn, claims: dict):
        return await conn.fetchrow(
            "select u.email, u.phone, u.password_hash, s.recovery from auth.users u"
            " join auth.sessions s on s.user_id = u.id"
            " where u.id = $1::uuid and s.id = $2::uuid",
            claims["sub"],
            claims["sid"],
        )

    @app.put("/user")
    async def update_user(body: PasswordChange, request: Request):
        """Changes the password or email, or turns an anonymous user into a permanent one.

        Password changes need the current password unless this is a password-reset session, and sign
        out every other session, since a password change often follows a leak.
        """
        claims = await current_session(request)
        if claims is None or claims["role"] != "authenticated":
            return error(401, "unauthorized", "a fully signed-in session is required")
        if body.password is not None and len(body.password) < MIN_PASSWORD_LENGTH:
            return error(
                422, "weak_password", f"password must be at least {MIN_PASSWORD_LENGTH} characters"
            )
        if body.phone is not None:
            if body.email is not None or body.password is not None:
                return error(422, "invalid_request", "change the phone on its own")
            return await request_phone_change(claims, body, request)
        if claims.get("is_anonymous"):
            if body.email is None or body.password is None:
                return error(422, "invalid_request", "anonymous users must set email and password")
            return await upgrade_anonymous(claims, body, request)
        if body.email is not None:
            if body.password is not None:
                return error(422, "invalid_request", "change the email and password separately")
            return await request_email_change(claims, body, request)
        if body.password is None:
            return error(422, "invalid_request", "nothing to change")

        async with app.state.pool.acquire() as conn:
            row = await own_row(conn, claims)
            if row is None:
                return error(401, "unauthorized", "a valid access token is required")
            if not row["recovery"] and row["password_hash"]:
                if failed := await check_current_password(row, body.current_password):
                    return failed
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

    async def request_email_change(claims: dict, body: PasswordChange, request: Request):
        """Mails a code to the new address and a heads-up to the old one; nothing changes yet."""
        new_email = normalize_email(body.email or "")
        if new_email is None:
            return error(422, "invalid_email", "email address is not valid")
        async with app.state.pool.acquire() as conn:
            row = await own_row(conn, claims)
            if row is None:
                return error(401, "unauthorized", "a valid access token is required")
            if new_email == row["email"]:
                return error(400, "same_email", "that is already your email")
            if row["password_hash"] and not row["recovery"]:
                if failed := await check_current_password(row, body.current_password):
                    return failed
            taken = await conn.fetchval(
                "select exists (select 1 from auth.users where lower(email) = $1)", new_email
            )
            if taken:
                return error(422, "email_taken", "a user with this email already exists")
            for limiter, key in (
                (otp_email_limiter, f"otp:{new_email}"),
                (otp_ip_limiter, client_ip(request)),
            ):
                if wait := limiter.retry_after(key):
                    return error(
                        429,
                        "too_many_requests",
                        "too many codes requested",
                        headers={"Retry-After": str(wait)},
                    )
                limiter.fail(key)
            code = f"{secrets.randbelow(10**6):06d}"
            await conn.execute(
                "insert into auth.email_changes (user_id, new_email, code_hash)"
                " values ($1::uuid, $2, $3) on conflict (user_id) do update"
                " set new_email = excluded.new_email, code_hash = excluded.code_hash,"
                " attempts = 0, created_at = now()",
                claims["sub"],
                new_email,
                digest(f"{claims['sub']}:{new_email}:{code}"),
            )
        try:
            await run_in_threadpool(
                mailer.send,
                new_email,
                "Confirm your new email",
                f"Your code to confirm this address is {code}. "
                f"It expires in {OTP_LIFETIME // 60} minutes.\n",
            )
        except (OSError, smtplib.SMTPException) as e:
            log.error("sending mail failed: %s", e)
            await app.state.pool.execute(
                "delete from auth.email_changes where user_id = $1::uuid", claims["sub"]
            )
            return error(503, "mail_unavailable", "could not send the email, try again later")
        # Best effort: lets the real owner react if someone else is taking over the account.
        try:
            await run_in_threadpool(
                mailer.send,
                row["email"],
                "Your email is being changed",
                f"Someone asked to change this account's email to {new_email}.\n"
                "If that was not you, reset your password now.\n",
            )
        except (OSError, smtplib.SMTPException) as e:
            log.error("sending notice failed: %s", e)
        return JSONResponse({"email_change_sent": True}, status_code=202)

    @app.post("/user/email/verify")
    async def confirm_email_change(body: EmailChangeVerify, request: Request):
        claims = await current_session(request)
        if claims is None or claims["role"] != "authenticated":
            return error(401, "unauthorized", "a fully signed-in session is required")
        invalid = error(400, "invalid_otp", "code is wrong, expired or already used")
        async with app.state.pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                "select new_email, code_hash, attempts,"
                " created_at > now() - make_interval(secs => $2) as fresh"
                " from auth.email_changes where user_id = $1::uuid for update",
                claims["sub"],
                OTP_LIFETIME,
            )
            if row is None:
                return invalid
            expected = digest(f"{claims['sub']}:{row['new_email']}:{body.token}")
            if not (
                row["fresh"]
                and row["attempts"] < OTP_MAX_ATTEMPTS
                and hmac.compare_digest(expected, row["code_hash"])
            ):
                await conn.execute(
                    "update auth.email_changes set attempts = attempts + 1"
                    " where user_id = $1::uuid",
                    claims["sub"],
                )
                return invalid
            await conn.execute(
                "delete from auth.email_changes where user_id = $1::uuid", claims["sub"]
            )
            try:
                await conn.execute(
                    "update auth.users set email = $2, email_confirmed_at = now(),"
                    " updated_at = now() where id = $1::uuid",
                    claims["sub"],
                    row["new_email"],
                )
            except asyncpg.UniqueViolationError:
                return error(422, "email_taken", "a user with this email already exists")
            await conn.execute(
                "update auth.sessions set revoked_at = now()"
                " where user_id = $1::uuid and id <> $2::uuid and revoked_at is null",
                claims["sub"],
                claims["sid"],
            )
            return await issue_session(
                conn, uuid.UUID(claims["sub"]), row["new_email"], uuid.UUID(claims["sid"])
            )

    async def request_phone_change(claims: dict, body: PasswordChange, request: Request):
        """Texts a code to the new number; nothing changes until it is entered.

        Also how an anonymous user becomes a permanent one with just a phone.
        """
        new_phone = normalize_phone(body.phone or "")
        if new_phone is None:
            return error(422, "invalid_phone", "phone number must be in E.164 form")
        async with app.state.pool.acquire() as conn:
            row = await own_row(conn, claims)
            if row is None:
                return error(401, "unauthorized", "a valid access token is required")
            if new_phone == row["phone"]:
                return error(400, "same_phone", "that is already your phone number")
            if row["password_hash"] and not row["recovery"]:
                if failed := await check_current_password(row, body.current_password):
                    return failed
            if await conn.fetchval("select 1 from auth.users where phone = $1", new_phone):
                return error(422, "phone_taken", "a user with this phone number already exists")
            if failed := sms_limited(new_phone, client_ip(request)):
                return failed
            code = f"{secrets.randbelow(10**6):06d}"
            await conn.execute(
                "insert into auth.phone_changes (user_id, new_phone, code_hash)"
                " values ($1::uuid, $2, $3) on conflict (user_id) do update"
                " set new_phone = excluded.new_phone, code_hash = excluded.code_hash,"
                " attempts = 0, created_at = now()",
                claims["sub"],
                new_phone,
                digest(f"{claims['sub']}:{new_phone}:{code}"),
            )
        minutes = OTP_LIFETIME // 60
        text = f"Your code to confirm this number is {code}. It expires in {minutes} minutes."
        try:
            await sms.send(app.state.http, new_phone, text)
        except httpx.HTTPError as e:
            log.error("sending SMS failed: %s", type(e).__name__)
            await app.state.pool.execute(
                "delete from auth.phone_changes where user_id = $1::uuid", claims["sub"]
            )
            return error(503, "sms_unavailable", "could not send the text message, try again later")
        return JSONResponse({"phone_change_sent": True}, status_code=202)

    @app.post("/user/phone/verify")
    async def confirm_phone_change(body: EmailChangeVerify, request: Request):
        claims = await current_session(request)
        if claims is None or claims["role"] != "authenticated":
            return error(401, "unauthorized", "a fully signed-in session is required")
        invalid = error(400, "invalid_otp", "code is wrong, expired or already used")
        async with app.state.pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                "select new_phone, code_hash, attempts,"
                " created_at > now() - make_interval(secs => $2) as fresh"
                " from auth.phone_changes where user_id = $1::uuid for update",
                claims["sub"],
                OTP_LIFETIME,
            )
            if row is None:
                return invalid
            expected = digest(f"{claims['sub']}:{row['new_phone']}:{body.token}")
            if not (
                row["fresh"]
                and row["attempts"] < OTP_MAX_ATTEMPTS
                and hmac.compare_digest(expected, row["code_hash"])
            ):
                await conn.execute(
                    "update auth.phone_changes set attempts = attempts + 1"
                    " where user_id = $1::uuid",
                    claims["sub"],
                )
                return invalid
            await conn.execute(
                "delete from auth.phone_changes where user_id = $1::uuid", claims["sub"]
            )
            try:
                email = await conn.fetchval(
                    "update auth.users set phone = $2, is_anonymous = false, updated_at = now()"
                    " where id = $1::uuid returning email",
                    claims["sub"],
                    row["new_phone"],
                )
            except asyncpg.UniqueViolationError:
                return error(422, "phone_taken", "a user with this phone number already exists")
            await conn.execute(
                "update auth.sessions set revoked_at = now()"
                " where user_id = $1::uuid and id <> $2::uuid and revoked_at is null",
                claims["sub"],
                claims["sid"],
            )
            return await issue_session(
                conn, uuid.UUID(claims["sub"]), email, uuid.UUID(claims["sid"])
            )

    async def upgrade_anonymous(claims: dict, body: PasswordChange, request: Request):
        """Gives an anonymous user an email and password; the user id and its data are kept."""
        email = normalize_email(body.email or "")
        if email is None:
            return error(422, "invalid_email", "email address is not valid")
        password_hash = await run_in_threadpool(hasher.hash, body.password)
        async with app.state.pool.acquire() as conn, conn.transaction():
            try:
                await conn.execute(
                    "update auth.users set email = $2, password_hash = $3, is_anonymous = false,"
                    " updated_at = now() where id = $1::uuid and is_anonymous",
                    claims["sub"],
                    email,
                    password_hash,
                )
            except asyncpg.UniqueViolationError:
                return error(422, "email_taken", "a user with this email already exists")
            session = await issue_session(
                conn, uuid.UUID(claims["sub"]), email, uuid.UUID(claims["sid"])
            )
        sent = False
        if config.smtp_url:
            sent = await send_code(email, "confirm", None, False, client_ip(request)) is None
        return session | {"confirmation_sent": sent}

    @app.post("/factors")
    async def enroll_factor(request: Request):
        claims = await current_session(request)
        # mfa_pending may enrol: that is how users get through a KILNBASE_AUTH_MFA_REQUIRED sign-in.
        # Users who already have a factor are stopped by the enrolled check below.
        if claims is None or claims["role"] not in ("authenticated", "mfa_pending"):
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
