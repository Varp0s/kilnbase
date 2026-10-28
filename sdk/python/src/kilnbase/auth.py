import base64
import hashlib
import secrets
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlencode

import httpx2 as httpx

from .errors import KilnbaseError, send

# Refresh this many seconds before expiry so requests never carry a dead token.
REFRESH_MARGIN = 60


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class AuthClient:
    """Keeps the session in memory only; sign in again after the process restarts."""

    def __init__(self, http: httpx.Client, url: str, api_key: str):
        self._http = http
        self._url = url
        self._api_key = api_key
        self._session: dict[str, Any] | None = None
        # Realtime runs on its own thread: two refreshes at once would replay a single-use
        # refresh token and end the session.
        self._refresh_lock = threading.Lock()
        self._listeners: list[Callable[[], None]] = []
        self._verifier: str | None = None
        self.mfa = MfaClient(self)

    @property
    def session(self) -> dict[str, Any] | None:
        return self._session

    @session.setter
    def session(self, value: dict[str, Any] | None) -> None:
        self._session = value
        for listener in self._listeners:
            listener()

    def sign_up(self, email: str, password: str) -> dict[str, Any]:
        return self._obtain("/auth/v1/signup", {"email": email, "password": password})

    def sign_in_with_password(self, email: str, password: str) -> dict[str, Any]:
        return self._obtain(
            "/auth/v1/token?grant_type=password", {"email": email, "password": password}
        )

    def sign_in_anonymously(self) -> dict[str, Any]:
        """A guest account (must be enabled on the server); keep it later with `update_user`."""
        return self._obtain("/auth/v1/anonymous", {})

    def update_user(
        self,
        password: str | None = None,
        *,
        current_password: str | None = None,
        email: str | None = None,
        phone: str | None = None,
    ) -> None:
        """
        One change at a time; `current_password` is needed when the account has a password
        (unless signed in through a password reset).

        - `password`: changes it and signs out other sessions.
        - `email` and `password` on an anonymous user: makes the account permanent.
        - `email` or `phone`: sends a code to the new address or number; nothing changes until it
          is passed to `confirm_email_change` / `confirm_phone_change`.
        """
        body = {
            "password": password,
            "current_password": current_password,
            "email": email,
            "phone": phone,
        }
        res = self._authed(
            "PUT", "/auth/v1/user", json={k: v for k, v in body.items() if v is not None}
        )
        # An upgrade returns a fresh session (the anonymous flag is gone from the token).
        if res.status_code == 200:
            self.session = res.json()

    def confirm_email_change(self, token: str) -> dict[str, Any]:
        """Applies a pending email change with the code sent to the new address."""
        self.session = self._authed(
            "POST", "/auth/v1/user/email/verify", json={"token": token}
        ).json()
        return self.session

    def confirm_phone_change(self, token: str) -> dict[str, Any]:
        """Applies a pending phone change with the texted code."""
        self.session = self._authed(
            "POST", "/auth/v1/user/phone/verify", json={"token": token}
        ).json()
        return self.session

    def sign_in_with_otp(
        self,
        email: str | None = None,
        *,
        phone: str | None = None,
        redirect_to: str | None = None,
        create_user: bool = True,
    ) -> None:
        """
        Emails a 6-digit code, plus a magic link to `redirect_to` when given, or texts a code to
        `phone` (E.164, e.g. "+15551234567"). The response is identical whether or not an account
        exists.
        """
        body = {
            "email": email,
            "phone": phone,
            "redirect_to": redirect_to,
            "create_user": create_user,
        }
        send(
            self._http,
            "POST",
            f"{self._url}/auth/v1/otp",
            headers={"apikey": self._api_key},
            json={k: v for k, v in body.items() if v is not None},
        )

    def verify_otp(
        self, type: str, token: str, *, email: str | None = None, phone: str | None = None
    ) -> dict[str, Any]:
        """
        `type="email"` with the emailed code and `email`, `"sms"` with the texted code and
        `phone`, or `"magiclink"` with its token.
        """
        body = {"type": type, "email": email, "phone": phone, "token": token}
        return self._obtain("/auth/v1/verify", {k: v for k, v in body.items() if v is not None})

    def sign_in_with_oauth(self, provider: str, *, redirect_to: str) -> str:
        """
        Returns the URL to send the browser to; the provider returns it to `redirect_to` with
        `?code=...`, which `exchange_code_for_session` turns into a session. The PKCE verifier
        stays in this client, so an intercepted code is useless.
        """
        verifier = _b64url(secrets.token_bytes(48))
        self._verifier = verifier
        params = {
            "provider": provider,
            "redirect_to": redirect_to,
            "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()),
        }
        return f"{self._url}/auth/v1/authorize?{urlencode(params)}"

    def exchange_code_for_session(self, code: str) -> dict[str, Any]:
        verifier, self._verifier = self._verifier, None
        if not verifier:
            raise KilnbaseError(400, "missing_verifier", "call sign_in_with_oauth first")
        return self._obtain(
            "/auth/v1/token?grant_type=authorization_code",
            {"code": code, "code_verifier": verifier},
        )

    def refresh_session(self) -> dict[str, Any]:
        # Refresh tokens are single-use: replaying a spent one ends the session server side.
        if not self.session:
            raise KilnbaseError(401, "not_signed_in", "no active session")
        try:
            return self._obtain(
                "/auth/v1/token?grant_type=refresh_token",
                {"refresh_token": self.session["refresh_token"]},
            )
        except KilnbaseError as e:
            if e.status == 401:
                self.session = None
            raise

    def sign_out(self) -> None:
        """Ends the session on the server too, so its refresh token stops working."""
        session, self.session = self.session, None
        if session:
            send(
                self._http,
                "POST",
                f"{self._url}/auth/v1/logout",
                headers={
                    "apikey": self._api_key,
                    "Authorization": f"Bearer {session['access_token']}",
                },
            )

    def get_session(self) -> dict[str, Any] | None:
        """The current session, refreshed first if it is about to expire."""
        with self._refresh_lock:
            if self.session and self.session["expires_at"] - REFRESH_MARGIN <= time.time():
                return self.refresh_session()
            return self.session

    def get_user(self) -> dict[str, Any]:
        if not self.get_session():
            raise KilnbaseError(401, "not_signed_in", "no active session")
        return send(self._http, "GET", f"{self._url}/auth/v1/user", headers=self.headers()).json()

    def headers(self) -> dict[str, str]:
        """`apikey` always; plus the user's access token once signed in."""
        session = self.get_session()
        if session:
            return {"apikey": self._api_key, "Authorization": f"Bearer {session['access_token']}"}
        return {"apikey": self._api_key}

    def _authed(self, method: str, path: str, **kwargs) -> httpx.Response:
        if not self.get_session():
            raise KilnbaseError(401, "not_signed_in", "no active session")
        return send(self._http, method, f"{self._url}{path}", headers=self.headers(), **kwargs)

    def _obtain(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = send(
            self._http, "POST", f"{self._url}{path}", headers={"apikey": self._api_key}, json=body
        )
        self.session = res.json()
        return self.session


class MfaClient:
    """TOTP second factor. Once a factor is verified, sign-ins need `verify()` first."""

    def __init__(self, auth: AuthClient):
        self._auth = auth

    def enroll(self) -> dict[str, Any]:
        """`id`, `type`, plus the base32 `secret` and `otpauth://` `uri` to show as a QR code."""
        return self._auth._authed("POST", "/auth/v1/factors").json()

    def verify(self, factor_id: str, code: str) -> dict[str, Any]:
        """Confirms an enrolment or completes a pending sign-in; the session is upgraded."""
        res = self._auth._authed(
            "POST", f"/auth/v1/factors/{quote(factor_id, safe='')}/verify", json={"code": code}
        )
        self._auth.session = res.json()
        return self._auth.session

    def unenroll(self, factor_id: str) -> None:
        self._auth._authed("DELETE", f"/auth/v1/factors/{quote(factor_id, safe='')}")
