import time
from typing import Any

import httpx2 as httpx

from .errors import KilnbaseError, send

# Refresh this many seconds before expiry so requests never carry a dead token.
REFRESH_MARGIN = 60


class AuthClient:
    """Keeps the session in memory only; sign in again after the process restarts."""

    def __init__(self, http: httpx.Client, url: str, api_key: str):
        self._http = http
        self._url = url
        self._api_key = api_key
        self.session: dict[str, Any] | None = None

    def sign_up(self, email: str, password: str) -> dict[str, Any]:
        return self._obtain("/auth/v1/signup", {"email": email, "password": password})

    def sign_in_with_password(self, email: str, password: str) -> dict[str, Any]:
        return self._obtain(
            "/auth/v1/token?grant_type=password", {"email": email, "password": password}
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

    def _obtain(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = send(
            self._http, "POST", f"{self._url}{path}", headers={"apikey": self._api_key}, json=body
        )
        self.session = res.json()
        return self.session
