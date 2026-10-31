import base64
import hashlib
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

import httpx2 as httpx

STATE_LIFETIME = 600
CODE_LIFETIME = 300

# Endpoints for providers we know; anything else is a generic OIDC provider configured by URL.
KNOWN = {
    "github": {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scope": "read:user user:email",
    },
    "google": {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scope": "openid email profile",
    },
}


@dataclass(frozen=True)
class Provider:
    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scope: str


@dataclass(frozen=True)
class ExternalUser:
    id: str
    email: str | None
    email_verified: bool


def load_providers(env: Mapping[str, str]) -> dict[str, Provider]:
    """Enabled by KILNBASE_OAUTH_<NAME>_CLIENT_ID/_CLIENT_SECRET, plus URLs for unknown names."""
    providers = {}
    prefix, suffix = "KILNBASE_OAUTH_", "_CLIENT_ID"
    for key, client_id in env.items():
        if not (key.startswith(prefix) and key.endswith(suffix)) or not client_id:
            continue
        name = key[len(prefix) : -len(suffix)].lower()
        upper = name.upper()

        def setting(field: str, _upper=upper, _name=name) -> str:
            value = env.get(f"KILNBASE_OAUTH_{_upper}_{field.upper()}") or KNOWN.get(_name, {}).get(
                field
            )
            if not value:
                raise ValueError(f"KILNBASE_OAUTH_{_upper}_{field.upper()} is required")
            return value

        providers[name] = Provider(
            name=name,
            client_id=client_id,
            client_secret=setting("client_secret"),
            authorize_url=setting("authorize_url"),
            token_url=setting("token_url"),
            userinfo_url=setting("userinfo_url"),
            scope=env.get(f"KILNBASE_OAUTH_{upper}_SCOPE")
            or KNOWN.get(name, {}).get("scope", "openid email"),
        )
    return providers


def redirect_allowed(url: str, allowed: list[str]) -> bool:
    """Exact match or a path under an allowed base; `https://app.com` never admits `https://app.com.evil`."""
    parts = urlsplit(url)
    if (
        # urlsplit drops newlines and tabs; the raw value goes into mails and Location headers.
        any(c.isspace() or not c.isprintable() for c in url)
        or parts.scheme not in ("http", "https")
        or not parts.netloc
        or parts.username
        or parts.password
    ):
        return False
    return any(url == base or url.startswith(base.rstrip("/") + "/") for base in allowed)


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def digest(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def authorize_redirect(provider: Provider, callback_url: str, state: str, verifier: str) -> str:
    query = urlencode(
        {
            "response_type": "code",
            "client_id": provider.client_id,
            "redirect_uri": callback_url,
            "scope": provider.scope,
            "state": state,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
    )
    return f"{provider.authorize_url}?{query}"


async def fetch_user(
    http: httpx.AsyncClient, provider: Provider, code: str, callback_url: str, verifier: str
) -> ExternalUser:
    """Exchanges the provider code and reads who signed in. Raises on any provider error."""
    token = await http.post(
        provider.token_url,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "code_verifier": verifier,
        },
        headers={"Accept": "application/json"},
    )
    token.raise_for_status()
    access_token = token.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}

    info = await http.get(provider.userinfo_url, headers=headers)
    info.raise_for_status()
    data = info.json()

    if provider.name == "github":
        # GitHub's profile email may be unverified or hidden; only a verified primary email counts.
        emails = await http.get("https://api.github.com/user/emails", headers=headers)
        emails.raise_for_status()
        primary = next((e for e in emails.json() if e.get("primary") and e.get("verified")), None)
        return ExternalUser(
            id=str(data["id"]),
            email=primary["email"].lower() if primary else None,
            email_verified=primary is not None,
        )
    email = data.get("email")
    return ExternalUser(
        id=str(data["sub"]),
        email=email.lower() if isinstance(email, str) else None,
        email_verified=data.get("email_verified") is True,
    )
