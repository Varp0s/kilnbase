import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import jwt

from .oauth import Provider, load_providers

# Value shipped in .env.example; refusing it stops people from running with published secrets.
PLACEHOLDER = "change-me"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    database_url: str
    private_jwk: dict
    authenticator_password: str
    migrations_dir: Path
    port: int
    public_url: str = "http://localhost:8000"
    redirect_urls: tuple[str, ...] = ()
    providers: dict[str, Provider] | None = None


def load(env: Mapping[str, str]) -> Config:
    database_url = _required(env, "DATABASE_URL")
    if urlsplit(database_url).password in (None, "", PLACEHOLDER):
        raise ConfigError("DATABASE_URL has no password or uses the example value")

    raw_jwk = _required(env, "KILNBASE_JWT_PRIVATE_JWK")
    try:
        jwk = json.loads(raw_jwk)
    except json.JSONDecodeError as e:
        raise ConfigError(f"KILNBASE_JWT_PRIVATE_JWK is not valid JSON: {e}") from e
    if not (
        isinstance(jwk, dict)
        and jwk.get("kty") == "EC"
        and jwk.get("crv") == "P-256"
        and jwk.get("d")
        and jwk.get("kid")
    ):
        raise ConfigError("KILNBASE_JWT_PRIVATE_JWK must be a private EC P-256 JWK with a kid")
    try:
        jwt.PyJWK.from_dict(jwk)
    except (jwt.PyJWTError, ValueError) as e:
        raise ConfigError(f"KILNBASE_JWT_PRIVATE_JWK is not a usable key: {e}") from e

    authenticator_password = _required(env, "KILNBASE_AUTHENTICATOR_PASSWORD")
    migrations_dir = Path(env.get("KILNBASE_MIGRATIONS_DIR", "/app/migrations"))

    port_raw = env.get("KILNBASE_AUTH_PORT", "9999")
    if not port_raw.isdigit() or not 0 < int(port_raw) < 65536:
        raise ConfigError(f"KILNBASE_AUTH_PORT is not a valid port: {port_raw}")

    public_url = env.get("KILNBASE_PUBLIC_URL", "http://localhost:8000").rstrip("/")
    redirect_urls = tuple(
        u.strip() for u in env.get("KILNBASE_AUTH_REDIRECT_URLS", "").split(",") if u.strip()
    )
    try:
        providers = load_providers(env)
    except ValueError as e:
        raise ConfigError(str(e)) from e

    return Config(
        public_url=public_url,
        redirect_urls=redirect_urls,
        providers=providers,
        database_url=database_url,
        private_jwk=jwk,
        authenticator_password=authenticator_password,
        migrations_dir=migrations_dir,
        port=int(port_raw),
    )


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value or value == PLACEHOLDER:
        raise ConfigError(
            f"{name} is missing or still set to the example value; run `kilnbase init`"
        )
    return value
