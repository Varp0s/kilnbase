from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

import jwt

PLACEHOLDER = "change-me"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    database_url: str
    service_role_key: str
    anon_claims: dict
    port: int = 3001
    # Stored files are read and written through core, which owns the storage backend.
    core_url: str = "http://core:8000"
    # Shown on the Connect page; the anon key is public by design.
    public_url: str = "http://localhost:8000"
    anon_key: str = ""


def load(env: Mapping[str, str]) -> Config:
    values = {}
    for name in ("DATABASE_URL", "KILNBASE_SERVICE_ROLE_KEY", "KILNBASE_ANON_KEY"):
        value = env.get(name, "").strip()
        if not value or PLACEHOLDER in value:
            raise ConfigError(f"{name} is missing or uses the example value; run `kilnbase init`")
        values[name] = value
    if urlsplit(values["DATABASE_URL"]).password in (None, ""):
        raise ConfigError("DATABASE_URL has no password")
    # Only our own .env provides these keys; their claims are what the REST API sees for them.
    claims = {}
    for name in ("KILNBASE_SERVICE_ROLE_KEY", "KILNBASE_ANON_KEY"):
        try:
            claims[name] = jwt.decode(values[name], options={"verify_signature": False})
        except jwt.InvalidTokenError as e:
            raise ConfigError(f"{name} is not a JWT: {e}") from e
    if claims["KILNBASE_SERVICE_ROLE_KEY"].get("role") != "service_role":
        raise ConfigError("KILNBASE_SERVICE_ROLE_KEY is not a service_role key")
    if claims["KILNBASE_ANON_KEY"].get("role") != "anon":
        raise ConfigError("KILNBASE_ANON_KEY is not an anon key")
    port = env.get("KILNBASE_STUDIO_PORT", "3001")
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ConfigError(f"KILNBASE_STUDIO_PORT is not a valid port: {port}")
    return Config(
        values["DATABASE_URL"],
        values["KILNBASE_SERVICE_ROLE_KEY"],
        claims["KILNBASE_ANON_KEY"],
        int(port),
        env.get("KILNBASE_STUDIO_CORE_URL", "http://core:8000").rstrip("/"),
        env.get("KILNBASE_PUBLIC_URL", "http://localhost:8000").rstrip("/"),
        values["KILNBASE_ANON_KEY"],
    )
