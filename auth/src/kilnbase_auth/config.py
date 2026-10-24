import json
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

# Value shipped in .env.example; refusing it stops people from running with published secrets.
PLACEHOLDER = "change-me"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    database_url: str
    private_jwk: dict
    port: int


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
    ):
        raise ConfigError("KILNBASE_JWT_PRIVATE_JWK must be a private EC P-256 JWK")

    port_raw = env.get("KILNBASE_AUTH_PORT", "9999")
    if not port_raw.isdigit() or not 0 < int(port_raw) < 65536:
        raise ConfigError(f"KILNBASE_AUTH_PORT is not a valid port: {port_raw}")

    return Config(database_url=database_url, private_jwk=jwk, port=int(port_raw))


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value or value == PLACEHOLDER:
        raise ConfigError(
            f"{name} is missing or still set to the example value; run `kilnbase init`"
        )
    return value
