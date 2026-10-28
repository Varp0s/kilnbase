import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import jwt

PLACEHOLDER = "change-me"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    # Public keys only: this service runs untrusted code and holds no secret worth stealing.
    keys: dict[str, jwt.PyJWK]
    anon_key: str
    functions_dir: Path
    gateway_url: str = "http://core:8000"
    port: int = 9000
    timeout: int = 10
    memory_mb: int = 256
    concurrency: int = 8
    # Where functions/requirements.txt was installed (set at boot), bound into every jail.
    deps_dir: Path | None = None
    # Where functions/package.json was installed (set at boot); its node_modules is bound likewise.
    node_deps_dir: Path | None = None


def _int(env: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = env.get(name, str(default))
    if not raw.isdigit() or not low <= int(raw) <= high:
        raise ConfigError(f"{name} must be a number from {low} to {high}")
    return int(raw)


def load(env: Mapping[str, str]) -> Config:
    raw_jwks = env.get("KILNBASE_JWKS", "")
    anon_key = env.get("KILNBASE_ANON_KEY", "").strip()
    if not raw_jwks or PLACEHOLDER in raw_jwks or not anon_key or PLACEHOLDER in anon_key:
        raise ConfigError("KILNBASE_JWKS and KILNBASE_ANON_KEY are required; run `kilnbase init`")
    try:
        jwks = json.loads(raw_jwks)
        keys = {k["kid"]: jwt.PyJWK.from_dict(k, algorithm="ES256") for k in jwks["keys"]}
    except (ValueError, KeyError, TypeError, jwt.PyJWKError) as e:
        raise ConfigError(f"KILNBASE_JWKS is not a valid JWK set: {e}") from e
    if not keys:
        raise ConfigError("KILNBASE_JWKS must contain at least one key")
    if any("d" in k for k in jwks["keys"]):
        raise ConfigError("KILNBASE_JWKS must hold public keys only")
    return Config(
        keys=keys,
        anon_key=anon_key,
        functions_dir=Path(env.get("KILNBASE_FUNCTIONS_DIR", "/functions")),
        gateway_url=env.get("KILNBASE_GATEWAY_URL", "http://core:8000").rstrip("/"),
        port=_int(env, "KILNBASE_FUNCTIONS_PORT", 9000, 1, 65535),
        timeout=_int(env, "KILNBASE_FUNCTIONS_TIMEOUT", 10, 1, 300),
        memory_mb=_int(env, "KILNBASE_FUNCTIONS_MEMORY_MB", 256, 64, 4096),
        concurrency=_int(env, "KILNBASE_FUNCTIONS_CONCURRENCY", 8, 1, 256),
    )
