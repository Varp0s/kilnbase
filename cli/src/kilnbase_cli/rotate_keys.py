import json
import os
import tempfile
from pathlib import Path

from .doctor import parse_env
from .init import api_key, new_s3_keys, new_signing_key, public_jwk, quoted_json

ACCESS_TOKEN_LIFETIME_HOURS = 1  # matches the auth service's access token lifetime


def rotate(text: str, retire: bool = False, s3: bool = False) -> tuple[str, str]:
    """Returns the new env file text and a summary; raises ValueError on an unusable file."""
    if s3:
        updates = new_s3_keys()
        summary = (
            f"New S3 key pair {updates['KILNBASE_S3_ACCESS_KEY_ID']}. Core accepts one pair, so "
            "the old one stops working when the stack restarts: update your S3 clients then."
        )
    else:
        updates, summary = signing_key_updates(parse_env(text), retire)

    lines = text.splitlines(keepends=True)
    missing = set(updates)
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0].strip()
        if key in updates and not line.startswith("#"):
            lines[i] = f"{key}={updates[key]}\n"
            missing.discard(key)
    if missing and not s3:
        raise ValueError(f"missing from the env file: {', '.join(sorted(missing))}")
    # Env files from before the S3 API have no S3 lines yet.
    if missing and lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines += [f"{k}={v}\n" for k, v in updates.items() if k in missing]
    return "".join(lines), summary


def signing_key_updates(env: dict[str, str], retire: bool) -> tuple[dict[str, str], str]:
    try:
        active = json.loads(env["KILNBASE_JWT_PRIVATE_JWK"])
        published = json.loads(env["KILNBASE_JWKS"])["keys"]
        active_kid = active["kid"]
    except (KeyError, TypeError, json.JSONDecodeError) as e:
        raise ValueError(
            f"KILNBASE_JWT_PRIVATE_JWK / KILNBASE_JWKS are missing or invalid: {e}"
        ) from e

    if retire:
        keep = [k for k in published if k.get("kid") == active_kid]
        if not keep:
            # Retiring would leave the signing key unverifiable and lock everyone out.
            raise ValueError(f"the active key {active_kid} is not in KILNBASE_JWKS; not retiring")
        updates = {"KILNBASE_JWKS": quoted_json({"keys": keep})}
        summary = (
            f"Retired {len(published) - len(keep)} key(s); KILNBASE_JWKS now holds only "
            f"{active_kid}. Tokens and API keys signed by retired keys stop working."
        )
    else:
        new = new_signing_key()
        updates = {
            "KILNBASE_JWT_PRIVATE_JWK": quoted_json(new),
            "KILNBASE_JWKS": quoted_json({"keys": [public_jwk(new), *published]}),
            "KILNBASE_ANON_KEY": api_key(new, "anon"),
            "KILNBASE_SERVICE_ROLE_KEY": api_key(new, "service_role"),
        }
        summary = (
            f"New signing key {new['kid']}; KILNBASE_JWKS still accepts {len(published)} older "
            "key(s), so existing sessions and the old API keys keep working.\n"
            "Hand the new KILNBASE_ANON_KEY / KILNBASE_SERVICE_ROLE_KEY to your apps, then wait "
            f"at least {ACCESS_TOKEN_LIFETIME_HOURS} hour (the access token lifetime) and run "
            "`kilnbase rotate-keys --retire`."
        )
    return updates, summary


def write_atomic(path: Path, text: str) -> None:
    """Readers see the old file or the new one, never a half-written secret file."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.chmod(tmp, path.stat().st_mode)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def run(env_file: Path, retire: bool, s3: bool = False) -> int:
    if not env_file.exists():
        print(f"{env_file} not found; run `kilnbase init`")
        return 1
    try:
        text, summary = rotate(env_file.read_text(encoding="utf-8"), retire, s3)
    except ValueError as e:
        print(f"rotate-keys: {e}")
        return 1
    write_atomic(env_file, text)
    print(summary)
    print("Apply it with: docker compose up -d")
    return 0
