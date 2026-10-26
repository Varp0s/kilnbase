"""End-to-end tests against a running stack (`docker compose up`). Enable with KILNBASE_E2E=1."""

import contextlib
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import httpx2 as httpx
import jwt
import pytest

ROOT = Path(__file__).resolve().parents[2]
BASE_URL = os.environ.get("KILNBASE_URL", "http://localhost:8000")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("KILNBASE_E2E") != "1":
        skip = pytest.mark.skip(reason="set KILNBASE_E2E=1 with the stack running")
        # Hook sees the whole session; only skip tests in this directory.
        here = Path(__file__).parent
        for item in items:
            if item.path.is_relative_to(here):
                item.add_marker(skip)


def read_env() -> dict[str, str]:
    pairs = (
        line.split("=", 1)
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    return {k: v.strip("'") for k, v in pairs}


def psql(sql: str) -> None:
    argv = [
        "docker",
        "compose",
        "exec",
        "-T",
        "db",
        "psql",
        "-U",
        "postgres",
        "-v",
        "ON_ERROR_STOP=1",
    ]
    subprocess.run(  # noqa: S603 - fixed argv, SQL comes from the test suite
        argv,
        input=sql,
        text=True,
        check=True,
        cwd=ROOT,
        capture_output=True,
    )


class Keys:
    def __init__(self, env: dict[str, str]):
        self.anon = env["KILNBASE_ANON_KEY"]
        self.service_role = env["KILNBASE_SERVICE_ROLE_KEY"]
        jwk = json.loads(env["KILNBASE_JWT_PRIVATE_JWK"])
        self._kid = jwk["kid"]
        self._key = jwt.PyJWK.from_dict(jwk).key

    def sign(self, claims: dict, key=None, kid: str | None = None) -> str:
        now = int(time.time())
        claims = {"iat": now, "exp": now + 600} | claims
        return jwt.encode(
            claims, key or self._key, algorithm="ES256", headers={"kid": kid or self._kid}
        )

    def user(self) -> tuple[str, str]:
        sub = str(uuid.uuid4())
        return sub, self.sign({"sub": sub, "role": "authenticated"})


@pytest.fixture(scope="session")
def keys() -> Keys:
    return Keys(read_env())


@pytest.fixture(scope="session")
def client():
    with httpx.Client(base_url=BASE_URL, timeout=10) as c:
        yield c


def wait_for_schema(client: httpx.Client, keys: Keys, table: str) -> None:
    """PostgREST reloads its schema cache asynchronously after NOTIFY."""
    headers = {"apikey": keys.service_role}
    for _ in range(50):
        if client.get(f"/rest/v1/{table}", headers=headers).status_code == 200:
            return
        time.sleep(0.2)
    raise AssertionError(f"{table} never appeared in the API")


def wait_for_gateway(client: httpx.Client) -> None:
    """For tests that restart services."""
    for _ in range(100):
        # The container may still be refusing connections.
        with contextlib.suppress(Exception):
            if client.get("/health").status_code == 200:
                return
        time.sleep(0.2)
    raise AssertionError("gateway did not come back")
