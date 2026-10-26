import json
import shutil
import subprocess

import jwt
import pytest
from conftest import ROOT, psql, read_env, wait_for_gateway, wait_for_schema
from cryptography.hazmat.primitives.asymmetric import ec
from kilnbase_cli.doctor import parse_env
from kilnbase_cli.rotate_keys import rotate

SCHEMA = """
drop table if exists public.e2e_rotate;
create table public.e2e_rotate (id int primary key);
alter table public.e2e_rotate enable row level security;
create policy readable on public.e2e_rotate for select to anon, authenticated using (true);
insert into public.e2e_rotate values (1);
notify pgrst, 'reload schema';
"""


def compose_up(env_file=None):
    argv = ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.test.yml"]
    if env_file:
        argv += ["--env-file", str(env_file)]
    subprocess.run(  # noqa: S603 - fixed argv
        [*argv, "up", "-d", "--wait"], cwd=ROOT, check=True, capture_output=True, timeout=300
    )


@pytest.fixture(scope="module")
def rotated(client, keys, tmp_path_factory):
    """Restarts the stack on a rotated copy of .env, then back on the real one."""
    psql(SCHEMA)
    env_file = tmp_path_factory.mktemp("rotate") / ".env"
    shutil.copy(ROOT / ".env", env_file)
    env_file.write_text(rotate(env_file.read_text(encoding="utf-8"))[0], encoding="utf-8")
    try:
        compose_up(env_file)
        wait_for_gateway(client)
        wait_for_schema(client, keys, "e2e_rotate")
        yield parse_env(env_file.read_text(encoding="utf-8"))
    finally:
        compose_up()
        wait_for_gateway(client)
        psql("drop table public.e2e_rotate;")


def rows(client, apikey, token=None):
    headers = {"apikey": apikey, "Authorization": f"Bearer {token or apikey}"}
    return client.get("/rest/v1/e2e_rotate", headers=headers)


def test_old_and_new_keys_both_work_after_rotation(client, keys, rotated):
    old = read_env()
    new_jwk = json.loads(rotated["KILNBASE_JWT_PRIVATE_JWK"])
    new_key = jwt.PyJWK.from_dict(new_jwk).key
    assert new_jwk["kid"] != json.loads(old["KILNBASE_JWT_PRIVATE_JWK"])["kid"]

    # API keys from before and after the rotation, and user tokens from either key.
    assert rows(client, old["KILNBASE_ANON_KEY"]).json() == [{"id": 1}]
    assert rows(client, rotated["KILNBASE_ANON_KEY"]).json() == [{"id": 1}]
    _, old_user = keys.user()
    new_user = keys.sign({"sub": "u", "role": "authenticated"}, new_key, new_jwk["kid"])
    assert rows(client, rotated["KILNBASE_ANON_KEY"], old_user).status_code == 200
    assert rows(client, rotated["KILNBASE_ANON_KEY"], new_user).status_code == 200

    # The auth service signs new sessions with the new key.
    r = client.post("/auth/v1/anonymous", headers={"apikey": rotated["KILNBASE_ANON_KEY"]})
    assert r.status_code == 200, r.text
    assert jwt.get_unverified_header(r.json()["access_token"])["kid"] == new_jwk["kid"]


def test_unknown_keys_are_still_rejected(client, keys, rotated):
    stranger = keys.sign({"role": "anon"}, ec.generate_private_key(ec.SECP256R1()), "stranger")
    assert rows(client, rotated["KILNBASE_ANON_KEY"], stranger).status_code == 401
