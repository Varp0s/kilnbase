import json
import os

import jwt
import pytest
from kilnbase_cli.doctor import parse_env
from kilnbase_cli.init import generate_env
from kilnbase_cli.rotate_keys import rotate, run


def jwks(env):
    return json.loads(env["KILNBASE_JWKS"])["keys"]


def verify(env, token):
    keys = {k["kid"]: jwt.PyJWK.from_dict(k).key for k in jwks(env)}
    return jwt.decode(token, keys[jwt.get_unverified_header(token)["kid"]], algorithms=["ES256"])


def test_two_rotations_keep_old_keys_until_retired():
    original = generate_env()
    first = parse_env(original)
    once, _ = rotate(original)
    twice, _ = rotate(once)
    env = parse_env(twice)

    assert len(jwks(env)) == 3
    assert env["POSTGRES_PASSWORD"] == first["POSTGRES_PASSWORD"]
    assert env["KILNBASE_ANON_KEY"] != first["KILNBASE_ANON_KEY"]
    # Old API keys still verify, new ones are signed by the new active key.
    assert verify(env, first["KILNBASE_ANON_KEY"])["role"] == "anon"
    active = json.loads(env["KILNBASE_JWT_PRIVATE_JWK"])["kid"]
    assert jwt.get_unverified_header(env["KILNBASE_SERVICE_ROLE_KEY"])["kid"] == active
    assert verify(env, env["KILNBASE_SERVICE_ROLE_KEY"])["role"] == "service_role"
    assert all("d" not in k for k in jwks(env))

    retired = parse_env(rotate(twice, retire=True)[0])
    assert [k["kid"] for k in jwks(retired)] == [active]
    with pytest.raises(KeyError):
        verify(retired, first["KILNBASE_ANON_KEY"])


def test_refuses_to_retire_the_signing_key():
    def jwks_line(text):
        return next(line for line in text.splitlines() if line.startswith("KILNBASE_JWKS="))

    text = generate_env()
    # A JWKS that does not contain the active key: retiring would lock everyone out.
    mismatched = text.replace(jwks_line(text), jwks_line(generate_env()))
    with pytest.raises(ValueError, match="not in KILNBASE_JWKS"):
        rotate(mismatched, retire=True)


def test_run_rewrites_in_place_and_keeps_permissions(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(generate_env(), encoding="utf-8")
    env_file.chmod(0o600)
    mode = env_file.stat().st_mode
    assert run(env_file, retire=False) == 0
    assert env_file.stat().st_mode == mode
    assert len(jwks(parse_env(env_file.read_text(encoding="utf-8")))) == 2
    assert os.listdir(tmp_path) == [".env"]  # no temp file left behind


def test_broken_file_is_not_touched(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("KILNBASE_JWKS=nope\n", encoding="utf-8")
    assert run(env_file, retire=False) == 1
    assert env_file.read_text(encoding="utf-8") == "KILNBASE_JWKS=nope\n"
