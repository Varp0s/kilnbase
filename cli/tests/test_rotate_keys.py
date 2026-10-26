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


def test_s3_rotation_replaces_only_the_s3_pair():
    original = generate_env()
    before = parse_env(original)
    after = parse_env(rotate(original, s3=True)[0])
    assert after["KILNBASE_S3_ACCESS_KEY_ID"] != before["KILNBASE_S3_ACCESS_KEY_ID"]
    assert after["KILNBASE_S3_SECRET_ACCESS_KEY"] != before["KILNBASE_S3_SECRET_ACCESS_KEY"]
    s3 = {"KILNBASE_S3_ACCESS_KEY_ID", "KILNBASE_S3_SECRET_ACCESS_KEY"}
    assert {k: v for k, v in after.items() if k not in s3} == {
        k: v for k, v in before.items() if k not in s3
    }


def test_s3_rotation_adds_the_pair_to_older_env_files():
    old = "".join(line + "\n" for line in generate_env().splitlines() if "S3" not in line)
    env = parse_env(rotate(old.rstrip("\n"), s3=True)[0])
    assert env["KILNBASE_S3_ACCESS_KEY_ID"].startswith("kb_")
    assert env["POSTGRES_PASSWORD"] == parse_env(old)["POSTGRES_PASSWORD"]
