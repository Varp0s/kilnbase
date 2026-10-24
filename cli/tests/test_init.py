import json

import jwt
from kilnbase_cli.init import generate_env, run


def parse(text: str) -> dict[str, str]:
    pairs = (line.split("=", 1) for line in text.splitlines() if line and not line.startswith("#"))
    return {k: v.strip("'") for k, v in pairs}


def test_api_keys_verify_against_published_jwks_only():
    env = parse(generate_env())
    jwks = jwt.PyJWKSet.from_dict(json.loads(env["KILNBASE_JWKS"]))
    public = jwks.keys[0]
    assert "d" not in json.loads(env["KILNBASE_JWKS"])["keys"][0]

    for name, role in [
        ("KILNBASE_ANON_KEY", "anon"),
        ("KILNBASE_SERVICE_ROLE_KEY", "service_role"),
    ]:
        claims = jwt.decode(env[name], public.key, algorithms=["ES256"])
        assert claims["role"] == role
        assert jwt.get_unverified_header(env[name])["kid"] == public.key_id


def test_every_run_produces_fresh_secrets():
    a, b = parse(generate_env()), parse(generate_env())
    assert a["POSTGRES_PASSWORD"] != b["POSTGRES_PASSWORD"]
    assert a["KILNBASE_JWT_PRIVATE_JWK"] != b["KILNBASE_JWT_PRIVATE_JWK"]


def test_refuses_to_overwrite_without_force(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("existing")
    assert run(env_file, force=False) == 1
    assert env_file.read_text() == "existing"
    assert run(env_file, force=True) == 0
    assert "KILNBASE_JWKS=" in env_file.read_text()
