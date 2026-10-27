import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from kilnbase_functions.auth import Unauthorized, caller
from kilnbase_functions.bootstrap import encode
from kilnbase_functions.config import ConfigError, load

PRIVATE = ec.generate_private_key(ec.SECP256R1())
OTHER = ec.generate_private_key(ec.SECP256R1())
PUBLIC_JWK = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(PRIVATE.public_key())) | {"kid": "k1"}
ENV = {"KILNBASE_JWKS": json.dumps({"keys": [PUBLIC_JWK]})}


def token(role="anon", key=PRIVATE, kid="k1", exp=3600, alg="ES256", **extra):
    claims = {"role": role, "exp": int(time.time()) + exp, **extra}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


ANON = token()
ENV["KILNBASE_ANON_KEY"] = ANON
KEYS = load(ENV).keys


def test_bearer_wins_over_the_api_key():
    assert caller(KEYS, ANON, None)["role"] == "anon"
    user = token("authenticated", sub="u1")
    assert caller(KEYS, ANON, f"Bearer {user}")["sub"] == "u1"


@pytest.mark.parametrize(
    "bad",
    [
        token(key=OTHER),
        token(kid="nope"),
        token(exp=-120),
        token(role="mfa_pending"),
        jwt.encode({"role": "anon", "exp": int(time.time()) + 60}, None, algorithm="none"),
        "not-a-token",
    ],
)
def test_forged_expired_and_unknown_tokens_are_rejected(bad):
    with pytest.raises(Unauthorized):
        caller(KEYS, ANON, f"Bearer {bad}")


def test_api_key_rules():
    with pytest.raises(Unauthorized):
        caller(KEYS, None, None)
    with pytest.raises(Unauthorized):
        caller(KEYS, token("authenticated"), None)  # a user token is not an API key
    with pytest.raises(Unauthorized):
        caller(KEYS, ANON, "Basic abc")


def test_config_refuses_private_keys_and_placeholders():
    private = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(PRIVATE)) | {"kid": "k1"}
    with pytest.raises(ConfigError, match="public keys only"):
        load(ENV | {"KILNBASE_JWKS": json.dumps({"keys": [private]})})
    with pytest.raises(ConfigError, match="required"):
        load(ENV | {"KILNBASE_ANON_KEY": "change-me"})


def test_handler_results_are_encoded():
    out = encode({"a": 1})
    assert out["status"] == 200 and out["headers"]["content-type"] == "application/json"
    assert json.loads(base64.b64decode(out["body_base64"])) == {"a": 1}
    out = encode(("created", 201, {"x-id": 7}))
    assert (out["status"], out["headers"]["x-id"]) == (201, "7")
    assert out["headers"]["content-type"].startswith("text/plain")
    assert encode(b"\x00")["headers"]["content-type"] == "application/octet-stream"
