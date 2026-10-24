import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt.algorithms import ECAlgorithm
from kilnbase_auth.app import create_app
from kilnbase_auth.config import PLACEHOLDER, ConfigError, load

JWK = json.dumps(
    json.loads(ECAlgorithm.to_jwk(ec.generate_private_key(ec.SECP256R1()))) | {"kid": "k1"}
)
VALID = {
    "DATABASE_URL": "postgres://postgres:s3cret@db:5432/postgres",
    "KILNBASE_JWT_PRIVATE_JWK": JWK,
    "KILNBASE_AUTHENTICATOR_PASSWORD": "pw",
}


def test_accepts_valid_config():
    assert load(VALID).port == 9999


@pytest.mark.parametrize(
    "override",
    [
        {"DATABASE_URL": ""},
        {"DATABASE_URL": f"postgres://postgres:{PLACEHOLDER}@db/postgres"},
        {"DATABASE_URL": "postgres://postgres@db/postgres"},
        {"KILNBASE_JWT_PRIVATE_JWK": PLACEHOLDER},
        {"KILNBASE_JWT_PRIVATE_JWK": "not json"},
        {"KILNBASE_JWT_PRIVATE_JWK": json.dumps({"kty": "EC", "crv": "P-256", "x": "a"})},
        {"KILNBASE_JWT_PRIVATE_JWK": json.dumps(json.loads(JWK) | {"d": "a"})},
        {
            "KILNBASE_JWT_PRIVATE_JWK": json.dumps(
                {k: v for k, v in json.loads(JWK).items() if k != "kid"}
            )
        },
        {"KILNBASE_AUTHENTICATOR_PASSWORD": PLACEHOLDER},
        {"KILNBASE_AUTH_PORT": "70000"},
    ],
)
def test_rejects_unsafe_config(override):
    with pytest.raises(ConfigError):
        load(VALID | override)


def test_health():
    client = TestClient(create_app(load(VALID)))
    assert client.get("/health").json() == {"status": "ok"}
