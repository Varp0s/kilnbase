import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from kilnbase_auth.app import normalize_email
from kilnbase_auth.ratelimit import FailureLimiter
from kilnbase_auth.tokens import Signer, hash_refresh_token, new_refresh_token


def private_jwk() -> dict:
    key = ec.generate_private_key(ec.SECP256R1())
    return json.loads(ECAlgorithm.to_jwk(key)) | {"kid": "k1"}


def test_signer_round_trip_and_rejects_other_keys():
    signer = Signer(private_jwk())
    token, _ = signer.access_token(
        "00000000-0000-0000-0000-000000000001", "a@b.co", "sid-1", "aal1", False
    )
    claims = signer.verify(token)
    assert claims["role"] == "authenticated"
    assert claims["aal"] == "aal1"
    assert jwt.get_unverified_header(token)["kid"] == "k1"

    with pytest.raises(jwt.InvalidTokenError):
        Signer(private_jwk()).verify(token)


def test_signer_rejects_api_keys():
    jwk = private_jwk()
    anon = jwt.encode(
        {"iss": "kilnbase", "role": "anon", "sub": "x", "sid": "y", "exp": 2**31},
        jwt.PyJWK.from_dict(jwk).key,
        algorithm="ES256",
    )
    with pytest.raises(jwt.InvalidTokenError):
        Signer(jwk).verify(anon)


def test_refresh_tokens_are_random_and_only_hashes_are_kept():
    a, a_hash = new_refresh_token()
    b, _ = new_refresh_token()
    assert a != b
    assert a_hash == hash_refresh_token(a)
    assert a.encode() not in a_hash


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (" Ada@Example.COM ", "ada@example.com"),
        ("no-at-sign", None),
        ("a@b", None),
        ("a@@b.co", None),
        ("a b@c.co", None),
        ("@b.co", None),
    ],
)
def test_normalize_email(raw, expected):
    assert normalize_email(raw) == expected


def test_failure_limiter_blocks_then_expires():
    now = [0.0]
    limiter = FailureLimiter(limit=3, window=60, clock=lambda: now[0])
    for _ in range(3):
        assert limiter.retry_after("k") == 0
        limiter.fail("k")
    assert limiter.retry_after("k") > 0
    assert limiter.retry_after("other") == 0
    now[0] = 61
    assert limiter.retry_after("k") == 0


def test_failure_limiter_reset():
    limiter = FailureLimiter(limit=1, window=60)
    limiter.fail("k")
    assert limiter.retry_after("k") > 0
    limiter.reset("k")
    assert limiter.retry_after("k") == 0


def test_pending_mfa_tokens_carry_a_non_api_role():
    signer = Signer(private_jwk())
    token, _ = signer.access_token("u", "a@b.co", "s", "aal1", True)
    assert signer.verify(token)["role"] == "mfa_pending"


def test_totp_steps_accept_drift_and_reject_replays():
    import pyotp
    from kilnbase_auth.mfa import matching_step

    secret = pyotp.random_base32()
    now = 1_800_000_000.0
    step = int(now // 30)
    totp = pyotp.TOTP(secret)
    assert matching_step(secret, totp.at(now), 0, now) == step
    assert matching_step(secret, totp.at(now - 30), 0, now) == step - 1
    assert matching_step(secret, totp.at(now + 30), 0, now) == step + 1
    assert matching_step(secret, totp.at(now - 60), 0, now) is None
    # Once a step is used, it and every earlier step are spent.
    assert matching_step(secret, totp.at(now), step, now) is None
    assert matching_step(secret, totp.at(now - 30), step, now) is None
    assert matching_step(secret, "000000" if totp.at(now) != "000000" else "111111", 0, now) is None
