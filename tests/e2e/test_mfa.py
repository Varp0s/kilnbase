import time
import uuid

import httpx2 as httpx
import jwt
import pyotp
import pytest

PASSWORD = "correct horse battery staple"


def api(keys, token=None):
    headers = {"apikey": keys.anon}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def sign_in(client, keys, email):
    r = client.post(
        "/auth/v1/token?grant_type=password",
        headers=api(keys),
        json={"email": email, "password": PASSWORD},
    )
    assert r.status_code == 200, r.text
    return r.json()


def verify(client, keys, token, factor_id, code):
    return client.post(
        f"/auth/v1/factors/{factor_id}/verify", headers=api(keys, token), json={"code": code}
    )


def rest_status(client, keys, token):
    return client.get("/rest/v1/", headers=api(keys, token)).status_code


@pytest.fixture
def enrolled(client, keys):
    """A user with a verified TOTP factor. Codes are taken from distinct time steps (now-30,
    now, now+30) so each one is fresh for the replay check."""
    email = f"mfa-{uuid.uuid4().hex[:10]}@example.com"
    session = client.post(
        "/auth/v1/signup", headers=api(keys), json={"email": email, "password": PASSWORD}
    ).json()
    factor = client.post("/auth/v1/factors", headers=api(keys, session["access_token"])).json()
    totp = pyotp.TOTP(factor["secret"])
    r = verify(client, keys, session["access_token"], factor["id"], totp.at(time.time() - 30))
    assert r.status_code == 200, r.text
    return {"email": email, "factor": factor["id"], "totp": totp, "session": r.json()}


def test_enrolment_returns_an_authenticator_uri(client, keys):
    session = client.post(
        "/auth/v1/signup",
        headers=api(keys),
        json={"email": f"uri-{uuid.uuid4().hex[:8]}@example.com", "password": PASSWORD},
    ).json()
    factor = client.post("/auth/v1/factors", headers=api(keys, session["access_token"])).json()
    assert factor["uri"].startswith("otpauth://totp/Kilnbase:")
    # Unverified enrolment does not change anything yet.
    assert sign_in(client, keys, session["user"]["email"])["mfa_required"] is False


def test_verified_enrolment_upgrades_the_session(client, keys, enrolled):
    claims = jwt.decode(enrolled["session"]["access_token"], options={"verify_signature": False})
    assert claims["aal"] == "aal2"
    assert claims["role"] == "authenticated"
    assert rest_status(client, keys, enrolled["session"]["access_token"]) == 200


def test_password_alone_is_not_enough_once_enrolled(client, keys, enrolled):
    pending = sign_in(client, keys, enrolled["email"])
    assert pending["mfa_required"] is True
    assert rest_status(client, keys, pending["access_token"]) == 401
    # Refreshing a pending session keeps it pending.
    refreshed = client.post(
        "/auth/v1/token?grant_type=refresh_token",
        headers=api(keys),
        json={"refresh_token": pending["refresh_token"]},
    ).json()
    assert refreshed["mfa_required"] is True

    r = verify(client, keys, refreshed["access_token"], enrolled["factor"], enrolled["totp"].now())
    assert r.status_code == 200, r.text
    assert rest_status(client, keys, r.json()["access_token"]) == 200
    # The pre-upgrade refresh token must not mint aal2 tokens.
    stale = client.post(
        "/auth/v1/token?grant_type=refresh_token",
        headers=api(keys),
        json={"refresh_token": refreshed["refresh_token"]},
    )
    assert stale.status_code == 401


def test_codes_cannot_be_replayed(client, keys, enrolled):
    code = enrolled["totp"].now()
    first = sign_in(client, keys, enrolled["email"])
    assert verify(client, keys, first["access_token"], enrolled["factor"], code).status_code == 200
    second = sign_in(client, keys, enrolled["email"])
    r = verify(client, keys, second["access_token"], enrolled["factor"], code)
    assert r.json()["code"] == "invalid_code"


def test_wrong_codes_are_rate_limited(client, keys, enrolled):
    pending = sign_in(client, keys, enrolled["email"])
    right = enrolled["totp"].now()
    wrong = "000000" if right != "000000" else "111111"
    codes = [
        verify(client, keys, pending["access_token"], enrolled["factor"], wrong).status_code
        for _ in range(6)
    ]
    assert codes == [400] * 5 + [429]
    assert (
        verify(client, keys, pending["access_token"], enrolled["factor"], right).status_code == 429
    )


def test_factor_removal_needs_aal2_and_is_listed(client, keys, enrolled):
    pending = sign_in(client, keys, enrolled["email"])
    url = f"/auth/v1/factors/{enrolled['factor']}"
    assert client.delete(url, headers=api(keys, pending["access_token"])).status_code == 403

    full = enrolled["session"]["access_token"]
    factors = client.get("/auth/v1/user", headers=api(keys, full)).json()["factors"]
    assert factors == [{"id": enrolled["factor"], "type": "totp", "verified": True}]
    assert client.delete(url, headers=api(keys, full)).status_code == 204
    assert sign_in(client, keys, enrolled["email"])["mfa_required"] is False


def test_cannot_enrol_twice_or_touch_others_factors(client, keys, enrolled):
    full = enrolled["session"]["access_token"]
    assert client.post("/auth/v1/factors", headers=api(keys, full)).status_code == 409
    other = client.post(
        "/auth/v1/signup",
        headers=api(keys),
        json={"email": f"o-{uuid.uuid4().hex[:8]}@example.com", "password": PASSWORD},
    ).json()
    r = verify(client, keys, other["access_token"], enrolled["factor"], enrolled["totp"].now())
    assert r.status_code == 404


MFA_REQUIRED_URL = "http://localhost:9998"  # auth-mfa in docker-compose.test.yml


def test_required_mfa_blocks_the_apis_until_a_factor_is_verified(client, keys):
    with httpx.Client(base_url=MFA_REQUIRED_URL) as strict:
        email = f"req-{uuid.uuid4().hex[:10]}@example.com"
        session = strict.post("/signup", json={"email": email, "password": PASSWORD}).json()
        assert session["mfa_required"] is True
        token = session["access_token"]
        assert rest_status(client, keys, token) == 401

        # The restricted token can enrol, and verifying upgrades it to a full session.
        factor = strict.post("/factors", headers={"Authorization": f"Bearer {token}"}).json()
        r = strict.post(
            f"/factors/{factor['id']}/verify",
            headers={"Authorization": f"Bearer {token}"},
            json={"code": pyotp.TOTP(factor["secret"]).now()},
        )
        assert r.status_code == 200, r.text
        assert rest_status(client, keys, r.json()["access_token"]) == 200

        # Guests have no credentials to protect and are exempt.
        guest = strict.post("/anonymous").json()
        assert guest["mfa_required"] is False
        assert rest_status(client, keys, guest["access_token"]) == 200
