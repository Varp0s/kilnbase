import hashlib
import hmac
import json
import re
import secrets
import time

import httpx2 as httpx
import jwt
import pytest

MOCK = "http://localhost:9100"
# docker-compose.test.yml
SECRET = "e2e-sms-secret-0123456789abcdef0123"


@pytest.fixture(scope="module", autouse=True)
def sms_hook():
    try:
        httpx.get(f"{MOCK}/hooks/sms", timeout=2)
    except httpx.HTTPError:
        pytest.skip("start the stack with docker-compose.test.yml to run phone tests")


def number() -> str:
    return f"+1555{secrets.randbelow(10**7):07d}"


def latest_code(phone: str) -> str | None:
    for _ in range(50):
        texts = [
            e
            for e in httpx.get(f"{MOCK}/hooks/sms").json()["received"]
            if json.loads(e["body"])["to"] == phone
        ]
        if texts:
            entry = texts[-1]
            headers = {k.lower(): v for k, v in entry["headers"].items()}
            signed = f"{headers['x-kilnbase-timestamp']}.{entry['body']}".encode()
            mac = hmac.new(SECRET.encode(), signed, hashlib.sha256).hexdigest()
            assert headers["x-kilnbase-signature"] == f"v1={mac}"
            return re.search(r"\b(\d{6})\b", json.loads(entry["body"])["body"]).group(1)
        time.sleep(0.1)
    return None


def request_code(client, keys, phone, **extra):
    return client.post("/auth/v1/otp", headers={"apikey": keys.anon}, json={"phone": phone} | extra)


def verify(client, keys, phone, token):
    body = {"type": "sms", "phone": phone, "token": token}
    return client.post("/auth/v1/verify", headers={"apikey": keys.anon}, json=body)


def test_phone_sign_in_creates_a_user_with_the_number_as_a_claim(client, keys):
    phone = number()
    # Spaces and dashes are dropped.
    spaced = f"{phone[:2]} {phone[2:5]}-{phone[5:]}"
    assert request_code(client, keys, spaced).json() == {"sent": True}
    code = latest_code(phone)
    assert code is not None

    r = verify(client, keys, phone, code)
    assert r.status_code == 200, r.text
    session = r.json()
    assert session["user"]["phone"] == phone and session["user"]["email"] is None
    claims = jwt.decode(session["access_token"], options={"verify_signature": False})
    assert claims["phone"] == phone and claims["role"] == "authenticated"

    # Codes are single use.
    assert verify(client, keys, phone, code).status_code == 400

    # Signing in again finds the same user.
    request_code(client, keys, phone, create_user=False)
    again = verify(client, keys, phone, latest_code(phone))
    assert again.json()["user"]["id"] == session["user"]["id"]

    me = client.get(
        "/auth/v1/user",
        headers={"apikey": keys.anon, "Authorization": f"Bearer {session['access_token']}"},
    )
    assert me.json()["phone"] == phone


def test_unknown_number_without_create_user_gets_no_text(client, keys):
    phone = number()
    assert request_code(client, keys, phone, create_user=False).json() == {"sent": True}
    assert not [
        e
        for e in httpx.get(f"{MOCK}/hooks/sms").json()["received"]
        if json.loads(e["body"])["to"] == phone
    ]


def test_wrong_codes_burn_the_code(client, keys):
    phone = number()
    request_code(client, keys, phone)
    code = latest_code(phone)
    wrong = f"{(int(code) + 1) % 10**6:06d}"
    for _ in range(5):
        assert verify(client, keys, phone, wrong).status_code == 400
    assert verify(client, keys, phone, code).status_code == 400


def test_invalid_requests(client, keys):
    h = {"apikey": keys.anon}
    assert request_code(client, keys, "12345").status_code == 422
    both = {"phone": number(), "email": "a@example.com"}
    assert client.post("/auth/v1/otp", headers=h, json=both).status_code == 422
    assert client.post("/auth/v1/otp", headers=h, json={}).status_code == 422


def test_hook_failure_answers_503_and_keeps_no_code(client, keys):
    phone = number()
    httpx.post(f"{MOCK}/hooks-status/sms", json={"status": 500})
    try:
        r = request_code(client, keys, phone)
        assert r.status_code == 503 and r.json()["code"] == "sms_unavailable"
    finally:
        httpx.post(f"{MOCK}/hooks-status/sms", json={"status": 200})
    code = latest_code(phone)
    assert verify(client, keys, phone, code).status_code == 400


def test_texts_per_number_are_limited(client, keys):
    phone = number()
    statuses = [request_code(client, keys, phone).status_code for _ in range(6)]
    assert statuses == [200] * 5 + [429]


def bearer(keys, token):
    return {"apikey": keys.anon, "Authorization": f"Bearer {token}"}


def test_adding_a_phone_to_an_account(client, keys):
    email = f"phone-{secrets.token_hex(5)}@example.com"
    password = "a long passphrase"
    session = client.post(
        "/auth/v1/signup",
        headers={"apikey": keys.anon},
        json={"email": email, "password": password},
    ).json()
    other = client.post(
        "/auth/v1/token?grant_type=password",
        headers={"apikey": keys.anon},
        json={"email": email, "password": password},
    ).json()
    token, phone = session["access_token"], number()

    # Like an email change, it needs the current password.
    r = client.put("/auth/v1/user", headers=bearer(keys, token), json={"phone": phone})
    assert r.status_code == 400
    body = {"phone": phone, "current_password": password}
    r = client.put("/auth/v1/user", headers=bearer(keys, token), json=body)
    assert r.status_code == 202, r.text
    code = latest_code(phone)

    r = client.post("/auth/v1/user/phone/verify", headers=bearer(keys, token), json={"token": code})
    assert r.status_code == 200, r.text
    claims = jwt.decode(r.json()["access_token"], options={"verify_signature": False})
    assert claims["phone"] == phone and claims["email"] == email
    # Other sessions are signed out.
    refresh = client.post(
        "/auth/v1/token?grant_type=refresh_token",
        headers={"apikey": keys.anon},
        json={"refresh_token": other["refresh_token"]},
    )
    assert refresh.status_code == 401

    # The number now signs in to the same account.
    request_code(client, keys, phone, create_user=False)
    again = verify(client, keys, phone, latest_code(phone))
    assert again.json()["user"]["id"] == session["user"]["id"]

    # Nobody else can claim it.
    taken = sign_in(client, keys, number())
    r = client.put("/auth/v1/user", headers=bearer(keys, taken), json={"phone": phone})
    assert r.status_code == 422 and r.json()["code"] == "phone_taken"


def sign_in(client, keys, phone) -> str:
    request_code(client, keys, phone)
    return verify(client, keys, phone, latest_code(phone)).json()["access_token"]


def test_anonymous_user_keeps_their_account_with_a_phone(client, keys):
    guest = client.post("/auth/v1/anonymous", headers={"apikey": keys.anon}).json()
    token, phone = guest["access_token"], number()
    r = client.put("/auth/v1/user", headers=bearer(keys, token), json={"phone": phone})
    assert r.status_code == 202, r.text
    r = client.post(
        "/auth/v1/user/phone/verify",
        headers=bearer(keys, token),
        json={"token": latest_code(phone)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["user"]["id"] == guest["user"]["id"]
    claims = jwt.decode(r.json()["access_token"], options={"verify_signature": False})
    assert claims["is_anonymous"] is False and claims["phone"] == phone


def test_phone_and_password(client, keys):
    phone = number()
    token = sign_in(client, keys, phone)
    password = "a phone user's passphrase"
    r = client.put("/auth/v1/user", headers=bearer(keys, token), json={"password": password})
    assert r.status_code == 204, r.text

    h = {"apikey": keys.anon}
    url = "/auth/v1/token?grant_type=password"
    r = client.post(url, headers=h, json={"phone": phone, "password": password})
    assert r.status_code == 200, r.text
    assert r.json()["user"]["phone"] == phone
    wrong = client.post(url, headers=h, json={"phone": phone, "password": "not it at all"})
    assert wrong.status_code == 400 and wrong.json()["code"] == "invalid_credentials"
    # A number nobody verified signs in to nothing.
    r = client.post(url, headers=h, json={"phone": number(), "password": password})
    assert r.status_code == 400
