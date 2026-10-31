import re
import time
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
import jwt
import pyotp
import pytest
from conftest import psql

MAILPIT = "http://localhost:8025"
APP = "http://localhost:3000/callback"
PASSWORD = "first long passphrase"


@pytest.fixture(scope="module", autouse=True)
def mail_server():
    try:
        httpx.get(f"{MAILPIT}/api/v1/info", timeout=2)
    except httpx.HTTPError:
        pytest.skip("start the stack with docker-compose.test.yml to run email tests")


def mails(to: str, subject: str) -> str | None:
    for _ in range(50):
        found = httpx.get(
            f"{MAILPIT}/api/v1/search", params={"query": f'to:{to} subject:"{subject}"'}
        ).json()
        if found["messages"]:
            return httpx.get(f"{MAILPIT}/api/v1/message/{found['messages'][0]['ID']}").json()[
                "Text"
            ]
        time.sleep(0.1)
    return None


def code_in(text):
    return re.search(r"is (\d{6})\.", text).group(1)


def api(keys, token=None):
    headers = {"apikey": keys.anon}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def claims(session):
    return jwt.decode(session["access_token"], options={"verify_signature": False})


def signup(client, keys, **extra):
    email = f"flow-{uuid.uuid4().hex[:10]}@example.com"
    r = client.post(
        "/auth/v1/signup", headers=api(keys), json={"email": email, "password": PASSWORD} | extra
    )
    assert r.status_code == 200, r.text
    return email, r.json()


def verify(client, keys, **body):
    return client.post("/auth/v1/verify", headers=api(keys), json=body)


def sign_in(client, keys, email, password):
    return client.post(
        "/auth/v1/token?grant_type=password",
        headers=api(keys),
        json={"email": email, "password": password},
    )


def recover(client, keys, email):
    r = client.post("/auth/v1/recover", headers=api(keys), json={"email": email})
    assert r.json() == {"sent": True}
    return code_in(mails(email, "Reset your password"))


def test_signup_confirmation(client, keys):
    email, session = signup(client, keys)
    assert session["confirmation_sent"] is True
    assert claims(session)["email_verified"] is False
    code = code_in(mails(email, "Confirm your email"))
    r = verify(client, keys, type="signup", email=email, token=code)
    assert r.status_code == 200, r.text
    assert claims(r.json())["email_verified"] is True
    user = client.get("/auth/v1/user", headers=api(keys, r.json()["access_token"])).json()
    assert user["email_confirmed_at"] is not None


def test_codes_only_work_for_their_purpose(client, keys):
    email, _ = signup(client, keys)
    code = code_in(mails(email, "Confirm your email"))
    assert verify(client, keys, type="email", email=email, token=code).status_code == 400
    assert verify(client, keys, type="recovery", email=email, token=code).status_code == 400


def test_password_reset_signs_out_everywhere(client, keys):
    email, first = signup(client, keys)
    r = verify(client, keys, type="recovery", email=email, token=recover(client, keys, email))
    assert r.status_code == 200, r.text
    reset = r.json()
    assert claims(reset)["amr"] == ["recovery"]

    new = "second long passphrase"
    r = client.put(
        "/auth/v1/user", headers=api(keys, reset["access_token"]), json={"password": new}
    )
    assert r.status_code == 204, r.text
    assert sign_in(client, keys, email, PASSWORD).status_code == 400
    assert sign_in(client, keys, email, new).status_code == 200
    # The session from before the reset is gone; the reset session no longer bypasses the check.
    assert client.get("/auth/v1/user", headers=api(keys, first["access_token"])).status_code == 401
    r = client.put(
        "/auth/v1/user",
        headers=api(keys, reset["access_token"]),
        json={"password": "third passphrase"},
    )
    assert r.json()["code"] == "invalid_credentials"


def test_unconfirmed_signup_cannot_hold_an_address(client, keys):
    """An attacker pre-registers the victim's address; the victim's magic link evicts them."""
    email, attacker = signup(client, keys)
    r = client.post("/auth/v1/otp", headers=api(keys), json={"email": email})
    assert r.json() == {"sent": True}
    code = code_in(mails(email, "Your sign-in code"))
    r = verify(client, keys, type="email", email=email, token=code)
    assert r.status_code == 200, r.text
    assert claims(r.json())["email_verified"] is True
    # The attacker's password and session are gone; only the address owner is signed in.
    assert sign_in(client, keys, email, PASSWORD).status_code == 400
    assert (
        client.get("/auth/v1/user", headers=api(keys, attacker["access_token"])).status_code == 401
    )
    r = client.post(
        "/auth/v1/token?grant_type=refresh_token",
        headers=api(keys),
        json={"refresh_token": attacker["refresh_token"]},
    )
    assert r.status_code == 401, r.text


def test_recover_does_not_reveal_accounts(client, keys):
    """Unknown and known addresses behave the same, including the per-address limit."""
    known = f"known-{uuid.uuid4().hex[:10]}@example.com"
    # Created directly: a sign-up's confirmation mail would already count against the limit.
    psql(f"insert into auth.users (email, email_confirmed_at) values ('{known}', now())")  # noqa: S608 - test data
    unknown = f"nobody-{uuid.uuid4().hex[:10]}@example.com"
    for address in (known, unknown):
        codes = [
            client.post("/auth/v1/recover", headers=api(keys), json={"email": address}).status_code
            for _ in range(6)
        ]
        assert codes == [200] * 5 + [429], (address, codes)


def test_reset_link(client, keys):
    email, _ = signup(client, keys)
    client.post("/auth/v1/recover", headers=api(keys), json={"email": email, "redirect_to": APP})
    link = re.search(r"(http://localhost:3000/callback\?\S+)", mails(email, "Reset your password"))
    query = parse_qs(urlsplit(link.group(1)).query)
    assert query["type"] == ["recovery"]
    assert verify(client, keys, type="recovery", token=query["token"][0]).status_code == 200


def test_normal_sessions_need_the_current_password(client, keys):
    email, session = signup(client, keys)
    token = session["access_token"]
    url = "/auth/v1/user"
    assert client.put(url, headers=api(keys, token), json={"password": "x" * 12}).status_code == 400
    r = client.put(
        url,
        headers=api(keys, token),
        json={"password": "another passphrase", "current_password": "wrong"},
    )
    assert r.status_code == 400
    r = client.put(
        url,
        headers=api(keys, token),
        json={"password": "another passphrase", "current_password": PASSWORD},
    )
    assert r.status_code == 204
    assert sign_in(client, keys, email, "another passphrase").status_code == 200


def test_unknown_email_gets_the_same_answer_and_no_mail(client, keys):
    email = f"nobody-{uuid.uuid4().hex[:8]}@example.com"
    r = client.post("/auth/v1/recover", headers=api(keys), json={"email": email})
    assert r.json() == {"sent": True}
    assert mails(email, "Reset your password") is None


def test_reset_does_not_bypass_mfa(client, keys):
    email, session = signup(client, keys)
    factor = client.post("/auth/v1/factors", headers=api(keys, session["access_token"])).json()
    totp = pyotp.TOTP(factor["secret"])
    client.post(
        f"/auth/v1/factors/{factor['id']}/verify",
        headers=api(keys, session["access_token"]),
        json={"code": totp.at(time.time() - 30)},
    )
    reset = verify(
        client, keys, type="recovery", email=email, token=recover(client, keys, email)
    ).json()
    assert reset["mfa_required"] is True
    r = client.put(
        "/auth/v1/user", headers=api(keys, reset["access_token"]), json={"password": "y" * 12}
    )
    assert r.status_code == 401
    upgraded = client.post(
        f"/auth/v1/factors/{factor['id']}/verify",
        headers=api(keys, reset["access_token"]),
        json={"code": totp.now()},
    ).json()
    r = client.put(
        "/auth/v1/user", headers=api(keys, upgraded["access_token"]), json={"password": "y" * 12}
    )
    assert r.status_code == 204
