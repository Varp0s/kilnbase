import re
import time
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
import pytest

MAILPIT = "http://localhost:8025"
APP = "http://localhost:3000/callback"


@pytest.fixture(scope="module", autouse=True)
def mail_server():
    try:
        httpx.get(f"{MAILPIT}/api/v1/info", timeout=2)
    except httpx.HTTPError:
        pytest.skip("start the stack with docker-compose.test.yml to run email tests")


def address():
    return f"otp-{uuid.uuid4().hex[:10]}@example.com"


def latest_mail(to: str) -> str | None:
    for _ in range(50):
        found = httpx.get(f"{MAILPIT}/api/v1/search", params={"query": f"to:{to}"}).json()
        if found["messages"]:
            message_id = found["messages"][0]["ID"]
            return httpx.get(f"{MAILPIT}/api/v1/message/{message_id}").json()["Text"]
        time.sleep(0.1)
    return None


def request_otp(client, keys, email, **extra):
    return client.post("/auth/v1/otp", headers={"apikey": keys.anon}, json={"email": email} | extra)


def verify(client, keys, **body):
    return client.post("/auth/v1/verify", headers={"apikey": keys.anon}, json=body)


def code_in(text):
    return re.search(r"code is (\d{6})", text).group(1)


def test_email_code_signs_in_a_new_user(client, keys):
    email = address()
    assert request_otp(client, keys, email).json() == {"sent": True}
    code = code_in(latest_mail(email))
    r = verify(client, keys, type="email", email=email, token=code)
    assert r.status_code == 200, r.text
    session = r.json()
    assert session["user"]["email"] == email
    rest = client.get(
        "/rest/v1/",
        headers={"apikey": keys.anon, "Authorization": f"Bearer {session['access_token']}"},
    )
    assert rest.status_code == 200
    # Single use.
    assert verify(client, keys, type="email", email=email, token=code).status_code == 400


def test_magic_link(client, keys):
    email = address()
    request_otp(client, keys, email, redirect_to=APP)
    link = re.search(r"(http://localhost:3000/callback\?\S+)", latest_mail(email)).group(1)
    token = parse_qs(urlsplit(link).query)["token"][0]
    assert verify(client, keys, type="magiclink", token=token).status_code == 200
    assert verify(client, keys, type="magiclink", token=token).status_code == 400


def test_wrong_codes_burn_the_code(client, keys):
    email = address()
    request_otp(client, keys, email)
    code = code_in(latest_mail(email))
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        assert verify(client, keys, type="email", email=email, token=wrong).status_code == 400
    # After five misses even the right code is refused.
    assert verify(client, keys, type="email", email=email, token=code).status_code == 400


def test_existing_accounts_cannot_be_probed(client, keys):
    unknown = address()
    r = request_otp(client, keys, unknown, create_user=False)
    assert r.json() == {"sent": True}
    assert latest_mail(unknown) is None


def test_redirects_are_allow_listed(client, keys):
    r = request_otp(client, keys, address(), redirect_to="https://evil.example/cb")
    assert r.json()["code"] == "redirect_not_allowed"


def test_sending_is_rate_limited_per_email(client, keys):
    email = address()
    codes = [request_otp(client, keys, email).status_code for _ in range(6)]
    assert codes == [200] * 5 + [429]
