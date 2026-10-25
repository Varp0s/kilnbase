import re
import time
import uuid

import httpx2 as httpx
import pytest

MAILPIT = "http://localhost:8025"
PASSWORD = "a long passphrase"


@pytest.fixture(scope="module", autouse=True)
def mail_server():
    try:
        httpx.get(f"{MAILPIT}/api/v1/info", timeout=2)
    except httpx.HTTPError:
        pytest.skip("start the stack with docker-compose.test.yml to run email tests")


def mail(to: str, subject: str) -> str | None:
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


def api(keys, token=None):
    headers = {"apikey": keys.anon}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def new_address():
    return f"change-{uuid.uuid4().hex[:10]}@example.com"


def signup(client, keys):
    email = new_address()
    session = client.post(
        "/auth/v1/signup", headers=api(keys), json={"email": email, "password": PASSWORD}
    ).json()
    return email, session


def change(client, keys, token, email, current=PASSWORD):
    return client.put(
        "/auth/v1/user",
        headers=api(keys, token),
        json={"email": email, "current_password": current},
    )


def confirm(client, keys, token, code):
    return client.post("/auth/v1/user/email/verify", headers=api(keys, token), json={"token": code})


def test_change_needs_the_code_from_the_new_address(client, keys):
    old, session = signup(client, keys)
    other_device = client.post(
        "/auth/v1/token?grant_type=password",
        headers=api(keys),
        json={"email": old, "password": PASSWORD},
    ).json()
    new = new_address()
    r = change(client, keys, session["access_token"], new)
    assert r.status_code == 202, r.text
    assert new in mail(old, "Your email is being changed")
    code = re.search(r"is (\d{6})\.", mail(new, "Confirm your new email")).group(1)

    # Nothing changes until the code is entered.
    me = client.get("/auth/v1/user", headers=api(keys, session["access_token"])).json()
    assert me["email"] == old

    r = confirm(client, keys, session["access_token"], code)
    assert r.status_code == 200, r.text
    assert r.json()["user"]["email"] == new
    signed_in = client.post(
        "/auth/v1/token?grant_type=password",
        headers=api(keys),
        json={"email": new, "password": PASSWORD},
    )
    assert signed_in.status_code == 200
    # Other sessions are signed out; the code is single use.
    assert (
        client.get("/auth/v1/user", headers=api(keys, other_device["access_token"])).status_code
        == 401
    )
    assert confirm(client, keys, r.json()["access_token"], code).status_code == 400


def test_change_requires_the_current_password(client, keys):
    _, session = signup(client, keys)
    r = change(client, keys, session["access_token"], new_address(), current="wrong")
    assert r.json()["code"] == "invalid_credentials"


def test_cannot_take_an_existing_email(client, keys):
    taken, _ = signup(client, keys)
    _, session = signup(client, keys)
    assert change(client, keys, session["access_token"], taken).json()["code"] == "email_taken"


def test_codes_are_bound_to_the_requesting_user(client, keys):
    _, alice = signup(client, keys)
    _, mallory = signup(client, keys)
    new = new_address()
    change(client, keys, alice["access_token"], new)
    code = re.search(r"is (\d{6})\.", mail(new, "Confirm your new email")).group(1)
    assert confirm(client, keys, mallory["access_token"], code).status_code == 400


def test_wrong_codes_burn_the_change(client, keys):
    _, session = signup(client, keys)
    new = new_address()
    change(client, keys, session["access_token"], new)
    code = re.search(r"is (\d{6})\.", mail(new, "Confirm your new email")).group(1)
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        confirm(client, keys, session["access_token"], wrong)
    assert confirm(client, keys, session["access_token"], code).status_code == 400
