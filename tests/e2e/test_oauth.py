import base64
import hashlib
import secrets
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
import pytest

MOCK = "http://localhost:9100"
APP = "http://localhost:3000/callback"


@pytest.fixture(scope="module", autouse=True)
def mock_provider():
    try:
        httpx.get(f"{MOCK}/healthz", timeout=2)
    except httpx.HTTPError:
        pytest.skip("start the stack with docker-compose.test.yml to run OAuth tests")


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.rstrip(b"=").decode()


def next_user(email=None, verified=True, sub=None):
    user = {
        "sub": sub or f"sub-{uuid.uuid4().hex[:8]}",
        "email": email or f"oauth-{uuid.uuid4().hex[:8]}@example.com",
        "email_verified": verified,
    }
    httpx.post(f"{MOCK}/next", json=user)
    return user


def browser_flow(client, challenge, redirect_to=APP):
    """Follows the redirects a browser would; returns the query the app receives."""
    r = client.get(
        "/auth/v1/authorize",
        params={"provider": "mock", "redirect_to": redirect_to, "code_challenge": challenge},
    )
    assert r.status_code == 302, r.text
    at_provider = httpx.get(r.headers["location"])
    assert at_provider.status_code == 302
    callback = urlsplit(at_provider.headers["location"])
    back = client.get(f"{callback.path}?{callback.query}")
    assert back.status_code == 302, back.text
    location = back.headers["location"]
    assert location.startswith(redirect_to)
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}, callback


def exchange(client, keys, code, verifier):
    return client.post(
        "/auth/v1/token?grant_type=authorization_code",
        headers={"apikey": keys.anon},
        json={"code": code, "code_verifier": verifier},
    )


def sign_in_with_provider(client, keys, **user):
    who = next_user(**user)
    verifier, challenge = pkce()
    query, _ = browser_flow(client, challenge)
    r = exchange(client, keys, query["code"], verifier)
    assert r.status_code == 200, r.text
    return who, r.json()


def test_provider_sign_in_creates_a_user_and_reuses_it(client, keys):
    who, session = sign_in_with_provider(client, keys)
    assert session["user"]["email"] == who["email"]
    _, again = sign_in_with_provider(client, keys, email=who["email"], sub=who["sub"])
    assert again["user"]["id"] == session["user"]["id"]
    r = client.get(
        "/rest/v1/",
        headers={"apikey": keys.anon, "Authorization": f"Bearer {again['access_token']}"},
    )
    assert r.status_code == 200


def test_verified_email_links_to_existing_password_account(client, keys):
    email = f"link-{uuid.uuid4().hex[:8]}@example.com"
    existing = client.post(
        "/auth/v1/signup",
        headers={"apikey": keys.anon},
        json={"email": email, "password": "a long passphrase"},
    ).json()
    _, session = sign_in_with_provider(client, keys, email=email)
    assert session["user"]["id"] == existing["user"]["id"]


def test_unverified_provider_email_cannot_claim_an_account(client, keys):
    email = f"victim-{uuid.uuid4().hex[:8]}@example.com"
    client.post(
        "/auth/v1/signup",
        headers={"apikey": keys.anon},
        json={"email": email, "password": "a long passphrase"},
    )
    next_user(email=email, verified=False)
    _, challenge = pkce()
    query, _ = browser_flow(client, challenge)
    assert query == {"error": "email_not_verified"}


def test_redirects_are_restricted_to_the_allow_list(client):
    _, challenge = pkce()
    for target in (
        "https://evil.example/cb",
        "http://localhost:3000.evil.example/cb",
        "javascript:alert(1)",
    ):
        r = client.get(
            "/auth/v1/authorize",
            params={"provider": "mock", "redirect_to": target, "code_challenge": challenge},
        )
        assert r.json()["code"] == "redirect_not_allowed", target


def test_pkce_is_required_and_enforced(client, keys):
    r = client.get(
        "/auth/v1/authorize",
        params={"provider": "mock", "redirect_to": APP, "code_challenge": "short"},
    )
    assert r.status_code == 400
    next_user()
    verifier, challenge = pkce()
    query, _ = browser_flow(client, challenge)
    # A stolen code is useless without the verifier, and a wrong guess burns it.
    assert exchange(client, keys, query["code"], secrets.token_urlsafe(48)).status_code == 400
    assert exchange(client, keys, query["code"], verifier).status_code == 400


def test_state_and_codes_are_single_use(client, keys):
    next_user()
    verifier, challenge = pkce()
    query, callback = browser_flow(client, challenge)
    replay = client.get(f"{callback.path}?{callback.query}")
    assert replay.json()["code"] == "invalid_state"
    assert exchange(client, keys, query["code"], verifier).status_code == 200
    assert exchange(client, keys, query["code"], verifier).status_code == 400


def test_unknown_provider(client):
    _, challenge = pkce()
    r = client.get(
        "/auth/v1/authorize",
        params={"provider": "nope", "redirect_to": APP, "code_challenge": challenge},
    )
    assert r.json()["code"] == "unknown_provider"
