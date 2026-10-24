import uuid

import pytest
from conftest import psql, wait_for_schema

PASSWORD = "correct horse battery staple"


@pytest.fixture(scope="module", autouse=True)
def schema(client, keys):
    psql("""
        drop table if exists public.e2e_notes;
        create table public.e2e_notes (
            id bigint generated always as identity primary key,
            owner uuid not null default auth.uid(),
            body text not null
        );
        alter table public.e2e_notes enable row level security;
        create policy own_notes on public.e2e_notes for all to authenticated
            using (owner = auth.uid()) with check (owner = auth.uid());
        notify pgrst, 'reload schema';
    """)
    wait_for_schema(client, keys, "e2e_notes")


def email() -> str:
    return f"user-{uuid.uuid4().hex[:12]}@example.com"


def api(keys, token=None):
    headers = {"apikey": keys.anon}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def signup(client, keys, address=None, password=PASSWORD):
    return client.post(
        "/auth/v1/signup",
        headers=api(keys),
        json={"email": address or email(), "password": password},
    )


def sign_in(client, keys, address, password=PASSWORD):
    return client.post(
        "/auth/v1/token?grant_type=password",
        headers=api(keys),
        json={"email": address, "password": password},
    )


def refresh(client, keys, token):
    return client.post(
        "/auth/v1/token?grant_type=refresh_token", headers=api(keys), json={"refresh_token": token}
    )


def test_auth_requires_api_key(client):
    assert (
        client.post("/auth/v1/signup", json={"email": email(), "password": PASSWORD}).status_code
        == 401
    )


def test_signup_session_works_against_rest_with_rls(client, keys):
    r = signup(client, keys)
    assert r.status_code == 200, r.text
    session = r.json()
    assert session["token_type"] == "bearer"

    r = client.post(
        "/rest/v1/e2e_notes",
        headers=api(keys, session["access_token"]) | {"Prefer": "return=representation"},
        json={"body": "hello"},
    )
    assert r.status_code == 201, r.text
    assert r.json()[0]["owner"] == session["user"]["id"]

    other = signup(client, keys).json()
    assert client.get("/rest/v1/e2e_notes", headers=api(keys, other["access_token"])).json() == []


def test_signup_validation(client, keys):
    address = email()
    assert signup(client, keys, address).status_code == 200
    assert signup(client, keys, address.upper()).json()["code"] == "email_taken"
    assert signup(client, keys, password="short").json()["code"] == "weak_password"
    assert signup(client, keys, address="not-an-email").json()["code"] == "invalid_email"
    r = client.post("/auth/v1/signup", headers=api(keys), json={"email": email()})
    assert r.status_code == 422


def test_password_grant(client, keys):
    address = email()
    signup(client, keys, address)
    assert sign_in(client, keys, address, "wrong password").json()["code"] == "invalid_credentials"
    # Unknown emails get the same answer as wrong passwords.
    assert sign_in(client, keys, email()).json()["code"] == "invalid_credentials"
    r = sign_in(client, keys, address.upper())
    assert r.status_code == 200, r.text
    assert r.json()["user"]["email"] == address


def test_user_endpoint(client, keys):
    session = signup(client, keys).json()
    r = client.get("/auth/v1/user", headers=api(keys, session["access_token"]))
    assert r.json()["id"] == session["user"]["id"]
    assert client.get("/auth/v1/user", headers=api(keys)).status_code == 401


def test_refresh_rotates_and_reuse_revokes_the_session(client, keys):
    first = signup(client, keys).json()

    second = refresh(client, keys, first["refresh_token"])
    assert second.status_code == 200, second.text
    second = second.json()
    assert second["refresh_token"] != first["refresh_token"]

    # Replaying the rotated token is treated as theft: it fails and kills the newer token too.
    assert refresh(client, keys, first["refresh_token"]).status_code == 401
    assert refresh(client, keys, second["refresh_token"]).status_code == 401
    assert client.get("/auth/v1/user", headers=api(keys, second["access_token"])).status_code == 401


def test_logout_revokes_refresh_token(client, keys):
    session = signup(client, keys).json()
    r = client.post("/auth/v1/logout", headers=api(keys, session["access_token"]))
    assert r.status_code == 204
    assert refresh(client, keys, session["refresh_token"]).status_code == 401


def test_garbage_refresh_token(client, keys):
    assert refresh(client, keys, "nope").status_code == 401
    assert (
        client.post("/auth/v1/token?grant_type=magic", headers=api(keys), json={}).status_code
        == 400
    )


def test_brute_force_is_rate_limited(client, keys):
    address = email()
    signup(client, keys, address)
    codes = [sign_in(client, keys, address, f"wrong-{i}").status_code for i in range(12)]
    assert codes[:10] == [400] * 10
    assert codes[10:] == [429, 429]
    # Even the right password is refused while blocked.
    r = sign_in(client, keys, address)
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0
