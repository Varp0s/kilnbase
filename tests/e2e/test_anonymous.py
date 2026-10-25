import uuid

import jwt
from conftest import psql, wait_for_schema


def api(keys, token=None):
    headers = {"apikey": keys.anon}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def anonymous(client, keys):
    r = client.post("/auth/v1/anonymous", headers=api(keys))
    assert r.status_code == 200, r.text
    return r.json()


def test_anonymous_users_are_real_rls_users(client, keys):
    psql("""
        drop table if exists public.e2e_carts;
        create table public.e2e_carts (
            id bigint generated always as identity primary key,
            owner uuid not null default auth.uid(),
            item text not null
        );
        alter table public.e2e_carts enable row level security;
        create policy own_cart on public.e2e_carts for all to authenticated
            using (owner = auth.uid()) with check (owner = auth.uid());
        notify pgrst, 'reload schema';
    """)
    wait_for_schema(client, keys, "e2e_carts")
    guest = anonymous(client, keys)
    claims = jwt.decode(guest["access_token"], options={"verify_signature": False})
    assert claims["is_anonymous"] is True
    assert guest["user"]["email"] is None
    r = client.post(
        "/rest/v1/e2e_carts", headers=api(keys, guest["access_token"]), json={"item": "book"}
    )
    assert r.status_code == 201, r.text
    other = anonymous(client, keys)
    assert client.get("/rest/v1/e2e_carts", headers=api(keys, other["access_token"])).json() == []


def test_upgrade_keeps_the_user_and_its_data(client, keys):
    guest = anonymous(client, keys)
    email = f"guest-{uuid.uuid4().hex[:8]}@example.com"
    r = client.put(
        "/auth/v1/user",
        headers=api(keys, guest["access_token"]),
        json={"email": email, "password": "a long passphrase"},
    )
    assert r.status_code == 200, r.text
    upgraded = r.json()
    assert upgraded["user"]["id"] == guest["user"]["id"]
    assert upgraded["user"]["is_anonymous"] is False
    assert (
        jwt.decode(upgraded["access_token"], options={"verify_signature": False})["is_anonymous"]
        is False
    )
    signed_in = client.post(
        "/auth/v1/token?grant_type=password",
        headers=api(keys),
        json={"email": email, "password": "a long passphrase"},
    ).json()
    assert signed_in["user"]["id"] == guest["user"]["id"]


def test_upgrade_cannot_take_an_existing_email(client, keys):
    email = f"taken-{uuid.uuid4().hex[:8]}@example.com"
    client.post(
        "/auth/v1/signup", headers=api(keys), json={"email": email, "password": "a long passphrase"}
    )
    guest = anonymous(client, keys)
    r = client.put(
        "/auth/v1/user",
        headers=api(keys, guest["access_token"]),
        json={"email": email, "password": "another passphrase"},
    )
    assert r.json()["code"] == "email_taken"
