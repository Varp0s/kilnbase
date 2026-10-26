"""The Python SDK driven against the running stack."""

import re
import time
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
import jwt
import pyotp
import pytest
from conftest import BASE_URL, psql, wait_for_schema
from kilnbase import KilnbaseError, create_client
from test_otp import APP, MAILPIT, code_in, latest_mail
from test_storage_images import png, png_size

PASSWORD = "correct horse battery staple"

SCHEMA = """
drop table if exists public.e2e_sdk_items;
create table public.e2e_sdk_items (
    id int primary key,
    owner uuid not null default auth.uid(),
    name text not null,
    qty int,
    note text
);
alter table public.e2e_sdk_items enable row level security;
create policy own_rows on public.e2e_sdk_items for all to authenticated
    using (owner = auth.uid()) with check (owner = auth.uid());
notify pgrst, 'reload schema';

delete from storage.objects where bucket_id like 'e2e-sdk-%';
delete from storage.buckets where id like 'e2e-sdk-%';
drop policy if exists e2e_sdk_own on storage.objects;
create policy e2e_sdk_own on storage.objects for all to authenticated
    using (bucket_id like 'e2e-sdk-%' and owner = auth.uid())
    with check (bucket_id like 'e2e-sdk-%' and owner = auth.uid());
"""


@pytest.fixture(scope="module", autouse=True)
def setup(client, keys):
    psql(SCHEMA)
    wait_for_schema(client, keys, "e2e_sdk_items")
    for body in ({"id": "e2e-sdk-private"}, {"id": "e2e-sdk-public", "public": True}):
        r = client.post("/storage/v1/bucket", headers={"apikey": keys.service_role}, json=body)
        assert r.status_code == 201, r.text


@pytest.fixture
def kb(keys):
    c = create_client(BASE_URL, keys.anon)
    yield c
    c.close()


def email():
    return f"sdk-{uuid.uuid4().hex[:10]}@example.com"


@pytest.fixture
def user(kb):
    kb.auth.sign_up(email(), PASSWORD)
    return kb


def mailpit_up():
    try:
        httpx.get(f"{MAILPIT}/api/v1/info", timeout=2)
    except httpx.HTTPError:
        pytest.skip("start the stack with docker-compose.test.yml to run email tests")


def aal(session):
    return jwt.decode(session["access_token"], options={"verify_signature": False})["aal"]


def test_sign_up_in_get_user_and_errors(keys, kb):
    addr = email()
    s = kb.auth.sign_up(addr, PASSWORD)
    assert s["user"]["email"] == addr
    assert kb.auth.get_user()["email"] == addr
    kb.auth.sign_out()
    assert kb.auth.session is None
    with pytest.raises(KilnbaseError) as e:
        kb.auth.get_user()
    assert e.value.status == 401

    s = kb.auth.sign_in_with_password(addr, PASSWORD)
    assert kb.auth.get_user()["id"] == s["user"]["id"]

    other = create_client(BASE_URL, keys.anon)
    with pytest.raises(KilnbaseError) as e:
        other.auth.sign_in_with_password(addr, "wrong password here")
    assert e.value.status in (400, 401)
    assert e.value.code and not e.value.code.startswith("http_")


def test_refresh_rotates_and_sign_out_revokes(keys, user):
    old = user.auth.session["refresh_token"]
    new = user.auth.refresh_session()
    assert new["refresh_token"] != old
    # Sign-out kills the live refresh token server side.
    token = user.auth.session["refresh_token"]
    user.auth.sign_out()
    again = create_client(BASE_URL, keys.anon)
    again.auth.session = {"refresh_token": token}
    with pytest.raises(KilnbaseError) as e:
        again.auth.refresh_session()
    assert e.value.status == 401


def test_spent_refresh_token_is_rejected(keys, user):
    old = user.auth.session["refresh_token"]
    user.auth.refresh_session()
    replay = create_client(BASE_URL, keys.anon)
    replay.auth.session = {"refresh_token": old}
    with pytest.raises(KilnbaseError) as e:
        replay.auth.refresh_session()
    assert e.value.status == 401


def test_update_user_changes_password(keys, user):
    addr = user.auth.get_user()["email"]
    new = "a brand new passphrase"
    user.auth.update_user(new, current_password=PASSWORD)
    fresh = create_client(BASE_URL, keys.anon)
    fresh.auth.sign_in_with_password(addr, new)
    with pytest.raises(KilnbaseError):
        fresh.auth.sign_in_with_password(addr, PASSWORD)


def test_anonymous_then_upgrade(keys, kb):
    guest = kb.auth.sign_in_anonymously()
    claims = jwt.decode(guest["access_token"], options={"verify_signature": False})
    assert claims["is_anonymous"]
    addr = email()
    kb.auth.update_user("a long passphrase", email=addr)
    assert kb.auth.session["user"]["is_anonymous"] is False
    again = create_client(BASE_URL, keys.anon)
    signed_in = again.auth.sign_in_with_password(addr, "a long passphrase")
    assert signed_in["user"]["id"] == guest["user"]["id"]


def test_otp_code(kb):
    mailpit_up()
    addr = email()
    kb.auth.sign_in_with_otp(addr)
    s = kb.auth.verify_otp("email", code_in(latest_mail(addr)), email=addr)
    assert s["user"]["email"] == addr
    assert kb.auth.get_user()["email"] == addr


def test_magic_link(kb):
    mailpit_up()
    addr = email()
    kb.auth.sign_in_with_otp(addr, redirect_to=APP)
    link = re.search(r"(http://localhost:3000/callback\?\S+)", latest_mail(addr)).group(1)
    token = parse_qs(urlsplit(link).query)["token"][0]
    assert kb.auth.verify_otp("magiclink", token)["user"]["email"] == addr


def test_mfa_round_trip(keys, user):
    addr = user.auth.get_user()["email"]
    factor = user.auth.mfa.enroll()
    assert factor["uri"].startswith("otpauth://")
    totp = pyotp.TOTP(factor["secret"])
    assert aal(user.auth.mfa.verify(factor["id"], totp.at(time.time() - 30))) == "aal2"

    # A password sign-in is now pending until the code is verified.
    other = create_client(BASE_URL, keys.anon)
    assert other.auth.sign_in_with_password(addr, PASSWORD)["mfa_required"] is True
    assert aal(other.auth.mfa.verify(factor["id"], totp.now())) == "aal2"
    other.auth.mfa.unenroll(factor["id"])
    assert other.auth.sign_in_with_password(addr, PASSWORD)["mfa_required"] is False


def test_rest_crud_and_isolation(keys, kb):
    kb.auth.sign_up(email(), PASSWORD)
    rows = [
        {"id": 1, "name": "Apple", "qty": 5, "note": None},
        {"id": 2, "name": "apricot", "qty": 10, "note": "x"},
        {"id": 3, "name": "Banana", "qty": 20, "note": None},
        {"id": 4, "name": "cherry, red", "qty": 30, "note": None},
    ]

    def t():
        return kb.from_("e2e_sdk_items")

    def names(q):
        return [r["name"] for r in q.execute()]

    assert len(t().insert(rows).execute()) == 4
    assert names(t().select("name").eq("id", 1)) == ["Apple"]
    assert names(t().select("name").ilike("name", "ap*").order("id")) == ["Apple", "apricot"]
    q = t().select("name").in_("name", ["cherry, red", "Banana"]).order("id")
    assert names(q) == ["Banana", "cherry, red"]
    assert names(t().select("name").is_("note", None).order("id")) == [
        "Apple",
        "Banana",
        "cherry, red",
    ]
    q = t().select("name").gt("qty", 5).lte("qty", 20).order("qty")
    assert names(q) == ["apricot", "Banana"]
    assert names(t().select("name").order("id", ascending=False).limit(2)) == [
        "cherry, red",
        "Banana",
    ]
    assert names(t().select("name").order("id").range(1, 2)) == ["apricot", "Banana"]
    assert t().select("*").eq("id", 3).single().execute()["name"] == "Banana"
    with pytest.raises(KilnbaseError):
        t().select("*").single().execute()

    assert t().update({"qty": 99}).eq("id", 1).execute()[0]["qty"] == 99
    up = t().upsert([{"id": 1, "name": "Apple2"}, {"id": 5, "name": "fig"}]).execute()
    assert {r["name"] for r in up} == {"Apple2", "fig"}
    assert t().select("name").eq("id", 1).single().execute()["name"] == "Apple2"

    # Another user sees nothing and cannot change anything.
    b = create_client(BASE_URL, keys.anon)
    b.auth.sign_up(email(), PASSWORD)
    assert b.from_("e2e_sdk_items").select("*").execute() == []
    assert b.from_("e2e_sdk_items").delete().eq("id", 1).execute() == []
    assert b.from_("e2e_sdk_items").update({"name": "hacked"}).eq("id", 1).execute() == []

    assert len(t().delete().eq("id", 5).execute()) == 1
    assert t().select("id").eq("id", 5).execute() == []


def test_storage_round_trip(client, user):
    bucket = user.storage.from_("e2e-sdk-private")
    path = f"dir/{uuid.uuid4().hex}.txt"
    assert bucket.upload(path, b"secret bytes", content_type="text/plain")["size"] == 12
    with pytest.raises(KilnbaseError):
        bucket.upload(path, b"again", content_type="text/plain")
    bucket.upload(path, b"v2 bytes", content_type="text/plain", upsert=True)
    assert bucket.download(path) == b"v2 bytes"

    signed = bucket.create_signed_url(path, 60)
    r = client.get(signed["signed_url"])  # no auth headers
    assert r.status_code == 200, r.text
    assert r.content == b"v2 bytes"

    bucket.remove(path)
    with pytest.raises(KilnbaseError) as e:
        bucket.download(path)
    assert e.value.status == 404


def test_public_url_and_image_transforms(client, user):
    pub = user.storage.from_("e2e-sdk-public")
    path = f"{uuid.uuid4().hex}.png"
    pub.upload(path, png(40, 20), content_type="image/png")
    r = client.get(pub.get_public_url(path))
    assert r.status_code == 200
    assert png_size(r.content) == (40, 20)

    t = {"width": 10, "resize": "contain"}
    assert png_size(pub.download(path, transform=t)) == (10, 5)
    r = client.get(pub.get_public_url(path, transform=t))
    assert r.status_code == 200, r.text
    assert png_size(r.content) == (10, 5)
