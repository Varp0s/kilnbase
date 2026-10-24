import os
import time
import uuid

import pytest
from conftest import psql

POLICIES = """
delete from storage.objects where bucket_id like 'e2e-%';
delete from storage.buckets where id like 'e2e-%';
drop policy if exists e2e_own on storage.objects;
create policy e2e_own on storage.objects for all to authenticated
    using (bucket_id like 'e2e-%' and owner = auth.uid())
    with check (bucket_id like 'e2e-%' and owner = auth.uid());
"""


@pytest.fixture(scope="module", autouse=True)
def buckets(client, keys):
    psql(POLICIES)
    service = {"apikey": keys.service_role}
    for body in (
        {"id": "e2e-private"},
        {"id": "e2e-public", "public": True},
        {"id": "e2e-images", "file_size_limit": 1024, "allowed_mime_types": ["image/*"]},
    ):
        r = client.post("/storage/v1/bucket", headers=service, json=body)
        assert r.status_code == 201, r.text


def h(keys, token=None, **extra):
    headers = {"apikey": keys.anon} | extra
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def name() -> str:
    return f"dir/{uuid.uuid4().hex}.txt"


def put(client, keys, token, bucket, path, data=b"hello", content_type="text/plain", method="POST"):
    return client.request(
        method,
        f"/storage/v1/object/{bucket}/{path}",
        headers=h(keys, token, **{"Content-Type": content_type}),
        content=data,
    )


def test_only_service_role_creates_buckets(client, keys):
    _, a = keys.user()
    for headers in (h(keys), h(keys, a)):
        r = client.post("/storage/v1/bucket", headers=headers, json={"id": "e2e-nope"})
        assert r.status_code == 403
    r = client.post(
        "/storage/v1/bucket", headers={"apikey": keys.service_role}, json={"id": "public"}
    )
    assert r.status_code == 400


def test_owner_round_trip_with_safe_headers(client, keys):
    _, a = keys.user()
    path = name()
    r = put(client, keys, a, "e2e-private", path, b"secret bytes")
    assert r.status_code == 200, r.text
    assert r.json()["size"] == 12

    r = client.get(f"/storage/v1/object/e2e-private/{path}", headers=h(keys, a))
    assert r.status_code == 200
    assert r.content == b"secret bytes"
    assert r.headers["content-type"] == "text/plain"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in r.headers["content-security-policy"]


def test_other_users_and_anon_cannot_touch_files(client, keys):
    _, a = keys.user()
    _, b = keys.user()
    path = name()
    put(client, keys, a, "e2e-private", path)
    url = f"/storage/v1/object/e2e-private/{path}"

    assert client.get(url, headers=h(keys, b)).status_code == 404
    assert client.get(url, headers=h(keys)).status_code == 404
    assert client.get(url).status_code == 401
    assert client.delete(url, headers=h(keys, b)).status_code == 404
    assert put(client, keys, b, "e2e-private", path, b"overwrite", method="PUT").status_code == 403
    assert client.get(url, headers=h(keys, a)).content == b"hello"

    assert put(client, keys, None, "e2e-private", name()).status_code == 403


@pytest.mark.parametrize("bad", ["%2e%2e/escape.txt", "a/%2e%2e/b.txt", "a//b.txt", "a%5Cb.txt"])
def test_rejects_traversal_and_odd_names(client, keys, bad):
    _, a = keys.user()
    assert put(client, keys, a, "e2e-private", bad).status_code == 400


def test_bucket_limits(client, keys):
    _, a = keys.user()
    assert put(client, keys, a, "e2e-images", "x.png", b"\0" * 2048, "image/png").status_code == 413
    assert put(client, keys, a, "e2e-images", "x.txt", b"hi", "text/plain").status_code == 415
    assert put(client, keys, a, "e2e-images", "ok.png", b"\0" * 512, "image/png").status_code == 200
    assert put(client, keys, a, "e2e-missing", "x.txt").status_code == 404


def test_create_conflicts_and_put_replaces(client, keys):
    _, a = keys.user()
    path = name()
    assert put(client, keys, a, "e2e-private", path, b"one").status_code == 200
    assert put(client, keys, a, "e2e-private", path, b"two").status_code == 409
    assert put(client, keys, a, "e2e-private", path, b"three", method="PUT").status_code == 200
    r = client.get(f"/storage/v1/object/e2e-private/{path}", headers=h(keys, a))
    assert r.content == b"three"


def test_public_bucket_needs_no_credentials(client, keys):
    _, a = keys.user()
    path = name()
    put(client, keys, a, "e2e-public", path, b"for everyone")
    r = client.get(f"/storage/v1/object/public/e2e-public/{path}")
    assert r.status_code == 200
    assert r.content == b"for everyone"

    private = name()
    put(client, keys, a, "e2e-private", private)
    assert client.get(f"/storage/v1/object/public/e2e-private/{private}").status_code == 404


def test_signed_urls(client, keys):
    _, a = keys.user()
    _, b = keys.user()
    path = name()
    put(client, keys, a, "e2e-private", path, b"shared")
    sign_url = f"/storage/v1/object/sign/e2e-private/{path}"

    assert client.post(sign_url, headers=h(keys, b), json={"expires_in": 60}).status_code == 404
    assert client.post(sign_url, headers=h(keys, a), json={"expires_in": 10**9}).status_code == 400

    signed = client.post(sign_url, headers=h(keys, a), json={"expires_in": 60}).json()["signed_url"]
    r = client.get(signed)
    assert r.status_code == 200
    assert r.content == b"shared"

    tampered = signed[:-1] + ("0" if signed[-1] != "0" else "1")
    assert client.get(tampered).status_code == 401
    other_file = signed.replace(path, name())
    assert client.get(other_file).status_code == 401

    short = client.post(sign_url, headers=h(keys, a), json={"expires_in": 1}).json()["signed_url"]
    time.sleep(2.1)
    assert client.get(short).status_code == 401


def test_delete(client, keys):
    _, a = keys.user()
    path = name()
    put(client, keys, a, "e2e-private", path)
    url = f"/storage/v1/object/e2e-private/{path}"
    assert client.delete(url, headers=h(keys, a)).status_code == 204
    assert client.get(url, headers=h(keys, a)).status_code == 404
    assert client.delete(url, headers=h(keys, a)).status_code == 404


def test_large_upload_streams(client, keys):
    _, a = keys.user()
    data = os.urandom(5 * 1024 * 1024)
    path = name()
    assert (
        put(client, keys, a, "e2e-private", path, data, "application/octet-stream").status_code
        == 200
    )
    assert client.get(f"/storage/v1/object/e2e-private/{path}", headers=h(keys, a)).content == data
