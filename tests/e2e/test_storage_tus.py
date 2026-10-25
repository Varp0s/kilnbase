import base64
import uuid

import pytest
from conftest import psql

# Not 'e2e-*': test_storage.py's policy opens every bucket with that prefix.
POLICIES = """
delete from storage.objects where bucket_id like 'tus-e2e%';
delete from storage.buckets where id like 'tus-e2e%';
drop policy if exists e2e_tus_own on storage.objects;
create policy e2e_tus_own on storage.objects for all to authenticated
    using (bucket_id = 'tus-e2e' and owner = auth.uid())
    with check (bucket_id = 'tus-e2e' and owner = auth.uid());
"""

BASE = "/storage/v1/upload/resumable"


@pytest.fixture(scope="module", autouse=True)
def buckets(client, keys):
    psql(POLICIES)
    for body in ({"id": "tus-e2e"}, {"id": "tus-e2e-locked"}):
        r = client.post("/storage/v1/bucket", headers={"apikey": keys.service_role}, json=body)
        assert r.status_code == 201, r.text


def h(keys, token, **extra):
    return {
        "apikey": keys.anon,
        "Authorization": f"Bearer {token}",
        "Tus-Resumable": "1.0.0",
    } | extra


def metadata(**fields):
    return ",".join(f"{k} {base64.b64encode(v.encode()).decode()}" for k, v in fields.items())


def create(client, keys, token, length, bucket="tus-e2e", name=None):
    name = name or f"big/{uuid.uuid4().hex}.bin"
    meta = metadata(bucketName=bucket, objectName=name, contentType="application/octet-stream")
    r = client.post(
        BASE, headers=h(keys, token, **{"Upload-Length": str(length), "Upload-Metadata": meta})
    )
    return r, name


def patch(client, keys, token, location, offset, data):
    headers = h(
        keys,
        token,
        **{"Upload-Offset": str(offset), "Content-Type": "application/offset+octet-stream"},
    )
    return client.patch(location, headers=headers, content=data)


def test_resume_after_partial_upload(client, keys):
    _, a = keys.user()
    data = bytes(range(256)) * 400
    r, name = create(client, keys, a, len(data))
    assert r.status_code == 201, r.text
    assert r.headers["tus-resumable"] == "1.0.0"
    location = r.headers["location"]

    r = patch(client, keys, a, location, 0, data[:40000])
    assert r.status_code == 204, r.text
    assert r.headers["upload-offset"] == "40000"

    r = client.head(location, headers=h(keys, a))
    assert r.status_code == 200
    assert (r.headers["upload-offset"], r.headers["upload-length"]) == ("40000", str(len(data)))

    assert patch(client, keys, a, location, 10, b"x").status_code == 409

    r = patch(client, keys, a, location, 40000, data[40000:])
    assert r.status_code == 204, r.text
    r = client.get(f"/storage/v1/object/tus-e2e/{name}", headers=h(keys, a))
    assert r.status_code == 200
    assert r.content == data
    # A finished upload is gone.
    assert client.head(location, headers=h(keys, a)).status_code == 404


def test_uploads_are_private_to_their_creator(client, keys):
    _, a = keys.user()
    _, b = keys.user()
    r, _ = create(client, keys, a, 10)
    location = r.headers["location"]
    assert client.head(location, headers=h(keys, b)).status_code == 404
    assert patch(client, keys, b, location, 0, b"0123456789").status_code == 404
    assert client.delete(location, headers=h(keys, b)).status_code == 404
    assert client.delete(location, headers=h(keys, a)).status_code == 204
    assert client.head(location, headers=h(keys, a)).status_code == 404


def test_bytes_past_the_declared_length_are_refused(client, keys):
    _, a = keys.user()
    r, _ = create(client, keys, a, 4)
    assert patch(client, keys, a, r.headers["location"], 0, b"12345").status_code == 413


def test_policy_is_checked_before_any_bytes(client, keys):
    _, a = keys.user()
    r, _ = create(client, keys, a, 10, bucket="tus-e2e-locked")
    assert r.status_code == 403, r.text
    r, name = create(client, keys, a, 1)
    patch(client, keys, a, r.headers["location"], 0, b"x")
    r, _ = create(client, keys, a, 1, name=name)
    assert r.status_code == 409, r.text


def test_protocol_errors(client, keys):
    _, a = keys.user()
    r = client.post(BASE, headers=h(keys, a, **{"Tus-Resumable": "0.2.2", "Upload-Length": "1"}))
    assert r.status_code == 412
    r = client.post(BASE, headers=h(keys, a, **{"Upload-Length": "1"}))
    assert r.status_code == 400
    r, _ = create(client, keys, a, 1)
    bad = client.patch(
        r.headers["location"],
        headers=h(keys, a, **{"Upload-Offset": "0", "Content-Type": "text/plain"}),
        content=b"x",
    )
    assert bad.status_code == 415
    assert client.head(f"{BASE}/not-a-uuid", headers=h(keys, a)).status_code == 404
