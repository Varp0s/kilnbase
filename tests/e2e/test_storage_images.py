import struct
import uuid
import zlib

import pytest
from conftest import psql
from test_storage import POLICIES, h, put


@pytest.fixture(scope="module", autouse=True)
def buckets(client, keys):
    psql(POLICIES)
    for body in ({"id": "e2e-img"}, {"id": "e2e-img-public", "public": True}):
        r = client.post("/storage/v1/bucket", headers={"apikey": keys.service_role}, json=body)
        assert r.status_code == 201, r.text


def png(width: int, height: int) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        )

    rows = b"".join(b"\0" + b"\xff\x00\x00" * width for _ in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


def png_size(data: bytes) -> tuple[int, int]:
    assert data.startswith(b"\x89PNG")
    return struct.unpack(">II", data[16:24])


def test_owner_gets_resized_image_others_do_not(client, keys):
    _, a = keys.user()
    _, b = keys.user()
    path = f"{uuid.uuid4().hex}.png"
    assert put(client, keys, a, "e2e-img", path, png(40, 20), "image/png").status_code == 200
    url = f"/storage/v1/render/image/authenticated/e2e-img/{path}"

    r = client.get(url, params={"width": 10, "resize": "contain"}, headers=h(keys, a))
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "image/png"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert png_size(r.content) == (10, 5)

    r = client.get(url, params={"width": 8, "format": "webp"}, headers=h(keys, a))
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/webp"

    assert client.get(url, params={"width": 10}, headers=h(keys, b)).status_code == 404
    assert client.get(url, params={"width": 10}).status_code == 401


@pytest.mark.parametrize(
    "params",
    [{"width": 0}, {"width": 9999}, {"resize": "crop"}, {"quality": 101}, {"format": "gif"}],
)
def test_rejects_bad_options(client, keys, params):
    _, a = keys.user()
    url = "/storage/v1/render/image/authenticated/e2e-img/missing.png"
    assert client.get(url, params=params, headers=h(keys, a)).status_code == 400


def test_only_images_are_transformed(client, keys):
    _, a = keys.user()
    path = f"{uuid.uuid4().hex}.txt"
    put(client, keys, a, "e2e-img", path, b"not an image")
    url = f"/storage/v1/render/image/authenticated/e2e-img/{path}"
    assert client.get(url, headers=h(keys, a)).status_code == 400

    # Claims to be an image but is not: imgproxy fails and the caller gets a clean error.
    fake = f"{uuid.uuid4().hex}.png"
    put(client, keys, a, "e2e-img", fake, b"garbage", "image/png")
    url = f"/storage/v1/render/image/authenticated/e2e-img/{fake}"
    assert client.get(url, headers=h(keys, a)).status_code == 422


def test_public_bucket_renders_without_credentials(client, keys):
    _, a = keys.user()
    path = f"{uuid.uuid4().hex}.png"
    put(client, keys, a, "e2e-img-public", path, png(30, 30), "image/png")
    r = client.get(f"/storage/v1/render/image/public/e2e-img-public/{path}", params={"height": 6})
    assert r.status_code == 200, r.text
    assert png_size(r.content) == (6, 6)
    assert "public" in r.headers["cache-control"]

    private = f"{uuid.uuid4().hex}.png"
    put(client, keys, a, "e2e-img", private, png(4, 4), "image/png")
    assert client.get(f"/storage/v1/render/image/public/e2e-img/{private}").status_code == 404
