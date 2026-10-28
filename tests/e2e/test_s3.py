"""S3-compatible API, exercised with a real S3 client (boto3) rather than our own signer."""

import base64
import hashlib
import hmac
import io
import os
import uuid
import zlib
from urllib.parse import quote

import boto3
import httpx2 as httpx
import pytest
from boto3.s3.transfer import TransferConfig
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.credentials import Credentials
from botocore.exceptions import ClientError
from conftest import BASE_URL, psql
from test_storage import POLICIES

ENDPOINT = f"{BASE_URL}/storage/v1/s3"
# Matches docker-compose.test.yml.
SERVICE_KEY = ("e2e-s3-key", "e2e-s3-secret-0123456789abcdef0123456789")


def s3(key_id: str, secret: str, token: str | None = None):
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        region_name="us-east-1",
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        aws_session_token=token,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 1},
        ),
    )


def user_client(keys):
    """Users sign with their access token as both secret and session token."""
    _, token = keys.user()
    return s3("user", token, token)


def code(exc: pytest.ExceptionInfo) -> str:
    return exc.value.response["Error"]["Code"]


@pytest.fixture(scope="module")
def service():
    return s3(*SERVICE_KEY)


@pytest.fixture(scope="module", autouse=True)
def buckets(client, keys):
    psql(POLICIES)
    for body in (
        {"id": "e2e-s3"},
        {"id": "e2e-s3-small", "file_size_limit": 16},
    ):
        r = client.post("/storage/v1/bucket", headers={"apikey": keys.service_role}, json=body)
        assert r.status_code == 201, r.text


@pytest.mark.parametrize("key", ["plain.txt", "dir/with space.txt", "ünïcode/ğ.txt", "a+b=c&d.txt"])
def test_service_round_trip(service, key):
    key = f"{uuid.uuid4().hex}/{key}"
    put = service.put_object(Bucket="e2e-s3", Key=key, Body=b"0123456789", ContentType="text/plain")
    assert put["ETag"]

    got = service.get_object(Bucket="e2e-s3", Key=key)
    assert got["Body"].read() == b"0123456789"
    assert got["ContentType"] == "text/plain"
    assert got["ContentLength"] == 10

    head = service.head_object(Bucket="e2e-s3", Key=key)
    assert head["ContentLength"] == 10
    assert head["ETag"] == put["ETag"]

    part = service.get_object(Bucket="e2e-s3", Key=key, Range="bytes=2-4")
    assert part["Body"].read() == b"234"
    assert part["ContentRange"] == "bytes 2-4/10"

    service.delete_object(Bucket="e2e-s3", Key=key)
    with pytest.raises(ClientError) as e:
        service.head_object(Bucket="e2e-s3", Key=key)
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404
    # Deleting a missing key succeeds, as on S3.
    service.delete_object(Bucket="e2e-s3", Key=key)


def test_rls_decides_for_users(keys):
    a, b = user_client(keys), user_client(keys)
    key = f"{uuid.uuid4().hex}.txt"
    a.put_object(Bucket="e2e-s3", Key=key, Body=b"mine")
    assert a.get_object(Bucket="e2e-s3", Key=key)["Body"].read() == b"mine"

    with pytest.raises(ClientError) as e:
        b.get_object(Bucket="e2e-s3", Key=key)
    assert code(e) == "NoSuchKey"
    assert key not in [o["Key"] for o in b.list_objects_v2(Bucket="e2e-s3").get("Contents", [])]
    assert key in [o["Key"] for o in a.list_objects_v2(Bucket="e2e-s3")["Contents"]]
    with pytest.raises(ClientError) as e:
        b.put_object(Bucket="e2e-s3", Key=key, Body=b"overwrite")
    assert code(e) == "AccessDenied"
    b.delete_object(Bucket="e2e-s3", Key=key)
    assert a.get_object(Bucket="e2e-s3", Key=key)["Body"].read() == b"mine"


def test_listing_with_prefix_delimiter_and_pages(service):
    root = uuid.uuid4().hex
    for name in ["a.txt", "b.txt", "c.txt", "dir1/x.txt", "dir1/y.txt", "dir2/z.txt"]:
        service.put_object(Bucket="e2e-s3", Key=f"{root}/{name}", Body=b"x")

    r = service.list_objects_v2(Bucket="e2e-s3", Prefix=f"{root}/", Delimiter="/")
    assert [o["Key"] for o in r["Contents"]] == [f"{root}/{n}" for n in ("a.txt", "b.txt", "c.txt")]
    assert [p["Prefix"] for p in r["CommonPrefixes"]] == [f"{root}/dir1/", f"{root}/dir2/"]

    seen, token = [], None
    while True:
        extra = {"ContinuationToken": token} if token else {}
        page = service.list_objects_v2(Bucket="e2e-s3", Prefix=f"{root}/", MaxKeys=2, **extra)
        seen += [o["Key"] for o in page.get("Contents", [])]
        if not page["IsTruncated"]:
            break
        token = page["NextContinuationToken"]
    assert len(seen) == 6 and seen == sorted(seen)

    with pytest.raises(ClientError) as e:
        service.list_objects_v2(Bucket="e2e-s3-missing")
    assert code(e) == "NoSuchBucket"


def test_presigned_urls(service):
    key = f"{uuid.uuid4().hex}/shared file.txt"
    put_url = service.generate_presigned_url(
        "put_object", Params={"Bucket": "e2e-s3", "Key": key}, ExpiresIn=60
    )
    assert httpx.put(put_url, content=b"via presigned put").status_code == 200

    url = service.generate_presigned_url(
        "get_object", Params={"Bucket": "e2e-s3", "Key": key}, ExpiresIn=60
    )
    r = httpx.get(url)
    assert r.status_code == 200
    assert r.content == b"via presigned put"

    tampered = url.replace("X-Amz-Expires=60", "X-Amz-Expires=600")
    assert httpx.get(tampered).status_code == 403


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def streamed_put(key, data, payload, *, trailer=None, tamper=lambda chunks: chunks):
    """PUTs `data` as aws-chunked (64 KiB chunks), signing the chunks as streaming SigV4 does.

    boto3 never sends signed chunks, so the request is built here; `tamper` edits the
    `[header line, data]` pairs (final 0-size chunk included) before they are sent.
    """
    url = f"{ENDPOINT}/e2e-s3/{quote(key)}"
    headers = {
        "x-amz-content-sha256": payload,
        "content-encoding": "aws-chunked",
        "x-amz-decoded-content-length": str(len(data)),
        "content-type": "text/plain",
    }
    if trailer:
        headers["x-amz-trailer"] = trailer[0]
    request = AWSRequest("PUT", url, headers=headers)
    SigV4Auth(Credentials(*SERVICE_KEY), "s3", "us-east-1").add_auth(request)
    amz_date = request.headers["X-Amz-Date"]
    scope = f"{amz_date[:8]}/us-east-1/s3/aws4_request"
    key_bytes = f"AWS4{SERVICE_KEY[1]}".encode()
    for part in (amz_date[:8], "us-east-1", "s3", "aws4_request"):
        key_bytes = hmac.new(key_bytes, part.encode(), hashlib.sha256).digest()
    previous = request.headers["Authorization"].rsplit("Signature=", 1)[1]

    def sign(algorithm, payload_hash):
        nonlocal previous
        sts = f"{algorithm}\n{amz_date}\n{scope}\n{previous}\n{payload_hash}"
        previous = hmac.new(key_bytes, sts.encode(), hashlib.sha256).hexdigest()
        return previous

    signed = payload.startswith("STREAMING-AWS4-HMAC-SHA256")
    pieces = [data[i : i + 65536] for i in range(0, len(data), 65536)] + [b""]
    chunks = []
    for piece in pieces:
        line = f"{len(piece):x}"
        if signed:
            digest = hashlib.sha256(piece).hexdigest()
            line += ";chunk-signature=" + sign(
                "AWS4-HMAC-SHA256-PAYLOAD", f"{EMPTY_SHA256}\n{digest}"
            )
        chunks.append([line, piece])
    body = b"".join(
        f"{line}\r\n".encode() + piece + (b"\r\n" if piece else b"")
        for line, piece in tamper(chunks)
    )
    if trailer:
        body += f"{trailer[0]}:{trailer[1]}\r\n".encode()
        if signed:
            canonical = f"{trailer[0]}:{trailer[1]}\n".encode()
            sig = sign("AWS4-HMAC-SHA256-TRAILER", hashlib.sha256(canonical).hexdigest())
            body += f"x-amz-trailer-signature:{sig}\r\n".encode()
    return httpx.put(url, headers=dict(request.headers), content=body + b"\r\n")


def crc32(data: bytes) -> str:
    return base64.b64encode(zlib.crc32(data).to_bytes(4, "big")).decode()


def test_streamed_uploads_verify_chunk_signatures_and_checksums(service):
    data = os.urandom(150 * 1024)
    signed = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
    trailer = ("x-amz-checksum-crc32", crc32(data))

    for payload, extra in [
        (signed, {}),
        (signed + "-TRAILER", {"trailer": trailer}),
        ("STREAMING-UNSIGNED-PAYLOAD-TRAILER", {"trailer": trailer}),
    ]:
        key = f"{uuid.uuid4().hex}/streamed.bin"
        r = streamed_put(key, data, payload, **extra)
        assert r.status_code == 200, (payload, r.text)
        assert service.get_object(Bucket="e2e-s3", Key=key)["Body"].read() == data

    def flip_byte(chunks):
        chunks[1][1] = b"x" + chunks[1][1][1:]
        return chunks

    def wrong_final_signature(chunks):
        line = chunks[-1][0]
        chunks[-1][0] = line[:-1] + ("1" if line[-1] == "0" else "0")
        return chunks

    def unsigned_chunk(chunks):
        chunks[0][0] = chunks[0][0].split(";")[0]
        return chunks

    for tamper, status, error in [
        (flip_byte, 403, "SignatureDoesNotMatch"),
        (wrong_final_signature, 403, "SignatureDoesNotMatch"),
        (unsigned_chunk, 400, "InvalidArgument"),
    ]:
        key = f"{uuid.uuid4().hex}.bin"
        r = streamed_put(key, data, signed, tamper=tamper)
        assert r.status_code == status and error in r.text, (tamper.__name__, r.text)
        with pytest.raises(ClientError):
            service.head_object(Bucket="e2e-s3", Key=key)

    bad = ("x-amz-checksum-crc32", crc32(data + b"!"))
    for payload in (signed + "-TRAILER", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"):
        r = streamed_put(f"{uuid.uuid4().hex}.bin", data, payload, trailer=bad)
        assert r.status_code == 400 and "BadDigest" in r.text, (payload, r.text)
    r = streamed_put(f"{uuid.uuid4().hex}.bin", data, "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD")
    assert r.status_code == 501

    with pytest.raises(ClientError) as e:
        service.put_object(
            Bucket="e2e-s3",
            Key=f"{uuid.uuid4().hex}.txt",
            Body=b"payload",
            ChecksumSHA256=base64.b64encode(hashlib.sha256(b"other").digest()).decode(),
        )
    assert code(e) == "BadDigest"


def test_bad_credentials_are_rejected(keys):
    with pytest.raises(ClientError) as e:
        s3(SERVICE_KEY[0], "wrong-secret").list_buckets()
    assert code(e) == "SignatureDoesNotMatch"
    with pytest.raises(ClientError) as e:
        s3("unknown", "whatever").list_buckets()
    assert code(e) == "InvalidAccessKeyId"
    with pytest.raises(ClientError) as e:
        s3("user", "not-a-token", "not-a-token").list_buckets()
    assert code(e) == "InvalidToken"
    _, token = keys.user()
    with pytest.raises(ClientError) as e:
        s3("user", "a-different-secret", token).list_buckets()
    assert code(e) == "SignatureDoesNotMatch"


def test_limits_and_unsupported_operations(service):
    with pytest.raises(ClientError) as e:
        service.put_object(Bucket="e2e-s3-small", Key="big.bin", Body=b"x" * 64)
    assert code(e) == "EntityTooLarge"
    with pytest.raises(ClientError) as e:
        service.get_object_acl(Bucket="e2e-s3", Key="anything")
    assert code(e) == "NotImplemented"
    assert "e2e-s3" in [b["Name"] for b in service.list_buckets()["Buckets"]]


def test_copy_object(service, keys):
    src = f"{uuid.uuid4().hex}/source file.txt"
    service.put_object(Bucket="e2e-s3", Key=src, Body=b"copy me", ContentType="text/plain")

    dst = f"{uuid.uuid4().hex}/ğ copy.txt"
    r = service.copy_object(Bucket="e2e-s3", Key=dst, CopySource={"Bucket": "e2e-s3", "Key": src})
    assert r["CopyObjectResult"]["ETag"]
    got = service.get_object(Bucket="e2e-s3", Key=dst)
    assert got["Body"].read() == b"copy me"
    assert got["ContentType"] == "text/plain"

    service.copy_object(
        Bucket="e2e-s3",
        Key=dst,
        CopySource={"Bucket": "e2e-s3", "Key": src},
        MetadataDirective="REPLACE",
        ContentType="application/octet-stream",
    )
    head = service.head_object(Bucket="e2e-s3", Key=dst)
    assert head["ContentType"] == "application/octet-stream"

    service.put_object(Bucket="e2e-s3", Key=src, Body=b"x" * 64)
    with pytest.raises(ClientError) as e:
        service.copy_object(Bucket="e2e-s3-small", Key=dst, CopySource=f"e2e-s3/{src}")
    assert code(e) == "EntityTooLarge"
    with pytest.raises(ClientError) as e:
        service.copy_object(Bucket="e2e-s3", Key=dst, CopySource="e2e-s3/missing.txt")
    assert code(e) == "NoSuchKey"
    with pytest.raises(ClientError) as e:
        service.copy_object(
            Bucket="e2e-s3", Key=dst, CopySource={"Bucket": "e2e-s3", "Key": src, "VersionId": "1"}
        )
    assert code(e) == "NotImplemented"

    # RLS reads the source as the caller: another user's object cannot be copied.
    a, b = user_client(keys), user_client(keys)
    mine = f"{uuid.uuid4().hex}.txt"
    a.put_object(Bucket="e2e-s3", Key=mine, Body=b"private")
    with pytest.raises(ClientError) as e:
        b.copy_object(Bucket="e2e-s3", Key=f"{uuid.uuid4().hex}.txt", CopySource=f"e2e-s3/{mine}")
    assert code(e) == "NoSuchKey"


def test_multipart_copy(keys):
    a, b = user_client(keys), user_client(keys)
    src, dst = f"{uuid.uuid4().hex}/src.bin", f"{uuid.uuid4().hex}/dst.bin"
    data = os.urandom(11 * 1024 * 1024)
    a.put_object(Bucket="e2e-s3", Key=src, Body=data)

    # Above the threshold the transfer manager copies with ranged UploadPartCopy calls.
    config = TransferConfig(
        multipart_threshold=5 * 1024 * 1024, multipart_chunksize=5 * 1024 * 1024
    )
    a.copy({"Bucket": "e2e-s3", "Key": src}, "e2e-s3", dst, Config=config)
    assert a.get_object(Bucket="e2e-s3", Key=dst)["Body"].read() == data
    with pytest.raises(ClientError) as e:
        a.copy_object(
            Bucket="e2e-s3", Key=dst, CopySource=f"e2e-s3/{src}", CopySourceIfMatch='"stale"'
        )
    assert code(e) == "PreconditionFailed"

    theirs = f"{uuid.uuid4().hex}.bin"
    upload = b.create_multipart_upload(Bucket="e2e-s3", Key=theirs)["UploadId"]
    with pytest.raises(ClientError) as e:
        b.upload_part_copy(
            Bucket="e2e-s3", Key=theirs, UploadId=upload, PartNumber=1, CopySource=f"e2e-s3/{src}"
        )
    assert code(e) == "NoSuchKey"
    upload = a.create_multipart_upload(Bucket="e2e-s3", Key=dst)["UploadId"]
    with pytest.raises(ClientError) as e:
        a.upload_part_copy(
            Bucket="e2e-s3",
            Key=dst,
            UploadId=upload,
            PartNumber=1,
            CopySource=f"e2e-s3/{src}",
            CopySourceRange=f"bytes=0-{len(data)}",
        )
    assert code(e) == "InvalidArgument"


def test_delete_objects(service, keys):
    root = uuid.uuid4().hex
    names = [f"{root}/a.txt", f"{root}/b & <c>.txt", f'{root}/it\'s "quoted".txt']
    for n in names:
        service.put_object(Bucket="e2e-s3", Key=n, Body=b"x")

    r = service.delete_objects(
        Bucket="e2e-s3",
        Delete={"Objects": [{"Key": n} for n in names + [f"{root}/missing.txt"]]},
    )
    assert sorted(d["Key"] for d in r["Deleted"]) == sorted(names + [f"{root}/missing.txt"])
    assert "Errors" not in r
    assert "Contents" not in service.list_objects_v2(Bucket="e2e-s3", Prefix=f"{root}/")

    # Another user's object stays: RLS hides it, so it reads as already gone.
    a, b = user_client(keys), user_client(keys)
    mine = f"{uuid.uuid4().hex}.txt"
    a.put_object(Bucket="e2e-s3", Key=mine, Body=b"mine")
    r = b.delete_objects(Bucket="e2e-s3", Delete={"Objects": [{"Key": mine}], "Quiet": True})
    assert "Deleted" not in r and "Errors" not in r
    assert a.get_object(Bucket="e2e-s3", Key=mine)["Body"].read() == b"mine"

    with pytest.raises(ClientError) as e:
        service.delete_objects(Bucket="e2e-s3-missing", Delete={"Objects": [{"Key": "x"}]})
    assert code(e) == "NoSuchBucket"


def test_multipart_upload_through_the_transfer_manager(keys):
    a = user_client(keys)
    key = f"{uuid.uuid4().hex}/big.bin"
    data = os.urandom(12 * 1024 * 1024)
    # 5 MB parts: the transfer manager uploads them concurrently, then completes.
    config = TransferConfig(
        multipart_threshold=5 * 1024 * 1024, multipart_chunksize=5 * 1024 * 1024
    )
    a.upload_fileobj(io.BytesIO(data), "e2e-s3", key, Config=config)
    out = io.BytesIO()
    a.download_fileobj("e2e-s3", key, out, Config=config)
    assert out.getvalue() == data


def test_multipart_uploads_belong_to_their_creator(keys):
    a, b = user_client(keys), user_client(keys)
    key = f"{uuid.uuid4().hex}.bin"
    upload = a.create_multipart_upload(Bucket="e2e-s3", Key=key)["UploadId"]
    part = a.upload_part(Bucket="e2e-s3", Key=key, UploadId=upload, PartNumber=1, Body=b"abc")

    with pytest.raises(ClientError) as e:
        b.upload_part(Bucket="e2e-s3", Key=key, UploadId=upload, PartNumber=2, Body=b"x")
    assert code(e) == "NoSuchUpload"
    done = {"Parts": [{"ETag": part["ETag"], "PartNumber": 1}]}
    with pytest.raises(ClientError) as e:
        b.complete_multipart_upload(Bucket="e2e-s3", Key=key, UploadId=upload, MultipartUpload=done)
    assert code(e) == "NoSuchUpload"
    with pytest.raises(ClientError) as e:
        a.complete_multipart_upload(
            Bucket="e2e-s3",
            Key=key,
            UploadId=upload,
            MultipartUpload={"Parts": [{"ETag": part["ETag"], "PartNumber": 3}]},
        )
    assert code(e) == "InvalidPart"

    a.complete_multipart_upload(Bucket="e2e-s3", Key=key, UploadId=upload, MultipartUpload=done)
    assert a.get_object(Bucket="e2e-s3", Key=key)["Body"].read() == b"abc"
    with pytest.raises(ClientError) as e:
        a.upload_part(Bucket="e2e-s3", Key=key, UploadId=upload, PartNumber=2, Body=b"late")
    assert code(e) == "NoSuchUpload"


def test_aborted_and_oversized_multipart_uploads(service):
    key = f"{uuid.uuid4().hex}.bin"
    upload = service.create_multipart_upload(Bucket="e2e-s3", Key=key)["UploadId"]
    service.upload_part(Bucket="e2e-s3", Key=key, UploadId=upload, PartNumber=1, Body=b"x")
    service.abort_multipart_upload(Bucket="e2e-s3", Key=key, UploadId=upload)
    with pytest.raises(ClientError) as e:
        service.upload_part(Bucket="e2e-s3", Key=key, UploadId=upload, PartNumber=2, Body=b"x")
    assert code(e) == "NoSuchUpload"

    upload = service.create_multipart_upload(Bucket="e2e-s3-small", Key=key)["UploadId"]
    parts = [
        {
            "ETag": service.upload_part(
                Bucket="e2e-s3-small", Key=key, UploadId=upload, PartNumber=n, Body=b"x" * 10
            )["ETag"],
            "PartNumber": n,
        }
        for n in (1, 2)
    ]
    with pytest.raises(ClientError) as e:
        service.complete_multipart_upload(
            Bucket="e2e-s3-small", Key=key, UploadId=upload, MultipartUpload={"Parts": parts}
        )
    assert code(e) == "EntityTooLarge"
