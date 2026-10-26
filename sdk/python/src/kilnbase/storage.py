from collections.abc import Callable
from typing import Any, Literal, TypedDict
from urllib.parse import quote, urlencode

import httpx2 as httpx

from .errors import send


def _encode_path(path: str) -> str:
    """Encodes each path segment but keeps `/` separators."""
    return "/".join(quote(p, safe="") for p in path.split("/"))


class TransformOptions(TypedDict, total=False):
    """Needs the server's optional image service; non-images are rejected."""

    width: int  # 1-2500 pixels; leave one out to keep the aspect ratio
    height: int
    resize: Literal["cover", "contain", "fill"]
    quality: int  # 1-100
    format: Literal["origin", "webp", "avif", "jpeg", "png"]


def _transform_query(t: TransformOptions) -> str:
    return urlencode({k: v for k, v in t.items() if v is not None})


class BucketClient:
    def __init__(self, http: httpx.Client, url: str, bucket: str, headers: Callable[[], dict]):
        self._http = http
        self._url = url
        self._bucket = quote(bucket, safe="")
        self._headers = headers

    def upload(
        self,
        path: str,
        data: bytes | str,
        *,
        content_type: str | None = None,
        upsert: bool = False,
    ) -> dict[str, Any]:
        headers = self._headers()
        if content_type:
            headers["Content-Type"] = content_type
        # PUT replaces an existing object; POST fails with already_exists.
        res = send(
            self._http,
            "PUT" if upsert else "POST",
            self._object_url(path),
            headers=headers,
            content=data,
        )
        return res.json()

    def download(self, path: str, *, transform: TransformOptions | None = None) -> bytes:
        """With `transform`, returns a resized/converted image instead of the stored bytes."""
        url = self._object_url(path)
        if transform:
            url = (
                f"{self._url}/storage/v1/render/image/authenticated/{self._bucket}/"
                f"{_encode_path(path)}?{_transform_query(transform)}"
            )
        return send(self._http, "GET", url, headers=self._headers()).content

    def remove(self, path: str) -> None:
        send(self._http, "DELETE", self._object_url(path), headers=self._headers())

    def create_signed_url(self, path: str, expires_in: int) -> dict[str, Any]:
        """A link anyone can open until it expires; only the object's readers may create one."""
        res = send(
            self._http,
            "POST",
            f"{self._url}/storage/v1/object/sign/{self._bucket}/{_encode_path(path)}",
            headers=self._headers(),
            json={"expires_in": expires_in},
        )
        body = res.json()
        return {"signed_url": f"{self._url}{body['signed_url']}", "expires_at": body["expires_at"]}

    def get_public_url(self, path: str, *, transform: TransformOptions | None = None) -> str:
        """URL of an object in a public bucket; no request is made."""
        if transform:
            return (
                f"{self._url}/storage/v1/render/image/public/{self._bucket}/"
                f"{_encode_path(path)}?{_transform_query(transform)}"
            )
        return f"{self._url}/storage/v1/object/public/{self._bucket}/{_encode_path(path)}"

    def _object_url(self, path: str) -> str:
        return f"{self._url}/storage/v1/object/{self._bucket}/{_encode_path(path)}"


class StorageClient:
    def __init__(self, http: httpx.Client, url: str, headers: Callable[[], dict]):
        self._http = http
        self._url = url
        self._headers = headers

    def from_(self, bucket: str) -> BucketClient:
        return BucketClient(self._http, self._url, bucket, self._headers)
