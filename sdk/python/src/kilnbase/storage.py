from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx2 as httpx

from .errors import send


def _encode_path(path: str) -> str:
    """Encodes each path segment but keeps `/` separators."""
    return "/".join(quote(p, safe="") for p in path.split("/"))


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

    def download(self, path: str) -> bytes:
        return send(self._http, "GET", self._object_url(path), headers=self._headers()).content

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

    def get_public_url(self, path: str) -> str:
        """URL of an object in a public bucket; no request is made."""
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
