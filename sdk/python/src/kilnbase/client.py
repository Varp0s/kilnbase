import httpx2 as httpx

from .auth import AuthClient
from .rest import Query
from .storage import StorageClient


class Client:
    def __init__(self, http: httpx.Client, url: str, api_key: str):
        url = url.rstrip("/")
        self._http = http
        self._url = url
        self.auth = AuthClient(http, url, api_key)
        self.storage = StorageClient(http, url, self.auth.headers)

    def from_(self, table: str) -> Query:
        """Query a table in the `public` schema."""
        return Query(self._http, self._url, table, self.auth.headers)

    def close(self) -> None:
        self._http.close()


def create_client(
    url: str, key: str, *, timeout: float = 30, transport: httpx.BaseTransport | None = None
) -> Client:
    """
    `url` is the gateway base URL, e.g. `http://localhost:8000`. `key` is the **anon** key; never
    ship the service_role key to untrusted code. `transport` exists for tests.
    """
    return Client(httpx.Client(timeout=timeout, transport=transport), url, key)
