import httpx2 as httpx


class KilnbaseError(Exception):
    """Any failed call: an HTTP error status, or `status == 0` when the network failed."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message


def raise_for_response(res: httpx.Response) -> None:
    """Reads a Kilnbase or PostgREST error body into a KilnbaseError."""
    if res.is_success:
        return
    try:
        body = res.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        body = {}
    raise KilnbaseError(
        res.status_code,
        str(body.get("code") or f"http_{res.status_code}"),
        str(body.get("message") or res.reason_phrase or "request failed"),
    )


def send(http: httpx.Client, method: str, url: str, **kwargs) -> httpx.Response:
    """One request; transport failures and HTTP errors both become KilnbaseError."""
    try:
        res = http.request(method, url, **kwargs)
    except httpx.HTTPError as e:
        raise KilnbaseError(0, "network_error", str(e)) from e
    raise_for_response(res)
    return res
