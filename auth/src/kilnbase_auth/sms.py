import json
import re
import time
from urllib.parse import urlsplit

import httpx2 as httpx

from .log import log
from .webhooks import sign

E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")


def normalize_phone(raw: str) -> str | None:
    """E.164 (+ and 8-15 digits); spaces, dots, dashes and parentheses are dropped."""
    phone = re.sub(r"[\s.()-]", "", raw)
    return phone if E164.match(phone) else None


def http_allowed(url: str) -> bool:
    """https, or http to a host on the internal network (a name without dots, or localhost)."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme == "https":
        return bool(host)
    return parts.scheme == "http" and (host in ("localhost", "127.0.0.1") or "." not in host)


class SmsSender:
    """POSTs {"to", "body"} to the operator's hook, which talks to their SMS provider.

    Signed like webhooks (X-Kilnbase-Signature over "<timestamp>.<body>" with the shared secret).
    """

    def __init__(self, url: str | None, secret: str | None):
        self.url, self.secret = url, secret

    async def send(self, http: httpx.AsyncClient, to: str, text: str) -> None:
        """Raises httpx.HTTPError when the hook cannot be reached or does not answer 2xx."""
        if self.url is None:
            # shortcut: dev-only fallback; codes land in logs, so production needs an SMS hook.
            log.warning("no SMS hook configured; message to %s: %s", to, text)
            return
        body = json.dumps({"to": to, "body": text})
        timestamp = int(time.time())
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Kilnbase-SMS",
            "X-Kilnbase-Timestamp": str(timestamp),
            "X-Kilnbase-Signature": sign(self.secret or "", timestamp, body),
        }
        res = await http.post(self.url, content=body, headers=headers, follow_redirects=False)
        res.raise_for_status()
