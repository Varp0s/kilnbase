"""Minimal OAuth2/OIDC provider for end-to-end tests. Standard library only.

POST /next {"sub", "email", "email_verified"} chooses who the next /authorize signs in.
Also a webhook receiver: POST /hooks/<name> is recorded (and answered with the status set by
POST /hooks-status/<name> {"status": 500}, default 200); GET /hooks/<name> lists what arrived.
"""

import base64
import hashlib
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

CLIENT_ID, CLIENT_SECRET = "mock-client", "mock-secret"
next_user = {"sub": "mock-1", "email": "mock@example.com", "email_verified": True}
codes: dict[str, dict] = {}
tokens: dict[str, dict] = {}
hooks: dict[str, list[dict]] = {}
hook_status: dict[str, int] = {}


def s256(verifier: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )


class Handler(BaseHTTPRequestHandler):
    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def do_GET(self):
        url = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/authorize":
            if q.get("client_id") != CLIENT_ID or q.get("code_challenge_method") != "S256":
                return self._json(400, {"error": "invalid_request"})
            code = secrets.token_urlsafe(16)
            codes[code] = {
                "user": dict(next_user),
                "challenge": q["code_challenge"],
                "redirect_uri": q["redirect_uri"],
            }
            self.send_response(302)
            self.send_header(
                "Location", f"{q['redirect_uri']}?{urlencode({'code': code, 'state': q['state']})}"
            )
            self.end_headers()
        elif url.path.startswith("/hooks/"):
            return self._json(200, {"received": hooks.get(url.path[7:], [])})
        elif url.path == "/userinfo":
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            user = tokens.get(token)
            return self._json(200, user) if user else self._json(401, {"error": "invalid_token"})
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):
        global next_user
        url = urlsplit(self.path)
        if url.path.startswith("/hooks/"):
            name = url.path[7:]
            entry = {"headers": dict(self.headers), "body": self._body().decode()}
            hooks.setdefault(name, []).append(entry)
            return self._json(hook_status.get(name, 200), {})
        if url.path.startswith("/hooks-status/"):
            hook_status[url.path[14:]] = json.loads(self._body())["status"]
            return self._json(200, {})
        if url.path == "/next":
            next_user = json.loads(self._body())
            return self._json(200, next_user)
        if url.path == "/token":
            form = {k: v[0] for k, v in parse_qs(self._body().decode()).items()}
            grant = codes.pop(form.get("code", ""), None)
            ok = (
                grant
                and form.get("client_secret") == CLIENT_SECRET
                and form.get("redirect_uri") == grant["redirect_uri"]
                and s256(form.get("code_verifier", "")) == grant["challenge"]
            )
            if not ok:
                return self._json(400, {"error": "invalid_grant"})
            token = secrets.token_urlsafe(16)
            tokens[token] = grant["user"]
            return self._json(200, {"access_token": token, "token_type": "bearer"})
        self._json(404, {"error": "not_found"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9100), Handler).serve_forever()  # noqa: S104 - test container
