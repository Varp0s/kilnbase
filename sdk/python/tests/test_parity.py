import base64
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
import pytest
from kilnbase import KilnbaseError
from test_client import KEY, make, session


def test_upsert_ilike_is_range():
    c, seen = make(lambda req: httpx.Response(201, json=[{"id": 1}]))
    c.from_("t").upsert([{"id": 1}]).execute()
    assert seen[0].method == "POST" and json.loads(seen[0].content) == [{"id": 1}]
    assert seen[0].headers["prefer"] == "return=representation,resolution=merge-duplicates"
    c.from_("t").select().ilike("n", "A%").is_("d", None).is_("ok", True).range(10, 19).execute()
    p = seen[1].url.params
    assert p["n"] == "ilike.A%" and p["d"] == "is.null" and p["ok"] == "is.true"
    assert p["offset"] == "10" and p["limit"] == "10"
    assert "prefer" not in seen[1].headers


def test_anonymous_and_update_user():
    def handler(req):
        if req.url.path == "/auth/v1/anonymous":
            assert json.loads(req.content) == {}
            return httpx.Response(200, json=session())
        assert req.method == "PUT" and req.headers["authorization"] == "Bearer at1"
        if json.loads(req.content).get("email"):
            return httpx.Response(200, json=session("at2", "rt2"))
        return httpx.Response(204)

    c, seen = make(handler)
    with pytest.raises(KilnbaseError) as e:
        c.auth.update_user("pw")
    assert e.value.code == "not_signed_in" and not seen
    c.auth.sign_in_anonymously()
    assert seen[0].headers["apikey"] == KEY
    c.auth.update_user("new", current_password="old")
    assert json.loads(seen[1].content) == {"password": "new", "current_password": "old"}
    assert seen[1].url.path == "/auth/v1/user" and c.auth.session["access_token"] == "at1"
    c.auth.update_user("new", email="a@b.c")
    assert json.loads(seen[2].content) == {"password": "new", "email": "a@b.c"}
    assert c.auth.session["access_token"] == "at2"


def test_otp_send_and_verify():
    def handler(req):
        if req.url.path == "/auth/v1/otp":
            return httpx.Response(204)
        return httpx.Response(200, json=session())

    c, seen = make(handler)
    c.auth.sign_in_with_otp("a@b.c")
    assert seen[0].method == "POST" and seen[0].headers["apikey"] == KEY
    assert json.loads(seen[0].content) == {"email": "a@b.c", "create_user": True}
    c.auth.sign_in_with_otp("a@b.c", redirect_to="http://x/cb", create_user=False)
    assert json.loads(seen[1].content) == {
        "email": "a@b.c",
        "redirect_to": "http://x/cb",
        "create_user": False,
    }
    c.auth.verify_otp("email", "123456", email="a@b.c")
    assert seen[2].url.path == "/auth/v1/verify"
    assert json.loads(seen[2].content) == {"type": "email", "email": "a@b.c", "token": "123456"}
    c.auth.verify_otp("magiclink", "tok")
    assert json.loads(seen[3].content) == {"type": "magiclink", "token": "tok"}
    assert c.auth.session["access_token"] == "at1"


def test_oauth_pkce_flow():
    c, seen = make(lambda req: httpx.Response(200, json=session()))
    with pytest.raises(KilnbaseError) as e:
        c.auth.exchange_code_for_session("c")
    assert e.value.code == "missing_verifier"
    url = c.auth.sign_in_with_oauth("github", redirect_to="http://x/cb?a=1")
    parts = urlsplit(url)
    q = parse_qs(parts.query)
    assert parts.path == "/auth/v1/authorize" and url.startswith("http://gw/")
    assert q["provider"] == ["github"] and q["redirect_to"] == ["http://x/cb?a=1"]
    c.auth.exchange_code_for_session("code1")
    assert seen[0].url.params["grant_type"] == "authorization_code"
    body = json.loads(seen[0].content)
    assert body["code"] == "code1"
    digest = hashlib.sha256(body["code_verifier"].encode()).digest()
    assert q["code_challenge"] == [base64.urlsafe_b64encode(digest).rstrip(b"=").decode()]
    with pytest.raises(KilnbaseError):  # the verifier is single-use
        c.auth.exchange_code_for_session("code1")


def test_mfa_enroll_verify_unenroll():
    factor = {"id": "f/1", "type": "totp", "secret": "S", "uri": "otpauth://x"}

    def handler(req):
        assert req.headers["authorization"] == "Bearer at1"
        if req.url.path == "/auth/v1/factors":
            assert req.method == "POST"
            return httpx.Response(200, json=factor)
        if req.url.path.endswith("/verify"):
            assert json.loads(req.content) == {"code": "123456"}
            return httpx.Response(200, json=session("at2", "rt2"))
        return httpx.Response(204)

    c, seen = make(handler)
    with pytest.raises(KilnbaseError) as e:
        c.auth.mfa.enroll()
    assert e.value.code == "not_signed_in" and not seen
    c.auth.session = session()
    assert c.auth.mfa.enroll() == factor
    assert c.auth.mfa.verify("f/1", "123456")["access_token"] == "at2"
    assert seen[1].url.raw_path == b"/auth/v1/factors/f%2F1/verify"
    assert c.auth.session["refresh_token"] == "rt2"
    c.auth.session = session()
    c.auth.mfa.unenroll("f/1")
    assert seen[2].method == "DELETE" and seen[2].url.raw_path == b"/auth/v1/factors/f%2F1"


def test_storage_image_transforms():
    c, seen = make(lambda req: httpx.Response(200, content=b"img"))
    b = c.storage.from_("b")
    t = {"width": 100, "resize": "cover", "format": "webp"}
    assert b.download("d/a b.png", transform=t) == b"img"
    assert seen[0].method == "GET" and seen[0].headers["apikey"] == KEY
    assert seen[0].url.path == "/storage/v1/render/image/authenticated/b/d/a b.png"
    assert dict(seen[0].url.params) == {"width": "100", "resize": "cover", "format": "webp"}
    assert b.get_public_url("d/a b.png", transform={"height": 5, "quality": 80}) == (
        "http://gw/storage/v1/render/image/public/b/d/a%20b.png?height=5&quality=80"
    )
    assert b.get_public_url("x.png", transform={}) == "http://gw/storage/v1/object/public/b/x.png"
    assert len(seen) == 1
