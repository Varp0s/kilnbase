import json
import time

import httpx2 as httpx
import pytest
from kilnbase import KilnbaseError, create_client

KEY = "anon-key"


def session(access="at1", refresh="rt1", expires_at=None):
    return {
        "access_token": access,
        "refresh_token": refresh,
        "expires_at": expires_at or int(time.time()) + 3600,
        "user": {"id": "u1"},
    }


def make(handler):
    """A client served by `handler(request) -> Response`, plus the log of requests it saw."""
    seen: list[httpx.Request] = []

    def wrapped(request):
        seen.append(request)
        return handler(request)

    return create_client("http://gw/", KEY, transport=httpx.MockTransport(wrapped)), seen


def test_sign_in_stores_session_and_sends_token():
    def handler(req):
        if req.url.path == "/auth/v1/token":
            assert req.url.params["grant_type"] == "password"
            assert json.loads(req.content) == {"email": "a@b.c", "password": "pw"}
            return httpx.Response(200, json=session())
        return httpx.Response(200, json=[{"id": 1}])

    c, seen = make(handler)
    c.from_("t").select().execute()
    assert seen[-1].headers["apikey"] == KEY
    assert "authorization" not in seen[-1].headers
    c.auth.sign_in_with_password("a@b.c", "pw")
    c.from_("t").select().execute()
    assert seen[-1].headers["authorization"] == "Bearer at1"
    assert seen[-1].headers["apikey"] == KEY


def test_sign_up_get_user_and_sign_out():
    def handler(req):
        if req.url.path == "/auth/v1/signup":
            return httpx.Response(200, json=session())
        if req.url.path == "/auth/v1/user":
            assert req.headers["authorization"] == "Bearer at1"
            return httpx.Response(200, json={"id": "u1"})
        if req.url.path == "/auth/v1/logout":
            return httpx.Response(204)
        raise AssertionError(req.url)

    c, seen = make(handler)
    with pytest.raises(KilnbaseError) as e:
        c.auth.get_user()
    assert (e.value.status, e.value.code) == (401, "not_signed_in")
    c.auth.sign_up("a@b.c", "pw")
    assert c.auth.get_user() == {"id": "u1"}
    c.auth.sign_out()
    assert c.auth.session is None
    assert seen[-1].url.path == "/auth/v1/logout"
    assert seen[-1].headers["authorization"] == "Bearer at1"
    c.auth.sign_out()  # no session: no request
    assert seen[-1].url.path == "/auth/v1/logout" and len(seen) == 3


def test_expiring_token_is_refreshed_before_use():
    def handler(req):
        if req.url.path == "/auth/v1/token":
            assert json.loads(req.content) == {"refresh_token": "rt1"}
            return httpx.Response(200, json=session("at2", "rt2"))
        return httpx.Response(200, json=[])

    c, seen = make(handler)
    c.auth.session = session(expires_at=int(time.time()) + 10)
    c.from_("t").select().execute()
    assert seen[0].url.params["grant_type"] == "refresh_token"
    assert seen[1].headers["authorization"] == "Bearer at2"
    assert c.auth.session["refresh_token"] == "rt2"


def test_failed_refresh_with_401_signs_out():
    c, _ = make(lambda req: httpx.Response(401, json={"code": "invalid_token", "message": "spent"}))
    c.auth.session = session()
    with pytest.raises(KilnbaseError) as e:
        c.auth.refresh_session()
    assert e.value.code == "invalid_token"
    assert c.auth.session is None


def test_query_builds_postgrest_url():
    c, seen = make(lambda req: httpx.Response(200, json=[{"id": 1}]))
    q = (
        c.from_("todos")
        .select("id,title")
        .eq("done", False)
        .neq("a", 1)
        .gt("b", 2)
        .gte("c", 3)
        .lt("d", 4)
        .lte("e", 5)
        .like("t", "x%")
        .in_("id", [1, "a,b", 'q"r'])
        .order("id", ascending=False)
        .limit(5)
    )
    assert q.execute() == [{"id": 1}]
    p = seen[0].url.params
    assert seen[0].url.path == "/rest/v1/todos" and seen[0].method == "GET"
    assert p["select"] == "id,title" and p["done"] == "eq.false" and p["limit"] == "5"
    assert [p[k] for k in "abcde"] == ["neq.1", "gt.2", "gte.3", "lt.4", "lte.5"]
    assert p["t"] == "like.x%" and p["order"] == "id.desc"
    assert p["id"] == 'in.(1,"a,b","q\\"r")'


def test_writes_return_representation():
    c, seen = make(lambda req: httpx.Response(201, json=[{"id": 1}]))
    c.from_("t").insert({"a": 1}).execute()
    assert seen[0].method == "POST" and json.loads(seen[0].content) == {"a": 1}
    assert seen[0].headers["prefer"] == "return=representation"
    c.from_("t").update({"a": 2}).eq("id", 1).execute()
    assert seen[1].method == "PATCH" and seen[1].url.params["id"] == "eq.1"
    c.from_("t").delete().eq("id", 1).execute()
    assert seen[2].method == "DELETE" and not seen[2].content


def test_single_asks_for_one_object():
    c, seen = make(lambda req: httpx.Response(200, json={"id": 1}))
    assert c.from_("t").select().eq("id", 1).single().execute() == {"id": 1}
    assert seen[0].headers["accept"] == "application/vnd.pgrst.object+json"


def test_empty_body_is_empty_list():
    c, _ = make(lambda req: httpx.Response(204))
    assert c.from_("t").delete().eq("id", 1).execute() == []


def test_error_shape_from_postgrest_body_and_fallback():
    c, _ = make(lambda req: httpx.Response(406, json={"code": "PGRST116", "message": "0 rows"}))
    with pytest.raises(KilnbaseError) as e:
        c.from_("t").single().execute()
    assert (e.value.status, e.value.code, e.value.message) == (406, "PGRST116", "0 rows")

    c, _ = make(lambda req: httpx.Response(502, content=b"<html>"))
    with pytest.raises(KilnbaseError) as e:
        c.from_("t").execute()
    assert (e.value.status, e.value.code) == (502, "http_502")


def test_network_error():
    def handler(req):
        raise httpx.ConnectError("refused")

    c, _ = make(handler)
    with pytest.raises(KilnbaseError) as e:
        c.from_("t").execute()
    assert (e.value.status, e.value.code) == (0, "network_error")


def test_storage_roundtrip():
    obj = {"id": "o1", "bucket": "b", "name": "d/f.txt", "size": 2, "mime_type": "text/plain"}

    def handler(req):
        if "/object/sign/" in req.url.path:
            assert json.loads(req.content) == {"expires_in": 60}
            return httpx.Response(200, json={"signed_url": "/storage/v1/x?t=1", "expires_at": 9})
        if req.method in ("POST", "PUT"):
            assert req.headers["content-type"] == "text/plain" and req.content == b"hi"
            return httpx.Response(200, json=obj)
        if req.method == "GET":
            return httpx.Response(200, content=b"hi")
        return httpx.Response(204)

    c, seen = make(handler)
    b = c.storage.from_("b")
    assert b.upload("d/f.txt", b"hi", content_type="text/plain") == obj
    assert seen[-1].method == "POST" and seen[-1].url.path == "/storage/v1/object/b/d/f.txt"
    b.upload("d/f.txt", b"hi", content_type="text/plain", upsert=True)
    assert seen[-1].method == "PUT"
    assert b.download("d/f.txt") == b"hi"
    b.remove("d/f.txt")
    assert seen[-1].method == "DELETE"
    assert b.create_signed_url("d/a b.txt", 60) == {
        "signed_url": "http://gw/storage/v1/x?t=1",
        "expires_at": 9,
    }
    assert b.get_public_url("d/a b.txt") == "http://gw/storage/v1/object/public/b/d/a%20b.txt"
    assert len(seen) == 5  # get_public_url made no request


def test_storage_error_raises():
    c, _ = make(lambda req: httpx.Response(404, json={"code": "not_found", "message": "no"}))
    with pytest.raises(KilnbaseError) as e:
        c.storage.from_("b").download("x")
    assert e.value.status == 404
