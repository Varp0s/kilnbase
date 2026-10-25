ORIGIN = "http://localhost:3000"


def test_preflight_allows_api_headers(client):
    r = client.options(
        "/rest/v1/anything",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "PATCH",
            "Access-Control-Request-Headers": "apikey, authorization, content-type, prefer",
        },
    )
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] in ("*", ORIGIN)
    allowed = r.headers["access-control-allow-headers"].lower()
    for header in ("apikey", "authorization", "content-type", "prefer"):
        assert header in allowed
    assert "PATCH" in r.headers["access-control-allow-methods"]


def test_responses_carry_cors_headers_and_no_credentials(client, keys):
    r = client.get("/rest/v1/", headers={"Origin": ORIGIN, "apikey": keys.anon})
    assert "access-control-allow-origin" in r.headers
    # Header-based auth only: cookies are never allowed cross-origin.
    assert r.headers.get("access-control-allow-credentials") != "true"
