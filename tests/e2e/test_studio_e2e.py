import json
import time
import uuid

import httpx2 as httpx
import pytest
from conftest import psql, wait_for_schema

STUDIO = "http://localhost:3001"
PASSWORD = "correct horse battery staple"

# A policy that depends on auth.uid() and on a claim, so mismatched claims would show.
SCHEMA = """
drop table if exists public.e2e_studio;
create table public.e2e_studio (
    id int primary key,
    owner uuid default auth.uid(),
    verified_only boolean not null default false
);
alter table public.e2e_studio enable row level security;
create policy own_rows on public.e2e_studio for all to authenticated
    using (owner = auth.uid()
           and (not verified_only or coalesce((auth.jwt() ->> 'email_verified')::boolean, false)))
    with check (owner = auth.uid());
create policy public_rows on public.e2e_studio for select to anon using (owner is null);
notify pgrst, 'reload schema';
"""


@pytest.fixture(scope="module", autouse=True)
def schema(client, keys):
    try:
        httpx.get(STUDIO, timeout=2)
    except httpx.HTTPError:
        pytest.skip("start the stack with docker-compose.test.yml (studio profile) for these tests")
    psql(SCHEMA)
    wait_for_schema(client, keys, "e2e_studio")
    yield
    psql("drop table if exists public.e2e_studio;")


def admin(keys) -> dict:
    return {"Authorization": f"Bearer {keys.service_role}"}


def view_as(keys, user_id: str | None) -> list[dict]:
    body = {"table": "e2e_studio", "user_id": user_id, "limit": 100}
    r = httpx.post(f"{STUDIO}/api/view-as", headers=admin(keys), json=body)
    assert r.status_code == 200, r.text
    assert not r.json()["denied"]
    return sorted(r.json()["rows"], key=lambda row: row["id"])


def rest(client, keys, token: str | None) -> list[dict]:
    headers = {"apikey": keys.anon} | ({"Authorization": f"Bearer {token}"} if token else {})
    r = client.get("/rest/v1/e2e_studio?order=id", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def sign_up(client, keys) -> dict:
    body = {"email": f"studio-{uuid.uuid4().hex[:10]}@example.com", "password": PASSWORD}
    r = client.post("/auth/v1/signup", headers={"apikey": keys.anon}, json=body)
    assert r.status_code in (200, 201), r.text
    return r.json()


def test_admin_api_needs_the_service_role_key(keys):
    assert httpx.get(f"{STUDIO}/api/tables").status_code == 401
    bad = {"Authorization": f"Bearer {keys.anon}"}
    assert httpx.get(f"{STUDIO}/api/tables", headers=bad).status_code == 401
    r = httpx.get(f"{STUDIO}/api/tables", headers=admin(keys))
    assert r.status_code == 200
    table = next(t for t in r.json() if t["name"] == "e2e_studio")
    assert table["rls"] and {p["name"] for p in table["policies"]} == {"own_rows", "public_rows"}


def test_pages_are_locked_down():
    r = httpx.get(f"{STUDIO}/")
    assert r.status_code == 200 and "<script" in r.text and "onclick" not in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "access-control-allow-origin" not in r.headers


def test_user_list_has_no_secrets(client, keys):
    sign_up(client, keys)
    users = httpx.get(f"{STUDIO}/api/users", headers=admin(keys)).json()
    assert users and set(users[0]) == {
        "id",
        "email",
        "created_at",
        "is_anonymous",
        "email_confirmed_at",
        "last_sign_in_at",
        "active_sessions",
    }


def test_view_as_matches_the_rest_api(client, keys):
    a, b = sign_up(client, keys), sign_up(client, keys)
    for session, ids in ((a, (1, 2)), (b, (3,))):
        headers = {"apikey": keys.anon, "Authorization": f"Bearer {session['access_token']}"}
        for i in ids:
            row = {"id": i, "verified_only": i == 2}
            r = client.post("/rest/v1/e2e_studio", headers=headers, json=row)
            assert r.status_code == 201, r.text
    psql("insert into public.e2e_studio (id, owner) values (4, null);")

    for session in (a, b):
        mine = view_as(keys, session["user"]["id"])
        assert mine == rest(client, keys, session["access_token"])
        assert mine  # each user sees something, so equality is not trivially []
    # Row 2 needs a verified email, which these users lack: the claim is honoured.
    assert [r["id"] for r in view_as(keys, a["user"]["id"])] == [1]
    assert (
        view_as(keys, None)
        == rest(client, keys, None)
        == [{"id": 4, "owner": None, "verified_only": False}]
    )

    # Table names are looked up, never spliced into SQL.
    r = httpx.post(
        f"{STUDIO}/api/view-as", headers=admin(keys), json={"table": "e2e_studio; drop table x"}
    )
    assert r.status_code == 404


def edit(keys, action, **body):
    return httpx.post(
        f"{STUDIO}/api/tables/e2e_studio/rows?action={action}", headers=admin(keys), json=body
    )


def test_table_editor_round_trip(keys):
    r = edit(keys, "insert", values={"id": 100})
    assert r.status_code == 200, r.text
    # Defaults apply to the columns left out.
    assert r.json()["row"] == {"id": 100, "owner": None, "verified_only": False}

    r = edit(keys, "update", key={"id": 100}, values={"verified_only": True})
    assert r.json()["row"]["verified_only"] is True

    page = httpx.get(f"{STUDIO}/api/tables/e2e_studio/rows?limit=200", headers=admin(keys)).json()
    assert page["key"] == ["id"]
    assert {"id": 100, "owner": None, "verified_only": True} in page["rows"]

    assert edit(keys, "insert", values={"id": 100}).json()["code"] == "database_error"
    assert edit(keys, "delete", key={"id": 100}).status_code == 200
    assert edit(keys, "delete", key={"id": 100}).status_code == 404


@pytest.mark.parametrize(
    ("action", "body"),
    [
        ("insert", {"values": {"id": 101, "nope": 1}}),
        ("insert", {"values": {'id" = 1; drop table x; --': 1}}),
        ("update", {"key": {"owner": None}, "values": {"id": 1}}),
        ("delete", {"key": {}}),
        ("truncate", {}),
    ],
)
def test_table_editor_rejects_unknown_columns_and_keys(keys, action, body):
    r = edit(keys, action, **body)
    assert r.status_code == 400 and r.json()["code"] == "invalid_request", r.text


def test_table_editor_needs_the_key_and_a_real_table(keys):
    assert httpx.get(f"{STUDIO}/api/tables/e2e_studio/rows").status_code == 401
    r = httpx.get(f"{STUDIO}/api/tables/e2e_studio; drop table x/rows", headers=admin(keys))
    assert r.status_code == 404


def sql(keys, query, rollback=False):
    r = httpx.post(
        f"{STUDIO}/api/sql", headers=admin(keys), json={"query": query, "rollback": rollback}
    )
    return r.status_code, r.json()


def test_sql_editor_returns_rows_and_runs_scripts(keys):
    status, body = sql(keys, "select 1 as a, 'x' as b, now() as c, '{1,2}'::int[] as d")
    assert status == 200, body
    assert body["columns"] == ["a", "b", "c", "d"] and body["rows"][0][:2] == [1, "x"]

    status, body = sql(keys, "select g from generate_series(1, 1000) g")
    assert len(body["rows"]) == 500 and body["truncated"]

    status, body = sql(keys, "create table public.e2e_sql (id int); drop table public.e2e_sql;")
    assert status == 200 and body["columns"] == [] and body["committed"], body


def test_sql_editor_can_roll_back_and_reports_errors(keys):
    status, body = sql(keys, "insert into public.e2e_studio (id) values (200)", rollback=True)
    assert status == 200 and not body["committed"], body
    _, body = sql(keys, "select count(*) from public.e2e_studio where id = 200")
    assert body["rows"] == [[0]]

    status, body = sql(keys, "select * from no_such_table")
    assert status == 400 and "no_such_table" in body["message"]
    assert httpx.post(f"{STUDIO}/api/sql", json={"query": "select 1"}).status_code == 401


def test_users_can_be_created_confirmed_signed_out_and_deleted(client, keys):
    email = f"studio-{uuid.uuid4().hex[:10]}@example.com"
    r = httpx.post(
        f"{STUDIO}/api/users",
        headers=admin(keys),
        json={"email": email, "password": PASSWORD, "email_confirmed": False},
    )
    assert r.status_code == 200, r.text
    user_id = r.json()["id"]
    dup = httpx.post(f"{STUDIO}/api/users", headers=admin(keys), json={"email": email.upper()})
    assert dup.json()["code"] == "email_taken"

    body = {"email": email, "password": PASSWORD}
    session = client.post(
        "/auth/v1/token?grant_type=password", headers={"apikey": keys.anon}, json=body
    )
    assert session.status_code == 200, session.text

    def act(action):
        return httpx.post(f"{STUDIO}/api/users/{user_id}/{action}", headers=admin(keys))

    assert act("confirm-email").status_code == 200
    assert act("sign-out").status_code == 200
    refresh = client.post(
        "/auth/v1/token?grant_type=refresh_token",
        headers={"apikey": keys.anon},
        json={"refresh_token": session.json()["refresh_token"]},
    )
    assert refresh.status_code in (400, 401), refresh.text
    assert act("delete").status_code == 200
    assert act("delete").status_code == 404
    assert act("promote").status_code == 400


def test_storage_browser(keys):
    bucket = f"studio-{uuid.uuid4().hex[:8]}"
    h = admin(keys)
    assert httpx.post(f"{STUDIO}/api/buckets", headers=h, json={"id": bucket}).status_code == 200
    assert any(b["id"] == bucket for b in httpx.get(f"{STUDIO}/api/buckets", headers=h).json())

    url = f"{STUDIO}/api/buckets/{bucket}/object"
    for name in ("docs/a b.txt", "docs/sub/c.txt", "top.txt"):
        r = httpx.post(
            url, params={"name": name}, headers=h | {"Content-Type": "text/plain"}, content=b"hi"
        )
        assert r.status_code < 300, r.text

    listing = httpx.get(f"{STUDIO}/api/buckets/{bucket}/objects", headers=h).json()
    assert [(o["name"], o["folder"]) for o in listing] == [("docs/", True), ("top.txt", False)]
    listing = httpx.get(
        f"{STUDIO}/api/buckets/{bucket}/objects", params={"prefix": "docs/"}, headers=h
    ).json()
    assert [o["name"] for o in listing] == ["sub/", "a b.txt"]

    r = httpx.get(url, params={"name": "docs/a b.txt"}, headers=h)
    assert r.content == b"hi" and r.headers["content-type"] == "application/octet-stream"
    assert httpx.post(f"{url}/delete", params={"name": "docs/a b.txt"}, headers=h).status_code < 300
    assert httpx.get(url, params={"name": "docs/a b.txt"}, headers=h).status_code == 404
    assert httpx.get(f"{STUDIO}/api/buckets").status_code == 401


def test_webhooks_are_managed_without_leaking_secrets(keys):
    h = admin(keys)
    name = f"studio-{uuid.uuid4().hex[:8]}"
    body = {
        "name": name,
        "table": "public.e2e_studio",
        "events": ["INSERT"],
        "url": "https://hooks.example.com/T000/secret-path",
    }
    r = httpx.post(f"{STUDIO}/api/webhooks", headers=h, json=body)
    assert r.status_code == 200 and len(r.json()["secret"]) == 64, r.text

    hook = next(
        w for w in httpx.get(f"{STUDIO}/api/webhooks", headers=h).json() if w["name"] == name
    )
    assert (
        hook["host"] == "https://hooks.example.com" and "secret" not in hook and "url" not in hook
    )

    def act(action):
        return httpx.post(f"{STUDIO}/api/webhooks/{name}/{action}", headers=h)

    assert act("disable").status_code == 200
    assert act("enable").status_code == 200
    assert act("delete").status_code == 200
    assert act("delete").status_code == 404
    bad = body | {"table": "public.no_such_table"}
    assert (
        httpx.post(f"{STUDIO}/api/webhooks", headers=h, json=bad).json()["code"] == "database_error"
    )
    assert httpx.post(f"{STUDIO}/api/webhook-deliveries/0/retry", headers=h).status_code == 404


def test_database_overview_and_extensions(keys):
    h = admin(keys)
    info = httpx.get(f"{STUDIO}/api/database", headers=h).json()
    assert info["version"].startswith("18") and info["bytes"] > 0
    names = {e["name"]: e for e in info["extensions"]}
    assert "vector" in names and "plpgsql" in names

    def act(name, action):
        return httpx.post(f"{STUDIO}/api/extensions/{name}/{action}", headers=h)

    was_installed = names["citext"]["installed_version"] is not None
    assert act("citext", "enable").status_code == 200
    ext = {
        e["name"]: e for e in httpx.get(f"{STUDIO}/api/database", headers=h).json()["extensions"]
    }
    assert ext["citext"]["schema"] == "extensions"
    if not was_installed:
        assert act("citext", "disable").status_code == 200
    assert act("no_such_ext", "enable").status_code == 404
    assert act("citext", "upgrade").status_code == 400


def test_cron_jobs(keys):
    h = admin(keys)
    was_enabled = httpx.get(f"{STUDIO}/api/cron", headers=h).json()["enabled"]
    if not was_enabled:
        no_cron = {"name": "x", "schedule": "* * * * *", "command": "select 1"}
        assert httpx.post(f"{STUDIO}/api/cron", headers=h, json=no_cron).status_code == 409
        assert httpx.post(f"{STUDIO}/api/extensions/pg_cron/enable", headers=h).status_code == 200
    name = f"e2e-{uuid.uuid4().hex[:8]}"
    try:
        job = {"name": name, "schedule": "0 3 * * *", "command": "select 1"}
        assert httpx.post(f"{STUDIO}/api/cron", headers=h, json=job).status_code == 200
        # cron.schedule would silently replace it.
        assert httpx.post(f"{STUDIO}/api/cron", headers=h, json=job).status_code == 409
        bad = job | {"name": f"{name}-bad", "schedule": "every tuesday"}
        r = httpx.post(f"{STUDIO}/api/cron", headers=h, json=bad)
        assert r.status_code == 400 and r.json()["code"] == "database_error"

        def listed():
            jobs = httpx.get(f"{STUDIO}/api/cron", headers=h).json()["jobs"]
            return next(j for j in jobs if j["name"] == name)

        assert listed()["active"] and listed()["schedule"] == "0 3 * * *"
        assert httpx.post(f"{STUDIO}/api/cron/{name}/disable", headers=h).status_code == 200
        assert not listed()["active"]
        assert httpx.post(f"{STUDIO}/api/cron/{name}/run", headers=h).status_code == 400
        assert httpx.post(f"{STUDIO}/api/cron/{name}/delete", headers=h).status_code == 200
        assert httpx.post(f"{STUDIO}/api/cron/{name}/delete", headers=h).status_code == 404
    finally:
        httpx.post(f"{STUDIO}/api/cron/{name}/delete", headers=h)
        if not was_enabled:
            httpx.post(f"{STUDIO}/api/extensions/pg_cron/disable", headers=h)


def test_queues(keys):
    h = admin(keys)
    was_enabled = httpx.get(f"{STUDIO}/api/queues", headers=h).json()["enabled"]
    if not was_enabled:
        assert httpx.post(f"{STUDIO}/api/queues", headers=h, json={"name": "x"}).status_code == 409
        assert httpx.post(f"{STUDIO}/api/extensions/pgmq/enable", headers=h).status_code == 200
    name = f"e2e_{uuid.uuid4().hex[:8]}"
    q = f"{STUDIO}/api/queues/{name}"
    try:
        assert httpx.post(f"{STUDIO}/api/queues", headers=h, json={"name": name}).status_code == 200
        assert httpx.post(f"{STUDIO}/api/queues", headers=h, json={"name": name}).status_code == 409
        bad = httpx.post(f"{STUDIO}/api/queues", headers=h, json={"name": "Bad-Name"})
        assert bad.status_code == 422

        r = httpx.post(f"{q}/messages", headers=h, json={"n": 1})
        assert r.status_code == 200 and isinstance(r.json()["msg_id"], int)
        # A peek, so the message stays readable and unread.
        for _ in range(2):
            messages = httpx.get(f"{q}/messages", headers=h).json()
            assert [(m["read_ct"], json.loads(m["message"])) for m in messages] == [(0, {"n": 1})]
        listed = next(
            x
            for x in httpx.get(f"{STUDIO}/api/queues", headers=h).json()["queues"]
            if x["name"] == name
        )
        assert listed["queue_length"] == 1

        assert httpx.post(f"{q}/purge", headers=h).status_code == 200
        assert httpx.get(f"{q}/messages", headers=h).json() == []
        assert httpx.post(f"{q}/rename", headers=h).status_code == 400
        assert httpx.post(f"{q}/delete", headers=h).status_code == 200
        assert httpx.get(f"{q}/messages", headers=h).status_code == 404
    finally:
        httpx.post(f"{q}/delete", headers=h)
        if not was_enabled:
            httpx.post(f"{STUDIO}/api/extensions/pgmq/disable", headers=h)


def test_connect_page_shows_only_public_values(keys):
    info = httpx.get(f"{STUDIO}/api/connect", headers=admin(keys)).json()
    assert info == {"url": "http://localhost:8000", "anon_key": keys.anon}


def test_logs_show_requests_from_core(client, keys):
    marker = f"/rest/v1/logs-probe-{uuid.uuid4().hex[:8]}"
    client.get(marker, headers={"apikey": keys.anon})
    for _ in range(50):
        r = httpx.get(
            f"{STUDIO}/api/logs", params={"service": "core", "q": marker}, headers=admin(keys)
        )
        if r.json()["entries"]:
            break
        time.sleep(0.2)
    entry = r.json()["entries"][0]
    assert entry["service"] == "core" and entry["path"] == marker and "core" in r.json()["services"]

    errors = httpx.get(f"{STUDIO}/api/logs", params={"level": "error"}, headers=admin(keys)).json()
    assert all(e["level"] in ("error", "critical") for e in errors["entries"])
    bad = httpx.get(f"{STUDIO}/api/logs", params={"service": "../etc/passwd"}, headers=admin(keys))
    assert bad.status_code == 400


def test_overview_counts(keys):
    info = httpx.get(f"{STUDIO}/api/overview", headers=admin(keys)).json()
    assert info["tables"] >= 1 and info["users"] >= 1 and info["version"].startswith("18")
    assert isinstance(info["recent_errors"], list) and info["errors_24h"] >= len(
        info["recent_errors"]
    )
    assert httpx.get(f"{STUDIO}/api/overview").status_code == 401
