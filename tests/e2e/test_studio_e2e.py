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
