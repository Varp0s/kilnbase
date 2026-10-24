import pytest
from conftest import psql, wait_for_schema
from cryptography.hazmat.primitives.asymmetric import ec

SCHEMA = """
drop view if exists public.e2e_leaky_view, public.e2e_safe_view;
drop table if exists public.e2e_todos, public.e2e_open;

create table public.e2e_todos (
    id bigint generated always as identity primary key,
    owner uuid not null default auth.uid(),
    title text not null
);
alter table public.e2e_todos enable row level security;
create policy own_rows on public.e2e_todos for all to authenticated
    using (owner = auth.uid()) with check (owner = auth.uid());

create table public.e2e_open (id int primary key);
insert into public.e2e_open values (1);

create view public.e2e_leaky_view as select * from public.e2e_todos;
create view public.e2e_safe_view with (security_invoker = true) as select * from public.e2e_todos;

notify pgrst, 'reload schema';
"""


@pytest.fixture(scope="module", autouse=True)
def schema(client, keys):
    psql(SCHEMA)
    wait_for_schema(client, keys, "e2e_todos")


def h(keys, bearer=None):
    headers = {"apikey": keys.anon}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return headers


def insert(client, headers, title):
    r = client.post(
        "/rest/v1/e2e_todos",
        headers=headers | {"Prefer": "return=representation"},
        json={"title": title},
    )
    assert r.status_code == 201, r.text
    return r.json()[0]


def test_requires_api_key(client):
    assert client.get("/rest/v1/e2e_todos").status_code == 401


def test_anon_sees_nothing_without_policy(client, keys):
    insert(client, h(keys, keys.user()[1]), "private")
    r = client.get("/rest/v1/e2e_todos", headers=h(keys))
    assert r.status_code == 200
    assert r.json() == []


def test_users_are_isolated(client, keys):
    a_id, a = keys.user()
    _, b = keys.user()
    row = insert(client, h(keys, a), "a's secret")
    assert row["owner"] == a_id

    assert client.get("/rest/v1/e2e_todos", headers=h(keys, b)).json() == []

    target = f"/rest/v1/e2e_todos?id=eq.{row['id']}"
    client.patch(target, headers=h(keys, b), json={"title": "hacked"})
    client.delete(target, headers=h(keys, b))
    mine = client.get(target, headers=h(keys, a)).json()
    assert mine == [row]


def test_user_cannot_insert_rows_for_someone_else(client, keys):
    _, a = keys.user()
    other = "00000000-0000-0000-0000-000000000001"
    r = client.post("/rest/v1/e2e_todos", headers=h(keys, a), json={"title": "x", "owner": other})
    assert r.status_code in (401, 403)


def test_service_role_sees_everything(client, keys):
    _, a = keys.user()
    row = insert(client, h(keys, a), "visible to service")
    r = client.get(f"/rest/v1/e2e_todos?id=eq.{row['id']}", headers={"apikey": keys.service_role})
    assert r.json() == [row]


@pytest.mark.parametrize("relation", ["e2e_open", "e2e_leaky_view"])
def test_unprotected_relations_are_not_exposed(client, keys, relation):
    _, a = keys.user()
    for headers in (h(keys), h(keys, a)):
        r = client.get(f"/rest/v1/{relation}", headers=headers)
        assert r.status_code in (401, 403, 404), (relation, r.status_code, r.text)


def test_security_invoker_view_applies_rls(client, keys):
    _, a = keys.user()
    _, b = keys.user()
    insert(client, h(keys, a), "through view")
    r = client.get("/rest/v1/e2e_safe_view", headers=h(keys, b))
    assert r.status_code == 200
    assert r.json() == []


def test_internal_schemas_are_not_reachable(client, keys):
    for schema in ("auth", "kilnbase"):
        r = client.get(
            "/rest/v1/schema_migrations",
            headers={"apikey": keys.service_role, "Accept-Profile": schema},
        )
        assert r.status_code >= 400, schema


def test_rejects_forged_expired_and_privileged_tokens(client, keys):
    other_key = ec.generate_private_key(ec.SECP256R1())
    bad = [
        keys.sign({"role": "authenticated", "sub": "x"}, key=other_key),
        keys.sign({"role": "authenticated", "exp": 1}),
        keys.sign({"role": "postgres"}),
        keys.sign({"role": "authenticated"}, kid="unknown"),
    ]
    for token in bad:
        assert client.get("/rest/v1/e2e_todos", headers=h(keys, token)).status_code == 401
    # A user token cannot stand in for the API key.
    _, a = keys.user()
    assert client.get("/rest/v1/e2e_todos", headers={"apikey": a}).status_code == 401
