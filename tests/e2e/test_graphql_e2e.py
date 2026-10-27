"""GraphQL through the gateway: the same callers and row level security as /rest/v1."""

import time

import pytest
from conftest import psql
from kilnbase_cli.backup import docker

SCHEMA = """
drop table if exists public.gql_notes, public.gql_open;

create table public.gql_notes (
    id bigint generated always as identity primary key,
    owner uuid not null default auth.uid(),
    title text not null
);
alter table public.gql_notes enable row level security;
create policy own_rows on public.gql_notes for all to authenticated
    using (owner = auth.uid()) with check (owner = auth.uid());

create table public.gql_open (id int primary key);
"""

FIELDS = "{ __schema { queryType { fields { name } } } }"


def gql(client, keys, query, token=None):
    headers = {"apikey": keys.anon} | ({"Authorization": f"Bearer {token}"} if token else {})
    return client.post("/graphql/v1", headers=headers, json={"query": query})


@pytest.fixture(scope="module", autouse=True)
def schema(client, keys):
    if gql(client, keys, "{ __typename }").status_code == 404:
        pytest.skip("start the stack with docker-compose.test.yml (graphql profile)")
    psql(SCHEMA)
    # The schema is built at startup, so new tables need a restart (as after `kilnbase migrate`).
    docker("restart", "kilnbase-graphql-1")
    for _ in range(100):
        r = gql(client, keys, FIELDS)
        if r.status_code == 200 and "allGqlNotes" in r.text:
            return
        time.sleep(0.2)
    raise AssertionError("gql_notes never appeared in the GraphQL schema")


def test_callers_are_verified(client, keys):
    assert client.post("/graphql/v1", json={"query": "{ __typename }"}).status_code == 401
    assert gql(client, keys, "{ __typename }", token="forged").status_code == 401


def test_tables_without_rls_are_not_served(client, keys):
    fields = gql(client, keys, FIELDS).json()["data"]["__schema"]["queryType"]["fields"]
    names = [f["name"] for f in fields]
    assert "allGqlNotes" in names
    assert not any("GqlOpen" in n for n in names)


def test_row_level_security_applies(client, keys):
    _, alice = keys.user()
    _, bob = keys.user()
    create = 'mutation { createGqlNote(input: {gqlNote: {title: "secret"}}) { gqlNote { title } } }'
    r = gql(client, keys, create, alice)
    assert r.json()["data"]["createGqlNote"]["gqlNote"]["title"] == "secret", r.text

    def titles(token=None):
        r = gql(client, keys, "{ allGqlNotes { nodes { title } } }", token)
        return [n["title"] for n in r.json()["data"]["allGqlNotes"]["nodes"]]

    assert titles(alice) == ["secret"]
    assert titles(bob) == []
    assert titles() == []

    r = gql(client, keys, create)  # anon has no insert policy
    assert r.json().get("errors"), r.text
