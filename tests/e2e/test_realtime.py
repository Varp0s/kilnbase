import json
import time
from contextlib import contextmanager
from urllib.parse import urlencode

import pytest
from conftest import BASE_URL, psql, wait_for_schema
from websockets.exceptions import InvalidStatus
from websockets.sync.client import connect

WS_URL = BASE_URL.replace("http", "ws", 1) + "/realtime/v1/websocket"

SCHEMA = """
drop table if exists public.e2e_rt, public.e2e_rt_plain, public.e2e_rt_open;
create table public.e2e_rt (
    id bigint generated always as identity primary key,
    owner uuid not null default auth.uid(),
    body text not null
);
alter table public.e2e_rt enable row level security;
create policy own_rt on public.e2e_rt for all to authenticated
    using (owner = auth.uid()) with check (owner = auth.uid());
select kilnbase.enable_realtime('public.e2e_rt');

create table public.e2e_rt_plain (id int primary key);
alter table public.e2e_rt_plain enable row level security;

create table public.e2e_rt_open (id int primary key);
select kilnbase.enable_realtime('public.e2e_rt_open');

notify pgrst, 'reload schema';
"""


@pytest.fixture(scope="module", autouse=True)
def schema(client, keys):
    psql(SCHEMA)
    wait_for_schema(client, keys, "e2e_rt")


@contextmanager
def socket(keys, token=None):
    params = {"apikey": keys.anon} | ({"access_token": token} if token else {})
    with connect(f"{WS_URL}?{urlencode(params)}", open_timeout=5) as ws:
        yield ws


def request(ws, message: dict) -> dict:
    ws.send(json.dumps(message))
    return json.loads(ws.recv(timeout=5))


def subscribe(ws, table="e2e_rt", sub_id="s1") -> dict:
    return request(ws, {"type": "subscribe", "id": sub_id, "table": table})


def next_event(ws, timeout=5.0) -> dict:
    return json.loads(ws.recv(timeout=timeout))


def assert_silent(ws, timeout=1.5):
    with pytest.raises(TimeoutError):
        ws.recv(timeout=timeout)


def rest(client, keys, token, method, path, **kwargs):
    headers = {"apikey": keys.anon, "Authorization": f"Bearer {token}"}
    headers |= {"Prefer": "return=representation"}
    return client.request(method, f"/rest/v1/{path}", headers=headers, **kwargs)


def test_connection_requires_api_key(keys):
    with pytest.raises(InvalidStatus) as exc:
        with connect(WS_URL, open_timeout=5):
            pass
    assert exc.value.response.status_code == 401
    _, user = keys.user()
    with pytest.raises(InvalidStatus):
        with connect(f"{WS_URL}?{urlencode({'apikey': user})}", open_timeout=5):
            pass


def test_changes_are_filtered_by_rls(client, keys):
    a_id, a = keys.user()
    _, b = keys.user()
    with socket(keys, a) as wa, socket(keys, b) as wb:
        assert subscribe(wa)["type"] == "subscribed"
        assert subscribe(wb)["type"] == "subscribed"

        row = rest(client, keys, a, "POST", "e2e_rt", json={"body": "for a only"}).json()[0]
        event = next_event(wa)
        assert event["op"] == "INSERT"
        assert event["id"] == "s1"
        assert event["record"]["body"] == "for a only"
        assert event["record"]["owner"] == a_id
        assert_silent(wb)

        rest(client, keys, a, "PATCH", f"e2e_rt?id=eq.{row['id']}", json={"body": "edited"})
        event = next_event(wa)
        assert event["op"] == "UPDATE"
        assert event["record"]["body"] == "edited"
        assert_silent(wb)

        rest(client, keys, a, "DELETE", f"e2e_rt?id=eq.{row['id']}")
        event = next_event(wa)
        assert event["op"] == "DELETE"
        assert event["old_pk"] == {"id": row["id"]}


def test_anon_without_policy_gets_nothing(client, keys):
    _, a = keys.user()
    with socket(keys) as anon:
        assert subscribe(anon)["type"] == "subscribed"
        rest(client, keys, a, "POST", "e2e_rt", json={"body": "hidden"})
        assert_silent(anon)


def test_large_rows_are_delivered(client, keys):
    _, a = keys.user()
    big = "x" * 20_000
    with socket(keys, a) as ws:
        subscribe(ws)
        rest(client, keys, a, "POST", "e2e_rt", json={"body": big})
        assert next_event(ws)["record"]["body"] == big


def test_subscription_checks(keys):
    _, a = keys.user()
    with socket(keys, a) as ws:
        assert subscribe(ws, "e2e_rt_open")["code"] == "forbidden"
        assert subscribe(ws, "does_not_exist")["code"] == "forbidden"
        assert subscribe(ws, 'e2e_rt"; drop table x; --')["code"] == "forbidden"
        assert subscribe(ws, "e2e_rt_plain")["code"] == "realtime_not_enabled"
        assert request(ws, {"type": "nonsense"})["code"] == "invalid_message"


def test_unsubscribe_stops_events(client, keys):
    _, a = keys.user()
    with socket(keys, a) as ws:
        subscribe(ws)
        assert request(ws, {"type": "unsubscribe", "id": "s1"})["type"] == "unsubscribed"
        rest(client, keys, a, "POST", "e2e_rt", json={"body": "after unsubscribe"})
        assert_silent(ws)


def test_expired_token_is_disconnected(client, keys):
    _, writer = keys.user()
    sub = keys.user()[0]
    short = keys.sign({"sub": sub, "role": "authenticated", "exp": int(time.time()) + 2})
    with socket(keys, short) as ws:
        subscribe(ws)
        time.sleep(3)  # open connections check exp strictly, without the handshake leeway
        rest(client, keys, writer, "POST", "e2e_rt", json={"body": "ping"})
        assert next_event(ws)["code"] == "token_expired"


def test_events_survive_a_listener_reconnect(client, keys):
    _, a = keys.user()
    with socket(keys, a) as ws:
        subscribe(ws)
        # Cut the server's LISTEN connection; it reconnects after ~2 s and must replay the gap.
        psql(
            "select pg_terminate_backend(pid) from pg_stat_activity"
            " where query ilike 'listen kilnbase_realtime%'"
        )
        rest(client, keys, a, "POST", "e2e_rt", json={"body": "during outage"})
        event = next_event(ws, timeout=10)
        assert event["record"]["body"] == "during outage"
        assert isinstance(event["event_id"], int)


def test_clients_resume_from_their_last_event(client, keys):
    _, a = keys.user()
    _, b = keys.user()
    with socket(keys, a) as ws:
        subscribe(ws)
        rest(client, keys, a, "POST", "e2e_rt", json={"body": "seen"})
        last = next_event(ws)["event_id"]

    # Offline: two own rows and one row RLS hides from us.
    rest(client, keys, a, "POST", "e2e_rt", json={"body": "missed 1"})
    rest(client, keys, b, "POST", "e2e_rt", json={"body": "not mine"})
    rest(client, keys, a, "POST", "e2e_rt", json={"body": "missed 2"})

    with socket(keys, a) as ws:
        ws.send(json.dumps({"type": "subscribe", "id": "s1", "table": "e2e_rt", "since": last}))
        assert json.loads(ws.recv(timeout=5))["type"] == "subscribed"
        bodies = [next_event(ws)["record"]["body"] for _ in range(2)]
        assert bodies == ["missed 1", "missed 2"]
        assert_silent(ws)


def test_resume_too_far_back_asks_for_a_refetch(keys):
    _, a = keys.user()
    with socket(keys, a) as ws:
        ws.send(json.dumps({"type": "subscribe", "id": "s1", "table": "e2e_rt", "since": -100}))
        assert json.loads(ws.recv(timeout=5))["type"] == "subscribed"
        assert json.loads(ws.recv(timeout=5))["code"] == "resync_required"
