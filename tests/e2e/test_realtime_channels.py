import json
from contextlib import contextmanager
from urllib.parse import urlencode

import pytest
from conftest import BASE_URL, psql
from websockets.sync.client import connect

WS_URL = BASE_URL.replace("http", "ws", 1) + "/realtime/v1/websocket"

OPEN = """
create or replace function realtime.authorize(channel text, action text) returns boolean
    language sql stable
    as $$
    select (channel like 'e2e-room:%' and auth.role() = 'authenticated')
        or (channel like 'e2e-read:%' and action = 'join' and auth.role() = 'authenticated')
        or channel = 'e2e-user:' || auth.uid()::text
    $$;
"""
CLOSE = """
create or replace function realtime.authorize(channel text, action text) returns boolean
    language sql stable
    as $$ select false $$;
"""


@pytest.fixture(scope="module", autouse=True)
def policy():
    psql(OPEN)
    yield
    psql(CLOSE)


@contextmanager
def socket(api_key, token=None):
    params = {"apikey": api_key} | ({"access_token": token} if token else {})
    with connect(f"{WS_URL}?{urlencode(params)}", open_timeout=5) as ws:
        yield ws


def send(ws, **message):
    ws.send(json.dumps(message))


def recv(ws, timeout=5.0):
    return json.loads(ws.recv(timeout=timeout))


def recv_type(ws, kind, timeout=5.0):
    """Next message of a given type, skipping unrelated ones."""
    while True:
        message = recv(ws, timeout)
        if message["type"] in (kind, "error"):
            return message


def silent(ws, timeout=1.0):
    with pytest.raises(TimeoutError):
        ws.recv(timeout=timeout)


def join(ws, channel):
    send(ws, type="join", id="j", channel=channel)
    reply = recv(ws)
    if reply["type"] == "joined":
        assert recv(ws)["type"] == "presence_state"
    return reply


def test_broadcast_reaches_other_members_only(keys):
    _, a = keys.user()
    _, b = keys.user()
    with socket(keys.anon, a) as wa, socket(keys.anon, b) as wb:
        assert join(wa, "e2e-room:1")["type"] == "joined"
        assert join(wb, "e2e-room:1")["type"] == "joined"
        send(wa, type="broadcast", channel="e2e-room:1", event="cursor", payload={"x": 1})
        got = recv(wb)
        assert got == {
            "type": "broadcast",
            "channel": "e2e-room:1",
            "event": "cursor",
            "payload": {"x": 1},
        }
        silent(wa)
        send(wa, type="broadcast", channel="e2e-room:1", event="echo", payload={}, self=True)
        assert recv(wa)["event"] == "echo"


def test_channels_are_closed_unless_authorized(keys):
    _, a = keys.user()
    with socket(keys.anon) as anon:
        assert join(anon, "e2e-room:1")["code"] == "forbidden"
    with socket(keys.anon, a) as wa:
        assert join(wa, "elsewhere")["code"] == "forbidden"
        assert join(wa, "e2e-read:news")["type"] == "joined"
        send(wa, type="broadcast", channel="e2e-read:news", event="x", payload={})
        assert recv(wa)["code"] == "forbidden"
        send(wa, type="broadcast", channel="e2e-room:9", event="x", payload={})
        assert recv(wa)["code"] == "not_joined"


def test_per_user_channels(keys):
    a_id, a = keys.user()
    _, b = keys.user()
    with socket(keys.anon, a) as wa, socket(keys.anon, b) as wb:
        assert join(wa, f"e2e-user:{a_id}")["type"] == "joined"
        assert join(wb, f"e2e-user:{a_id}")["code"] == "forbidden"


def test_service_role_can_broadcast_anywhere(keys):
    _, a = keys.user()
    with socket(keys.anon, a) as wa, socket(keys.service_role) as server:
        join(wa, "e2e-room:svc")
        assert join(server, "e2e-room:svc")["type"] == "joined"
        send(server, type="broadcast", channel="e2e-room:svc", event="notice", payload={"ok": True})
        assert recv(wa)["event"] == "notice"


def test_presence_join_sync_and_leave(keys):
    a_id, a = keys.user()
    b_id, b = keys.user()
    with socket(keys.anon, a) as wa:
        join(wa, "e2e-room:presence")
        send(wa, type="presence", channel="e2e-room:presence", state={"name": "ada"})
        assert recv_type(wa, "presence_diff")["joins"]  # own diff

        with socket(keys.anon, b) as wb:
            send(wb, type="join", id="j", channel="e2e-room:presence")
            assert recv(wb)["type"] == "joined"
            state = recv(wb)
            assert state["type"] == "presence_state"
            assert [e["user"] for e in state["state"].values()] == [a_id]
            assert list(state["state"].values())[0]["state"] == {"name": "ada"}

            send(wb, type="presence", channel="e2e-room:presence", state={"name": "bob"})
            diff = recv_type(wa, "presence_diff")
            assert [e["user"] for e in diff["joins"].values()] == [b_id]

        # B's socket closed: A is told B left.
        diff = recv_type(wa, "presence_diff")
        assert [e["user"] for e in diff["leaves"].values()] == [b_id]


def test_presence_state_is_size_limited(keys):
    _, a = keys.user()
    with socket(keys.anon, a) as wa:
        join(wa, "e2e-room:big")
        send(wa, type="presence", channel="e2e-room:big", state={"blob": "x" * 5000})
        assert recv(wa)["code"] == "too_large"


def test_senders_are_rate_limited(keys):
    _, a = keys.user()
    with socket(keys.anon, a) as wa:
        join(wa, "e2e-room:flood")
        for i in range(60):
            send(wa, type="broadcast", channel="e2e-room:flood", event="spam", payload={"i": i})
        assert recv(wa)["code"] == "rate_limited"
