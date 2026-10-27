import json
import queue
import threading
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
import pytest
from kilnbase import create_client
from test_client import KEY, session
from websockets.sync.server import serve


@pytest.fixture
def server():
    """A fake realtime endpoint: yields (url, connections of (params, inbox, ws))."""
    connections: queue.Queue = queue.Queue()

    def handler(ws):
        inbox: queue.Queue = queue.Queue()
        connections.put((parse_qs(urlsplit(ws.request.path).query), inbox, ws))
        for raw in ws:
            inbox.put(json.loads(raw))

    with serve(handler, "127.0.0.1", 0) as srv:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        yield f"http://127.0.0.1:{srv.socket.getsockname()[1]}", connections
        srv.shutdown()


def client_for(url):
    def handler(req):
        return httpx.Response(200, json=session("at2", "rt2"))

    return create_client(url, KEY, transport=httpx.MockTransport(handler))


def wait_until(predicate, timeout=5.0):
    done = threading.Event()
    for _ in range(int(timeout / 0.02)):
        if predicate():
            return
        done.wait(0.02)
    raise AssertionError("condition not met")


def test_subscribe_dedupes_and_resumes_after_reconnect(server):
    url, connections = server
    c = client_for(url)
    events, errors = [], []
    cancel = c.realtime.subscribe("todos", events.append, errors.append)

    params, inbox, ws = connections.get(timeout=5)
    assert params == {"apikey": [KEY]}
    assert inbox.get(timeout=5) == {"type": "subscribe", "id": "s1", "table": "todos"}
    change = {"type": "change", "id": "s1", "event_id": 7, "op": "INSERT", "record": {"id": 1}}
    ws.send(json.dumps(change))
    ws.send(json.dumps(change))  # a resume can repeat an event
    ws.send(json.dumps({"type": "error", "id": "s1", "code": "lagged", "message": "slow"}))
    wait_until(lambda: errors)
    assert [e["event_id"] for e in events] == [7]
    assert errors == [{"code": "lagged", "message": "slow"}]

    ws.close()
    _, inbox, ws = connections.get(timeout=5)
    assert inbox.get(timeout=5) == {"type": "subscribe", "id": "s1", "table": "todos", "since": 7}

    cancel()
    assert inbox.get(timeout=5) == {"type": "unsubscribe", "id": "s1"}
    wait_until(lambda: c.realtime._thread is None)
    c.close()


def test_session_change_reconnects_with_the_new_token(server):
    url, connections = server
    c = client_for(url)
    c.realtime.subscribe("todos", lambda e: None)
    params, inbox, _ = connections.get(timeout=5)
    assert "access_token" not in params
    inbox.get(timeout=5)

    c.auth.sign_in_with_password("a@b.c", "pw")
    params, inbox, _ = connections.get(timeout=5)
    assert params["access_token"] == ["at2"]
    assert inbox.get(timeout=5)["type"] == "subscribe"

    c.auth.session = None  # what sign_out does locally
    params, _, _ = connections.get(timeout=5)
    assert "access_token" not in params
    c.close()


TRACKED = {"type": "presence", "channel": "room:1", "state": {"name": "Ada"}}


def test_channel_presence_and_broadcast(server):
    url, connections = server
    c = client_for(url)
    got, states = [], []
    room = c.realtime.channel(
        "room:1", on_broadcast=lambda ev, p: got.append((ev, p)), on_presence=states.append
    )
    _, inbox, ws = connections.get(timeout=5)
    assert inbox.get(timeout=5) == {"type": "join", "id": "ch:room:1", "channel": "room:1"}

    room.track({"name": "Ada"})
    assert inbox.get(timeout=5) == TRACKED
    room.send("cursor", {"x": 1}, self_=True)
    assert inbox.get(timeout=5)["self"] is True

    ws.send(json.dumps({"type": "broadcast", "channel": "room:1", "event": "e", "payload": 2}))
    a, b = {"user": "u1", "state": 1}, {"user": "u2", "state": 2}
    ws.send(json.dumps({"type": "presence_state", "channel": "room:1", "state": {"k1": a}}))
    diff = {"type": "presence_diff", "channel": "room:1", "joins": {"k2": b}, "leaves": {"k1": a}}
    ws.send(json.dumps(diff))
    wait_until(lambda: len(states) == 2)
    assert got == [("e", 2)]
    assert states == [{"k1": a}, {"k2": b}]

    # After a reconnect the channel is re-joined and the tracked state re-published.
    ws.close()
    _, inbox, ws = connections.get(timeout=5)
    assert inbox.get(timeout=5)["type"] == "join"
    ws.send(json.dumps({"type": "joined", "id": "ch:room:1", "channel": "room:1"}))
    assert inbox.get(timeout=5) == TRACKED

    room.leave()
    assert inbox.get(timeout=5) == {"type": "leave", "channel": "room:1"}
    wait_until(lambda: c.realtime._thread is None)
    c.close()
