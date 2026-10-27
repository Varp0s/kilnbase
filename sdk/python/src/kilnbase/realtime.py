import json
import logging
import threading
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

from websockets.sync.client import ClientConnection, connect

from .auth import AuthClient

log = logging.getLogger("kilnbase")

MAX_BACKOFF = 30.0
RECENT_IDS = 1000

ChangeHandler = Callable[[dict[str, Any]], None]
ErrorHandler = Callable[[dict[str, str]], None]


def _join_id(name: str) -> str:
    return f"ch:{name}"


class _Subscription:
    def __init__(self, table: str, on_change: ChangeHandler, on_error: ErrorHandler | None):
        self.table = table
        self.on_change = on_change
        self.on_error = on_error
        # Newest event received, sent as `since` on resubscribe so missed changes are replayed.
        self.last: int | None = None
        # Recently delivered ids, oldest first: a resume can repeat events that also arrive live.
        self.recent: dict[int, None] = {}


class Channel:
    """A broadcast/presence channel; access is decided by `realtime.authorize()` on the server."""

    def __init__(
        self,
        rt: RealtimeClient,
        name: str,
        on_broadcast: Callable[[str, Any], None] | None,
        on_presence: Callable[[dict[str, Any]], None] | None,
        on_error: ErrorHandler | None,
    ):
        self._rt = rt
        self.name = name
        self.on_broadcast = on_broadcast
        self.on_presence = on_presence
        self.on_error = on_error
        self.tracked: Any = None
        self.presence: dict[str, Any] = {}

    def send(self, event: str, payload: Any = None, *, self_: bool = False) -> None:
        """Sends to every other member (and to yourself with `self_=True`)."""
        self._rt._send(
            {
                "type": "broadcast",
                "channel": self.name,
                "event": event,
                "payload": {} if payload is None else payload,
                "self": self_,
            }
        )

    def track(self, state: Any) -> None:
        """Publishes (or replaces) your presence state; it is restored after reconnects."""
        self.tracked = state
        self._rt._send({"type": "presence", "channel": self.name, "state": state})

    def untrack(self) -> None:
        self.tracked = None
        self._rt._send({"type": "presence", "channel": self.name, "state": None})

    def leave(self) -> None:
        self._rt._leave(self)


class RealtimeClient:
    """
    One shared WebSocket per client, run by a background thread: callbacks are called on that
    thread. It opens on the first subscription or channel, re-subscribes and re-joins everything
    after reconnects, and reconnects with the new token whenever the session changes (sign-in,
    sign-out, refresh). Subscriptions resume where they left off; on a `resync_required` error,
    refetch over REST.
    """

    def __init__(self, url: str, api_key: str, auth: AuthClient):
        self._url = url
        self._api_key = api_key
        self._auth = auth
        self._lock = threading.Lock()
        self._subs: dict[str, _Subscription] = {}
        self._channels: dict[str, Channel] = {}
        self._counter = 0
        self._ws: ClientConnection | None = None
        self._thread: threading.Thread | None = None
        self._wake = threading.Event()
        auth._listeners.append(self._drop)

    def subscribe(
        self, table: str, on_change: ChangeHandler, on_error: ErrorHandler | None = None
    ) -> Callable[[], None]:
        """Row changes for a table enabled with `kilnbase.enable_realtime`; returns a canceller."""
        with self._lock:
            self._counter += 1
            sub_id = f"s{self._counter}"
            self._subs[sub_id] = _Subscription(table, on_change, on_error)
            self._send({"type": "subscribe", "id": sub_id, "table": table})
        self._start()

        def cancel() -> None:
            with self._lock:
                self._subs.pop(sub_id, None)
            self._send({"type": "unsubscribe", "id": sub_id})
            self._close_if_idle()

        return cancel

    def channel(
        self,
        name: str,
        *,
        on_broadcast: Callable[[str, Any], None] | None = None,
        on_presence: Callable[[dict[str, Any]], None] | None = None,
        on_error: ErrorHandler | None = None,
    ) -> Channel:
        """`on_presence` receives the full, current presence state whenever it changes."""
        ch = Channel(self, name, on_broadcast, on_presence, on_error)
        with self._lock:
            self._channels[name] = ch
            self._send({"type": "join", "id": _join_id(name), "channel": name})
        self._start()
        return ch

    def close(self) -> None:
        """Drops every subscription and channel and stops the background thread."""
        with self._lock:
            self._subs.clear()
            self._channels.clear()
        self._drop()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)

    def _leave(self, ch: Channel) -> None:
        with self._lock:
            if self._channels.get(ch.name) is ch:
                del self._channels[ch.name]
        self._send({"type": "leave", "channel": ch.name})
        self._close_if_idle()

    def _idle(self) -> bool:
        return not self._subs and not self._channels

    def _close_if_idle(self) -> None:
        if self._idle():
            self._drop()

    def _drop(self) -> None:
        """Closes the socket; the thread reconnects (with the current session) unless idle."""
        self._wake.set()
        ws = self._ws
        if ws:
            ws.close()

    def _start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._run, name="kilnbase-realtime", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        attempt = 0
        while not self._idle():
            self._wake.clear()
            try:
                params = {"apikey": self._api_key}
                session = self._auth.get_session()
                if session:
                    params["access_token"] = session["access_token"]
                base = self._url.replace("http", "ws", 1)
                with connect(f"{base}/realtime/v1/websocket?{urlencode(params)}") as ws:
                    if not self._resume(ws):
                        continue
                    attempt = 0
                    for raw in ws:
                        self._receive(raw)
            except Exception as e:  # any failure means "reconnect later"
                log.debug("realtime connection failed: %s", e)
            finally:
                self._ws = None
            if self._idle():
                break
            # A deliberate drop (session change) reconnects at once; failures back off.
            if not self._wake.is_set():
                self._wake.wait(min(MAX_BACKOFF, 0.5 * 2**attempt))
                attempt += 1
        with self._lock:
            # A subscribe that raced the exit must not be left without a thread.
            if self._thread is threading.current_thread():
                self._thread = None
        if not self._idle():
            self._start()

    def _resume(self, ws: ClientConnection) -> bool:
        # Publishing the socket and taking the snapshot under one lock makes every subscription
        # either part of the snapshot or sent by `subscribe` itself, never both.
        with self._lock:
            if self._wake.is_set():
                return False  # dropped while connecting (session change, close): start over
            self._ws = ws
            subs = list(self._subs.items())
            names = list(self._channels)
        for sub_id, sub in subs:
            msg: dict[str, Any] = {"type": "subscribe", "id": sub_id, "table": sub.table}
            if sub.last is not None:
                msg["since"] = sub.last
            self._send(msg)
        for name in names:
            self._send({"type": "join", "id": _join_id(name), "channel": name})
        return True

    def _receive(self, raw: str | bytes) -> None:
        try:
            msg = json.loads(raw)
        except ValueError:
            return
        if not isinstance(msg, dict):
            return
        name = msg.get("channel")
        ch = self._channels.get(name) if isinstance(name, str) else None
        try:
            self._dispatch(msg, ch)
        except Exception:
            log.exception("realtime callback failed")

    def _dispatch(self, msg: dict[str, Any], ch: Channel | None) -> None:
        match msg.get("type"):
            case "change":
                sub = self._subs.get(str(msg.get("id")))
                event_id = msg.get("event_id")
                if not sub or not isinstance(event_id, int) or event_id in sub.recent:
                    return
                sub.recent[event_id] = None
                if len(sub.recent) > RECENT_IDS:
                    del sub.recent[next(iter(sub.recent))]
                sub.last = event_id if sub.last is None else max(sub.last, event_id)
                sub.on_change(msg)
            case "joined":
                # Presence is per connection, so it has to be re-published after every (re)join.
                if ch and ch.tracked is not None:
                    self._send({"type": "presence", "channel": ch.name, "state": ch.tracked})
            case "broadcast":
                if ch and ch.on_broadcast:
                    ch.on_broadcast(str(msg.get("event")), msg.get("payload"))
            case "presence_state":
                if ch:
                    ch.presence = dict(msg.get("state") or {})
                    if ch.on_presence:
                        ch.on_presence(dict(ch.presence))
            case "presence_diff":
                if ch:
                    for key in msg.get("leaves") or {}:
                        ch.presence.pop(key, None)
                    ch.presence.update(msg.get("joins") or {})
                    if ch.on_presence:
                        ch.on_presence(dict(ch.presence))
            case "error":
                error = {"code": str(msg.get("code")), "message": str(msg.get("message"))}
                msg_id = msg.get("id") if isinstance(msg.get("id"), str) else None
                sub = self._subs.get(msg_id) if msg_id else None
                target = (
                    self._channels.get(msg_id[3:]) if msg_id and msg_id.startswith("ch:") else None
                )
                if sub:
                    handlers = [sub.on_error]
                elif target:
                    handlers = [target.on_error]
                else:
                    # Errors without an id concern the whole connection.
                    handlers = [s.on_error for s in self._subs.values()]
                    handlers += [c.on_error for c in self._channels.values()]
                for handler in handlers:
                    if handler:
                        handler(error)

    def _send(self, message: dict[str, Any]) -> None:
        ws = self._ws
        if ws is None:
            return  # `_resume` sends it once connected
        try:
            ws.send(json.dumps(message))
        except Exception as e:  # the reader thread reconnects and resends
            log.debug("realtime send failed: %s", e)
