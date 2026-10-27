# kilnbase (Python client)

Sync Python client for a Kilnbase gateway: auth, REST queries, storage and realtime. It mirrors the
TypeScript SDK in `sdk/js`, except that failures raise `KilnbaseError` (`status`, `code`, `message`)
instead of returning `{data, error}`. Requires Python 3.15+, `httpx2` and `websockets`.

```python
from kilnbase import KilnbaseError, create_client

client = create_client("http://localhost:8000", "<anon key>")

client.auth.sign_up("me@example.com", "a-long-password")
client.auth.sign_in_with_password("me@example.com", "a-long-password")  # token is sent from now on

try:
    client.from_("todos").insert({"title": "write docs"}).execute()
    todos = (
        client.from_("todos").select("id,title").eq("done", False).order("id").limit(10).execute()
    )
    one = client.from_("todos").select().eq("id", 1).single().execute()
except KilnbaseError as e:
    print(e.status, e.code, e.message)  # status 0 / "network_error" when the gateway is unreachable

bucket = client.storage.from_("avatars")
bucket.upload("me/face.png", b"...", content_type="image/png", upsert=True)
data = bucket.download("me/face.png")
link = bucket.create_signed_url("me/face.png", 3600)  # {"signed_url": ..., "expires_at": ...}
public = bucket.get_public_url("me/face.png")
bucket.remove("me/face.png")

client.auth.sign_out()
```

Realtime (protocol in `docs/realtime-protocol.md`) runs on one background thread per client, so the
callbacks are called on that thread. The socket reconnects with the new token on sign-in, sign-out and
refresh, and subscriptions resume where they left off; on a `resync_required` error, refetch over REST.

```python
cancel = client.realtime.subscribe("todos", lambda e: print(e["op"], e.get("record")), print)
room = client.realtime.channel(
    "room:42", on_broadcast=lambda event, payload: ..., on_presence=lambda state: ...
)
room.track({"name": "Ada"})  # restored after reconnects
room.send("cursor", {"x": 10})  # self_=True to receive it too
room.leave()
cancel()
client.close()  # also stops the realtime thread
```

More, same as the JS client: `upsert`, `ilike`, `is_`, `range` on queries; `sign_in_anonymously`,
`update_user`, `sign_in_with_otp` / `verify_otp` (code or magic link), `sign_in_with_oauth` +
`exchange_code_for_session` (PKCE), `auth.mfa.enroll/verify/unenroll`; and
`download(path, transform={"width": 200})` / `get_public_url(path, transform=...)` for images.

Use the **anon** key, never `service_role`. The session lives in memory only and is refreshed
automatically shortly before it expires. Apart from the realtime thread it starts, the client is not thread-safe.

Tests: `uv run pytest sdk/python/tests`.
