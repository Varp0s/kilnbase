# kilnbase (Python client)

Sync Python client for a Kilnbase gateway: auth, REST queries and storage. It mirrors the TypeScript
SDK in `sdk/js`, except that failures raise `KilnbaseError` (`status`, `code`, `message`) instead of
returning `{data, error}`. Realtime is not supported yet. Requires Python 3.15+ and `httpx2`.

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

Use the **anon** key, never `service_role`. The session lives in memory only and is refreshed
automatically shortly before it expires. The client is not thread-safe.

Tests: `uv run pytest sdk/python/tests`.
