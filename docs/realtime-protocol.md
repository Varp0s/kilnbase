# Realtime protocol

JSON text frames over a WebSocket at `/realtime/v1/websocket`.

## Connecting

Browsers cannot set headers on WebSockets, so credentials are query parameters:

```
ws://localhost:8000/realtime/v1/websocket?apikey=<anon key>&access_token=<user access token>
```

`access_token` is optional; without it the connection acts as `anon`. A missing or invalid key fails the
handshake with HTTP 401. When the access token expires the server sends `token_expired` and closes the
socket; reconnect with a fresh token.

## Enabling a table

```sql
select kilnbase.enable_realtime('public.todos');   -- needs a primary key
select kilnbase.disable_realtime('public.todos');
```

## Client → server

```json
{"type": "subscribe", "id": "todos-1", "table": "todos"}
{"type": "unsubscribe", "id": "todos-1"}
```

`id` is chosen by the client (1–128 characters) and echoed on every event. Up to 100 subscriptions per
connection. Only tables in `public` that the caller may `SELECT` can be subscribed to.

## Server → client

```json
{"type": "subscribed", "id": "todos-1", "table": "todos"}
{"type": "unsubscribed", "id": "todos-1"}
{"type": "change", "id": "todos-1", "table": "todos", "op": "INSERT", "record": {"id": 1, "title": "…"}}
{"type": "change", "id": "todos-1", "table": "todos", "op": "UPDATE", "record": {"id": 1, "title": "…"}}
{"type": "change", "id": "todos-1", "table": "todos", "op": "DELETE", "old_pk": {"id": 1}}
{"type": "error", "code": "forbidden", "message": "…"}
```

Error codes: `invalid_message`, `forbidden`, `realtime_not_enabled`, `too_many_subscriptions`, `lagged`,
`token_expired`, `internal`.

## Delivery rules

- `INSERT` and `UPDATE` events are re-read **as the subscriber**, so row level security decides who receives
  them. A row the subscriber cannot see is never sent.
- `DELETE` events carry only the primary key, because the row no longer exists to be checked. They reach every
  subscriber of the table (all of whom were checked for `SELECT` on the table when subscribing).
- Rows of any size are delivered; only the primary key travels through `NOTIFY`.
- Delivery is at-most-once. Changes committed while the server is reconnecting to Postgres, or while a slow
  client lags (`lagged` error), are lost — refetch over REST to resync.

## Broadcast and presence channels

Channels carry client-to-client messages that never touch a table: cursors, typing indicators, who is online.
They are **closed by default**. Open them by replacing `realtime.authorize`, which runs as the calling user
(so `auth.uid()` and `auth.jwt()` work); `action` is `join` (receive broadcasts and presence) or `broadcast`
(send). The `service_role` key skips the check.

```sql
create or replace function realtime.authorize(channel text, action text) returns boolean
    language sql stable as $$
    select channel like 'room:%' or channel = 'user:' || auth.uid()::text $$;
```

Client → server:

```json
{"type": "join", "id": "j1", "channel": "room:42"}
{"type": "leave", "channel": "room:42"}
{"type": "broadcast", "channel": "room:42", "event": "cursor", "payload": {"x": 10}, "self": false}
{"type": "presence", "channel": "room:42", "state": {"name": "Ada"}}
{"type": "presence", "channel": "room:42", "state": null}
```

Server → client:

```json
{"type": "joined", "id": "j1", "channel": "room:42"}
{"type": "presence_state", "channel": "room:42", "state": {"<key>": {"user": "<uuid>", "state": {...}}}}
{"type": "broadcast", "channel": "room:42", "event": "cursor", "payload": {"x": 10}}
{"type": "presence_diff", "channel": "room:42", "joins": {...}, "leaves": {...}}
{"type": "left", "channel": "room:42"}
```

Additional error codes: `not_joined`, `too_many_channels`, `too_large`, `rate_limited`.

Rules:

- Broadcasts are not echoed to the sender unless `"self": true`.
- Presence is per connection and disappears when the socket closes; others receive a `presence_diff` leave.
  Presence state is limited to 4 KB.
- A connection may send 50 broadcast/presence messages per second and join 100 channels.
- Fan-out happens inside one `core` process; several replicas need a shared bus (not implemented yet).
