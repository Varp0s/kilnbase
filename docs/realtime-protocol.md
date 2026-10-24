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
