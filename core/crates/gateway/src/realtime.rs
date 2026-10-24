use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use deadpool_postgres::Pool;
use futures_util::stream::{SplitSink, StreamExt};
use futures_util::{SinkExt, stream};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::{broadcast, mpsc};
use tokio_postgres::{AsyncMessage, NoTls};

use crate::AppState;
use crate::auth::{self, Caller};
use crate::db;

const CHANNEL: &str = "kilnbase_realtime";
const MAX_SUBSCRIPTIONS: usize = 100;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// One row change as published by `kilnbase.notify_change()`.
#[derive(Debug, Deserialize)]
pub struct Change {
    schema: String,
    table: String,
    op: String,
    pk: Map<String, Value>,
}

pub type Hub = broadcast::Sender<Arc<Change>>;

pub fn hub() -> Hub {
    broadcast::channel(4096).0
}

/// Keeps one LISTEN connection open forever, reconnecting on failure.
/// shortcut: events committed while disconnected are lost; switch to logical replication
/// (pgoutput + a slot) when delivery must survive reconnects.
pub fn spawn_listener(database_url: String, hub: Hub) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = listen(&database_url, &hub).await {
                eprintln!("kilnbase-core: realtime listener error: {e}");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

async fn listen(database_url: &str, hub: &Hub) -> Result<(), tokio_postgres::Error> {
    let (client, mut connection) = tokio_postgres::connect(database_url, NoTls).await?;
    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
    let driver = tokio::spawn(async move {
        let mut messages = stream::poll_fn(move |cx| connection.poll_message(cx));
        while let Some(message) = messages.next().await {
            match message {
                Ok(AsyncMessage::Notification(n)) => {
                    if notify_tx.send(n).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("kilnbase-core: realtime connection lost: {e}");
                    break;
                }
            }
        }
    });
    client.batch_execute(&format!("listen {CHANNEL}")).await?;
    eprintln!("kilnbase-core: realtime listening");

    while let Some(n) = notify_rx.recv().await {
        match serde_json::from_str::<Change>(n.payload()) {
            // No receivers is fine: nobody is subscribed right now.
            Ok(change) => drop(hub.send(Arc::new(change))),
            Err(e) => eprintln!("kilnbase-core: bad realtime payload: {e}"),
        }
    }
    drop(client);
    let _ = driver.await;
    Ok(())
}

#[derive(Deserialize)]
pub struct ConnectParams {
    apikey: Option<String>,
    access_token: Option<String>,
}

/// Browsers cannot set headers on WebSockets, so credentials come as query parameters.
pub async fn websocket(
    State(st): State<Arc<AppState>>,
    Query(params): Query<ConnectParams>,
    ws: WebSocketUpgrade,
) -> Response {
    let caller = match auth::authorize_tokens(
        &st.keys,
        params.apikey.as_deref(),
        params.access_token.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    ws.max_message_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| session(st, caller, socket))
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    Subscribe { id: String, table: String },
    Unsubscribe { id: String },
}

type Sink = SplitSink<WebSocket, Message>;

async fn send(sink: &mut Sink, value: Value) -> bool {
    sink.send(Message::Text(Utf8Bytes::from(value.to_string())))
        .await
        .is_ok()
}

async fn session(st: Arc<AppState>, caller: Caller, socket: WebSocket) {
    let (mut sink, mut incoming) = socket.split();
    let mut changes = st.realtime.subscribe();
    // subscription id -> table name (always in schema `public`)
    let mut subs: HashMap<String, String> = HashMap::new();

    loop {
        tokio::select! {
            message = incoming.next() => {
                let Some(Ok(message)) = message else { break };
                let reply = match message {
                    Message::Text(text) => handle_client(&st.storage.pool, &caller, &mut subs, &text).await,
                    Message::Close(_) => break,
                    _ => continue,
                };
                if !send(&mut sink, reply).await {
                    break;
                }
            }
            change = changes.recv() => {
                let change = match change {
                    Ok(c) => c,
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        let warn = json!({ "type": "error", "code": "lagged",
                            "message": format!("{missed} changes were dropped; refetch to resync") });
                        if !send(&mut sink, warn).await { break }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if change.schema != "public" {
                    continue;
                }
                let ids: Vec<&String> = subs.iter().filter(|(_, t)| **t == change.table).map(|(id, _)| id).collect();
                if ids.is_empty() {
                    continue;
                }
                if caller.expired() {
                    let msg = json!({ "type": "error", "code": "token_expired",
                        "message": "access token expired; reconnect with a fresh one" });
                    let _ = send(&mut sink, msg).await;
                    break;
                }
                let body = if change.op == "DELETE" {
                    // The row is gone and cannot be re-checked; subscribers were vetted for
                    // SELECT on the table when they subscribed.
                    json!({ "old_pk": change.pk })
                } else {
                    match visible_row(&st.storage.pool, &caller, &change).await {
                        Ok(Some(record)) => json!({ "record": record }),
                        Ok(None) => continue,
                        Err(e) => {
                            eprintln!("kilnbase-core: realtime visibility check failed: {e:?}");
                            continue;
                        }
                    }
                };
                for id in ids {
                    let mut event = json!({ "type": "change", "id": id, "table": change.table, "op": change.op });
                    if let (Value::Object(e), Value::Object(b)) = (&mut event, &body) {
                        e.extend(b.clone());
                    }
                    if !send(&mut sink, event).await {
                        return;
                    }
                }
            }
        }
    }
}

async fn handle_client(
    pool: &Pool,
    caller: &Caller,
    subs: &mut HashMap<String, String>,
    text: &str,
) -> Value {
    let error =
        |code: &str, message: &str| json!({ "type": "error", "code": code, "message": message });
    let message = match serde_json::from_str::<ClientMessage>(text) {
        Ok(m) => m,
        Err(_) => return error("invalid_message", "expected subscribe or unsubscribe"),
    };
    match message {
        ClientMessage::Unsubscribe { id } => {
            subs.remove(&id);
            json!({ "type": "unsubscribed", "id": id })
        }
        ClientMessage::Subscribe { id, table } => {
            if subs.len() >= MAX_SUBSCRIPTIONS && !subs.contains_key(&id) {
                return error("too_many_subscriptions", "limit is 100 per connection");
            }
            if id.is_empty() || id.len() > 128 {
                return error(
                    "invalid_message",
                    "subscription id must be 1-128 characters",
                );
            }
            match can_subscribe(pool, caller, &table).await {
                Ok(Access::Allowed) => {
                    subs.insert(id.clone(), table.clone());
                    json!({ "type": "subscribed", "id": id, "table": table })
                }
                Ok(Access::Denied) => error("forbidden", "table not found or not readable"),
                Ok(Access::NotEnabled) => error(
                    "realtime_not_enabled",
                    "run select kilnbase.enable_realtime('public.<table>') first",
                ),
                Err(e) => {
                    eprintln!("kilnbase-core: realtime subscribe check failed: {e:?}");
                    error("internal", "internal error")
                }
            }
        }
    }
}

enum Access {
    Allowed,
    Denied,
    NotEnabled,
}

async fn can_subscribe(
    pool: &Pool,
    caller: &Caller,
    table: &str,
) -> Result<Access, crate::error::ApiError> {
    let mut client = db::client(pool).await?;
    let tx = db::begin_as(&mut client, caller).await?;
    // Unprotected tables have no SELECT grant for API roles, so they can never be subscribed to.
    let row = tx
        .query_one(
            "select r is not null and has_table_privilege(r, 'SELECT'),
                    exists (select 1 from pg_trigger where tgrelid = r and tgname = 'kilnbase_realtime')
               from to_regclass(format('%I.%I', 'public', $1::text)) r",
            &[&table],
        )
        .await
        .map_err(db::internal)?;
    Ok(
        match (row.get::<_, Option<bool>>(0), row.get::<_, bool>(1)) {
            (Some(true), true) => Access::Allowed,
            (Some(true), false) => Access::NotEnabled,
            _ => Access::Denied,
        },
    )
}

fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Re-reads the changed row as the subscriber; `None` when RLS hides it.
async fn visible_row(
    pool: &Pool,
    caller: &Caller,
    change: &Change,
) -> Result<Option<Value>, crate::error::ApiError> {
    if change.pk.is_empty() {
        return Ok(None);
    }
    let table = format!(
        "{}.{}",
        quote_ident(&change.schema),
        quote_ident(&change.table)
    );
    let matches: Vec<String> = change
        .pk
        .keys()
        .map(|col| format!("t.{c} = k.{c}", c = quote_ident(col)))
        .collect();
    // jsonb_populate_record gives the key values their real column types, so the lookup uses
    // the primary key index.
    let sql = format!(
        "select to_jsonb(t)::text from {table} t, jsonb_populate_record(null::{table}, $1::text::jsonb) k where {}",
        matches.join(" and ")
    );
    let mut client = db::client(pool).await?;
    let tx = db::begin_as(&mut client, caller).await?;
    let pk = Value::Object(change.pk.clone()).to_string();
    let row = tx.query_opt(&sql, &[&pk]).await.map_err(db::internal)?;
    Ok(row.and_then(|r| serde_json::from_str(&r.get::<_, String>(0)).ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_identifiers() {
        assert_eq!(quote_ident("todos"), "\"todos\"");
        assert_eq!(
            quote_ident("a\"; drop table x; --"),
            "\"a\"\"; drop table x; --\""
        );
    }

    #[test]
    fn parses_trigger_payload() {
        let c: Change = serde_json::from_str(
            r#"{"schema":"public","table":"todos","op":"INSERT","pk":{"id":5}}"#,
        )
        .unwrap();
        assert_eq!(c.table, "todos");
        assert_eq!(c.pk["id"], 5);
    }

    #[test]
    fn parses_client_messages() {
        assert!(matches!(
            serde_json::from_str::<ClientMessage>(r#"{"type":"subscribe","id":"a","table":"t"}"#),
            Ok(ClientMessage::Subscribe { .. })
        ));
        assert!(serde_json::from_str::<ClientMessage>(r#"{"type":"drop"}"#).is_err());
    }
}
