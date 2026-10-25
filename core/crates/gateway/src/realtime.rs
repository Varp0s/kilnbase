use std::collections::{HashMap, HashSet, VecDeque};
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
use crate::channels;
use crate::db;

const CHANNEL: &str = "kilnbase_realtime";
const MAX_SUBSCRIPTIONS: usize = 100;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Events a resuming client may catch up on; beyond that it must refetch.
const REPLAY_LIMIT: i64 = 1000;
/// How far below the newest seen id a reconnecting listener looks, to catch transactions that
/// committed out of id order while it was away.
const RECONNECT_OVERLAP: i64 = 1000;
const RETENTION: &str = "10 minutes";

/// One row change as published by `kilnbase.notify_change()`.
#[derive(Debug, Deserialize)]
pub struct Change {
    /// Outbox id; increases with insertion order and lets clients resume.
    id: i64,
    schema: String,
    table: String,
    op: String,
    pk: Map<String, Value>,
}

pub type Hub = broadcast::Sender<Arc<Change>>;

pub fn hub() -> Hub {
    broadcast::channel(4096).0
}

/// Ids already published, so replays after a reconnect never deliver an event twice.
#[derive(Default)]
struct Seen {
    ids: HashSet<i64>,
    order: VecDeque<i64>,
    newest: Option<i64>,
}

impl Seen {
    const CAPACITY: usize = 50_000;

    /// True if `id` is new.
    fn insert(&mut self, id: i64) -> bool {
        if !self.ids.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > Self::CAPACITY
            && let Some(old) = self.order.pop_front()
        {
            self.ids.remove(&old);
        }
        self.newest = Some(self.newest.map_or(id, |n| n.max(id)));
        true
    }
}

/// Keeps one LISTEN connection open forever. After a reconnect it replays the outbox from just
/// below the newest event it saw, so nothing committed while it was away is lost.
pub fn spawn_listener(database_url: String, pool: Pool, hub: Hub) {
    let pruner = pool.clone();
    tokio::spawn(async move {
        let mut seen = Seen::default();
        loop {
            if let Err(e) = listen(&database_url, &pool, &hub, &mut seen).await {
                eprintln!("kilnbase-core: realtime listener error: {e}");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            if let Err(e) = prune(&pruner).await {
                eprintln!("kilnbase-core: pruning realtime events failed: {e:?}");
            }
        }
    });
}

async fn prune(pool: &Pool) -> Result<(), crate::error::ApiError> {
    let mut client = db::client(pool).await?;
    let tx = db::begin_as_service(&mut client).await?;
    tx.execute(
        &format!(
            // The newest row is always kept: `replay` needs some retained id to tell a pruned gap
            // from "nothing happened".
            "delete from kilnbase.realtime_events where created_at < now() - interval '{RETENTION}'
               and id < (select max(id) from kilnbase.realtime_events)"
        ),
        &[],
    )
    .await
    .map_err(db::internal)?;
    tx.commit().await.map_err(db::internal)
}

/// Outbox rows after `after`, optionally for one public table, plus the oldest id still retained.
async fn load_events(
    pool: &Pool,
    table: Option<&str>,
    after: i64,
    limit: i64,
) -> Result<(Vec<Change>, Option<i64>), crate::error::ApiError> {
    let mut client = db::client(pool).await?;
    let tx = db::begin_as_service(&mut client).await?;
    let rows = tx
        .query(
            "select id, schema_name, table_name, op, pk::text from kilnbase.realtime_events
              where id > $1 and ($2::text is null or (schema_name = 'public' and table_name = $2))
              order by id limit $3",
            &[&after, &table, &limit],
        )
        .await
        .map_err(db::internal)?;
    let oldest: Option<i64> = tx
        .query_one("select min(id) from kilnbase.realtime_events", &[])
        .await
        .map_err(db::internal)?
        .get(0);
    let changes = rows
        .into_iter()
        .filter_map(|r| {
            Some(Change {
                id: r.get(0),
                schema: r.get(1),
                table: r.get(2),
                op: r.get(3),
                pk: serde_json::from_str(&r.get::<_, String>(4)).ok()?,
            })
        })
        .collect();
    Ok((changes, oldest))
}

async fn listen(
    database_url: &str,
    pool: &Pool,
    hub: &Hub,
    seen: &mut Seen,
) -> Result<(), tokio_postgres::Error> {
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

    // LISTEN is active before the replay query, so nothing can fall between the two.
    if let Some(newest) = seen.newest {
        match load_events(pool, None, newest - RECONNECT_OVERLAP, i64::MAX).await {
            Ok((missed, _)) => {
                for change in missed {
                    if seen.insert(change.id) {
                        drop(hub.send(Arc::new(change)));
                    }
                }
            }
            Err(e) => eprintln!("kilnbase-core: realtime replay failed: {e:?}"),
        }
    }

    while let Some(n) = notify_rx.recv().await {
        match serde_json::from_str::<Change>(n.payload()) {
            // No receivers is fine: nobody is subscribed right now.
            Ok(change) => {
                if seen.insert(change.id) {
                    drop(hub.send(Arc::new(change)));
                }
            }
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
    Subscribe {
        id: String,
        table: String,
        /// Resume after this event id (from a previous connection's `event_id`).
        #[serde(default)]
        since: Option<i64>,
    },
    Unsubscribe {
        id: String,
    },
    Join {
        id: String,
        channel: String,
    },
    Leave {
        channel: String,
    },
    Broadcast {
        channel: String,
        event: String,
        #[serde(default)]
        payload: Value,
        /// Also deliver to the sending connection.
        #[serde(default, rename = "self")]
        include_self: bool,
    },
    Presence {
        channel: String,
        /// null stops tracking.
        #[serde(default)]
        state: Option<Value>,
    },
}

type Sink = SplitSink<WebSocket, Message>;

async fn send(sink: &mut Sink, value: Value) -> bool {
    sink.send(Message::Text(Utf8Bytes::from(value.to_string())))
        .await
        .is_ok()
}

fn expired_message() -> Value {
    json!({ "type": "error", "code": "token_expired",
        "message": "access token expired; reconnect with a fresh one" })
}

async fn session(st: Arc<AppState>, caller: Caller, socket: WebSocket) {
    let (mut sink, mut incoming) = socket.split();
    let mut changes = st.realtime.subscribe();
    let mut channel_events = st.channels.subscribe();
    let mut member = st.channels.member();
    // subscription id -> table name (always in schema `public`)
    let mut subs: HashMap<String, String> = HashMap::new();
    let pool = &st.storage.pool;

    'session: loop {
        tokio::select! {
            message = incoming.next() => {
                let Some(Ok(message)) = message else { break };
                let text = match message {
                    Message::Text(text) => text,
                    Message::Close(_) => break,
                    _ => continue,
                };
                if caller.expired() {
                    let _ = send(&mut sink, expired_message()).await;
                    break;
                }
                let replies = match serde_json::from_str::<ClientMessage>(&text) {
                    Err(_) => vec![json!({ "type": "error", "code": "invalid_message",
                        "message": "unknown or malformed message" })],
                    Ok(ClientMessage::Join { id, channel }) => {
                        st.channels.join(pool, &caller, &mut member, &id, &channel).await
                    }
                    Ok(ClientMessage::Leave { channel }) => vec![st.channels.leave(&mut member, &channel)],
                    Ok(ClientMessage::Broadcast { channel, event, payload, include_self }) => st
                        .channels
                        .broadcast(pool, &caller, &mut member, &channel,
                            channels::Outgoing { event, payload, include_self })
                        .await
                        .into_iter()
                        .collect(),
                    Ok(ClientMessage::Presence { channel, state }) => st
                        .channels
                        .presence(&caller, &mut member, &channel, state)
                        .into_iter()
                        .collect(),
                    Ok(ClientMessage::Subscribe { id, table, since }) => {
                        let reply = handle_client(pool, &caller, &mut subs,
                            ClientMessage::Subscribe { id: id.clone(), table: table.clone(), since: None }).await;
                        let mut out = vec![reply.clone()];
                        if reply["type"] == "subscribed" && let Some(since) = since {
                            out.extend(replay(pool, &caller, &id, &table, since).await);
                        }
                        out
                    }
                    Ok(table_message) => vec![handle_client(pool, &caller, &mut subs, table_message).await],
                };
                for reply in replies {
                    if !send(&mut sink, reply).await {
                        break 'session;
                    }
                }
            }
            event = channel_events.recv() => {
                match event {
                    Ok(event) => {
                        if let Some(body) = st.channels.deliver(&member, &event)
                            && !send(&mut sink, body).await
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        let warn = json!({ "type": "error", "code": "lagged",
                            "message": format!("{missed} channel messages were dropped") });
                        if !send(&mut sink, warn).await { break }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
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
                    let _ = send(&mut sink, expired_message()).await;
                    break;
                }
                for event in render(pool, &caller, &change, &ids).await {
                    if !send(&mut sink, event).await {
                        break 'session;
                    }
                }
            }
        }
    }
    // Others must see this connection's presence disappear however the socket ended.
    st.channels.disconnect(&mut member);
}

/// The messages `caller` gets for `change`, one per matching subscription; empty if RLS hides it.
async fn render(pool: &Pool, caller: &Caller, change: &Change, ids: &[&String]) -> Vec<Value> {
    let body = if change.op == "DELETE" {
        // The row is gone and cannot be re-checked; subscribers were vetted for SELECT on the
        // table when they subscribed.
        json!({ "old_pk": change.pk })
    } else {
        match visible_row(pool, caller, change).await {
            Ok(Some(record)) => json!({ "record": record }),
            Ok(None) => return Vec::new(),
            Err(e) => {
                eprintln!("kilnbase-core: realtime visibility check failed: {e:?}");
                return Vec::new();
            }
        }
    };
    ids.iter()
        .map(|id| {
            let mut event = json!({ "type": "change", "id": id, "event_id": change.id,
                "table": change.table, "op": change.op });
            if let (Value::Object(e), Value::Object(b)) = (&mut event, &body) {
                e.extend(b.clone());
            }
            event
        })
        .collect()
}

/// Catch-up for a client resuming after `since`; asks it to refetch when the gap is unknowable.
/// Events arriving live during the catch-up may be sent twice; clients dedupe by `event_id`.
/// shortcut: a transaction that took an id below `since` but committed after it is not replayed;
/// resume from a commit-ordered position (logical replication LSN) if that ever matters.
async fn replay(pool: &Pool, caller: &Caller, id: &str, table: &str, since: i64) -> Vec<Value> {
    let resync = json!({ "type": "error", "id": id, "code": "resync_required",
        "message": "too many changes were missed; refetch the table" });
    let (changes, oldest) = match load_events(pool, Some(table), since, REPLAY_LIMIT + 1).await {
        Ok(found) => found,
        Err(e) => {
            eprintln!("kilnbase-core: realtime resume failed: {e:?}");
            return vec![resync];
        }
    };
    // Older events may have been pruned, or more happened than we replay: a refetch is the only
    // way to be complete.
    let pruned = oldest.is_some_and(|oldest| oldest > since + 1);
    if pruned || changes.len() as i64 > REPLAY_LIMIT {
        return vec![resync];
    }
    let owner = id.to_owned();
    let mut out = Vec::new();
    for change in &changes {
        out.extend(render(pool, caller, change, &[&owner]).await);
    }
    out
}

async fn handle_client(
    pool: &Pool,
    caller: &Caller,
    subs: &mut HashMap<String, String>,
    message: ClientMessage,
) -> Value {
    match message {
        ClientMessage::Unsubscribe { id } => {
            subs.remove(&id);
            json!({ "type": "unsubscribed", "id": id })
        }
        ClientMessage::Subscribe { id, table, .. } => {
            let mut reply = subscribe(pool, caller, subs, &id, &table).await;
            // Echo the id on errors too, so clients can tell which subscription failed.
            reply["id"] = Value::String(id);
            reply
        }
        // Channel messages are routed in `session`.
        _ => json!({ "type": "error", "code": "invalid_message", "message": "unexpected message" }),
    }
}

async fn subscribe(
    pool: &Pool,
    caller: &Caller,
    subs: &mut HashMap<String, String>,
    id: &str,
    table: &str,
) -> Value {
    let error =
        |code: &str, message: &str| json!({ "type": "error", "code": code, "message": message });
    if subs.len() >= MAX_SUBSCRIPTIONS && !subs.contains_key(id) {
        return error("too_many_subscriptions", "limit is 100 per connection");
    }
    if id.is_empty() || id.len() > 128 {
        return error(
            "invalid_message",
            "subscription id must be 1-128 characters",
        );
    }
    match can_subscribe(pool, caller, table).await {
        Ok(Access::Allowed) => {
            subs.insert(id.to_owned(), table.to_owned());
            json!({ "type": "subscribed", "table": table })
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
    fn seen_ids_deduplicate_and_track_the_newest() {
        let mut seen = Seen::default();
        assert!(seen.insert(5));
        assert!(seen.insert(3));
        assert!(!seen.insert(5));
        assert_eq!(seen.newest, Some(5));
        for id in 10..(10 + Seen::CAPACITY as i64) {
            seen.insert(id);
        }
        // The oldest ids are forgotten once capacity is exceeded, bounding memory.
        assert!(seen.insert(5));
        assert_eq!(seen.ids.len(), Seen::CAPACITY);
    }

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
            r#"{"id":1,"schema":"public","table":"todos","op":"INSERT","pk":{"id":5}}"#,
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
