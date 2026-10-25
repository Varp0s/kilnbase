//! Broadcast and presence channels: client-to-client messages that never touch a table.
//!
//! Access is decided per channel and action by `realtime.authorize()`, evaluated as the caller.
//! shortcut: fan-out and presence live in this process; with several core replicas, route channel
//! events through Postgres NOTIFY (or a broker) so clients on different replicas see each other.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use deadpool_postgres::Pool;
use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::auth::Caller;
use crate::db;
use crate::error::ApiError;

const MAX_CHANNELS: usize = 100;
const MAX_PRESENCE_BYTES: usize = 4096;
/// Broadcast + presence messages a connection may send per second.
const MAX_MESSAGES_PER_SECOND: u32 = 50;

pub struct ChannelEvent {
    channel: String,
    origin: u64,
    include_origin: bool,
    body: Value,
}

pub struct Channels {
    tx: broadcast::Sender<std::sync::Arc<ChannelEvent>>,
    /// channel -> presence key -> {"user", "state"}
    presence: Mutex<HashMap<String, HashMap<String, Value>>>,
    next_id: AtomicU64,
}

impl Default for Channels {
    fn default() -> Self {
        Self {
            tx: broadcast::channel(4096).0,
            presence: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }
}

/// A client broadcast: an application-defined event name and JSON payload.
pub struct Outgoing {
    pub event: String,
    pub payload: Value,
    pub include_self: bool,
}

/// One connection's view: joined channels, cached authorisations and its send budget.
pub struct Member {
    id: u64,
    joined: HashSet<String>,
    tracked: HashSet<String>,
    allowed: HashMap<(String, &'static str), bool>,
    window: Instant,
    sent: u32,
}

pub fn valid_channel(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && !name.chars().any(char::is_control)
}

fn error(code: &str, message: &str) -> Value {
    json!({ "type": "error", "code": code, "message": message })
}

impl Channels {
    pub fn subscribe(&self) -> broadcast::Receiver<std::sync::Arc<ChannelEvent>> {
        self.tx.subscribe()
    }

    pub fn member(&self) -> Member {
        Member {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            joined: HashSet::new(),
            tracked: HashSet::new(),
            allowed: HashMap::new(),
            window: Instant::now(),
            sent: 0,
        }
    }

    fn publish(&self, channel: &str, origin: u64, include_origin: bool, body: Value) {
        // No receivers is fine.
        let _ = self.tx.send(std::sync::Arc::new(ChannelEvent {
            channel: channel.to_owned(),
            origin,
            include_origin,
            body,
        }));
    }

    /// What this member should receive for `event`, if anything.
    pub fn deliver(&self, member: &Member, event: &ChannelEvent) -> Option<Value> {
        let own = event.origin == member.id;
        (member.joined.contains(&event.channel) && (!own || event.include_origin))
            .then(|| event.body.clone())
    }

    pub async fn join(
        &self,
        pool: &Pool,
        caller: &Caller,
        member: &mut Member,
        id: &str,
        channel: &str,
    ) -> Vec<Value> {
        let tagged = |mut v: Value| {
            v["id"] = Value::String(id.to_owned());
            vec![v]
        };
        if !valid_channel(channel) {
            return tagged(error(
                "invalid_message",
                "channel names are 1-255 characters",
            ));
        }
        if member.joined.len() >= MAX_CHANNELS && !member.joined.contains(channel) {
            return tagged(error("too_many_channels", "limit is 100 per connection"));
        }
        match authorized(pool, caller, member, channel, "join").await {
            Ok(true) => {}
            Ok(false) => return tagged(error("forbidden", "not allowed to join this channel")),
            Err(e) => {
                eprintln!("kilnbase-core: channel authorisation failed: {e:?}");
                return tagged(error("internal", "internal error"));
            }
        }
        member.joined.insert(channel.to_owned());
        let state = self
            .presence
            .lock()
            .map(|p| p.get(channel).cloned().unwrap_or_default())
            .unwrap_or_default();
        vec![
            json!({ "type": "joined", "id": id, "channel": channel }),
            json!({ "type": "presence_state", "channel": channel, "state": state }),
        ]
    }

    pub fn leave(&self, member: &mut Member, channel: &str) -> Value {
        self.untrack(member, channel);
        member.joined.remove(channel);
        json!({ "type": "left", "channel": channel })
    }

    pub async fn broadcast(
        &self,
        pool: &Pool,
        caller: &Caller,
        member: &mut Member,
        channel: &str,
        message: Outgoing,
    ) -> Option<Value> {
        if !member.joined.contains(channel) {
            return Some(error("not_joined", "join the channel first"));
        }
        if !member.within_budget() {
            return Some(error("rate_limited", "too many messages; slow down"));
        }
        match authorized(pool, caller, member, channel, "broadcast").await {
            Ok(true) => {}
            Ok(false) => return Some(error("forbidden", "not allowed to send on this channel")),
            Err(e) => {
                eprintln!("kilnbase-core: channel authorisation failed: {e:?}");
                return Some(error("internal", "internal error"));
            }
        }
        let body = json!({ "type": "broadcast", "channel": channel,
            "event": message.event, "payload": message.payload });
        self.publish(channel, member.id, message.include_self, body);
        None
    }

    /// `state: Some` starts or updates this connection's presence; `None` stops it.
    pub fn presence(
        &self,
        caller: &Caller,
        member: &mut Member,
        channel: &str,
        state: Option<Value>,
    ) -> Option<Value> {
        if !member.joined.contains(channel) {
            return Some(error("not_joined", "join the channel first"));
        }
        if !member.within_budget() {
            return Some(error("rate_limited", "too many messages; slow down"));
        }
        let Some(state) = state else {
            self.untrack(member, channel);
            return None;
        };
        if state.to_string().len() > MAX_PRESENCE_BYTES {
            return Some(error("too_large", "presence state is limited to 4 KB"));
        }
        let key = member.id.to_string();
        let entry = json!({ "user": caller.claims.get("sub"), "state": state });
        if let Ok(mut p) = self.presence.lock() {
            p.entry(channel.to_owned())
                .or_default()
                .insert(key.clone(), entry.clone());
        }
        member.tracked.insert(channel.to_owned());
        let body = json!({ "type": "presence_diff", "channel": channel,
            "joins": { key: entry }, "leaves": {} });
        self.publish(channel, member.id, true, body);
        None
    }

    fn untrack(&self, member: &mut Member, channel: &str) {
        if !member.tracked.remove(channel) {
            return;
        }
        let key = member.id.to_string();
        let removed = self.presence.lock().ok().and_then(|mut p| {
            let entries = p.get_mut(channel)?;
            let removed = entries.remove(&key);
            if entries.is_empty() {
                p.remove(channel);
            }
            removed
        });
        if let Some(entry) = removed {
            let body = json!({ "type": "presence_diff", "channel": channel,
                "joins": {}, "leaves": { key: entry } });
            self.publish(channel, member.id, false, body);
        }
    }

    /// Called when the socket closes, so others see the user leave.
    pub fn disconnect(&self, member: &mut Member) {
        for channel in member.tracked.clone() {
            self.untrack(member, &channel);
        }
    }
}

impl Member {
    fn within_budget(&mut self) -> bool {
        if self.window.elapsed() >= Duration::from_secs(1) {
            self.window = Instant::now();
            self.sent = 0;
        }
        self.sent += 1;
        self.sent <= MAX_MESSAGES_PER_SECOND
    }
}

async fn authorized(
    pool: &Pool,
    caller: &Caller,
    member: &mut Member,
    channel: &str,
    action: &'static str,
) -> Result<bool, ApiError> {
    if caller.role == "service_role" {
        return Ok(true);
    }
    // Cached for the connection's lifetime; tokens are short-lived and re-checked for expiry.
    if let Some(&ok) = member.allowed.get(&(channel.to_owned(), action)) {
        return Ok(ok);
    }
    let mut client = db::client(pool).await?;
    let tx = db::begin_as(&mut client, caller).await?;
    let ok: bool = tx
        .query_one(
            "select coalesce(realtime.authorize($1, $2), false)",
            &[&channel, &action],
        )
        .await
        .map_err(db::internal)?
        .get(0);
    member.allowed.insert((channel.to_owned(), action), ok);
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_names() {
        assert!(valid_channel("room:1"));
        assert!(!valid_channel(""));
        assert!(!valid_channel("a\nb"));
        assert!(!valid_channel(&"x".repeat(256)));
    }

    #[test]
    fn budget_resets_each_second() {
        let channels = Channels::default();
        let mut m = channels.member();
        for _ in 0..MAX_MESSAGES_PER_SECOND {
            assert!(m.within_budget());
        }
        assert!(!m.within_budget());
        m.window = Instant::now() - Duration::from_secs(2);
        assert!(m.within_budget());
    }

    #[test]
    fn delivery_respects_membership_and_self() {
        let channels = Channels::default();
        let mut a = channels.member();
        let b = channels.member();
        a.joined.insert("room".into());
        let event = |origin, include_origin| ChannelEvent {
            channel: "room".into(),
            origin,
            include_origin,
            body: json!({}),
        };
        assert!(channels.deliver(&a, &event(b.id, false)).is_some());
        assert!(channels.deliver(&a, &event(a.id, false)).is_none());
        assert!(channels.deliver(&a, &event(a.id, true)).is_some());
        assert!(channels.deliver(&b, &event(a.id, false)).is_none());
    }
}
