//! One JSON object per line on stderr, the same shape as the auth service:
//! `{"ts": <unix seconds>, "level": "...", "service": "core", "msg": "..."}` plus event fields.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use serde_json::{Map, Value, json};

pub fn line(level: &str, msg: &str, fields: Map<String, Value>) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| (d.as_millis() as f64) / 1000.0);
    let mut obj = Map::new();
    obj.insert("ts".into(), json!(ts));
    obj.insert("level".into(), json!(level));
    obj.insert("service".into(), json!("core"));
    obj.insert("msg".into(), json!(msg));
    obj.extend(fields);
    Value::Object(obj).to_string()
}

pub fn emit(level: &str, msg: &str, fields: Map<String, Value>) {
    eprintln!("{}", line(level, msg, fields));
}

macro_rules! log_info {
    ($($arg:tt)*) => { $crate::log::emit("info", &format!($($arg)*), Default::default()) };
}

macro_rules! log_error {
    ($($arg:tt)*) => { $crate::log::emit("error", &format!($($arg)*), Default::default()) };
}

/// Access log. The query string is left out: it carries signed-URL tokens, API keys and
/// access tokens (`?apikey=`, `?token=`, `?access_token=`, S3 presigned signatures).
pub async fn access(req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let start = Instant::now();
    let res = next.run(req).await;
    let mut fields = Map::new();
    fields.insert("method".into(), json!(method));
    fields.insert("path".into(), json!(path));
    fields.insert("status".into(), json!(res.status().as_u16()));
    fields.insert(
        "ms".into(),
        json!((start.elapsed().as_micros() as f64) / 1000.0),
    );
    emit("info", "request", fields);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_json_with_the_shared_fields() {
        let mut fields = Map::new();
        fields.insert("status".into(), json!(200));
        let v: Value = serde_json::from_str(&line("info", "say \"hi\"\n", fields)).unwrap();
        assert_eq!(v["level"], "info");
        assert_eq!(v["service"], "core");
        assert_eq!(v["msg"], "say \"hi\"\n");
        assert_eq!(v["status"], 200);
        assert!(v["ts"].as_f64().unwrap() > 1.7e9);
    }
}
