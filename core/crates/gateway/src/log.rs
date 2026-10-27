//! One JSON object per line on stderr, the same shape as the auth service:
//! `{"ts": <unix seconds>, "level": "...", "service": "core", "msg": "..."}` plus event fields.
//! With KILNBASE_LOG_DIR set, the same lines also go to `core.log` there (for Studio).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
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

/// Kept at about twice this: the current file plus one rotated `.1`.
const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;

static FILE_SINK: OnceLock<SyncSender<String>> = OnceLock::new();

/// Starts the file writer. Lines are handed over through a bounded channel, so a slow disk never
/// holds up a request; when it is full, lines are dropped from the file (stderr still has them).
pub fn init_file(dir: &Path) -> std::io::Result<()> {
    let path = dir.join("core.log");
    let file = open(&path)?;
    let (tx, rx) = sync_channel(4096);
    std::thread::spawn(move || write_lines(rx, path, file, MAX_FILE_BYTES));
    let _ = FILE_SINK.set(tx);
    Ok(())
}

fn open(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn write_lines(rx: Receiver<String>, path: PathBuf, mut file: File, max: u64) {
    let mut size = file.metadata().map_or(0, |m| m.len());
    for line in rx {
        if size >= max {
            let rotated = path.with_extension("log.1");
            if fs::rename(&path, &rotated).is_ok()
                && let Ok(f) = open(&path)
            {
                file = f;
                size = 0;
            }
        }
        if writeln!(file, "{line}").is_ok() {
            size += line.len() as u64 + 1;
        }
    }
}

pub fn emit(level: &str, msg: &str, fields: Map<String, Value>) {
    let line = line(level, msg, fields);
    eprintln!("{line}");
    if let Some(tx) = FILE_SINK.get() {
        let _ = tx.try_send(line);
    }
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

    #[test]
    fn the_file_rotates_at_its_size_limit() {
        let dir = std::env::temp_dir().join(format!("kilnbase-log-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("core.log");
        let (tx, rx) = sync_channel(16);
        for i in 0..5 {
            tx.send(format!("line {i} xxxxxxxxxx")).unwrap();
        }
        drop(tx);
        write_lines(rx, path.clone(), open(&path).unwrap(), 40);
        let current = fs::read_to_string(&path).unwrap();
        let rotated = fs::read_to_string(dir.join("core.log.1")).unwrap();
        // 18-byte lines against a 40-byte limit: three lines, then a rotation.
        assert_eq!(
            current,
            "line 3 xxxxxxxxxx
line 4 xxxxxxxxxx
"
        );
        assert!(
            rotated.starts_with("line 0")
                && rotated.ends_with(
                    "line 2 xxxxxxxxxx
"
                )
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
