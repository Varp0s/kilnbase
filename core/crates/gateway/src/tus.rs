//! Resumable uploads over tus 1.0: core protocol plus the creation and termination extensions.
//! Partial uploads live in `uploads/<id>/` until the last byte arrives, then become an object
//! through the same insert-as-caller path as a plain upload.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

use crate::AppState;
use crate::auth::{self, Caller};
use crate::error::ApiError;
use crate::storage::{NewObject, Storage, bad_request, drain, mime_essence, too_large};

const VERSION: &str = "1.0.0";
// shortcut: abandoned uploads are only swept when a new one starts; add a timer if disks fill up.
const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

#[derive(Serialize, Deserialize)]
struct Meta {
    bucket: String,
    name: String,
    mime: String,
    length: u64,
    role: String,
    sub: Option<String>,
}

/// Every tus response carries the protocol version.
pub async fn version_header(mut res: Response) -> Response {
    res.headers_mut()
        .insert("tus-resumable", HeaderValue::from_static(VERSION));
    res
}

fn check_version(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers.get("tus-resumable").and_then(|v| v.to_str().ok()) == Some(VERSION) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "unsupported_version",
            "Tus-Resumable must be 1.0.0",
        ))
    }
}

fn header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.parse().ok()
}

/// `key base64,key base64,...`; values are optional. `None` if malformed.
fn parse_metadata(raw: &str) -> Option<HashMap<String, String>> {
    let mut out = HashMap::new();
    for pair in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once(' ').unwrap_or((pair, ""));
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_graphic()) {
            return None;
        }
        let value = base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .ok()?;
        out.insert(key.to_owned(), String::from_utf8(value).ok()?);
    }
    Some(out)
}

fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", "upload not found")
}

fn conflict(message: &'static str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "conflict", message)
}

fn io_error(e: std::io::Error) -> ApiError {
    eprintln!("kilnbase-core: resumable upload io error: {e}");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal error",
    )
}

fn sub(caller: &Caller) -> Option<String> {
    caller
        .claims
        .get("sub")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn upload_dir(storage: &Storage, id: Uuid) -> PathBuf {
    storage.dir.join("uploads").join(id.to_string())
}

/// Loads an upload owned by `caller`. Unknown, malformed and foreign ids all look the same.
async fn open(storage: &Storage, id: &str, caller: &Caller) -> Result<(Uuid, Meta), ApiError> {
    let id = Uuid::parse_str(id).map_err(|_| not_found())?;
    let raw = match tokio::fs::read(upload_dir(storage, id).join("meta.json")).await {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(not_found()),
        Err(e) => return Err(io_error(e)),
    };
    let meta: Meta = serde_json::from_slice(&raw).map_err(|_| not_found())?;
    if meta.role != caller.role || meta.sub != sub(caller) {
        return Err(not_found());
    }
    Ok((id, meta))
}

/// Marks an upload as receiving data; released on drop, including when the client disconnects.
struct Busy<'a>(&'a Storage, Uuid);

impl<'a> Busy<'a> {
    fn take(storage: &'a Storage, id: Uuid) -> Result<Self, ApiError> {
        let mut set = storage
            .busy_uploads
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if set.insert(id) {
            Ok(Busy(storage, id))
        } else {
            Err(conflict("upload is already in progress"))
        }
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0
            .busy_uploads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.1);
    }
}

pub(crate) async fn sweep(storage: &Storage) {
    let Ok(mut entries) = tokio::fs::read_dir(storage.dir.join("uploads")).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        // Without `data` (a creation in progress, or one that failed) the directory's age counts.
        let meta = match tokio::fs::metadata(entry.path().join("data")).await {
            Ok(m) => Ok(m),
            Err(_) => tokio::fs::metadata(entry.path()).await,
        };
        let age = meta
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok());
        if age.is_some_and(|a| a > MAX_AGE) {
            let _ = tokio::fs::remove_dir_all(entry.path()).await;
        }
    }
}

/// POST: declares the object and its length; bytes follow in PATCH requests.
pub async fn create(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    check_version(&headers)?;
    let caller = auth::authorize(&st.keys, &headers)?;
    let length = header_u64(&headers, "upload-length")
        .ok_or_else(|| bad_request("Upload-Length is required"))?;
    let meta = headers
        .get("upload-metadata")
        .map_or(Some(HashMap::new()), |v| parse_metadata(v.to_str().ok()?))
        .ok_or_else(|| bad_request("invalid Upload-Metadata"))?;
    let field = |k: &str| meta.get(k).cloned();
    let bucket = field("bucketName").ok_or_else(|| bad_request("bucketName is required"))?;
    let name = field("objectName").ok_or_else(|| bad_request("objectName is required"))?;
    let content_type = field("contentType")
        .map(|v| HeaderValue::from_str(&v))
        .transpose()
        .map_err(|_| bad_request("invalid contentType"))?;
    let mime =
        mime_essence(content_type.as_ref()).ok_or_else(|| bad_request("invalid contentType"))?;

    let storage = &st.storage;
    let object = NewObject {
        bucket: &bucket,
        name: &name,
        mime: &mime,
        upsert: false,
    };
    if length > object.limit(storage).await? {
        return Err(too_large());
    }
    // Refuse up front what the final insert would refuse, so nobody can park data they may not store.
    object.check(storage, &caller).await?;
    sweep(storage).await;

    let id = Uuid::new_v4();
    let dir = upload_dir(storage, id);
    tokio::fs::create_dir(&dir).await.map_err(io_error)?;
    tokio::fs::File::create(dir.join("data"))
        .await
        .map_err(io_error)?;
    let meta = Meta {
        bucket,
        name,
        mime,
        length,
        role: caller.role.to_owned(),
        sub: sub(&caller),
    };
    let json = serde_json::to_vec(&meta).map_err(|_| bad_request("invalid metadata"))?;
    tokio::fs::write(dir.join("meta.json"), json)
        .await
        .map_err(io_error)?;

    let location = HeaderValue::from_str(&format!("/storage/v1/upload/resumable/{id}"))
        .map_err(|_| bad_request("invalid id"))?;
    Ok((StatusCode::CREATED, [(header::LOCATION, location)]).into_response())
}

/// HEAD: how many bytes the server has, so the client knows where to resume.
pub async fn status(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    check_version(&headers)?;
    let caller = auth::authorize(&st.keys, &headers)?;
    let (id, meta) = open(&st.storage, &id, &caller).await?;
    let offset = tokio::fs::metadata(upload_dir(&st.storage, id).join("data"))
        .await
        .map_err(io_error)?
        .len();
    Ok((
        StatusCode::OK,
        [
            ("upload-offset", HeaderValue::from(offset)),
            ("upload-length", HeaderValue::from(meta.length)),
            ("cache-control", HeaderValue::from_static("no-store")),
        ],
    )
        .into_response())
}

/// PATCH: appends bytes at `Upload-Offset`; the last byte turns the upload into an object.
pub async fn append(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let (parts, mut body) = req.into_parts();
    let storage = &st.storage;
    let checked = async {
        check_version(&parts.headers)?;
        let caller = auth::authorize(&st.keys, &parts.headers)?;
        if parts
            .headers
            .get(header::CONTENT_TYPE)
            .map(HeaderValue::as_bytes)
            != Some(b"application/offset+octet-stream")
        {
            return Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid_content_type",
                "Content-Type must be application/offset+octet-stream",
            ));
        }
        let offset = header_u64(&parts.headers, "upload-offset")
            .ok_or_else(|| bad_request("Upload-Offset is required"))?;
        let (id, meta) = open(storage, &id, &caller).await?;
        let busy = Busy::take(storage, id)?;

        let data_path = upload_dir(storage, id).join("data");
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&data_path)
            .await
            .map_err(io_error)?;
        let size = file.metadata().await.map_err(io_error)?.len();
        if offset != size {
            return Err(conflict("Upload-Offset does not match the stored length"));
        }
        file.seek(SeekFrom::Start(size)).await.map_err(io_error)?;
        Ok((caller, id, meta, busy, data_path, file, size))
    }
    .await;
    let (caller, id, meta, _busy, data_path, mut file, mut size) = match checked {
        Ok(v) => v,
        Err(e) => return Err(drain(body, e).await),
    };

    let mut interrupted = false;
    while let Some(frame) = body.frame().await {
        // Bytes already written stay: that is what makes the upload resumable.
        let Ok(frame) = frame else {
            interrupted = true;
            break;
        };
        if let Ok(data) = frame.into_data() {
            if size + data.len() as u64 > meta.length {
                return Err(too_large());
            }
            file.write_all(&data).await.map_err(io_error)?;
            // Wait for the write to land, so a dropped request cannot leave one in flight.
            file.flush().await.map_err(io_error)?;
            size += data.len() as u64;
        }
    }
    file.sync_all().await.map_err(io_error)?;
    drop(file);
    if interrupted {
        return Err(bad_request("upload interrupted"));
    }

    if size == meta.length {
        // The finishing caller's own token decides: it may be newer than the one that created it.
        let object = NewObject {
            bucket: &meta.bucket,
            name: &meta.name,
            mime: &meta.mime,
            upsert: false,
        };
        object.store(storage, &caller, size, &data_path).await?;
        let _ = tokio::fs::remove_dir_all(upload_dir(storage, id)).await;
    }
    Ok((
        StatusCode::NO_CONTENT,
        [("upload-offset", HeaderValue::from(size))],
    )
        .into_response())
}

/// DELETE: abandons an upload and frees its space.
pub async fn terminate(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    check_version(&headers)?;
    let caller = auth::authorize(&st.keys, &headers)?;
    let (id, _) = open(&st.storage, &id, &caller).await?;
    let _busy = Busy::take(&st.storage, id)?;
    tokio::fs::remove_dir_all(upload_dir(&st.storage, id))
        .await
        .map_err(io_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata() {
        let m = parse_metadata("bucketName YQ==, objectName ZGlyL2YudHh0,empty").unwrap();
        assert_eq!(m["bucketName"], "a");
        assert_eq!(m["objectName"], "dir/f.txt");
        assert_eq!(m["empty"], "");
        assert!(parse_metadata("").unwrap().is_empty());
        assert!(parse_metadata("key !!notbase64").is_none());
        assert!(parse_metadata("key /w==").is_none(), "not utf-8");
    }

    proptest::proptest! {
        #[test]
        fn metadata_parsing_never_panics(s in r"\PC{0,80}") {
            let _ = parse_metadata(&s);
        }
    }
}
