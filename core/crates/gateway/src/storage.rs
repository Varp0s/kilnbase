use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use deadpool_postgres::Pool;
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

use crate::AppState;
use crate::auth::{self, Caller};
use crate::db;
use crate::error::ApiError;

pub struct Storage {
    pub pool: Pool,
    pub dir: PathBuf,
    pub max_file_size: u64,
    pub signing_key: hmac::Key,
    /// Image transformations are off unless an imgproxy instance is configured.
    pub imgproxy_url: Option<String>,
    /// Region S3 clients must sign for.
    pub s3_region: String,
    /// Access key id and secret that act as service_role over the S3 API.
    pub s3_keys: Option<(String, String)>,
    /// Resumable uploads currently receiving a PATCH.
    pub busy_uploads: std::sync::Mutex<std::collections::HashSet<uuid::Uuid>>,
}

const MAX_SIGNED_URL_LIFETIME: u64 = 7 * 24 * 3600;

impl Storage {
    pub async fn prepare_dirs(&self) -> std::io::Result<()> {
        tokio::fs::create_dir_all(self.dir.join("tmp")).await?;
        tokio::fs::create_dir_all(self.dir.join("uploads")).await?;
        tokio::fs::create_dir_all(self.dir.join("objects")).await
    }

    pub(crate) fn object_path(&self, id: &str) -> PathBuf {
        // Files are named by the database-generated UUID, never by the user-supplied name.
        self.dir.join("objects").join(id)
    }
}

/// Object names are `/`-separated paths; reject anything that could be read as traversal or
/// smuggle control characters into logs and headers.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 1024
        && !name.chars().any(|c| c.is_control() || c == '\\')
        && name
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

pub(crate) fn bad_request(message: &'static str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_request", message)
}

fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", "object not found")
}

pub(crate) fn too_large() -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
        "file exceeds the size limit",
    )
}

/// `type/subtype` without parameters, lower-cased; `None` if malformed.
pub(crate) fn mime_essence(raw: Option<&HeaderValue>) -> Option<String> {
    let Some(raw) = raw else {
        return Some("application/octet-stream".into());
    };
    let essence = raw
        .to_str()
        .ok()?
        .split(';')
        .next()?
        .trim()
        .to_ascii_lowercase();
    let (kind, sub) = essence.split_once('/')?;
    let token = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$&-^_.+".contains(c))
    };
    (token(kind) && token(sub)).then_some(essence)
}

fn mime_allowed(mime: &str, allowed: Option<&[String]>) -> bool {
    let Some(allowed) = allowed else { return true };
    allowed
        .iter()
        .any(|pattern| match pattern.strip_suffix("/*") {
            Some(prefix) => mime.split('/').next() == Some(prefix),
            None => pattern == mime,
        })
}

/// Deletes the file on drop unless `keep` is called; covers every early return during upload.
struct TempFile(Option<PathBuf>);

impl TempFile {
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// An uploaded body in a temp file, deleted on drop unless `keep` is called after it was stored.
pub(crate) struct Received {
    tmp: TempFile,
    pub path: PathBuf,
    pub size: u64,
}

impl Received {
    pub fn keep(self) {
        self.tmp.keep();
    }
}

/// Streams `body` to a temp file, enforcing `limit` as bytes arrive rather than trusting headers.
/// `filter` sees every frame first (S3 uses it to strip aws-chunked framing and hash the payload).
pub(crate) async fn receive(
    storage: &Storage,
    mut body: Body,
    limit: u64,
    mut filter: impl FnMut(Bytes) -> Result<Bytes, ApiError>,
) -> Result<Received, ApiError> {
    let path = storage
        .dir
        .join("tmp")
        .join(uuid::Uuid::new_v4().to_string());
    let tmp = TempFile(Some(path.clone()));
    let mut file = tokio::fs::File::create(&path).await.map_err(io_error)?;
    let mut size: u64 = 0;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| bad_request("upload interrupted"))?;
        if let Ok(data) = frame.into_data() {
            let data = filter(data)?;
            size += data.len() as u64;
            if size > limit {
                return Err(too_large());
            }
            file.write_all(&data).await.map_err(io_error)?;
        }
    }
    file.sync_all().await.map_err(io_error)?;
    Ok(Received { tmp, path, size })
}

struct BucketSettings {
    file_size_limit: Option<i64>,
    allowed_mime_types: Option<Vec<String>>,
}

async fn bucket_settings(pool: &Pool, bucket: &str) -> Result<BucketSettings, ApiError> {
    let mut client = db::client(pool).await?;
    let tx = db::begin_as_service(&mut client).await?;
    let row = tx
        .query_opt(
            "select file_size_limit, allowed_mime_types from storage.buckets where id = $1",
            &[&bucket],
        )
        .await
        .map_err(db::internal)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "bucket_not_found",
                "bucket not found",
            )
        })?;
    Ok(BucketSettings {
        file_size_limit: row.get(0),
        allowed_mime_types: row.get(1),
    })
}

/// What is about to be written; shared by plain and resumable uploads.
pub(crate) struct NewObject<'a> {
    pub bucket: &'a str,
    pub name: &'a str,
    pub mime: &'a str,
    pub upsert: bool,
}

impl NewObject<'_> {
    /// Validates the name and the bucket's MIME allow-list; returns the size limit in bytes.
    pub(crate) async fn limit(&self, storage: &Storage) -> Result<u64, ApiError> {
        if !valid_name(self.name) {
            return Err(bad_request("invalid object name"));
        }
        let settings = bucket_settings(&storage.pool, self.bucket).await?;
        if !mime_allowed(self.mime, settings.allowed_mime_types.as_deref()) {
            return Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "mime_type_not_allowed",
                "this bucket does not accept that content-type",
            ));
        }
        Ok(settings.file_size_limit.map_or(storage.max_file_size, |l| {
            (l as u64).min(storage.max_file_size)
        }))
    }

    fn sql(&self) -> &'static str {
        if self.upsert {
            "insert into storage.objects (bucket_id, name, size, mime_type) values ($1, $2, $3, $4)
             on conflict (bucket_id, name) do update
                set size = excluded.size, mime_type = excluded.mime_type, updated_at = now()
             returning id::text"
        } else {
            "insert into storage.objects (bucket_id, name, size, mime_type) values ($1, $2, $3, $4)
             returning id::text"
        }
    }

    /// Runs the insert as `caller` and rolls it back, so RLS and name conflicts are reported
    /// before any bytes are accepted.
    pub(crate) async fn check(&self, storage: &Storage, caller: &Caller) -> Result<(), ApiError> {
        let mut client = db::client(&storage.pool).await?;
        let tx = db::begin_as(&mut client, caller).await?;
        tx.query_one(self.sql(), &[&self.bucket, &self.name, &0i64, &self.mime])
            .await
            .map_err(db::internal)?;
        Ok(())
    }

    /// Inserts the row as `caller` and moves the finished file at `src` into place.
    pub(crate) async fn store(
        &self,
        storage: &Storage,
        caller: &Caller,
        size: u64,
        src: &std::path::Path,
    ) -> Result<String, ApiError> {
        let mut client = db::client(&storage.pool).await?;
        let tx = db::begin_as(&mut client, caller).await?;
        let id: String = tx
            .query_one(
                self.sql(),
                &[&self.bucket, &self.name, &(size as i64), &self.mime],
            )
            .await
            .map_err(db::internal)?
            .get(0);
        // Rename before commit: a failed commit leaves an orphan file, never a row without data.
        tokio::fs::rename(src, storage.object_path(&id))
            .await
            .map_err(io_error)?;
        tx.commit().await.map_err(db::internal)?;
        Ok(id)
    }
}

/// Reads a small rejected body before answering: closing with unread bytes sends a TCP reset,
/// and the client would see a broken connection instead of the error.
pub(crate) async fn drain<E>(body: Body, e: E) -> E {
    let limited = http_body_util::Limited::new(body, 64 * 1024);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), limited.collect()).await;
    e
}

/// POST creates (409 if the name is taken); PUT creates or replaces.
pub async fn upload(
    State(st): State<Arc<AppState>>,
    Path((bucket, name)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ApiError> {
    let (parts, body) = req.into_parts();
    let upsert = parts.method == Method::PUT;
    let checked = async {
        let caller = auth::authorize(&st.keys, &parts.headers)?;
        let mime = mime_essence(parts.headers.get(header::CONTENT_TYPE))
            .ok_or_else(|| bad_request("invalid content-type"))?;
        let object = NewObject {
            bucket: &bucket,
            name: &name,
            mime: &mime,
            upsert,
        };
        let limit = object.limit(&st.storage).await?;
        let declared = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
        if declared.is_some_and(|len| len > limit) {
            return Err(too_large());
        }
        Ok((caller, mime, limit))
    }
    .await;
    let (caller, mime, limit) = match checked {
        Ok(v) => v,
        Err(e) => return Err(drain(body, e).await),
    };
    let storage = &st.storage;
    let object = NewObject {
        bucket: &bucket,
        name: &name,
        mime: &mime,
        upsert,
    };

    let received = receive(storage, body, limit, Ok).await?;
    let size = received.size;
    let id = object.store(storage, &caller, size, &received.path).await?;
    received.keep();

    Ok(
        Json(json!({ "id": id, "bucket": bucket, "name": name, "size": size, "mime_type": mime }))
            .into_response(),
    )
}

pub async fn download(
    State(st): State<Arc<AppState>>,
    Path((bucket, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let caller = auth::authorize(&st.keys, &headers)?;
    let object = find_as(&st.storage, Some(&caller), &bucket, &name, false).await?;
    serve(&st.storage, object, "private, no-store").await
}

pub async fn download_public(
    State(st): State<Arc<AppState>>,
    Path((bucket, name)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let object = find_as(&st.storage, None, &bucket, &name, true).await?;
    serve(&st.storage, object, "public, max-age=3600").await
}

pub async fn delete(
    State(st): State<Arc<AppState>>,
    Path((bucket, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let caller = auth::authorize(&st.keys, &headers)?;
    remove(&st.storage, &caller, &bucket, &name).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Deletes the row as `caller` (RLS decides), then the file; `not_found` if there was no row.
pub(crate) async fn remove(
    storage: &Storage,
    caller: &Caller,
    bucket: &str,
    name: &str,
) -> Result<(), ApiError> {
    let mut client = db::client(&storage.pool).await?;
    let tx = db::begin_as(&mut client, caller).await?;
    let row = tx
        .query_opt(
            "delete from storage.objects where bucket_id = $1 and name = $2 returning id::text",
            &[&bucket, &name],
        )
        .await
        .map_err(db::internal)?
        .ok_or_else(not_found)?;
    tx.commit().await.map_err(db::internal)?;
    let id: String = row.get(0);
    if let Err(e) = tokio::fs::remove_file(storage.object_path(&id)).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("kilnbase-core: could not remove object file {id}: {e}");
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct SignRequest {
    expires_in: u64,
}

pub async fn sign(
    State(st): State<Arc<AppState>>,
    Path((bucket, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<SignRequest>,
) -> Result<Response, ApiError> {
    let caller = auth::authorize(&st.keys, &headers)?;
    if body.expires_in == 0 || body.expires_in > MAX_SIGNED_URL_LIFETIME {
        return Err(bad_request(
            "expires_in must be between 1 second and 7 days",
        ));
    }
    // Only someone who can read the object may share it.
    find_as(&st.storage, Some(&caller), &bucket, &name, false).await?;
    let exp = now() + body.expires_in;
    let tag = hmac::sign(
        &st.storage.signing_key,
        signed_message(&bucket, &name, exp).as_bytes(),
    );
    let token = format!("{exp}.{}", hex(tag.as_ref()));
    let url = format!(
        "/storage/v1/object/sign/{bucket}/{}?token={token}",
        encode_path(&name)
    );
    Ok(Json(json!({ "signed_url": url, "expires_at": exp })).into_response())
}

#[derive(Deserialize)]
pub struct SignedQuery {
    token: String,
}

pub async fn download_signed(
    State(st): State<Arc<AppState>>,
    Path((bucket, name)): Path<(String, String)>,
    Query(q): Query<SignedQuery>,
) -> Result<Response, ApiError> {
    let invalid = || {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_signature",
            "invalid or expired link",
        )
    };
    let (exp, tag) = q.token.split_once('.').ok_or_else(invalid)?;
    let exp: u64 = exp.parse().map_err(|_| invalid())?;
    let tag = unhex(tag).ok_or_else(invalid)?;
    if exp < now() {
        return Err(invalid());
    }
    // Constant-time comparison.
    hmac::verify(
        &st.storage.signing_key,
        signed_message(&bucket, &name, exp).as_bytes(),
        &tag,
    )
    .map_err(|_| invalid())?;
    let object = find_as(&st.storage, None, &bucket, &name, false).await?;
    serve(&st.storage, object, "private, no-store").await
}

struct ObjectRef {
    id: String,
    mime_type: String,
    size: i64,
}

/// Looks the object up as `caller` (RLS applies), or as service_role when `caller` is None —
/// only for public buckets or already-verified signed links.
async fn find_as(
    storage: &Storage,
    caller: Option<&Caller>,
    bucket: &str,
    name: &str,
    public_only: bool,
) -> Result<ObjectRef, ApiError> {
    if !valid_name(name) {
        return Err(not_found());
    }
    let mut client = db::client(&storage.pool).await?;
    let tx = match caller {
        Some(c) => db::begin_as(&mut client, c).await?,
        None => db::begin_as_service(&mut client).await?,
    };
    // Bucket rows have no user policies, so only service-role lookups may join them.
    let sql = if public_only {
        "select o.id::text, o.mime_type, o.size
           from storage.objects o join storage.buckets b on b.id = o.bucket_id
          where o.bucket_id = $1 and o.name = $2 and b.public"
    } else {
        "select id::text, mime_type, size from storage.objects where bucket_id = $1 and name = $2"
    };
    let row = tx
        .query_opt(sql, &[&bucket, &name])
        .await
        .map_err(db::internal)?
        // Missing and forbidden look the same, so object names cannot be probed.
        .ok_or_else(not_found)?;
    Ok(ObjectRef {
        id: row.get(0),
        mime_type: row.get(1),
        size: row.get(2),
    })
}

async fn serve(
    storage: &Storage,
    object: ObjectRef,
    cache: &'static str,
) -> Result<Response, ApiError> {
    let file = tokio::fs::File::open(storage.object_path(&object.id))
        .await
        .map_err(io_error)?;
    let mut res = Body::from_stream(ReaderStream::new(file)).into_response();
    let h = res.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&object.mime_type) {
        h.insert(header::CONTENT_TYPE, v);
    }
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(object.size));
    content_headers(h, cache);
    Ok(res)
}

pub(crate) fn content_headers(h: &mut HeaderMap, cache: &'static str) {
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    // Uploaded HTML/SVG must never run as script on the API's origin.
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
}

const MAX_DIMENSION: u32 = 2500;

#[derive(Deserialize)]
pub struct Transform {
    width: Option<u32>,
    height: Option<u32>,
    resize: Option<String>,
    quality: Option<u8>,
    format: Option<String>,
}

impl Transform {
    /// imgproxy processing options, built only from validated values so callers cannot pass
    /// arbitrary options (or a different source) through.
    fn options(&self) -> Result<String, ApiError> {
        let dim = |v: Option<u32>| match v {
            None => Ok(0),
            Some(n @ 1..=MAX_DIMENSION) => Ok(n),
            Some(_) => Err(bad_request("width and height must be between 1 and 2500")),
        };
        let (w, h) = (dim(self.width)?, dim(self.height)?);
        let resize = match self.resize.as_deref().unwrap_or("cover") {
            "cover" => "fill",
            "contain" => "fit",
            "fill" => "force",
            _ => return Err(bad_request("resize must be cover, contain or fill")),
        };
        let mut opts = format!("rs:{resize}:{w}:{h}");
        match self.quality {
            None => {}
            Some(q @ 1..=100) => opts.push_str(&format!("/q:{q}")),
            Some(_) => return Err(bad_request("quality must be between 1 and 100")),
        }
        match self.format.as_deref().unwrap_or("origin") {
            "origin" => {}
            f @ ("webp" | "avif" | "jpeg" | "png") => opts.push_str(&format!("/f:{f}")),
            _ => {
                return Err(bad_request(
                    "format must be origin, webp, avif, jpeg or png",
                ));
            }
        }
        Ok(opts)
    }
}

pub async fn render(
    State(st): State<Arc<AppState>>,
    Path((bucket, name)): Path<(String, String)>,
    Query(t): Query<Transform>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let caller = auth::authorize(&st.keys, &headers)?;
    let options = t.options()?;
    let object = find_as(&st.storage, Some(&caller), &bucket, &name, false).await?;
    transform(&st, object, &options, "private, no-store").await
}

pub async fn render_public(
    State(st): State<Arc<AppState>>,
    Path((bucket, name)): Path<(String, String)>,
    Query(t): Query<Transform>,
) -> Result<Response, ApiError> {
    let options = t.options()?;
    let object = find_as(&st.storage, None, &bucket, &name, true).await?;
    transform(&st, object, &options, "public, max-age=3600").await
}

async fn transform(
    st: &AppState,
    object: ObjectRef,
    options: &str,
    cache: &'static str,
) -> Result<Response, ApiError> {
    let Some(base) = &st.storage.imgproxy_url else {
        return Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "transformations_disabled",
            "image transformations are not enabled on this server",
        ));
    };
    if !object.mime_type.starts_with("image/") {
        return Err(bad_request("only images can be transformed"));
    }
    // imgproxy is reachable only from core (internal network), so URLs are unsigned; the id is
    // a database UUID and needs no escaping.
    let uri: Uri = format!("{base}/_/{options}/plain/local:///objects/{}", object.id)
        .parse()
        .map_err(|_| bad_request("invalid transformation"))?;
    let res = st.http.get(uri).await.map_err(|e| {
        eprintln!("kilnbase-core: imgproxy error: {e}");
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "upstream_unavailable",
            "image service unavailable",
        )
    })?;
    if !res.status().is_success() {
        eprintln!("kilnbase-core: imgproxy answered {}", res.status());
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "cannot_transform",
            "the image could not be transformed",
        ));
    }
    let content_type = res.headers().get(header::CONTENT_TYPE).cloned();
    let mut out = Body::new(res.into_body()).into_response();
    let h = out.headers_mut();
    if let Some(v) = content_type {
        h.insert(header::CONTENT_TYPE, v);
    }
    content_headers(h, cache);
    Ok(out)
}

#[derive(Deserialize)]
pub struct NewBucket {
    id: String,
    #[serde(default)]
    public: bool,
    file_size_limit: Option<i64>,
    allowed_mime_types: Option<Vec<String>>,
}

pub async fn create_bucket(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<NewBucket>,
) -> Result<Response, ApiError> {
    let caller = auth::authorize(&st.keys, &headers)?;
    if caller.role != "service_role" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "creating buckets requires the service_role key",
        ));
    }
    let mut client = db::client(&st.storage.pool).await?;
    let tx = db::begin_as(&mut client, &caller).await?;
    tx.execute(
        "insert into storage.buckets (id, public, file_size_limit, allowed_mime_types)
         values ($1, $2, $3, $4)",
        &[
            &body.id,
            &body.public,
            &body.file_size_limit,
            &body.allowed_mime_types,
        ],
    )
    .await
    .map_err(db::internal)?;
    tx.commit().await.map_err(db::internal)?;
    Ok((StatusCode::CREATED, Json(json!({ "id": body.id }))).into_response())
}

fn signed_message(bucket: &str, name: &str, exp: u64) -> String {
    // Neither bucket ids nor valid names can contain '\n', so the fields cannot be shifted.
    format!("{bucket}\n{name}\n{exp}")
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn encode_path(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn io_error(e: std::io::Error) -> ApiError {
    eprintln!("kilnbase-core: storage io error: {e}");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal error",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in [
            "a.txt",
            "dir/sub/file.png",
            "unicode-ğüş.txt",
            "with space.txt",
        ] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "", "/abs", "a//b", "../x", "a/../b", "a/./b", "a/", "a\\b", "a\nb", "a\0b",
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert!(!valid_name(&"a".repeat(1025)));
    }

    #[test]
    fn mime_parsing_and_allow_list() {
        assert_eq!(
            mime_essence(None).as_deref(),
            Some("application/octet-stream")
        );
        let png = HeaderValue::from_static("Image/PNG; charset=x");
        assert_eq!(mime_essence(Some(&png)).as_deref(), Some("image/png"));
        let bad = HeaderValue::from_static("nonsense");
        assert_eq!(mime_essence(Some(&bad)), None);

        let allowed = vec!["image/*".to_string(), "application/pdf".to_string()];
        assert!(mime_allowed("image/png", Some(&allowed)));
        assert!(mime_allowed("application/pdf", Some(&allowed)));
        assert!(!mime_allowed("text/html", Some(&allowed)));
        assert!(mime_allowed("text/html", None));
    }

    #[test]
    fn hex_round_trip_and_path_encoding() {
        assert_eq!(unhex(&hex(&[0, 15, 255])).unwrap(), vec![0, 15, 255]);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
        assert_eq!(encode_path("a b/ğ?.txt"), "a%20b/%C4%9F%3F.txt");
    }

    #[test]
    fn transform_options() {
        let t = |w, h, resize: Option<&str>, q, f: Option<&str>| {
            Transform {
                width: w,
                height: h,
                resize: resize.map(Into::into),
                quality: q,
                format: f.map(Into::into),
            }
            .options()
        };
        assert_eq!(t(None, None, None, None, None).unwrap(), "rs:fill:0:0");
        assert_eq!(
            t(
                Some(200),
                Some(100),
                Some("contain"),
                Some(70),
                Some("webp")
            )
            .unwrap(),
            "rs:fit:200:100/q:70/f:webp"
        );
        assert!(t(Some(0), None, None, None, None).is_err());
        assert!(t(Some(2501), None, None, None, None).is_err());
        assert!(t(None, None, Some("rs:x"), None, None).is_err());
        assert!(t(None, None, None, Some(0), None).is_err());
        assert!(t(None, None, None, None, Some("webp/plain/http:")).is_err());
    }

    proptest::proptest! {
        #[test]
        fn accepted_names_never_traverse(name in r"\PC{0,64}|[a-z./\\]{0,16}") {
            if valid_name(&name) {
                proptest::prop_assert!(!name.starts_with('/'));
                proptest::prop_assert!(name.split('/').all(|s| s != ".." && s != "." && !s.is_empty()));
                proptest::prop_assert!(!name.contains('\\'));
                proptest::prop_assert!(!name.chars().any(char::is_control));
            }
        }

        #[test]
        fn signature_decoding_never_panics(s in r"\PC{0,80}") {
            let _ = unhex(&s);
        }

        #[test]
        fn encoded_paths_only_contain_safe_bytes(name in r"\PC{0,64}") {
            let encoded = encode_path(&name);
            proptest::prop_assert!(encoded.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~/%".contains(&b)));
        }
    }
}
