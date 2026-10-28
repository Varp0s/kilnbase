//! S3-compatible API at `/storage/v1/s3` (path-style addressing) so existing S3 tools and SDKs
//! work. Requests are verified with SigV4, then go through the same RLS-checked paths as the
//! native storage API.
//!
//! Credentials: the configured key pair acts as service_role and belongs on servers only. Any
//! other access key id must come with `x-amz-security-token` holding a Kilnbase access token,
//! which is also the signing secret, so apps never hold a shared secret.

use std::path::PathBuf;
use std::sync::Arc;

use aws_lc_rs::{digest, hmac};
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::AppState;
use crate::auth::{self, Caller};
use crate::db;
use crate::error::ApiError;
use crate::storage::{self, NewObject, bad_request, hex, now, unhex};
use crate::tus;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const PREFIX: &str = "/storage/v1/s3";
const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const MAX_SKEW: u64 = 15 * 60;
const MAX_PRESIGN: u64 = 7 * 24 * 3600;
const XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
const ISO_DATE: &str = r#"to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')"#;

pub struct S3Error {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

fn err(status: StatusCode, code: &'static str, message: &'static str) -> S3Error {
    S3Error {
        status,
        code,
        message,
    }
}

fn denied(message: &'static str) -> S3Error {
    err(StatusCode::FORBIDDEN, "AccessDenied", message)
}

fn not_implemented() -> S3Error {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        "this S3 operation is not supported",
    )
}

impl IntoResponse for S3Error {
    fn into_response(self) -> Response {
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>{}</Code><Message>{}</Message></Error>"#,
            self.code,
            xml(self.message)
        );
        (
            self.status,
            [(header::CONTENT_TYPE, "application/xml")],
            body,
        )
            .into_response()
    }
}

/// S3 clients only understand S3 error codes, so native errors are translated.
impl From<ApiError> for S3Error {
    fn from(e: ApiError) -> Self {
        let (status, code) = match e.code() {
            "not_found" => (StatusCode::NOT_FOUND, "NoSuchKey"),
            "bucket_not_found" => (StatusCode::NOT_FOUND, "NoSuchBucket"),
            "forbidden" | "unauthorized" => (StatusCode::FORBIDDEN, "AccessDenied"),
            "payload_too_large" => (StatusCode::BAD_REQUEST, "EntityTooLarge"),
            "invalid_request" | "mime_type_not_allowed" => {
                (StatusCode::BAD_REQUEST, "InvalidArgument")
            }
            "database_unavailable" => (StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable"),
            _ => (e.status(), "InternalError"),
        };
        err(status, code, e.message())
    }
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Undoes the escaping XML request bodies use for keys, including numeric references.
fn xml_unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let (entity, after) = rest[i + 1..].split_once(';')?;
        out.push(match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let n = match entity.strip_prefix("#x") {
                    Some(h) => u32::from_str_radix(h, 16).ok()?,
                    None => entity.strip_prefix('#')?.parse().ok()?,
                };
                char::from_u32(n)?
            }
        });
        rest = after;
    }
    out.push_str(rest);
    Some(out)
}

fn xml_response(body: String) -> Response {
    (
        [(header::CONTENT_TYPE, "application/xml")],
        format!(r#"<?xml version="1.0" encoding="UTF-8"?>{body}"#),
    )
        .into_response()
}

/// RFC 3986 encoding as SigV4 defines it: everything but unreserved characters, optionally `/`.
fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Decodes `%XX` escapes only; `+` stays a plus, as S3 clients mean it.
fn pct_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn parse_query(raw: &str) -> Option<Vec<(String, String)>> {
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            Some((pct_decode(k)?, pct_decode(v)?))
        })
        .collect()
}

struct Target {
    bucket: String,
    key: String,
    query: Vec<(String, String)>,
}

impl Target {
    fn parse(uri: &Uri) -> Option<Self> {
        let rest = uri.path().strip_prefix(PREFIX)?;
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
        Some(Target {
            bucket: pct_decode(bucket)?,
            key: pct_decode(key)?,
            query: parse_query(uri.query().unwrap_or(""))?,
        })
    }

    fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Sub-resources we don't implement (`?acl`, `?tagging`, `?uploads` …) must not fall
    /// through to the plain object or bucket operation.
    fn only_params(&self, allowed: &[&str]) -> Result<(), S3Error> {
        let ok = self
            .query
            .iter()
            .all(|(k, _)| k.starts_with("X-Amz-") || k == "x-id" || allowed.contains(&k.as_str()));
        if ok { Ok(()) } else { Err(not_implemented()) }
    }
}

// ---- SigV4 ----

/// `(credential, signed headers, signature)` from an `Authorization` header.
fn parse_authorization(v: &str) -> Option<(&str, &str, &str)> {
    let rest = v.strip_prefix(ALGORITHM)?.strip_prefix(' ')?;
    let (mut cred, mut signed, mut sig) = (None, None, None);
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=')?;
        match k {
            "Credential" => cred = Some(v),
            "SignedHeaders" => signed = Some(v),
            "Signature" => sig = Some(v),
            _ => {}
        }
    }
    Some((cred?, signed?, sig?))
}

fn canonical_request(
    method: &str,
    path: &str,
    query: &[(String, String)],
    headers: &HeaderMap,
    signed_headers: &str,
    payload_hash: &str,
) -> Option<String> {
    // Decode and re-encode, so the result is the once-encoded form whatever the client escaped.
    let uri = path
        .split('/')
        .map(|seg| pct_decode(seg).map(|s| uri_encode(&s, false)))
        .collect::<Option<Vec<_>>>()?
        .join("/");
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .filter(|(k, _)| k != "X-Amz-Signature")
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    pairs.sort();
    let query = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let mut canonical_headers = String::new();
    for name in signed_headers.split(';') {
        let values = headers
            .get_all(name)
            .iter()
            .map(|v| {
                Some(
                    v.to_str()
                        .ok()?
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" "),
                )
            })
            .collect::<Option<Vec<_>>>()?;
        if values.is_empty() {
            return None;
        }
        canonical_headers.push_str(&format!("{name}:{}\n", values.join(",")));
    }
    Some(format!(
        "{method}\n{uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    ))
}

fn signing_key(secret: &str, date: &str, region: &str) -> hmac::Key {
    let mac = |key: &[u8], data: &str| {
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes())
    };
    let k = mac(format!("AWS4{secret}").as_bytes(), date);
    let k = mac(k.as_ref(), region);
    let k = mac(k.as_ref(), "s3");
    let k = mac(k.as_ref(), "aws4_request");
    hmac::Key::new(hmac::HMAC_SHA256, k.as_ref())
}

fn string_to_sign(amz_date: &str, scope: &str, canonical: &str) -> String {
    let hash = digest::digest(&digest::SHA256, canonical.as_bytes());
    format!("{ALGORITHM}\n{amz_date}\n{scope}\n{}", hex(hash.as_ref()))
}

/// Seconds since the epoch for an `YYYYMMDDTHHMMSSZ` timestamp.
fn parse_amz_date(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 16
        || b[8] != b'T'
        || b[15] != b'Z'
        || !b
            .iter()
            .enumerate()
            .all(|(i, c)| i == 8 || i == 15 || c.is_ascii_digit())
    {
        return None;
    }
    let n = |from: usize, to: usize| s[from..to].parse::<i64>().ok();
    let (y, m, d) = (n(0, 4)?, n(4, 6)?, n(6, 8)?);
    let (hh, mm, ss) = (n(9, 11)?, n(11, 13)?, n(13, 15)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss).ok()
}

fn service_caller() -> Caller {
    Caller {
        token: String::new(),
        role: "service_role",
        claims: json!({ "role": "service_role" }),
    }
}

fn authenticate(
    st: &AppState,
    method: &Method,
    uri: &Uri,
    t: &Target,
    headers: &HeaderMap,
) -> Result<Caller, S3Error> {
    let header = |k: &str| headers.get(k).and_then(|v| v.to_str().ok());
    let mismatch = || {
        err(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "the request signature does not match",
        )
    };
    let presigned = t.param("X-Amz-Algorithm").is_some();
    let (credential, signed, signature, amz_date, payload_hash, expires) = if presigned {
        if t.param("X-Amz-Algorithm") != Some(ALGORITHM) {
            return Err(denied("unsupported signing algorithm"));
        }
        let expires = t
            .param("X-Amz-Expires")
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|e| (1..=MAX_PRESIGN).contains(e))
            .ok_or_else(|| denied("X-Amz-Expires must be between 1 second and 7 days"))?;
        (
            t.param("X-Amz-Credential"),
            t.param("X-Amz-SignedHeaders"),
            t.param("X-Amz-Signature"),
            t.param("X-Amz-Date"),
            Some("UNSIGNED-PAYLOAD"),
            Some(expires),
        )
    } else {
        let auth = header("authorization").ok_or_else(|| denied("missing credentials"))?;
        let (c, s, sig) =
            parse_authorization(auth).ok_or_else(|| denied("malformed Authorization header"))?;
        (
            Some(c),
            Some(s),
            Some(sig),
            header("x-amz-date"),
            header("x-amz-content-sha256"),
            None,
        )
    };
    let (Some(credential), Some(signed), Some(signature), Some(amz_date), Some(payload_hash)) =
        (credential, signed, signature, amz_date, payload_hash)
    else {
        return Err(denied("incomplete signature"));
    };

    // `<key id>/<date>/<region>/s3/aws4_request`; the key id is split off last as it is free-form.
    let mut scope = credential.rsplitn(5, '/');
    let (Some("aws4_request"), Some("s3"), Some(region), Some(date), Some(key_id)) = (
        scope.next(),
        scope.next(),
        scope.next(),
        scope.next(),
        scope.next(),
    ) else {
        return Err(denied("malformed credential scope"));
    };
    if region != st.storage.s3_region {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            "the credential scope names the wrong region",
        ));
    }
    if date.len() != 8 || !amz_date.starts_with(date) {
        return Err(denied("credential date does not match the request date"));
    }
    let signed_at = parse_amz_date(amz_date).ok_or_else(|| denied("invalid request date"))?;
    let now = now();
    let fresh = match expires {
        Some(e) => signed_at <= now + MAX_SKEW && now <= signed_at + e,
        None => signed_at.abs_diff(now) <= MAX_SKEW,
    };
    if !fresh {
        return Err(denied("request has expired or the clock is skewed"));
    }
    let signed_list: Vec<&str> = signed.split(';').collect();
    let required: &[&str] = if presigned {
        &["host"]
    } else {
        &["host", "x-amz-content-sha256", "x-amz-date"]
    };
    if required.iter().any(|r| !signed_list.contains(r)) {
        return Err(denied(
            "host, x-amz-date and x-amz-content-sha256 must be signed",
        ));
    }

    let token = header("x-amz-security-token").or(t.param("X-Amz-Security-Token"));
    let (secret, caller) = match &st.storage.s3_keys {
        Some((id, secret)) if id == key_id => (secret.as_str(), service_caller()),
        _ => {
            let token = token.ok_or_else(|| {
                err(
                    StatusCode::FORBIDDEN,
                    "InvalidAccessKeyId",
                    "unknown access key; send a Kilnbase access token as the session token",
                )
            })?;
            let caller = auth::verify_token(&st.keys, token).map_err(|_| {
                err(
                    StatusCode::FORBIDDEN,
                    "InvalidToken",
                    "invalid or expired session token",
                )
            })?;
            (token, caller)
        }
    };
    let canonical = canonical_request(
        method.as_str(),
        uri.path(),
        &t.query,
        headers,
        signed,
        payload_hash,
    )
    .ok_or_else(mismatch)?;
    let tag = unhex(signature).ok_or_else(mismatch)?;
    let sts = string_to_sign(
        amz_date,
        &format!("{date}/{region}/s3/aws4_request"),
        &canonical,
    );
    // Constant-time comparison.
    hmac::verify(&signing_key(secret, date, region), sts.as_bytes(), &tag)
        .map_err(|_| mismatch())?;
    Ok(caller)
}

// ---- aws-chunked ----

#[derive(Default, Clone, Copy, PartialEq, Debug)]
enum Chunk {
    #[default]
    Size,
    Data(u64),
    DataEnd,
    Trailer,
    Done,
}

/// Strips `aws-chunked` framing (what SDKs send for streamed uploads over TLS).
// shortcut: chunk signatures and checksum trailers are not verified, so these bodies get the
// same trust as UNSIGNED-PAYLOAD; verify them if integrity beyond TLS is ever required.
#[derive(Default)]
struct AwsChunked {
    state: Chunk,
    line: Vec<u8>,
}

impl AwsChunked {
    fn feed(&mut self, mut input: &[u8]) -> Result<Bytes, ()> {
        let mut out = Vec::with_capacity(input.len());
        while !input.is_empty() {
            match self.state {
                Chunk::Data(n) => {
                    let take = usize::try_from(n).map_or(input.len(), |n| n.min(input.len()));
                    out.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    let left = n - take as u64;
                    self.state = if left == 0 {
                        Chunk::DataEnd
                    } else {
                        Chunk::Data(left)
                    };
                }
                Chunk::Done => return Err(()),
                _ => match input.iter().position(|&b| b == b'\n') {
                    None => {
                        self.line.extend_from_slice(input);
                        input = &[];
                    }
                    Some(i) => {
                        self.line.extend_from_slice(&input[..=i]);
                        input = &input[i + 1..];
                        let line = std::mem::take(&mut self.line);
                        self.on_line(line.strip_suffix(b"\r\n").ok_or(())?)?;
                    }
                },
            }
            if self.line.len() > 8192 {
                return Err(());
            }
        }
        Ok(Bytes::from(out))
    }

    fn on_line(&mut self, line: &[u8]) -> Result<(), ()> {
        self.state = match self.state {
            Chunk::Size => {
                let size = line.split(|&b| b == b';').next().ok_or(())?;
                let size = std::str::from_utf8(size).map_err(|_| ())?;
                if size.is_empty() || size.len() > 15 {
                    return Err(());
                }
                match u64::from_str_radix(size, 16).map_err(|_| ())? {
                    0 => Chunk::Trailer,
                    n => Chunk::Data(n),
                }
            }
            Chunk::DataEnd if line.is_empty() => Chunk::Size,
            Chunk::Trailer if line.is_empty() => Chunk::Done,
            Chunk::Trailer => Chunk::Trailer,
            _ => return Err(()),
        };
        Ok(())
    }
}

// ---- operations ----

pub async fn handle(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let Some(target) = Target::parse(&parts.uri) else {
        return storage::drain(
            body,
            err(
                StatusCode::BAD_REQUEST,
                "InvalidURI",
                "invalid request path",
            ),
        )
        .await
        .into_response();
    };
    let caller = match authenticate(&st, &parts.method, &parts.uri, &target, &parts.headers) {
        Ok(c) => c,
        Err(e) => return storage::drain(body, e).await.into_response(),
    };
    let (has_bucket, has_key) = (!target.bucket.is_empty(), !target.key.is_empty());
    let multipart = target.param("uploadId").is_some();
    // Operations that read the body return directly; the rest leave it unread.
    let with_body = match parts.method {
        Method::PUT if has_key && multipart => {
            Some(upload_part(&st, &caller, &target, &parts.headers, body).await)
        }
        Method::PUT if has_key && parts.headers.contains_key("x-amz-copy-source") => {
            Some(copy_object(&st, &caller, &target, &parts.headers).await)
        }
        Method::PUT if has_key => {
            Some(put_object(&st, &caller, &target, &parts.headers, body).await)
        }
        Method::POST if has_key && multipart => {
            Some(complete_multipart(&st, &caller, &target, &parts.headers, body).await)
        }
        Method::POST if has_bucket && !has_key && target.param("delete").is_some() => {
            Some(delete_objects(&st, &caller, &target, &parts.headers, body).await)
        }
        _ => None,
    };
    if let Some(result) = with_body {
        return result.unwrap_or_else(IntoResponse::into_response);
    }
    let result = match parts.method {
        Method::POST if has_key && target.param("uploads").is_some() => {
            create_multipart(&st, &caller, &target, &parts.headers).await
        }
        Method::DELETE if has_key && multipart => abort_multipart(&st, &caller, &target).await,
        Method::GET if !has_bucket => list_buckets(&st, &caller).await,
        Method::GET if !has_key && target.param("location").is_some() => {
            bucket_location(&st, &target).await
        }
        Method::GET if !has_key => list_objects(&st, &caller, &target).await,
        Method::HEAD if has_bucket && !has_key => head_bucket(&st, &target).await,
        Method::GET | Method::HEAD if has_key => {
            get_object(
                &st,
                &caller,
                &target,
                &parts.headers,
                parts.method == Method::HEAD,
            )
            .await
        }
        Method::DELETE if has_key => delete_object(&st, &caller, &target).await,
        _ => Err(not_implemented()),
    };
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn bucket_exists(st: &AppState, bucket: &str) -> Result<(), S3Error> {
    let mut client = db::client(&st.storage.pool).await?;
    let tx = db::begin_as_service(&mut client).await?;
    tx.query_opt("select 1 from storage.buckets where id = $1", &[&bucket])
        .await
        .map_err(db::internal)?
        .map(|_| ())
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
            )
        })
}

async fn head_bucket(st: &AppState, t: &Target) -> Result<Response, S3Error> {
    bucket_exists(st, &t.bucket).await?;
    Ok(StatusCode::OK.into_response())
}

async fn bucket_location(st: &AppState, t: &Target) -> Result<Response, S3Error> {
    bucket_exists(st, &t.bucket).await?;
    Ok(xml_response(format!(
        r#"<LocationConstraint xmlns="{XMLNS}">{}</LocationConstraint>"#,
        xml(&st.storage.s3_region)
    )))
}

/// Buckets visible to the caller; users see none unless a policy on `storage.buckets` allows it.
async fn list_buckets(st: &AppState, caller: &Caller) -> Result<Response, S3Error> {
    let mut client = db::client(&st.storage.pool).await?;
    let tx = db::begin_as(&mut client, caller).await?;
    let rows = tx
        .query(
            r#"select id, to_char(created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
                 from storage.buckets order by id"#,
            &[],
        )
        .await
        .map_err(db::internal)?;
    let mut body = format!(
        r#"<ListAllMyBucketsResult xmlns="{XMLNS}"><Owner><ID>kilnbase</ID></Owner><Buckets>"#
    );
    for row in rows {
        let (id, created): (String, String) = (row.get(0), row.get(1));
        body.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>{created}</CreationDate></Bucket>",
            xml(&id)
        ));
    }
    body.push_str("</Buckets></ListAllMyBucketsResult>");
    Ok(xml_response(body))
}

/// ListObjectsV2. Continuation tokens are the hex of the last key (or skipped prefix) returned.
async fn list_objects(st: &AppState, caller: &Caller, t: &Target) -> Result<Response, S3Error> {
    t.only_params(&[
        "list-type",
        "prefix",
        "delimiter",
        "max-keys",
        "continuation-token",
        "start-after",
        "encoding-type",
        "fetch-owner",
    ])?;
    if t.param("list-type") != Some("2") {
        return Err(err(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "only ListObjectsV2 (list-type=2) is supported",
        ));
    }
    let invalid = |m| err(StatusCode::BAD_REQUEST, "InvalidArgument", m);
    let prefix = t.param("prefix").unwrap_or("");
    let delimiter = t.param("delimiter").filter(|d| !d.is_empty());
    let max_keys = match t.param("max-keys") {
        None => 1000,
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| invalid("max-keys must be a number"))?
            .clamp(1, 1000),
    };
    let url_encoded = t.param("encoding-type") == Some("url");
    let mut cursor = match t.param("continuation-token") {
        Some(token) => unhex(token)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| invalid("invalid continuation token"))?,
        None => t.param("start-after").unwrap_or("").to_owned(),
    };
    bucket_exists(st, &t.bucket).await?;

    let mut client = db::client(&st.storage.pool).await?;
    let tx = db::begin_as(&mut client, caller).await?;
    let sql = format!(
        r#"select name, size, {ISO_DATE}, id::text from storage.objects
            where bucket_id = $1 and left(name, length($2)) = $2 and name collate "C" > $3
            order by name collate "C" limit 1000"#
    );
    let mut contents = String::new();
    let mut prefixes: Vec<String> = Vec::new();
    let mut count = 0;
    let mut next = None;
    // shortcut: one query per common prefix and the "C" collation skips the name index; fine
    // for thousands of objects, add an index on (bucket_id, name collate "C") if lists get slow.
    'pages: loop {
        let rows = tx
            .query(&sql, &[&t.bucket, &prefix, &cursor])
            .await
            .map_err(db::internal)?;
        let full_page = rows.len() == 1000;
        for row in rows {
            if count == max_keys {
                next = Some(cursor);
                break 'pages;
            }
            let name: String = row.get(0);
            if let Some(d) = delimiter
                && let Some(i) = name[prefix.len()..].find(d)
            {
                let common = name[..prefix.len() + i + d.len()].to_owned();
                // Everything else under this prefix sorts before this cursor in byte order.
                cursor = format!("{common}\u{10FFFF}");
                prefixes.push(common);
                count += 1;
                continue 'pages;
            }
            let (size, modified, id): (i64, String, String) = (row.get(1), row.get(2), row.get(3));
            contents.push_str(&format!(
                "<Contents><Key>{}</Key><LastModified>{modified}</LastModified><ETag>&quot;{id}&quot;</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                encode_key(&name, url_encoded)
            ));
            count += 1;
            cursor = name;
        }
        if !full_page {
            break;
        }
    }

    let mut body = format!(
        r#"<ListBucketResult xmlns="{XMLNS}"><Name>{}</Name><Prefix>{}</Prefix><KeyCount>{count}</KeyCount><MaxKeys>{max_keys}</MaxKeys><IsTruncated>{}</IsTruncated>"#,
        xml(&t.bucket),
        encode_key(prefix, url_encoded),
        next.is_some()
    );
    if let Some(d) = delimiter {
        body.push_str(&format!(
            "<Delimiter>{}</Delimiter>",
            encode_key(d, url_encoded)
        ));
    }
    if url_encoded {
        body.push_str("<EncodingType>url</EncodingType>");
    }
    if let Some(token) = t.param("continuation-token") {
        body.push_str(&format!(
            "<ContinuationToken>{}</ContinuationToken>",
            xml(token)
        ));
    }
    if let Some(after) = t.param("start-after") {
        body.push_str(&format!(
            "<StartAfter>{}</StartAfter>",
            encode_key(after, url_encoded)
        ));
    }
    if let Some(next) = next {
        body.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            hex(next.as_bytes())
        ));
    }
    body.push_str(&contents);
    for p in prefixes {
        body.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            encode_key(&p, url_encoded)
        ));
    }
    body.push_str("</ListBucketResult>");
    Ok(xml_response(body))
}

fn encode_key(key: &str, url_encoded: bool) -> String {
    if url_encoded {
        uri_encode(key, true)
    } else {
        xml(key)
    }
}

fn no_such_key() -> S3Error {
    err(
        StatusCode::NOT_FOUND,
        "NoSuchKey",
        "the specified key does not exist",
    )
}

/// `(start, len)` for an `x-amz-copy-source-range`, which must name both ends inside the source.
fn copy_range(raw: &str, size: u64) -> Option<(u64, u64)> {
    let (a, b) = raw.strip_prefix("bytes=")?.split_once('-')?;
    let (a, b) = (a.parse::<u64>().ok()?, b.parse::<u64>().ok()?);
    (a <= b && b < size).then(|| (a, b - a + 1))
}

/// `(start, len)` for a single `bytes=` range; `None` serves the whole object, as HTTP allows
/// for ranges a server does not understand.
fn parse_range(raw: &str, size: u64) -> Result<Option<(u64, u64)>, S3Error> {
    let Some(spec) = raw.strip_prefix("bytes=") else {
        return Ok(None);
    };
    if spec.contains(',') {
        return Ok(None);
    }
    let Some((a, b)) = spec.split_once('-') else {
        return Ok(None);
    };
    let unsatisfiable = || {
        err(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "the requested range is not satisfiable",
        )
    };
    let (start, end) = match (a.parse::<u64>().ok(), b.parse::<u64>().ok()) {
        (Some(s), Some(e)) if s <= e => (s, e.min(size.saturating_sub(1))),
        (Some(s), None) if b.is_empty() => (s, size.saturating_sub(1)),
        (None, Some(n)) if a.is_empty() && n > 0 => {
            (size.saturating_sub(n), size.saturating_sub(1))
        }
        _ => return Ok(None),
    };
    if size == 0 || start >= size {
        return Err(unsatisfiable());
    }
    Ok(Some((start, end - start + 1)))
}

async fn get_object(
    st: &AppState,
    caller: &Caller,
    t: &Target,
    headers: &HeaderMap,
    head: bool,
) -> Result<Response, S3Error> {
    t.only_params(&[])?;
    if !storage::valid_name(&t.key) {
        return Err(no_such_key());
    }
    let mut client = db::client(&st.storage.pool).await?;
    let tx = db::begin_as(&mut client, caller).await?;
    let row = tx
        .query_opt(
            r#"select id::text, mime_type, size,
                      to_char(updated_at at time zone 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS "GMT"')
                 from storage.objects where bucket_id = $1 and name = $2"#,
            &[&t.bucket, &t.key],
        )
        .await
        .map_err(db::internal)?
        .ok_or_else(no_such_key)?;
    drop(tx);
    let (id, mime, size, modified): (String, String, i64, String) =
        (row.get(0), row.get(1), row.get(2), row.get(3));
    let size = size as u64;
    let range = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        Some(raw) => parse_range(raw, size)?,
        None => None,
    };
    let (start, len) = range.unwrap_or((0, size));

    let body = if head {
        Body::empty()
    } else {
        let mut file = tokio::fs::File::open(st.storage.object_path(&id))
            .await
            .map_err(io_error)?;
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(io_error)?;
        Body::from_stream(ReaderStream::new(file.take(len)))
    };
    let mut res = body.into_response();
    if range.is_some() {
        *res.status_mut() = StatusCode::PARTIAL_CONTENT;
    }
    let h = res.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&mime) {
        h.insert(header::CONTENT_TYPE, v);
    }
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Ok(v) = HeaderValue::from_str(&format!("\"{id}\"")) {
        h.insert(header::ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(&modified) {
        h.insert(header::LAST_MODIFIED, v);
    }
    if range.is_some()
        && let Ok(v) = HeaderValue::from_str(&format!("bytes {start}-{}/{size}", start + len - 1))
    {
        h.insert(header::CONTENT_RANGE, v);
    }
    storage::content_headers(h, "private, no-store");
    Ok(res)
}

async fn put_object(
    st: &AppState,
    caller: &Caller,
    t: &Target,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    let storage = &st.storage;
    let checked = async {
        t.only_params(&[])?;
        let mime = storage::mime_essence(headers.get(header::CONTENT_TYPE))
            .ok_or_else(|| bad_request("invalid content-type"))?;
        let object = NewObject {
            bucket: &t.bucket,
            name: &t.key,
            mime: &mime,
            upsert: true,
        };
        let limit = object.limit(storage).await?;
        if declared_length(headers).is_some_and(|len| len > limit) {
            return Err(storage::too_large().into());
        }
        // RLS decides before any bytes are accepted.
        object.check(storage, caller).await?;
        Ok((mime, limit))
    }
    .await;
    let (mime, limit) = match checked {
        Ok(v) => v,
        Err(e) => return Err(storage::drain(body, e).await),
    };
    let received = receive_payload(st, headers, body, limit).await?;
    let object = NewObject {
        bucket: &t.bucket,
        name: &t.key,
        mime: &mime,
        upsert: true,
    };
    let id = object
        .store(storage, caller, received.size, &received.path)
        .await?;
    received.keep();
    let mut res = StatusCode::OK.into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("\"{id}\"")) {
        res.headers_mut().insert(header::ETAG, v);
    }
    Ok(res)
}

/// Whether an If-Match style list (`*`, or quoted ETags) names the object with this id.
fn etag_matches(list: &str, id: &str) -> bool {
    list.split(',')
        .map(|t| t.trim().trim_start_matches("W/").trim_matches('"'))
        .any(|t| t == "*" || t == id)
}

struct Source {
    id: String,
    mime: String,
    size: u64,
    modified: String,
}

/// The object `x-amz-copy-source` names, read as the caller so RLS decides.
async fn copy_source(
    st: &AppState,
    caller: &Caller,
    headers: &HeaderMap,
) -> Result<Source, S3Error> {
    let source = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // `?versionId=` and date preconditions would need history we don't keep; ETags we have.
    if source.contains('?')
        || headers.keys().any(|k| {
            k.as_str().starts_with("x-amz-copy-source-if-") && !k.as_str().ends_with("-match")
        })
    {
        return Err(not_implemented());
    }
    let (src_bucket, src_key) = pct_decode(source.strip_prefix('/').unwrap_or(source))
        .and_then(|s| s.split_once('/').map(|(b, k)| (b.to_owned(), k.to_owned())))
        .filter(|(b, k)| !b.is_empty() && !k.is_empty())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "x-amz-copy-source must be bucket/key",
            )
        })?;
    let mut client = db::client(&st.storage.pool).await?;
    let tx = db::begin_as(&mut client, caller).await?;
    let sql = format!(
        "select id::text, mime_type, size, {ISO_DATE} from storage.objects
          where bucket_id = $1 and name = $2"
    );
    let row = tx
        .query_opt(&sql, &[&src_bucket, &src_key])
        .await
        .map_err(db::internal)?
        .ok_or_else(no_such_key)?;
    let id: String = row.get(0);
    let matches = |name: &str| {
        let value = headers.get(name)?.to_str().ok()?;
        Some(etag_matches(value, &id))
    };
    if matches("x-amz-copy-source-if-match") == Some(false)
        || matches("x-amz-copy-source-if-none-match") == Some(true)
    {
        return Err(err(
            StatusCode::PRECONDITION_FAILED,
            "PreconditionFailed",
            "the copy source does not meet the precondition",
        ));
    }
    Ok(Source {
        id,
        mime: row.get(1),
        size: row.get::<_, i64>(2) as u64,
        modified: row.get(3),
    })
}

/// CopyObject. The source is read and the target written as the caller, so RLS decides both.
async fn copy_object(
    st: &AppState,
    caller: &Caller,
    t: &Target,
    headers: &HeaderMap,
) -> Result<Response, S3Error> {
    t.only_params(&[])?;
    let src = copy_source(st, caller, headers).await?;
    let mut mime = src.mime;
    if headers
        .get("x-amz-metadata-directive")
        .is_some_and(|v| v == "REPLACE")
    {
        mime = storage::mime_essence(headers.get(header::CONTENT_TYPE))
            .ok_or_else(|| bad_request("invalid content-type"))?;
    }
    let object = NewObject {
        bucket: &t.bucket,
        name: &t.key,
        mime: &mime,
        upsert: true,
    };
    let limit = object.limit(&st.storage).await?;
    // A source deleted meanwhile surfaces as `not_found`, i.e. NoSuchKey.
    let copied = storage::assemble(&st.storage, &[st.storage.object_path(&src.id)], limit).await?;
    let id = object
        .store(&st.storage, caller, copied.size, &copied.path)
        .await?;
    copied.keep();
    let modified: String = {
        let mut client = db::client(&st.storage.pool).await?;
        let tx = db::begin_as_service(&mut client).await?;
        let sql = format!("select {ISO_DATE} from storage.objects where id = $1::text::uuid");
        tx.query_one(&sql, &[&id])
            .await
            .map_err(db::internal)?
            .get(0)
    };
    Ok(xml_response(format!(
        r#"<CopyObjectResult xmlns="{XMLNS}"><LastModified>{modified}</LastModified><ETag>&quot;{id}&quot;</ETag></CopyObjectResult>"#
    )))
}

/// Reads a small XML request body, holding it to a declared x-amz-content-sha256.
async fn read_xml(headers: &HeaderMap, body: Body) -> Result<String, S3Error> {
    let malformed = || {
        err(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "the request body is not valid",
        )
    };
    let raw = http_body_util::Limited::new(body, 2 * 1024 * 1024)
        .collect()
        .await
        .map_err(|_| malformed())?
        .to_bytes();
    let (payload, _) = payload_mode(headers);
    let expected = (payload.len() == 64).then(|| unhex(payload)).flatten();
    if expected.is_some_and(|e| digest::digest(&digest::SHA256, &raw).as_ref() != e.as_slice()) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "XAmzContentSHA256Mismatch",
            "the payload does not match x-amz-content-sha256",
        ));
    }
    String::from_utf8(raw.to_vec()).map_err(|_| malformed())
}

/// `(keys, quiet)` from a DeleteObjects body.
fn delete_request(body: &str) -> Option<(Vec<String>, bool)> {
    let keys = body
        .split("<Key>")
        .skip(1)
        .map(|s| xml_unescape(s.split_once("</Key>")?.0))
        .collect::<Option<Vec<_>>>()?;
    let quiet = body
        .split_once("<Quiet>")
        .and_then(|(_, s)| s.split_once("</Quiet>"))
        .is_some_and(|(q, _)| q.trim() == "true");
    Some((keys, quiet))
}

/// DeleteObjects: up to 1000 keys, each removed as the caller; as with DeleteObject, a missing
/// key counts as deleted.
async fn delete_objects(
    st: &AppState,
    caller: &Caller,
    t: &Target,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    if let Err(e) = t.only_params(&["delete"]) {
        return Err(storage::drain(body, e).await);
    }
    let raw = read_xml(headers, body).await?;
    let (keys, quiet) = delete_request(&raw)
        .filter(|(k, _)| (1..=1000).contains(&k.len()))
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "list between 1 and 1000 keys to delete",
            )
        })?;
    bucket_exists(st, &t.bucket).await?;
    let mut out = format!(r#"<DeleteResult xmlns="{XMLNS}">"#);
    // shortcut: one transaction per key; batch them if large deletes get slow.
    for key in keys {
        match storage::remove(&st.storage, caller, &t.bucket, &key).await {
            Err(e) if e.code() != "not_found" => {
                let e = S3Error::from(e);
                out.push_str(&format!(
                    "<Error><Key>{}</Key><Code>{}</Code><Message>{}</Message></Error>",
                    xml(&key),
                    e.code,
                    xml(e.message)
                ));
            }
            _ if quiet => {}
            _ => out.push_str(&format!("<Deleted><Key>{}</Key></Deleted>", xml(&key))),
        }
    }
    out.push_str("</DeleteResult>");
    Ok(xml_response(out))
}

/// `(payload hash, aws-chunked)`; presigned uploads carry no hash header and are unsigned.
fn payload_mode(headers: &HeaderMap) -> (&str, bool) {
    let header = |k: &str| headers.get(k).and_then(|v| v.to_str().ok());
    let payload = header("x-amz-content-sha256").unwrap_or("UNSIGNED-PAYLOAD");
    let chunked = payload.starts_with("STREAMING-")
        || header("content-encoding").is_some_and(|v| v.contains("aws-chunked"));
    (payload, chunked)
}

/// The size the client says the object has, without aws-chunked framing.
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    let name = if payload_mode(headers).1 {
        "x-amz-decoded-content-length"
    } else {
        "content-length"
    };
    headers.get(name)?.to_str().ok()?.parse().ok()
}

/// Streams the body to a temp file, stripping aws-chunked framing and checking a declared SHA-256.
async fn receive_payload(
    st: &AppState,
    headers: &HeaderMap,
    body: Body,
    limit: u64,
) -> Result<storage::Received, S3Error> {
    let (payload, chunked) = payload_mode(headers);
    let expected = (payload.len() == 64).then(|| unhex(payload)).flatten();
    let mut decoder = chunked.then(AwsChunked::default);
    let mut hasher = digest::Context::new(&digest::SHA256);
    let received = storage::receive(&st.storage, body, limit, |data| {
        let data = match &mut decoder {
            Some(d) => d
                .feed(&data)
                .map_err(|()| bad_request("malformed aws-chunked body"))?,
            None => data,
        };
        hasher.update(&data);
        Ok(data)
    })
    .await?;
    if decoder.is_some_and(|d| d.state != Chunk::Done) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "IncompleteBody",
            "the aws-chunked body ended early",
        ));
    }
    if expected.is_some_and(|e| hasher.finish().as_ref() != e.as_slice()) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "XAmzContentSHA256Mismatch",
            "the payload does not match x-amz-content-sha256",
        ));
    }
    Ok(received)
}

// ---- multipart uploads ----
// Parts live in `uploads/s3-<id>/` next to tus uploads, so the same 24-hour sweep removes
// abandoned ones; the prefix keeps the two protocols from opening each other's uploads.

const MAX_PARTS: u32 = 10_000;

#[derive(Serialize, Deserialize)]
struct Multipart {
    bucket: String,
    name: String,
    mime: String,
    limit: u64,
    role: String,
    sub: Option<String>,
}

fn caller_sub(caller: &Caller) -> Option<String> {
    caller
        .claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn no_such_upload() -> S3Error {
    err(
        StatusCode::NOT_FOUND,
        "NoSuchUpload",
        "the specified upload does not exist",
    )
}

fn upload_dir(st: &AppState, id: Uuid) -> PathBuf {
    st.storage.dir.join("uploads").join(format!("s3-{id}"))
}

/// Loads an upload started by `caller` for this bucket and key; anything else looks missing.
async fn open_upload(
    st: &AppState,
    caller: &Caller,
    t: &Target,
) -> Result<(PathBuf, Multipart), S3Error> {
    let id = t
        .param("uploadId")
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or_else(no_such_upload)?;
    let dir = upload_dir(st, id);
    let raw = match tokio::fs::read(dir.join("meta.json")).await {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(no_such_upload()),
        Err(e) => return Err(io_error(e)),
    };
    let meta: Multipart = serde_json::from_slice(&raw).map_err(|_| no_such_upload())?;
    if meta.bucket != t.bucket
        || meta.name != t.key
        || meta.role != caller.role
        || meta.sub != caller_sub(caller)
    {
        return Err(no_such_upload());
    }
    Ok((dir, meta))
}

async fn create_multipart(
    st: &AppState,
    caller: &Caller,
    t: &Target,
    headers: &HeaderMap,
) -> Result<Response, S3Error> {
    t.only_params(&["uploads"])?;
    let mime = storage::mime_essence(headers.get(header::CONTENT_TYPE))
        .ok_or_else(|| bad_request("invalid content-type"))?;
    let object = NewObject {
        bucket: &t.bucket,
        name: &t.key,
        mime: &mime,
        upsert: true,
    };
    let limit = object.limit(&st.storage).await?;
    object.check(&st.storage, caller).await?;
    tus::sweep(&st.storage).await;

    let id = Uuid::new_v4();
    let dir = upload_dir(st, id);
    tokio::fs::create_dir(&dir).await.map_err(io_error)?;
    let meta = Multipart {
        bucket: t.bucket.clone(),
        name: t.key.clone(),
        mime,
        limit,
        role: caller.role.to_owned(),
        sub: caller_sub(caller),
    };
    let raw = serde_json::to_vec(&meta).map_err(|e| io_error(std::io::Error::other(e)))?;
    tokio::fs::write(dir.join("meta.json"), raw)
        .await
        .map_err(io_error)?;
    Ok(xml_response(format!(
        r#"<InitiateMultipartUploadResult xmlns="{XMLNS}"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>"#,
        xml(&t.bucket),
        xml(&t.key)
    )))
}

async fn upload_part(
    st: &AppState,
    caller: &Caller,
    t: &Target,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    let checked = async {
        t.only_params(&["partNumber", "uploadId"])?;
        let part = t
            .param("partNumber")
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|n| (1..=MAX_PARTS).contains(n))
            .ok_or_else(|| {
                err(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "partNumber must be between 1 and 10000",
                )
            })?;
        let (dir, meta) = open_upload(st, caller, t).await?;
        if declared_length(headers).is_some_and(|len| len > meta.limit) {
            return Err(storage::too_large().into());
        }
        Ok((part, dir, meta.limit))
    }
    .await;
    let (part, dir, limit) = match checked {
        Ok(v) => v,
        Err(e) => return Err(storage::drain(body, e).await),
    };
    let copied = if headers.contains_key("x-amz-copy-source") {
        Some(copy_source(st, caller, headers).await?)
    } else {
        None
    };
    let received = match &copied {
        None => receive_payload(st, headers, body, limit).await?,
        // UploadPartCopy: the part is (a range of) a stored object instead of the body.
        Some(src) => {
            let (start, len) = match headers.get("x-amz-copy-source-range") {
                None => (0, src.size),
                Some(v) => v
                    .to_str()
                    .ok()
                    .and_then(|v| copy_range(v, src.size))
                    .ok_or_else(|| {
                        err(
                            StatusCode::BAD_REQUEST,
                            "InvalidArgument",
                            "x-amz-copy-source-range must be bytes=first-last within the source",
                        )
                    })?,
            };
            let mut file = match tokio::fs::File::open(st.storage.object_path(&src.id)).await {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(no_such_key()),
                Err(e) => return Err(io_error(e)),
            };
            file.seek(std::io::SeekFrom::Start(start))
                .await
                .map_err(io_error)?;
            let body = Body::from_stream(ReaderStream::new(file.take(len)));
            storage::receive(&st.storage, body, limit, Ok).await?
        }
    };
    // Fails if the upload was completed or aborted meanwhile; the temp file is then dropped.
    tokio::fs::rename(&received.path, dir.join(format!("part-{part:05}")))
        .await
        .map_err(|_| no_such_upload())?;
    let size = received.size;
    received.keep();
    if let Some(src) = copied {
        return Ok(xml_response(format!(
            r#"<CopyPartResult xmlns="{XMLNS}"><LastModified>{}</LastModified><ETag>&quot;{part}-{size}&quot;</ETag></CopyPartResult>"#,
            src.modified
        )));
    }
    let mut res = StatusCode::OK.into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("\"{part}-{size}\"")) {
        res.headers_mut().insert(header::ETAG, v);
    }
    Ok(res)
}

/// Part numbers from a CompleteMultipartUpload body, in the order given.
fn completed_parts(body: &str) -> Option<Vec<u32>> {
    body.split("<PartNumber>")
        .skip(1)
        .map(|s| s.split("</PartNumber>").next()?.trim().parse().ok())
        .collect()
}

async fn complete_multipart(
    st: &AppState,
    caller: &Caller,
    t: &Target,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    let opened = async {
        t.only_params(&["uploadId"])?;
        open_upload(st, caller, t).await
    }
    .await;
    let (dir, meta) = match opened {
        Ok(v) => v,
        Err(e) => return Err(storage::drain(body, e).await),
    };
    let parts = completed_parts(&read_xml(headers, body).await?)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "the part list is not valid",
            )
        })?;
    if !parts.windows(2).all(|w| w[0] < w[1]) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "InvalidPartOrder",
            "parts must be listed in ascending order",
        ));
    }
    let files: Vec<PathBuf> = parts
        .iter()
        .map(|n| dir.join(format!("part-{n:05}")))
        .collect();
    let assembled = storage::assemble(&st.storage, &files, meta.limit)
        .await
        .map_err(|e| {
            if e.code() == "not_found" {
                err(
                    StatusCode::BAD_REQUEST,
                    "InvalidPart",
                    "a listed part was not uploaded",
                )
            } else {
                e.into()
            }
        })?;
    let object = NewObject {
        bucket: &meta.bucket,
        name: &meta.name,
        mime: &meta.mime,
        upsert: true,
    };
    let id = object
        .store(&st.storage, caller, assembled.size, &assembled.path)
        .await?;
    assembled.keep();
    let _ = tokio::fs::remove_dir_all(&dir).await;
    Ok(xml_response(format!(
        r#"<CompleteMultipartUploadResult xmlns="{XMLNS}"><Bucket>{}</Bucket><Key>{}</Key><ETag>&quot;{id}&quot;</ETag></CompleteMultipartUploadResult>"#,
        xml(&t.bucket),
        xml(&t.key)
    )))
}

async fn abort_multipart(st: &AppState, caller: &Caller, t: &Target) -> Result<Response, S3Error> {
    t.only_params(&["uploadId"])?;
    let (dir, _) = open_upload(st, caller, t).await?;
    tokio::fs::remove_dir_all(&dir).await.map_err(io_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// S3 answers 204 whether or not the key existed.
async fn delete_object(st: &AppState, caller: &Caller, t: &Target) -> Result<Response, S3Error> {
    t.only_params(&[])?;
    match storage::remove(&st.storage, caller, &t.bucket, &t.key).await {
        Ok(()) => {}
        Err(e) if e.code() == "not_found" => {}
        Err(e) => return Err(e.into()),
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn io_error(e: std::io::Error) -> S3Error {
    log_error!("s3 io error: {e}");
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalError",
        "internal error",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn sign(canonical: &str) -> String {
        let sts = string_to_sign(
            "20130524T000000Z",
            "20130524/us-east-1/s3/aws4_request",
            canonical,
        );
        hex(hmac::sign(
            &signing_key(SECRET, "20130524", "us-east-1"),
            sts.as_bytes(),
        )
        .as_ref())
    }

    /// The GET example from the AWS SigV4 documentation (header-based authentication).
    #[test]
    fn matches_aws_header_example() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_static("examplebucket.s3.amazonaws.com"),
        );
        headers.insert("range", HeaderValue::from_static("bytes=0-9"));
        headers.insert(
            "x-amz-content-sha256",
            HeaderValue::from_static(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        );
        headers.insert("x-amz-date", HeaderValue::from_static("20130524T000000Z"));
        let canonical = canonical_request(
            "GET",
            "/test.txt",
            &[],
            &headers,
            "host;range;x-amz-content-sha256;x-amz-date",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        assert_eq!(
            sign(&canonical),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// The presigned URL example from the AWS SigV4 documentation.
    #[test]
    fn matches_aws_presigned_example() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_static("examplebucket.s3.amazonaws.com"),
        );
        let query = parse_query(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=ignored",
        )
        .unwrap();
        let canonical = canonical_request(
            "GET",
            "/test.txt",
            &query,
            &headers,
            "host",
            "UNSIGNED-PAYLOAD",
        )
        .unwrap();
        assert_eq!(
            sign(&canonical),
            "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
        );
    }

    #[test]
    fn canonical_uri_is_encoded_once_whatever_the_client_escaped() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("h"));
        let c = |path| canonical_request("GET", path, &[], &headers, "host", "x").unwrap();
        assert_eq!(c("/b/a%20b%2Bc.txt"), c("/b/a b+c.txt"));
        assert!(c("/b/a%20b%2Bc.txt").starts_with("GET\n/b/a%20b%2Bc.txt\n"));
        assert!(c("/b/%C4%9F").starts_with("GET\n/b/%C4%9F\n"));
    }

    #[test]
    fn dates_and_authorization_parsing() {
        assert_eq!(parse_amz_date("20130524T000000Z"), Some(1_369_353_600));
        assert_eq!(parse_amz_date("19700101T000001Z"), Some(1));
        for bad in [
            "2013-05-24T000000Z",
            "20131324T000000Z",
            "20130524T000000",
            "+0130524T000000Z",
        ] {
            assert_eq!(parse_amz_date(bad), None, "{bad}");
        }
        assert_eq!(
            parse_authorization(
                "AWS4-HMAC-SHA256 Credential=AK/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc"
            ),
            Some((
                "AK/20130524/us-east-1/s3/aws4_request",
                "host;x-amz-date",
                "abc"
            ))
        );
        assert_eq!(parse_authorization("AWS4-HMAC-SHA256 Credential=AK"), None);
    }

    #[test]
    fn completed_part_lists() {
        let body = "<CompleteMultipartUpload><Part><ETag>\"1-5\"</ETag><PartNumber>1</PartNumber></Part><Part><PartNumber> 2 </PartNumber></Part></CompleteMultipartUpload>";
        assert_eq!(completed_parts(body), Some(vec![1, 2]));
        assert_eq!(completed_parts("<CompleteMultipartUpload/>"), Some(vec![]));
        assert_eq!(completed_parts("<PartNumber>x</PartNumber>"), None);
    }

    #[test]
    fn delete_requests_and_xml_entities() {
        let body = "<Delete><Quiet>true</Quiet><Object><Key>a&amp;b&#xD;&#38;.txt</Key></Object><Object><Key>c</Key><VersionId>x</VersionId></Object></Delete>";
        assert_eq!(
            delete_request(body),
            Some((vec!["a&b\r&.txt".to_owned(), "c".to_owned()], true))
        );
        assert_eq!(
            delete_request("<Delete><Object><Key>x</Key></Object></Delete>"),
            Some((vec!["x".to_owned()], false))
        );
        assert_eq!(delete_request("<Key>unclosed"), None);
        for bad in ["&bogus;", "&#xZZ;", "&#1114112;", "a & b"] {
            assert_eq!(xml_unescape(bad), None, "{bad}");
        }
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-9", 100).ok().flatten(), Some((0, 10)));
        assert_eq!(parse_range("bytes=90-", 100).ok().flatten(), Some((90, 10)));
        assert_eq!(parse_range("bytes=-10", 100).ok().flatten(), Some((90, 10)));
        assert_eq!(
            parse_range("bytes=95-200", 100).ok().flatten(),
            Some((95, 5))
        );
        assert_eq!(parse_range("bytes=0-1,5-6", 100).ok().flatten(), None);
        assert_eq!(parse_range("items=0-1", 100).ok().flatten(), None);
        assert!(parse_range("bytes=100-", 100).is_err());
        assert_eq!(copy_range("bytes=0-99", 100), Some((0, 100)));
        assert!(etag_matches("\"x\"", "x") && etag_matches("\"a\", W/\"x\"", "x"));
        assert!(etag_matches("*", "x") && !etag_matches("\"y\"", "x"));
        assert_eq!(copy_range("bytes=10-10", 100), Some((10, 1)));
        for bad in ["bytes=0-100", "bytes=5-4", "bytes=-5", "bytes=5-", "0-5"] {
            assert_eq!(copy_range(bad, 100), None, "{bad}");
        }
    }

    #[test]
    fn aws_chunked_decoding_across_frame_boundaries() {
        let body = b"5;chunk-signature=abc\r\nhello\r\n6\r\n world\r\n0\r\nx-amz-checksum-crc32:AAAA\r\n\r\n";
        for split in 0..body.len() {
            let mut d = AwsChunked::default();
            let mut out = d.feed(&body[..split]).unwrap().to_vec();
            out.extend_from_slice(&d.feed(&body[split..]).unwrap());
            assert_eq!(out, b"hello world", "split at {split}");
            assert_eq!(d.state, Chunk::Done);
        }
        for bad in [&b"zz\r\nhello"[..], b"5\r\nhelloXX\r\n", b"0\r\n\r\nextra"] {
            assert!(AwsChunked::default().feed(bad).is_err(), "{bad:?}");
        }
        let mut d = AwsChunked::default();
        d.feed(b"5\r\nhel").unwrap();
        assert_ne!(d.state, Chunk::Done);
    }

    proptest::proptest! {
        #[test]
        fn chunk_parser_never_panics(input in proptest::collection::vec(proptest::num::u8::ANY, 0..256)) {
            let _ = AwsChunked::default().feed(&input);
        }

        #[test]
        fn query_and_path_decoding_never_panics(s in r"\PC{0,64}") {
            let _ = parse_query(&s);
            let _ = pct_decode(&s);
            let _ = parse_amz_date(&s);
            let _ = parse_authorization(&s);
            let _ = delete_request(&s);
        }
    }
}
