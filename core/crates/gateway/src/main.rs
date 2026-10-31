// Declared first so its macros are in scope in every other module.
#[macro_use]
mod log;
mod auth;
mod channels;
mod config;
mod db;
mod error;
mod proxy;
mod realtime;
mod s3;
mod storage;
mod tus;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, head, post};
use axum::{Json, Router};
use jsonwebtoken::DecodingKey;
use serde_json::json;

struct AppState {
    keys: HashMap<String, DecodingKey>,
    postgrest_url: String,
    auth_url: String,
    functions_url: Option<String>,
    graphql_url: Option<String>,
    trusted_proxies: Vec<config::Cidr>,
    http: proxy::HttpClient,
    storage: storage::Storage,
    realtime: realtime::Hub,
    channels: channels::Channels,
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Some(dir) = std::env::var_os("KILNBASE_LOG_DIR").filter(|d| !d.is_empty())
        && let Err(e) = log::init_file(std::path::Path::new(&dir))
    {
        // Logging to a file is a convenience for Studio; stderr still works.
        log_error!("cannot write logs to {}: {e}", dir.to_string_lossy());
    }
    let cfg = match config::load(|k| std::env::var(k).ok()) {
        Ok(cfg) => cfg,
        Err(e) => {
            log_error!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let pool = match db::pool(&cfg.database_url) {
        Ok(p) => p,
        Err(e) => {
            log_error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let storage = storage::Storage {
        pool,
        dir: cfg.storage_dir,
        max_file_size: cfg.storage_max_file_size,
        signing_key: aws_lc_rs::hmac::Key::new(
            aws_lc_rs::hmac::HMAC_SHA256,
            cfg.storage_signing_key.as_bytes(),
        ),
        imgproxy_url: cfg.imgproxy_url,
        s3_region: cfg.s3_region,
        s3_keys: cfg.s3_keys,
        busy_uploads: Default::default(),
    };
    if let Err(e) = storage.prepare_dirs().await {
        log_error!(
            "storage directory {} is not writable: {e}",
            storage.dir.display()
        );
        return ExitCode::FAILURE;
    }

    let hub = realtime::hub();
    realtime::spawn_listener(cfg.database_url.clone(), storage.pool.clone(), hub.clone());

    let state = Arc::new(AppState {
        keys: cfg.keys,
        postgrest_url: cfg.postgrest_url,
        auth_url: cfg.auth_url,
        functions_url: cfg.functions_url,
        graphql_url: cfg.graphql_url,
        trusted_proxies: cfg.trusted_proxies,
        http: proxy::client(),
        storage,
        realtime: hub,
        channels: channels::Channels::default(),
    });
    let cors = cors_layer(cfg.cors_origins.as_deref());
    let resumable = Router::new()
        .route("/storage/v1/upload/resumable", post(tus::create))
        .route(
            "/storage/v1/upload/resumable/{id}",
            head(tus::status).patch(tus::append).delete(tus::terminate),
        )
        .route_layer(axum::middleware::map_response(tus::version_header));
    let app = Router::new()
        .route("/health", get(|| async { Json(json!({ "status": "ok" })) }))
        .route("/rest/v1/", any(rest))
        .route("/rest/v1/{*path}", any(rest))
        .route("/auth/v1/{*path}", any(auth_service))
        .route("/functions/v1/{name}", any(function))
        .route("/graphql/v1", any(graphql))
        .route("/realtime/v1/websocket", get(realtime::websocket))
        .route("/storage/v1/bucket", post(storage::create_bucket))
        .route(
            "/storage/v1/object/public/{bucket}/{*name}",
            get(storage::download_public),
        )
        .route(
            "/storage/v1/render/image/authenticated/{bucket}/{*name}",
            get(storage::render),
        )
        .route(
            "/storage/v1/render/image/public/{bucket}/{*name}",
            get(storage::render_public),
        )
        .route(
            "/storage/v1/object/sign/{bucket}/{*name}",
            get(storage::download_signed).post(storage::sign),
        )
        .route(
            "/storage/v1/object/{bucket}/{*name}",
            get(storage::download)
                .post(storage::upload)
                .put(storage::upload)
                .delete(storage::delete),
        )
        .route("/storage/v1/s3", any(s3::handle))
        .route("/storage/v1/s3/", any(s3::handle))
        .route("/storage/v1/s3/{*rest}", any(s3::handle))
        .merge(resumable)
        .layer(cors)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            client_address,
        ))
        .layer(axum::middleware::from_fn(log::access))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            log_error!("cannot bind {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    log_info!("listening on {addr}");

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        log_error!("server error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn rest(State(st): State<Arc<AppState>>, mut req: Request) -> Response {
    let token = match auth::authorize(&st.keys, req.headers()) {
        Ok(caller) => caller.token,
        Err(e) => return e.into_response(),
    };
    // Verified JWTs are base64url + dots, so this cannot fail; handled anyway rather than unwrapped.
    let Ok(bearer) = HeaderValue::from_str(&format!("Bearer {token}")) else {
        return error::ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", "invalid token")
            .into_response();
    };
    req.headers_mut().insert(header::AUTHORIZATION, bearer);
    req.headers_mut().remove("apikey");

    let path_and_query = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let upstream_path = path_and_query
        .strip_prefix("/rest/v1")
        .unwrap_or(path_and_query)
        .to_owned();
    proxy::forward(&st.http, &st.postgrest_url, &upstream_path, req).await
}

/// Upstream services (auth's rate limits, PostgREST's `request.headers`, functions) see the
/// client address in `x-forwarded-for` and nothing else a client claimed about itself.
async fn client_address(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let forwarded = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let ip = client_ip(peer.ip(), forwarded, &st.trusted_proxies);
    for name in [
        "forwarded",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
    ] {
        req.headers_mut().remove(name);
    }
    // Overwrite, never append: a client-supplied value would let callers dodge IP rate limits.
    if let Ok(value) = HeaderValue::from_str(&ip.to_string()) {
        req.headers_mut().insert("x-forwarded-for", value);
    }
    next.run(req).await
}

/// The peer, unless it is a trusted proxy: then the address it appended to `x-forwarded-for`
/// (the last one; earlier entries are whatever the client sent).
fn client_ip(peer: IpAddr, forwarded: Option<&str>, trusted: &[config::Cidr]) -> IpAddr {
    if !trusted.iter().any(|range| range.contains(peer)) {
        return peer;
    }
    forwarded
        .and_then(|list| list.rsplit(',').next())
        .and_then(|last| last.trim().parse().ok())
        .unwrap_or(peer)
}

/// Auth endpoints only need a valid API key: refresh calls legitimately carry expired access
/// tokens, and the auth service verifies bearer tokens itself where it needs them.
async fn auth_service(State(st): State<Arc<AppState>>, mut req: Request) -> Response {
    // Provider sign-in starts and ends with browser navigations, which cannot carry headers;
    // SAML IdPs return by posting a form to the callback.
    let browser_redirect = matches!(
        (req.method(), req.uri().path()),
        (&Method::GET, "/auth/v1/authorize" | "/auth/v1/callback")
            | (&Method::POST, "/auth/v1/callback")
    );
    if !browser_redirect && let Err(e) = auth::check_api_key(&st.keys, req.headers()) {
        return e.into_response();
    }
    req.headers_mut().remove("apikey");
    let path_and_query = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let upstream_path = path_and_query
        .strip_prefix("/auth/v1")
        .unwrap_or(path_and_query)
        .to_owned();
    proxy::forward(&st.http, &st.auth_url, &upstream_path, req).await
}

/// Largest request body passed to a function; the runner enforces the same limit on streams.
const FUNCTION_BODY_LIMIT: u64 = 1024 * 1024;

async fn function(
    State(st): State<Arc<AppState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    req: Request,
) -> Response {
    let not_found = || {
        error::ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such function").into_response()
    };
    let Some(upstream) = &st.functions_url else {
        return not_found();
    };
    if !valid_function_name(&name) {
        return not_found();
    }
    // Checked here so bad calls never reach the runner; the runner checks again, since code
    // running inside it can call it directly.
    if let Err(e) = auth::authorize(&st.keys, req.headers()) {
        return e.into_response();
    }
    let too_large = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > FUNCTION_BODY_LIMIT);
    if too_large {
        return error::ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "request body is larger than 1 MiB",
        )
        .into_response();
    }
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    proxy::forward(&st.http, upstream, &format!("/{name}{query}"), req).await
}

/// Checked here like every API call; the GraphQL service verifies the token again itself.
async fn graphql(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let Some(upstream) = &st.graphql_url else {
        return error::ApiError::new(StatusCode::NOT_FOUND, "not_found", "GraphQL is not enabled")
            .into_response();
    };
    if let Err(e) = auth::authorize(&st.keys, req.headers()) {
        return e.into_response();
    }
    let path = req
        .uri()
        .query()
        .map_or("/".to_owned(), |q| format!("/?{q}"));
    proxy::forward(&st.http, upstream, &path, req).await
}

fn valid_function_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn cors_layer(origins: Option<&[String]>) -> tower_http::cors::CorsLayer {
    use axum::http::HeaderName;
    use tower_http::cors::{AllowOrigin, CorsLayer};

    let allow_origin = match origins {
        None => AllowOrigin::any(),
        Some(list) => AllowOrigin::list(list.iter().filter_map(|o| HeaderValue::from_str(o).ok())),
    };
    let headers = [
        "apikey",
        "authorization",
        "content-type",
        "prefer",
        "range",
        "accept-profile",
        "content-profile",
        "tus-resumable",
        "upload-length",
        "upload-metadata",
        "upload-offset",
    ];
    let exposed = [
        "content-range",
        "retry-after",
        "location",
        "tus-resumable",
        "upload-length",
        "upload-offset",
    ];
    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers(headers.map(HeaderName::from_static))
        .expose_headers(exposed.map(HeaderName::from_static))
        .max_age(std::time::Duration::from_secs(3600))
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}

#[cfg(test)]
mod tests {
    use super::client_ip;
    use crate::config::Cidr;
    use std::net::IpAddr;

    #[test]
    fn only_a_trusted_proxy_may_name_the_client() {
        let proxy: IpAddr = "172.18.0.5".parse().unwrap();
        let direct: IpAddr = "203.0.113.9".parse().unwrap();
        let trusted = [
            Cidr::parse("172.18.0.0/16").unwrap(),
            Cidr::parse("::1").unwrap(),
        ];
        let spoofed = Some("1.2.3.4, 198.51.100.7");
        // A client's own header is ignored.
        assert_eq!(client_ip(direct, spoofed, &trusted), direct);
        assert_eq!(client_ip(direct, spoofed, &[]), direct);
        // The proxy's appended entry wins over whatever the client prepended.
        assert_eq!(
            client_ip(proxy, spoofed, &trusted),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(client_ip(proxy, Some("garbage"), &trusted), proxy);
        assert_eq!(client_ip(proxy, None, &trusted), proxy);
        assert!(Cidr::parse("::1").unwrap().contains("::1".parse().unwrap()));
        assert!(
            !Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains("::1".parse().unwrap())
        );
        for bad in ["", "proxy", "10.0.0.0/33", "10.0.0.0/x", "::1/129"] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn function_names_cannot_leave_their_directory() {
        assert!(super::valid_function_name("hello-world_2"));
        for bad in [
            "",
            "..",
            "../x",
            "a/b",
            "Hello",
            "a.b",
            "a%2fb",
            &"x".repeat(64),
        ] {
            assert!(!super::valid_function_name(bad), "{bad}");
        }
    }
}
