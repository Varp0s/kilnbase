mod auth;
mod config;
mod db;
mod error;
mod proxy;
mod realtime;
mod storage;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use jsonwebtoken::DecodingKey;
use serde_json::json;

struct AppState {
    keys: HashMap<String, DecodingKey>,
    postgrest_url: String,
    auth_url: String,
    http: proxy::HttpClient,
    storage: storage::Storage,
    realtime: realtime::Hub,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cfg = match config::load(|k| std::env::var(k).ok()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("kilnbase-core: {e}");
            return ExitCode::FAILURE;
        }
    };

    let pool = match db::pool(&cfg.database_url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("kilnbase-core: {e}");
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
    };
    if let Err(e) = storage.prepare_dirs().await {
        eprintln!(
            "kilnbase-core: storage directory {} is not writable: {e}",
            storage.dir.display()
        );
        return ExitCode::FAILURE;
    }

    let hub = realtime::hub();
    realtime::spawn_listener(cfg.database_url.clone(), hub.clone());

    let state = Arc::new(AppState {
        keys: cfg.keys,
        postgrest_url: cfg.postgrest_url,
        auth_url: cfg.auth_url,
        http: proxy::client(),
        storage,
        realtime: hub,
    });
    let cors = cors_layer(cfg.cors_origins.as_deref());
    let app = Router::new()
        .route("/health", get(|| async { Json(json!({ "status": "ok" })) }))
        .route("/rest/v1/", any(rest))
        .route("/rest/v1/{*path}", any(rest))
        .route("/auth/v1/{*path}", any(auth_service))
        .route("/realtime/v1/websocket", get(realtime::websocket))
        .route("/storage/v1/bucket", post(storage::create_bucket))
        .route(
            "/storage/v1/object/public/{bucket}/{*name}",
            get(storage::download_public),
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
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kilnbase-core: cannot bind {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("kilnbase-core: listening on {addr}");

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        eprintln!("kilnbase-core: server error: {e}");
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

/// Auth endpoints only need a valid API key: refresh calls legitimately carry expired access
/// tokens, and the auth service verifies bearer tokens itself where it needs them.
async fn auth_service(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
) -> Response {
    // Provider sign-in starts and ends with browser navigations, which cannot carry headers.
    let browser_redirect = req.method() == axum::http::Method::GET
        && matches!(req.uri().path(), "/auth/v1/authorize" | "/auth/v1/callback");
    if !browser_redirect && let Err(e) = auth::check_api_key(&st.keys, req.headers()) {
        return e.into_response();
    }
    req.headers_mut().remove("apikey");
    // Overwrite, never append: a client-supplied value would let callers dodge IP rate limits.
    if let Ok(ip) = HeaderValue::from_str(&peer.ip().to_string()) {
        req.headers_mut().insert("x-forwarded-for", ip);
    }
    let path_and_query = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let upstream_path = path_and_query
        .strip_prefix("/auth/v1")
        .unwrap_or(path_and_query)
        .to_owned();
    proxy::forward(&st.http, &st.auth_url, &upstream_path, req).await
}

fn cors_layer(origins: Option<&[String]>) -> tower_http::cors::CorsLayer {
    use axum::http::{HeaderName, Method};
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
    ];
    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers(headers.map(HeaderName::from_static))
        .expose_headers(["content-range", "retry-after"].map(HeaderName::from_static))
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
