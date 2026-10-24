mod config;

use std::net::SocketAddr;
use std::process::ExitCode;

use axum::{Json, Router, routing::get};
use serde_json::json;

#[tokio::main]
async fn main() -> ExitCode {
    let cfg = match config::load(|k| std::env::var(k).ok()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("kilnbase-core: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Parsed now so a bad key fails at boot; JWT verification uses it from Phase 1.
    let _jwks = cfg.jwks;

    let app = Router::new().route("/health", get(|| async { Json(json!({ "status": "ok" })) }));

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kilnbase-core: cannot bind {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("kilnbase-core: listening on {addr}");

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("kilnbase-core: server error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
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
