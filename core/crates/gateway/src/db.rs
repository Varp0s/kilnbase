use axum::http::StatusCode;
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Transaction};
use serde_json::Value;
use tokio_postgres::NoTls;
use tokio_postgres::error::SqlState;

use crate::auth::Caller;
use crate::error::ApiError;

pub fn pool(url: &str) -> Result<Pool, String> {
    let config: tokio_postgres::Config = url
        .parse()
        .map_err(|e| format!("KILNBASE_DATABASE_URL is invalid: {e}"))?;
    let manager = Manager::from_config(
        config,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    Pool::builder(manager)
        .max_size(16)
        .build()
        .map_err(|e| format!("cannot build database pool: {e}"))
}

pub async fn client(pool: &Pool) -> Result<Object, ApiError> {
    pool.get().await.map_err(|e| {
        log_error!("database unavailable: {e}");
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            "database unavailable",
        )
    })
}

/// The only way this service queries data: a transaction running as the caller's role, with the
/// caller's claims visible to RLS policies through `auth.uid()` / `auth.jwt()`.
pub async fn begin_as<'a>(
    client: &'a mut Object,
    caller: &Caller,
) -> Result<Transaction<'a>, ApiError> {
    begin_with(client, caller.role, &caller.claims).await
}

/// For reads that are not on behalf of a user (bucket settings, public and signed downloads).
pub async fn begin_as_service(client: &mut Object) -> Result<Transaction<'_>, ApiError> {
    begin_with(client, "service_role", &Value::Object(Default::default())).await
}

async fn begin_with<'a>(
    client: &'a mut Object,
    role: &'static str,
    claims: &Value,
) -> Result<Transaction<'a>, ApiError> {
    let tx = client.transaction().await.map_err(internal)?;
    // `role` is a &'static str from a fixed allow-list, never user input.
    tx.batch_execute(&format!("set local role {role}"))
        .await
        .map_err(internal)?;
    tx.execute(
        "select set_config('request.jwt.claims', $1, true)",
        &[&claims.to_string()],
    )
    .await
    .map_err(internal)?;
    Ok(tx)
}

/// Maps database errors to API errors without leaking SQL details to clients.
pub fn internal(e: tokio_postgres::Error) -> ApiError {
    match e.code() {
        Some(c) if *c == SqlState::INSUFFICIENT_PRIVILEGE => {
            ApiError::new(StatusCode::FORBIDDEN, "forbidden", "not allowed by policy")
        }
        Some(c) if *c == SqlState::UNIQUE_VIOLATION => ApiError::new(
            StatusCode::CONFLICT,
            "already_exists",
            "resource already exists",
        ),
        Some(c) if *c == SqlState::CHECK_VIOLATION => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_request", "invalid value")
        }
        _ => {
            log_error!("database error: {e}");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "internal error",
            )
        }
    }
}
