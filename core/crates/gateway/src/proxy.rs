use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::error::ApiError;

pub type HttpClient = Client<HttpConnector, Body>;

pub fn client() -> HttpClient {
    Client::builder(TokioExecutor::new()).build_http()
}

const HOP_BY_HOP: &[header::HeaderName] = &[
    header::CONNECTION,
    header::HOST,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

/// Streams the request to `upstream + path_and_query` and the response back; bodies are never buffered.
pub async fn forward(
    client: &HttpClient,
    upstream: &str,
    path_and_query: &str,
    mut req: Request,
) -> Response {
    let Ok(uri) = format!("{upstream}{path_and_query}").parse::<Uri>() else {
        return ApiError::new(StatusCode::BAD_REQUEST, "bad_request", "invalid path")
            .into_response();
    };
    *req.uri_mut() = uri;
    for name in HOP_BY_HOP {
        req.headers_mut().remove(name);
    }

    match client.request(req).await {
        Ok(mut res) => {
            for name in HOP_BY_HOP {
                res.headers_mut().remove(name);
            }
            res.map(Body::new)
        }
        Err(e) => {
            log_error!("upstream {upstream} error: {e}");
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "upstream_unavailable",
                "upstream service unavailable",
            )
            .into_response()
        }
    }
}
