use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::{middleware::anomaly::AnomalyDetector, AppState};

pub async fn response_inspector_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let response = next.run(request).await;
    let status = response.status();

    if status == StatusCode::BAD_REQUEST
        || status == StatusCode::UNPROCESSABLE_ENTITY
    {
        let should_ban = AnomalyDetector::record_bad_request(
            &state.redis,
            &ip,
        ).await;

        if should_ban {
            tracing::warn!("IP {} auto-banned after repeated bad requests", ip);
        }
    }

    if status == StatusCode::UNAUTHORIZED {
        tracing::warn!("Unauthorized request from IP: {}", ip);
    }

    response
}