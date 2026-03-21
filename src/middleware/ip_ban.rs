use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::{middleware::anomaly::AnomalyDetector, AppState};

pub async fn ip_ban_middleware(
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

    if AnomalyDetector::is_banned(&state.redis, &ip).await {
        let ttl = AnomalyDetector::get_ban_ttl(&state.redis, &ip).await;
        tracing::warn!("Banned IP {} attempted access. TTL: {}s", ip, ttl);
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Your IP has been temporarily banned due to suspicious activity",
                "ban_expires_in_seconds": ttl,
                "reason": "Too many failed or malicious requests detected"
            })),
        )
            .into_response();
    }

    next.run(request).await
}