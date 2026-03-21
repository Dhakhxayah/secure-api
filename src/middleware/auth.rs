use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use redis::AsyncCommands;
use serde_json::json;
use std::sync::Arc;

use crate::{utils::jwt::verify_token_with_fingerprint, AppState};

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {

    // CHECK API KEY first — X-API-Key header
    if let Some(api_key_value) = request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        match crate::routes::api_keys::verify_api_key(&state, &api_key_value).await {
            Some(claims) => {
                request.extensions_mut().insert(claims);
                request.extensions_mut().insert(api_key_value);
                return next.run(request).await;
            }
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid or expired API key"})),
                )
                    .into_response();
            }
        }
    }

    // CHECK JWT Bearer token
    let auth_value = match request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.to_string(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing Authorization header or X-API-Key"})),
            )
                .into_response();
        }
    };

    if !auth_value.starts_with("Bearer ") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid authorization format. Use: Bearer <token>"
            })),
        )
            .into_response();
    }

    let token = auth_value["Bearer ".len()..].to_string();

    // Check token blacklist
    let blacklist_key = format!("blacklist:{}", token);
    if let Ok(mut conn) = state.redis.get_async_connection().await {
        let blacklisted: Option<String> = conn
            .get(&blacklist_key)
            .await
            .unwrap_or(None);

        if blacklisted.is_some() {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Token has been invalidated. Please login again."
                })),
            )
                .into_response();
        }
    }

    // Verify token signature and fingerprint
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    match verify_token_with_fingerprint(&token, &user_agent) {
        Ok(claims) => {
            request.extensions_mut().insert(claims);
            request.extensions_mut().insert(token);
            next.run(request).await
        }
        Err(e) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid or expired token",
                "details": e
            })),
        )
            .into_response(),
    }
}