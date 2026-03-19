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

use crate::{utils::jwt::verify_token, AppState};

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {

    // Extract token as owned String immediately
    // This drops the borrow on `request` so we can mutate it later
    
    // Check authorization header exists
    let auth_value = match request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.to_string(), // owned String — no borrow kept
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing Authorization header"})),
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

    // CHECK 1: Is token blacklisted?
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

    // CHECK 2: Is token valid and not expired?
    match verify_token(&token) {
        Ok(claims) => {
            // Now safe to mutate request — no borrows active
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