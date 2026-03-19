use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use redis::AsyncCommands;
use serde_json::json;
use std::sync::Arc;

use crate::AppState;

// Different endpoints get different rate limits
// Login is strictest — prevents brute force
// General endpoints are relaxed
struct EndpointLimit {
    requests: i64,  // max requests allowed
    window: i64,    // time window in seconds
}

fn get_limit_for_path(path: &str, method: &str) -> EndpointLimit {
    match (method, path) {
        // Login — very strict: 5 attempts per minute
        ("POST", "/auth/login") => EndpointLimit {
            requests: 5,
            window: 60,
        },
        // Register — moderate: 10 per minute
        ("POST", "/auth/register") => EndpointLimit {
            requests: 10,
            window: 60,
        },
        // Logout — moderate: 10 per minute
        ("POST", "/auth/logout") => EndpointLimit {
            requests: 10,
            window: 60,
        },
        // All other endpoints — relaxed: 60 per minute
        _ => EndpointLimit {
            requests: 60,
            window: 60,
        },
    }
}

pub async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {

    // Get client IP
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Get the path and method to determine which limit applies
    let path = request.uri().path().to_string();
    let method = request.method().as_str().to_string();

    // Get the limit for this specific endpoint
    let limit = get_limit_for_path(&path, &method);

    // Unique Redis key per IP + endpoint
    // This means login and /health have SEPARATE counters
    let redis_key = format!(
        "rate_limit:{}:{}:{}",
        ip,
        method.to_lowercase(),
        path.replace('/', "_")
    );

    let mut redis_conn = match state.redis.get_async_connection().await {
        Ok(conn) => conn,
        Err(_) => {
            // Redis down — let request through rather than block everyone
            return next.run(request).await;
        }
    };

    // Increment counter for this IP + endpoint
    let count: i64 = redis_conn
        .incr(&redis_key, 1)
        .await
        .unwrap_or(1);

    // Set expiry on first request
    if count == 1 {
        let _: () = redis_conn
            .expire(&redis_key, limit.window)
            .await
            .unwrap_or(());
    }

    if count > limit.requests {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "Too many requests",
                "message": format!(
                    "Limit for this endpoint is {} requests per {} seconds. Try again later.",
                    limit.requests, limit.window
                ),
                "limit": limit.requests,
                "retry_after": limit.window
            })),
        )
            .into_response();
    }

    // Add rate limit headers to response
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        "X-RateLimit-Limit",
        limit.requests.to_string().parse().unwrap(),
    );
    headers.insert(
        "X-RateLimit-Remaining",
        (limit.requests - count).max(0).to_string().parse().unwrap(),
    );

    response
}