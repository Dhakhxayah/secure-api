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
use std::time::{SystemTime, UNIX_EPOCH};

use crate::AppState;

struct EndpointLimit {
    requests: i64,
    window_secs: i64,
}

fn get_limit_for_path(path: &str, method: &str) -> EndpointLimit {
    match (method, path) {
        // Login — very strict: 5 per minute
        ("POST", "/auth/login") => EndpointLimit {
            requests: 5,
            window_secs: 60,
        },
        // Register — moderate: 10 per minute
        ("POST", "/auth/register") => EndpointLimit {
            requests: 10,
            window_secs: 60,
        },
        // Logout — moderate: 10 per minute
        ("POST", "/auth/logout") => EndpointLimit {
            requests: 10,
            window_secs: 60,
        },
        // Everything else — relaxed: 60 per minute
        _ => EndpointLimit {
            requests: 60,
            window_secs: 60,
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

    let path = request.uri().path().to_string();
    let method = request.method().as_str().to_string();
    let limit = get_limit_for_path(&path, &method);

    // Get current timestamp in milliseconds
    // Using milliseconds gives us sub-second precision
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as f64;

    // Window start = now - window_secs (in milliseconds)
    let window_start = now_ms - (limit.window_secs as f64 * 1000.0);

    // Unique key per IP + method + path
    let redis_key = format!(
        "sliding:{}:{}:{}",
        ip,
        method.to_lowercase(),
        path.replace('/', "_")
    );

    let mut conn = match state.redis.get_async_connection().await {
        Ok(c) => c,
        Err(_) => return next.run(request).await,
    };

    // SLIDING WINDOW ALGORITHM — 3 atomic Redis operations:

    // STEP 1: Remove all timestamps outside the current window
    // ZREMRANGEBYSCORE removes all members with score < window_start
    // This cleans up old requests that no longer count
    let _: () = redis::cmd("ZREMRANGEBYSCORE")
        .arg(&redis_key)
        .arg("-inf")           // from negative infinity
        .arg(window_start)     // up to window start
        .query_async(&mut conn)
        .await
        .unwrap_or(());

    // STEP 2: Count how many requests remain in the window
    let count: i64 = redis::cmd("ZCARD")
        .arg(&redis_key)
        .query_async(&mut conn)
        .await
        .unwrap_or(0);

    if count >= limit.requests {
        // Too many requests in the sliding window
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "Too many requests",
                "message": format!(
                    "Sliding window limit: {} requests per {} seconds.",
                    limit.requests, limit.window_secs
                ),
                "algorithm": "sliding_window",
                "limit": limit.requests,
                "window_seconds": limit.window_secs,
                "retry_after": limit.window_secs
            })),
        )
            .into_response();
    }

    // STEP 3: Add current request timestamp to the sorted set
    // Score = timestamp (used for range queries)
    // Member = timestamp as string (must be unique)
    let member = format!("{:.3}", now_ms);
    let _: () = redis::cmd("ZADD")
        .arg(&redis_key)
        .arg(now_ms)       // score = timestamp
        .arg(&member)      // member = timestamp string
        .query_async(&mut conn)
        .await
        .unwrap_or(());

    // Set expiry so Redis auto-cleans idle keys
    let _: () = redis::cmd("EXPIRE")
        .arg(&redis_key)
        .arg(limit.window_secs)
        .query_async(&mut conn)
        .await
        .unwrap_or(());

    // Add rate limit headers to response
    let remaining = (limit.requests - count - 1).max(0);
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        "X-RateLimit-Limit",
        limit.requests.to_string().parse().unwrap(),
    );
    headers.insert(
        "X-RateLimit-Remaining",
        remaining.to_string().parse().unwrap(),
    );
    headers.insert(
        "X-RateLimit-Algorithm",
        "sliding_window".parse().unwrap(),
    );

    response
}