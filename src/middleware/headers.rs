use axum::{body::Body, extract::Request, middleware::Next, response::Response};
use http::HeaderValue;

// This middleware adds security headers to EVERY response
// It runs after your route handler builds the response,
// and injects these headers before sending to the client
pub async fn secure_headers_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    // Let the request continue and get the response
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Prevents browsers from guessing content types
    // Stops MIME-sniffing attacks
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );

    // Prevents your site from being embedded in iframes
    // Stops clickjacking attacks
    headers.insert(
        "X-Frame-Options",
        HeaderValue::from_static("DENY"),
    );

    // Forces browsers to use HTTPS for 1 year
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    // Tells browser what content is allowed to load
    // 'self' means only from your own domain
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'self'"),
    );

    // Controls how much referrer info is shared
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("geolocation=(), camera=(), microphone=()"),
    );

    response
}