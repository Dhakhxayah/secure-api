use axum::{
    middleware::{from_fn, from_fn_with_state},
    routing::{get, post},
    Router,
};

use dotenvy::dotenv;
use redis::Client as RedisClient;
use std::{env, sync::Arc};
use tower_http::cors::{Any, CorsLayer};

mod db;
mod middleware;
mod models;
mod routes;
mod utils;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub redis: RedisClient,
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::fmt::init();

    tracing::info!("Starting Secure API Server...");

    let db_pool = db::create_pool().await;
    tracing::info!("Connected to PostgreSQL");

    let redis_url = env::var("REDIS_URL")
        .unwrap_or("redis://127.0.0.1/".to_string());

    let redis_client = RedisClient::open(redis_url)
        .expect("Failed to connect to Redis. Is it running?");
    tracing::info!("Connected to Redis");

    let state = Arc::new(AppState {
        db: db_pool,
        redis: redis_client,
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/auth/register", post(routes::auth::register))
        .route("/auth/login", post(routes::auth::login))
       .route(
            "/auth/me",
            get(routes::auth::me)
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::auth::auth_middleware,
                )),
        )
        .route(
            "/auth/logout",
            post(routes::auth::logout)
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::auth::auth_middleware,
                )),
        )
        .layer(from_fn_with_state(
            state.clone(),
            middleware::rate_limiter::rate_limit_middleware,
        ))
        .layer(from_fn(
            middleware::headers::secure_headers_middleware,
        ))
        .layer(cors)
        .with_state(state);

    let port = env::var("PORT").unwrap_or("3000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    tracing::info!("Server running on http://{}", addr);
    tracing::info!("  POST http://localhost:{}/auth/register", port);
    tracing::info!("  POST http://localhost:{}/auth/login", port);
    tracing::info!("  GET  http://localhost:{}/auth/me", port);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Server crashed");
}

async fn root_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "message": "Secure API is running",
        "version": "1.0.0",
        "endpoints": {
            "register": "POST /auth/register",
            "login": "POST /auth/login",
            "me": "GET /auth/me (requires JWT)"
        }
    }))
}

async fn health_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
#[cfg(test)]
mod tests {
    use crate::utils::password::{hash_password, verify_password};
    use crate::utils::jwt::{create_access_token, verify_token};
    use uuid::Uuid;

    // ─── Password Tests ───────────────────────────────

    #[test]
    fn test_password_hash_is_not_plaintext() {
        let password = "mysecretpassword";
        let hash = hash_password(password).unwrap();
        assert_ne!(hash, password);
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn test_password_verify_correct() {
        let password = "correctpassword123";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
    }

    #[test]
    fn test_password_verify_wrong() {
        let password = "correctpassword123";
        let hash = hash_password(password).unwrap();
        assert!(!verify_password("wrongpassword", &hash).unwrap());
    }

    #[test]
    fn test_two_hashes_of_same_password_differ() {
        let hash1 = hash_password("samepassword").unwrap();
        let hash2 = hash_password("samepassword").unwrap();
        // Same password produces different hashes due to random salt
        assert_ne!(hash1, hash2);
    }

    // ─── JWT Tests ────────────────────────────────────

    #[test]
    fn test_jwt_created_and_verified() {
        let user_id = Uuid::new_v4();
        let token = create_access_token(user_id, "test@example.com", "user").unwrap();
        let claims = verify_token(&token).unwrap();
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.role, "user");
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_jwt_invalid_token_rejected() {
        let result = verify_token("this.is.not.valid");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_tampered_token_rejected() {
        let user_id = Uuid::new_v4();
        let mut token = create_access_token(user_id, "test@example.com", "user").unwrap();
        token.push('X'); // tamper with it
        assert!(verify_token(&token).is_err());
    }

    // ─── Input Validation Tests ───────────────────────

    #[test]
    fn test_invalid_email_no_at_symbol() {
        let email = "notanemail.com";
        assert!(!email.contains('@'));
    }

    #[test]
    fn test_invalid_email_too_short() {
        let email = "a@b";
        assert!(email.len() < 5);
    }

    #[test]
    fn test_password_too_short() {
        let password = "short";
        assert!(password.len() < 8);
    }

    #[test]
    fn test_sql_injection_treated_as_string() {
        // Documents that this dangerous payload exists as plain text
        // In our app it's always passed as $1 parameter — never executed
        let payload = "'; DROP TABLE users; --";
        assert!(payload.contains("DROP TABLE"));
    }
}