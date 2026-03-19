use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    models::user::{AuthResponse, LoginRequest, RegisterRequest},
    utils::{
        jwt::{create_access_token, create_refresh_token},
        password::{hash_password, verify_password},
    },
    AppState,
};

// POST /auth/register
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {

    if !body.email.contains('@') || body.email.len() < 5 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid email format"})),
        ));
    }

    if body.password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Password must be at least 8 characters"})),
        ));
    }

    let existing = sqlx::query!(
        "SELECT id FROM users WHERE email = $1",
        body.email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Database error: {}", e)})),
    ))?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "Email already registered"})),
        ));
    }

    let password_hash = hash_password(&body.password)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        ))?;

    let user_id = Uuid::new_v4();

    sqlx::query!(
        r#"
        INSERT INTO users (id, email, password_hash, role, created_at, updated_at)
        VALUES ($1, $2, $3, 'user', NOW(), NOW())
        "#,
        user_id,
        body.email,
        password_hash,
    )
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Failed to create user: {}", e)})),
    ))?;

    sqlx::query!(
        r#"
        INSERT INTO audit_logs (id, user_id, action, details, created_at)
        VALUES ($1, $2, 'REGISTER', 'New user registered', NOW())
        "#,
        Uuid::new_v4(),
        user_id,
    )
    .execute(&state.db)
    .await
    .ok();

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Account created successfully",
            "user_id": user_id
        })),
    ))
}

// POST /auth/login
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoginRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), (StatusCode, Json<Value>)> {

    let user = sqlx::query!(
        r#"
        SELECT id, email, password_hash, role, is_locked,
               failed_login_attempts, locked_until
        FROM users
        WHERE email = $1
        "#,
        body.email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Database error: {}", e)})),
    ))?;

    let user = match user {
        Some(u) => u,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid credentials"})),
            ))
        }
    };

    if user.is_locked {
        if let Some(locked_until) = user.locked_until {
            if Utc::now() < locked_until {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "Account is locked due to too many failed attempts",
                        "locked_until": locked_until
                    })),
                ));
            } else {
                sqlx::query!(
                    "UPDATE users SET is_locked = false, failed_login_attempts = 0,
                     locked_until = NULL WHERE id = $1",
                    user.id
                )
                .execute(&state.db)
                .await
                .ok();
            }
        }
    }

    let password_valid = verify_password(&body.password, &user.password_hash)
        .map_err(|_| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Password verification failed"})),
        ))?;

    if !password_valid {
        let new_attempts = user.failed_login_attempts + 1;

        if new_attempts >= 5 {
            sqlx::query!(
                r#"UPDATE users
                   SET failed_login_attempts = $1,
                       is_locked = true,
                       locked_until = NOW() + INTERVAL '15 minutes'
                   WHERE id = $2"#,
                new_attempts,
                user.id
            )
            .execute(&state.db)
            .await
            .ok();

            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "Account locked for 15 minutes due to too many failed attempts"
                })),
            ));
        } else {
            sqlx::query!(
                "UPDATE users SET failed_login_attempts = $1 WHERE id = $2",
                new_attempts,
                user.id
            )
            .execute(&state.db)
            .await
            .ok();
        }

        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid credentials",
                "attempts_remaining": 5 - new_attempts
            })),
        ));
    }

    sqlx::query!(
        "UPDATE users SET failed_login_attempts = 0, is_locked = false WHERE id = $1",
        user.id
    )
    .execute(&state.db)
    .await
    .ok();

    let access_token = create_access_token(user.id, &user.email, &user.role)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        ))?;

    let refresh_token = create_refresh_token(user.id, &user.email, &user.role)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        ))?;

    sqlx::query!(
        r#"INSERT INTO audit_logs (id, user_id, action, details, created_at)
           VALUES ($1, $2, 'LOGIN_SUCCESS', 'User logged in', NOW())"#,
        Uuid::new_v4(),
        user.id,
    )
    .execute(&state.db)
    .await
    .ok();

    Ok((
        StatusCode::OK,
        Json(AuthResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 900,
        }),
    ))
}

// GET /auth/me
pub async fn me(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<crate::utils::jwt::Claims>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user ID in token"})),
        ))?;

    let user = sqlx::query!(
        "SELECT id, email, role, created_at FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Database error: {}", e)})),
    ))?;

    match user {
        Some(u) => Ok(Json(json!({
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "created_at": u.created_at
        }))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "User not found"})),
        )),
    }
}

// POST /auth/logout
// Adds the token to Redis blacklist so it can't be used again
// Even if token hasn't expired yet, it will be rejected
pub async fn logout(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<crate::utils::jwt::Claims>,
    axum::Extension(raw_token): axum::Extension<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {

    // Add token to Redis blacklist
    // Key: "blacklist:<token>"
    // Value: "1"
    // Expiry: same as token expiry so Redis auto-cleans it
    let blacklist_key = format!("blacklist:{}", raw_token);

    let mut redis_conn = state.redis
        .get_async_connection()
        .await
        .map_err(|_| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Could not connect to Redis"})),
        ))?;

    // Calculate remaining TTL of the token
    let now = chrono::Utc::now().timestamp() as usize;
    let ttl = if claims.exp > now { claims.exp - now } else { 1 };

    // Store in blacklist until token naturally expires
    let _: () = redis::AsyncCommands::set_ex(
        &mut redis_conn,
        &blacklist_key,
        "1",
        ttl as u64,
    )
    .await
    .map_err(|_| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "Failed to blacklist token"})),
    ))?;

    // Log the logout
    let user_id = Uuid::parse_str(&claims.sub).ok();
    if let Some(uid) = user_id {
        sqlx::query!(
            r#"INSERT INTO audit_logs (id, user_id, action, details, created_at)
               VALUES ($1, $2, 'LOGOUT', 'User logged out', NOW())"#,
            Uuid::new_v4(),
            uid,
        )
        .execute(&state.db)
        .await
        .ok();
    }

    Ok(Json(json!({
        "message": "Logged out successfully. Token has been invalidated."
    })))
}