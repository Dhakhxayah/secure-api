use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use sha2::{Digest, Sha256};

use crate::{
    models::user::{AuthResponse, DeleteAccountRequest, LoginRequest, RegisterRequest},
    utils::{
        encryption::{decrypt, encrypt},
        jwt::{create_access_token, create_refresh_token},
        password::{hash_password, verify_password},
        sanitize::{looks_like_xss, sanitize_email, sanitize_text},
    },
    AppState,
};

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {

    if looks_like_xss(&body.email) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid input detected"})),
        ));
    }

    let email = sanitize_email(&body.email);

    if !email.contains('@') || email.len() < 5 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid email format"})),
        ));
    }

    let password = sanitize_text(&body.password, 128)
        .map_err(|e| (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e})),
        ))?;

    if password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Password must be at least 8 characters"})),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(email.as_bytes());
    let email_hash = format!("{:x}", hasher.finalize());

    let existing = sqlx::query!(
        "SELECT id FROM users WHERE email_hash = $1",
        email_hash
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

    let password_hash = hash_password(&password)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        ))?;

    let user_id = Uuid::new_v4();

    let encrypted_email = encrypt(&email)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Encryption failed: {}", e)})),
        ))?;

    sqlx::query!(
        r#"
        INSERT INTO users (id, email, email_hash, password_hash, role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, 'user', NOW(), NOW())
        "#,
        user_id,
        encrypted_email,
        email_hash,
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

pub async fn login(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), (StatusCode, Json<Value>)> {

    let request_headers = &headers;

    let mut hasher = Sha256::new();
    hasher.update(body.email.to_lowercase().as_bytes());
    let email_hash = format!("{:x}", hasher.finalize());

    let user = sqlx::query!(
        r#"
        SELECT id, email, password_hash, role, is_locked,
               failed_login_attempts, locked_until
        FROM users
        WHERE email_hash = $1
        AND deleted_at IS NULL
        "#,
        email_hash
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Database error: {}", e)})),
    ))?;

    let user = match user {
        Some(u) => u,
        None => return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid credentials"})),
        )),
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

    let user_agent = request_headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok());

    let decrypted_email = decrypt(&user.email)
        .unwrap_or_else(|_| user.email.clone());

    let access_token = create_access_token(user.id, &decrypted_email, &user.role, user_agent)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        ))?;

    let refresh_token = create_refresh_token(user.id, &decrypted_email, &user.role, user_agent)
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
        "SELECT id, email, role, created_at FROM users WHERE id = $1 AND deleted_at IS NULL",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Database error: {}", e)})),
    ))?;

    match user {
        Some(u) => {
            let decrypted_email = decrypt(&u.email)
                .unwrap_or_else(|_| u.email.clone());
            Ok(Json(json!({
                "id": u.id,
                "email": decrypted_email,
                "role": u.role,
                "created_at": u.created_at
            })))
        },
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "User not found"})),
        )),
    }
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<crate::utils::jwt::Claims>,
    axum::Extension(raw_token): axum::Extension<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {

    let blacklist_key = format!("blacklist:{}", raw_token);

    let mut redis_conn = state.redis
        .get_async_connection()
        .await
        .map_err(|_| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Could not connect to Redis"})),
        ))?;

    let now = chrono::Utc::now().timestamp() as usize;
    let ttl = if claims.exp > now { claims.exp - now } else { 1 };

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

pub async fn delete_account(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<crate::utils::jwt::Claims>,
    Json(body): Json<DeleteAccountRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user ID"})),
        ))?;

    let user = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE id = $1 AND deleted_at IS NULL",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "Database error"})),
    ))?;

    let user = match user {
        Some(u) => u,
        None => return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "User not found"})),
        )),
    };

    let valid = verify_password(&body.password, &user.password_hash)
        .map_err(|_| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Password verification failed"})),
        ))?;

    if !valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Incorrect password"})),
        ));
    }

    sqlx::query!(
        "UPDATE users SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1",
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "Failed to delete account"})),
    ))?;

    sqlx::query!(
        r#"INSERT INTO audit_logs (id, user_id, action, details, created_at)
           VALUES ($1, $2, 'ACCOUNT_DELETED', 'User soft deleted their account', NOW())"#,
        Uuid::new_v4(),
        user_id,
    )
    .execute(&state.db)
    .await
    .ok();

    Ok(Json(json!({
        "message": "Account successfully deleted"
    })))
}