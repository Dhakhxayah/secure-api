use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    models::user::{ApiKeyInfo, CreateApiKeyRequest, CreateApiKeyResponse},
    AppState,
};

// Generate a cryptographically random API key
// Format: sk_live_<32 random hex chars>
fn generate_api_key() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Generate random bytes using multiple sources
    let uuid1 = Uuid::new_v4();
    let uuid2 = Uuid::new_v4();
    let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or(0);

    let mut hasher = DefaultHasher::new();
    uuid1.hash(&mut hasher);
    uuid2.hash(&mut hasher);
    timestamp.hash(&mut hasher);
    let hash1 = hasher.finish();

    // Use SHA-256 for the final key generation
    let mut sha = Sha256::new();
    sha.update(uuid1.as_bytes());
    sha.update(uuid2.as_bytes());
    sha.update(&timestamp.to_le_bytes());
    sha.update(&hash1.to_le_bytes());
    let result = sha.finalize();

    format!("sk_live_{}", hex::encode(result))
}

// Hash an API key for storage
fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

// POST /api-keys
// Create a new API key for the authenticated user
pub async fn create_api_key(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<crate::utils::jwt::Claims>,
    Json(body): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), (StatusCode, Json<Value>)> {

    // Validate name
    if body.name.is_empty() || body.name.len() > 100 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Key name must be 1-100 characters"})),
        ));
    }

    // Validate scopes
    let valid_scopes = ["read", "write", "admin"];
    for scope in &body.scopes {
        if !valid_scopes.contains(&scope.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("Invalid scope '{}'. Valid: read, write, admin", scope)
                })),
            ));
        }
    }

    if body.scopes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "At least one scope is required"})),
        ));
    }

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user ID"})),
        ))?;

    // Check user exists and is not deleted
    let user = sqlx::query!(
        "SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "Database error"})),
    ))?;

    if user.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "User not found"})),
        ));
    }

    // Generate the raw API key — shown ONCE to user
    let raw_key = generate_api_key();

    // Store only the hash — never the raw key
    let key_hash = hash_api_key(&raw_key);

    // Prefix for identification (sk_live_ab12cd34)
    // Users can identify keys without seeing full key
    let key_prefix = raw_key[..16].to_string();

    // Calculate expiry if specified
    let expires_at = body.expires_in_days.map(|days| {
        Utc::now() + chrono::Duration::days(days)
    });

    let key_id = Uuid::new_v4();

    // Store hashed key in database
    sqlx::query!(
        r#"
        INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, scopes, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        "#,
        key_id,
        user_id,
        body.name,
        key_hash,
        key_prefix,
        &body.scopes,
        expires_at,
    )
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Failed to create API key: {}", e)})),
    ))?;

    // Log key creation
    sqlx::query!(
        r#"INSERT INTO audit_logs (id, user_id, action, details, created_at)
           VALUES ($1, $2, 'API_KEY_CREATED', $3, NOW())"#,
        Uuid::new_v4(),
        user_id,
        format!("Created API key: {}", body.name),
    )
    .execute(&state.db)
    .await
    .ok();

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            id: key_id,
            name: body.name,
            key: raw_key,        // shown ONCE — user must save this
            key_prefix,
            scopes: body.scopes,
            expires_at,
            message: "Save this key now — it will never be shown again!".to_string(),
        }),
    ))
}

// GET /api-keys
// List all API keys for the authenticated user (no raw keys shown)
pub async fn list_api_keys(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<crate::utils::jwt::Claims>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user ID"})),
        ))?;

    let keys = sqlx::query!(
        r#"
        SELECT id, name, key_prefix, scopes, expires_at,
               last_used_at, is_active, created_at
        FROM api_keys
        WHERE user_id = $1
        ORDER BY created_at DESC
        "#,
        user_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "Database error"})),
    ))?;

    let key_list: Vec<ApiKeyInfo> = keys.into_iter().map(|k| ApiKeyInfo {
        id: k.id,
        name: k.name,
        key_prefix: k.key_prefix,
        scopes: k.scopes,
        expires_at: k.expires_at,
        last_used_at: k.last_used_at,
        is_active: k.is_active,
        created_at: k.created_at,
    }).collect();

    Ok(Json(json!({
        "keys": key_list,
        "total": key_list.len()
    })))
}

// DELETE /api-keys/:id
// Revoke an API key
pub async fn revoke_api_key(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<crate::utils::jwt::Claims>,
    axum::extract::Path(key_id): axum::extract::Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user ID"})),
        ))?;

    // Deactivate the key — only if it belongs to this user
    let result = sqlx::query!(
        r#"
        UPDATE api_keys
        SET is_active = false
        WHERE id = $1 AND user_id = $2
        "#,
        key_id,
        user_id,
    )
    .execute(&state.db)
    .await
    .map_err(|_| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "Database error"})),
    ))?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "API key not found"})),
        ));
    }

    // Log revocation
    sqlx::query!(
        r#"INSERT INTO audit_logs (id, user_id, action, details, created_at)
           VALUES ($1, $2, 'API_KEY_REVOKED', $3, NOW())"#,
        Uuid::new_v4(),
        user_id,
        format!("Revoked API key: {}", key_id),
    )
    .execute(&state.db)
    .await
    .ok();

    Ok(Json(json!({"message": "API key revoked successfully"})))
}

// Verify an API key from request header
// Used by api_key_middleware
pub async fn verify_api_key(
    state: &AppState,
    raw_key: &str,
) -> Option<crate::utils::jwt::Claims> {

    // Hash the incoming key to compare with stored hash
    let key_hash = hash_api_key(raw_key);

    let key = sqlx::query!(
        r#"
        SELECT ak.id, ak.user_id, ak.scopes, ak.expires_at, ak.is_active,
               u.email, u.role
        FROM api_keys ak
        JOIN users u ON ak.user_id = u.id
        WHERE ak.key_hash = $1
        AND ak.is_active = true
        AND u.deleted_at IS NULL
        "#,
        key_hash
    )
    .fetch_optional(&state.db)
    .await
    .ok()??;

    // Check if key has expired
    if let Some(expires_at) = key.expires_at {
        if Utc::now() > expires_at {
            return None;
        }
    }

    // Update last_used_at
    sqlx::query!(
        "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
        key.id
    )
    .execute(&state.db)
    .await
    .ok();

    // Decrypt email
    let email = crate::utils::encryption::decrypt(&key.email)
        .unwrap_or_else(|_| key.email.clone());

    // Return claims — same structure as JWT claims
    Some(crate::utils::jwt::Claims {
        sub: key.user_id.to_string(),
        email,
        role: key.role,
        exp: 9999999999,
        iat: Utc::now().timestamp() as usize,
        token_type: "api_key".to_string(),
        fingerprint: None,
    })
}