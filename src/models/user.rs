use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// This struct maps to the users table in PostgreSQL
// Every field here matches a column in the table
// #[derive] automatically adds useful abilities to this struct:
// - Serialize: convert to JSON (for sending responses)
// - Deserialize: convert from JSON (for reading requests)
// - sqlx::FromRow: convert from a database row automatically
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,

    // We never send password_hash in responses
    // #[serde(skip_serializing)] means it's excluded from JSON output
    #[serde(skip_serializing)]
    pub password_hash: String,

    pub role: String,
    pub is_locked: bool,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// This is what the client sends when registering
// We only need email and password — nothing else
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

// This is what the client sends when logging in
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

// This is what we send BACK after successful login
// Contains both tokens
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,  // always "Bearer"
    pub expires_in: u64,     // seconds until access token expires
}