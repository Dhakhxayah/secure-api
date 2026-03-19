use chrono::Utc;
use dotenvy::dotenv;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

// Claims are the data stored INSIDE the JWT token
// When you decode a token, you get these fields back
// This data is visible to anyone who has the token (it's base64 encoded)
// So NEVER put sensitive data like passwords here
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,    // "subject" — the user's UUID
    pub email: String,  // user's email
    pub role: String,   // "user" or "admin"
    pub exp: usize,     // expiry timestamp (Unix time)
    pub iat: usize,     // issued-at timestamp
    pub token_type: String, // "access" or "refresh"
}

fn get_jwt_secret() -> String {
    dotenv().ok();
    env::var("JWT_SECRET").expect("JWT_SECRET must be set")
}

// Creates a new JWT access token (short-lived: 15 minutes)
pub fn create_access_token(
    user_id: Uuid,
    email: &str,
    role: &str,
) -> Result<String, String> {
    dotenv().ok();

    // Read expiry duration from .env (900 seconds = 15 minutes)
    let expiry_secs: u64 = env::var("ACCESS_TOKEN_EXPIRY")
        .unwrap_or("900".to_string())
        .parse()
        .unwrap_or(900);

    let now = Utc::now().timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: now + expiry_secs as usize,  // expires 15 min from now
        iat: now,                          // issued right now
        token_type: "access".to_string(),
    };

    // Sign the token with your secret key
    // Anyone with the secret can verify it — keep it safe!
    encode(
        &Header::default(), // uses HS256 algorithm
        &claims,
        &EncodingKey::from_secret(get_jwt_secret().as_bytes()),
    )
    .map_err(|e| format!("Failed to create access token: {}", e))
}

// Creates a new JWT refresh token (long-lived: 7 days)
pub fn create_refresh_token(
    user_id: Uuid,
    email: &str,
    role: &str,
) -> Result<String, String> {
    dotenv().ok();

    let expiry_secs: u64 = env::var("REFRESH_TOKEN_EXPIRY")
        .unwrap_or("604800".to_string())
        .parse()
        .unwrap_or(604800);

    let now = Utc::now().timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: now + expiry_secs as usize,
        iat: now,
        token_type: "refresh".to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(get_jwt_secret().as_bytes()),
    )
    .map_err(|e| format!("Failed to create refresh token: {}", e))
}

// Verifies a token and returns its claims if valid
// Called on every protected request
pub fn verify_token(token: &str) -> Result<Claims, String> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(get_jwt_secret().as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|e| format!("Invalid token: {}", e))
}
