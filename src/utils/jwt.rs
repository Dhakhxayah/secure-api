use chrono::Utc;
use dotenvy::dotenv;
use jsonwebtoken::{
    decode, encode,
    Algorithm,
    DecodingKey,
    EncodingKey,
    Header,
    Validation,
};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use uuid::Uuid;

// Claims stored inside every JWT token
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,         // user UUID
    pub email: String,
    pub role: String,
    pub exp: usize,          // expiry timestamp
    pub iat: usize,          // issued at timestamp
    pub token_type: String,  // "access" or "refresh"

    // Token fingerprint — SHA256 hash of User-Agent
    // If token is stolen and used from different browser → rejected
    pub fingerprint: Option<String>,
}

// Load private key from file for SIGNING tokens
fn load_private_key() -> EncodingKey {
    dotenv().ok();
    let path = env::var("PRIVATE_KEY_PATH")
        .unwrap_or("keys/private.pem".to_string());

    let pem = fs::read_to_string(&path)
        .expect(&format!("Cannot read private key from {}", path));

    EncodingKey::from_rsa_pem(pem.as_bytes())
        .expect("Invalid RSA private key format")
}

// Load public key from file for VERIFYING tokens
fn load_public_key() -> DecodingKey {
    dotenv().ok();
    let path = env::var("PUBLIC_KEY_PATH")
        .unwrap_or("keys/public.pem".to_string());

    let pem = fs::read_to_string(&path)
        .expect(&format!("Cannot read public key from {}", path));

   DecodingKey::from_rsa_pem(pem.as_bytes())
        .expect("Invalid RSA public key format")
}

// Create a fingerprint hash from the User-Agent string
// This binds the token to the specific browser/client
pub fn create_fingerprint(user_agent: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    user_agent.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

// Create access token — short lived (15 minutes)
// fingerprint: pass the User-Agent header value
pub fn create_access_token(
    user_id: Uuid,
    email: &str,
    role: &str,
    user_agent: Option<&str>,
) -> Result<String, String> {
    dotenv().ok();

    let expiry_secs: u64 = env::var("ACCESS_TOKEN_EXPIRY")
        .unwrap_or("900".to_string())
        .parse()
        .unwrap_or(900);

    let now = Utc::now().timestamp() as usize;

    // Create fingerprint from User-Agent if provided
    let fingerprint = user_agent.map(|ua| create_fingerprint(ua));

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: now + expiry_secs as usize,
        iat: now,
        token_type: "access".to_string(),
        fingerprint,
    };

    // RS256 — sign with PRIVATE key
    encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &load_private_key(),
    )
    .map_err(|e| format!("Failed to create access token: {}", e))
}

// Create refresh token — long lived (7 days)
pub fn create_refresh_token(
    user_id: Uuid,
    email: &str,
    role: &str,
    user_agent: Option<&str>,
) -> Result<String, String> {
    dotenv().ok();

    let expiry_secs: u64 = env::var("REFRESH_TOKEN_EXPIRY")
        .unwrap_or("604800".to_string())
        .parse()
        .unwrap_or(604800);

    let now = Utc::now().timestamp() as usize;
    let fingerprint = user_agent.map(|ua| create_fingerprint(ua));

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: now + expiry_secs as usize,
        iat: now,
        token_type: "refresh".to_string(),
        fingerprint,
    };

    // RS256 — sign with PRIVATE key
    encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &load_private_key(),
    )
    .map_err(|e| format!("Failed to create refresh token: {}", e))
}

// Verify a token — checks signature AND optionally fingerprint
// user_agent: pass the current request's User-Agent to verify fingerprint
pub fn verify_token(token: &str) -> Result<Claims, String> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;

    // Verify with PUBLIC key — cannot forge without private key
    decode::<Claims>(
        token,
        &load_public_key(),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| format!("Invalid token: {}", e))
}

// Verify token AND check fingerprint matches current User-Agent
pub fn verify_token_with_fingerprint(
    token: &str,
    user_agent: &str,
) -> Result<Claims, String> {
    let claims = verify_token(token)?;

    // If token has a fingerprint, verify it matches current User-Agent
    if let Some(ref stored_fingerprint) = claims.fingerprint {
        let current_fingerprint = create_fingerprint(user_agent);
        if *stored_fingerprint != current_fingerprint {
            return Err(
                "Token fingerprint mismatch — possible token theft detected".to_string()
            );
        }
    }

    Ok(claims)
}