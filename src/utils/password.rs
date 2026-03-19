use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

// WHY HASHING?
// Never store plain passwords in a database.
// If your DB gets hacked, attackers get hashes — not real passwords.
// Argon2 is the strongest modern password hashing algorithm.
// It's intentionally slow (takes ~100ms) to make brute force attacks impractical.

pub fn hash_password(password: &str) -> Result<String, String> {
    // Generate a random salt
    // Salt is random data added to password before hashing
    // This ensures two users with same password get different hashes
    let salt = SaltString::generate(&mut OsRng);

    // Create an Argon2 hasher with default settings
    let argon2 = Argon2::default();

    // Hash the password with the salt
    // Result looks like: "$argon2id$v=19$m=19456,t=2,p=1$..."
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("Failed to hash password: {}", e))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    // Parse the stored hash string back into a PasswordHash object
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| format!("Failed to parse hash: {}", e))?;

    // Verify the provided password against the stored hash
    // Argon2 extracts the salt from the hash and re-hashes to compare
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
