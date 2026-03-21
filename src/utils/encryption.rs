// Field-Level Encryption using AES-256-GCM
//
// WHY AES-256-GCM?
// - AES-256: Military-grade encryption, 256-bit key
// - GCM: Galois/Counter Mode — provides both encryption AND authentication
//   meaning it detects if encrypted data was tampered with
//
// HOW IT WORKS:
// Encrypt: plaintext + key + nonce → ciphertext
// Decrypt: ciphertext + key + nonce → plaintext
//
// Nonce: A random number used once per encryption
// Every encryption uses a different nonce so same plaintext
// produces different ciphertext each time

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dotenvy::dotenv;
use std::env;

// Get encryption key from environment
// Key must be exactly 32 bytes for AES-256
fn get_encryption_key() -> [u8; 32] {
    dotenv().ok();
    let key_str = env::var("ENCRYPTION_KEY")
        .unwrap_or("default_key_change_in_production!!".to_string());

    let mut key = [0u8; 32];
    let bytes = key_str.as_bytes();

    // Fill key array — pad or truncate to exactly 32 bytes
    let len = bytes.len().min(32);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

// Encrypt a plaintext string
// Returns base64-encoded string: "nonce:ciphertext"
// We store nonce alongside ciphertext so we can decrypt later
pub fn encrypt(plaintext: &str) -> Result<String, String> {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Cipher init failed: {}", e))?;

    // Generate random nonce — 12 bytes for AES-GCM
    // NEVER reuse a nonce with the same key
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Encode both nonce and ciphertext as base64
    // Format: "base64(nonce):base64(ciphertext)"
    let nonce_b64 = BASE64.encode(nonce.as_slice());
    let cipher_b64 = BASE64.encode(&ciphertext);

    Ok(format!("{}:{}", nonce_b64, cipher_b64))
}

// Decrypt an encrypted string
// Input format: "base64(nonce):base64(ciphertext)"
pub fn decrypt(encrypted: &str) -> Result<String, String> {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Cipher init failed: {}", e))?;

    // Split into nonce and ciphertext parts
    let parts: Vec<&str> = encrypted.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("Invalid encrypted format".to_string());
    }

    // Decode from base64
    let nonce_bytes = BASE64.decode(parts[0])
        .map_err(|e| format!("Nonce decode failed: {}", e))?;
    let ciphertext = BASE64.decode(parts[1])
        .map_err(|e| format!("Ciphertext decode failed: {}", e))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decrypt — also verifies data hasn't been tampered with
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext)
        .map_err(|e| format!("UTF-8 decode failed: {}", e))
}

// Check if a string looks like it's already encrypted
// Encrypted strings have our "nonce:ciphertext" format
#[allow(dead_code)]
pub fn is_encrypted(value: &str) -> bool {
    let parts: Vec<&str> = value.splitn(2, ':').collect();
    if parts.len() != 2 {
        return false;
    }
    // Both parts should be valid base64
    BASE64.decode(parts[0]).is_ok() && BASE64.decode(parts[1]).is_ok()
}

#[cfg(test)]
mod encryption_tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original = "test@example.com";
        let encrypted = encrypt(original).unwrap();
        let decrypted = decrypt(&encrypted).unwrap();
        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_encrypted_value_differs_from_plaintext() {
        let original = "test@example.com";
        let encrypted = encrypt(original).unwrap();
        assert_ne!(original, encrypted);
    }

    #[test]
    fn test_same_input_produces_different_ciphertext() {
        // Different nonces mean different ciphertext every time
        let encrypted1 = encrypt("test@example.com").unwrap();
        let encrypted2 = encrypt("test@example.com").unwrap();
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let encrypted = encrypt("test@example.com").unwrap();
        let mut tampered = encrypted.clone();
        tampered.push_str("TAMPERED");
        let result = decrypt(&tampered);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_format_fails() {
        let result = decrypt("notencrypted");
        assert!(result.is_err());
    }
}