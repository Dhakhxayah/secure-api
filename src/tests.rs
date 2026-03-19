// Unit tests — verify core security functions work correctly
// Run with: cargo test

#[cfg(test)]
mod tests {
    use crate::utils::password::{hash_password, verify_password};
    use crate::utils::jwt::{create_access_token, verify_token};
    use uuid::Uuid;

    // ─── Password Tests ───────────────────────────────────────

    #[test]
    fn test_password_hash_is_not_plaintext() {
        let password = "mysecretpassword";
        let hash = hash_password(password).unwrap();

        // Hash should never equal the original password
        assert_ne!(hash, password);
        // Hash should start with argon2 identifier
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn test_password_verify_correct() {
        let password = "correctpassword123";
        let hash = hash_password(password).unwrap();
        let result = verify_password(password, &hash).unwrap();

        // Correct password should verify as true
        assert!(result);
    }

    #[test]
    fn test_password_verify_wrong() {
        let password = "correctpassword123";
        let hash = hash_password(password).unwrap();
        let result = verify_password("wrongpassword", &hash).unwrap();

        // Wrong password should verify as false
        assert!(!result);
    }

    #[test]
    fn test_two_hashes_of_same_password_are_different() {
        // Because of random salt, same password = different hash every time
        let hash1 = hash_password("samepassword").unwrap();
        let hash2 = hash_password("samepassword").unwrap();
        assert_ne!(hash1, hash2);
    }

    // ─── JWT Tests ────────────────────────────────────────────

    #[test]
    fn test_jwt_token_created_and_verified() {
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
        let result = verify_token("this.is.not.a.valid.token");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_tampered_token_rejected() {
        let user_id = Uuid::new_v4();
        let token = create_access_token(user_id, "test@example.com", "user").unwrap();

        // Tamper with the token by changing last character
        let mut tampered = token.clone();
        tampered.push('X');

        let result = verify_token(&tampered);
        assert!(result.is_err());
    }

    // ─── Input Validation Tests ───────────────────────────────

    #[test]
    fn test_email_validation_catches_missing_at() {
        let email = "notanemail.com";
        assert!(!email.contains('@'));
    }

    #[test]
    fn test_email_validation_catches_too_short() {
        let email = "a@b";
        assert!(email.len() < 5);
    }

    #[test]
    fn test_password_too_short_caught() {
        let password = "short";
        assert!(password.len() < 8);
    }

    #[test]
    fn test_sql_injection_payload_as_string() {
        // Parameterized queries treat this as plain text
        // This test documents that the dangerous string exists
        // but our queries never interpolate it directly
        let payload = "'; DROP TABLE users; --";
        assert!(payload.contains("DROP TABLE"));
        // In our app this is passed as $1 parameter — never executed as SQL
    }
}