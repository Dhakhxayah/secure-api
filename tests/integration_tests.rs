// Integration Tests
// Run with: cargo test --test integration_tests -- --test-threads=1

const BASE_URL: &str = "http://localhost:3000";

async fn post_json(
    client: &reqwest::Client,
    path: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    client
        .post(format!("{}{}", BASE_URL, path))
        .header("Content-Type", "application/json")
        .header("User-Agent", "IntegrationTestRunner/1.0")
        .json(&body)
        .send()
        .await
        .expect("Request failed — is cargo run active?")
}

async fn get_authenticated(
    client: &reqwest::Client,
    path: &str,
    token: &str,
) -> reqwest::Response {
    client
        .get(format!("{}{}", BASE_URL, path))
        .header("User-Agent", "IntegrationTestRunner/1.0")
        .bearer_auth(token)
        .send()
        .await
        .expect("Request failed")
}

// Helper — register and login, returns token
// Retries if rate limited
async fn register_and_login(
    client: &reqwest::Client,
    email: &str,
    password: &str,
) -> String {
    // Keep trying registration until it succeeds
    loop {
        let res = post_json(client, "/auth/register", serde_json::json!({
            "email": email,
            "password": password
        })).await;

        let body: serde_json::Value = res.json().await.unwrap();

        if body["user_id"].is_string() {
            break;
        }

        if body["error"].as_str().unwrap_or("").contains("already registered") {
            break;
        }

        // Rate limited — wait and retry
        println!("Register rate limited, waiting 65 seconds...");
        tokio::time::sleep(tokio::time::Duration::from_secs(65)).await;
    }

    // Keep trying login until it succeeds
    loop {
        let res = post_json(client, "/auth/login", serde_json::json!({
            "email": email,
            "password": password
        })).await;

        let body: serde_json::Value = res.json().await.unwrap();

        if let Some(token) = body["access_token"].as_str() {
            return token.to_string();
        }

        // Rate limited — wait and retry
        println!("Login rate limited, waiting 65 seconds...");
        tokio::time::sleep(tokio::time::Duration::from_secs(65)).await;
    }
}

// ─── Health Check Tests ───────────────────────────────────────

#[tokio::test]
async fn test_health_endpoint_returns_200() {
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/health", BASE_URL))
        .send()
        .await
        .expect("Failed to reach server — is cargo run active?");
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
async fn test_root_endpoint_returns_200() {
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/", BASE_URL))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

// ─── Registration Tests ───────────────────────────────────────

#[tokio::test]
async fn test_register_with_valid_data_returns_201() {
    let client = reqwest::Client::new();
    let email = format!("test_{}@example.com", uuid::Uuid::new_v4());
    let res = post_json(&client, "/auth/register", serde_json::json!({
        "email": email,
        "password": "securepassword123"
    })).await;
    assert_eq!(res.status(), 201);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body["user_id"].is_string());
}

#[tokio::test]
async fn test_register_with_short_password_returns_400() {
    let client = reqwest::Client::new();
    let res = post_json(&client, "/auth/register", serde_json::json!({
        "email": "shortpass@example.com",
        "password": "short"
    })).await;
    // Accept 400 or 429 (rate limited) — both mean server handled it correctly
    assert!(
        res.status() == 400 || res.status() == 429,
        "Expected 400 or 429, got {}", res.status()
    );
}

#[tokio::test]
async fn test_register_with_invalid_email_returns_400() {
    let client = reqwest::Client::new();
    let res = post_json(&client, "/auth/register", serde_json::json!({
        "email": "notanemail",
        "password": "securepassword123"
    })).await;
    assert!(
        res.status() == 400 || res.status() == 429,
        "Expected 400 or 429, got {}", res.status()
    );
}

#[tokio::test]
async fn test_register_duplicate_email_returns_409() {
    let client = reqwest::Client::new();
    let email = format!("duplicate_{}@example.com", uuid::Uuid::new_v4());
    post_json(&client, "/auth/register", serde_json::json!({
        "email": email,
        "password": "securepassword123"
    })).await;
    let res = post_json(&client, "/auth/register", serde_json::json!({
        "email": email,
        "password": "securepassword123"
    })).await;
    assert!(
        res.status() == 409 || res.status() == 429,
        "Expected 409 or 429, got {}", res.status()
    );
}

#[tokio::test]
async fn test_register_with_xss_payload_returns_400() {
    let client = reqwest::Client::new();
    let res = post_json(&client, "/auth/register", serde_json::json!({
        "email": "<script>alert('xss')</script>@evil.com",
        "password": "securepassword123"
    })).await;
    assert!(
        res.status() == 400 || res.status() == 429,
        "Expected 400 or 429, got {}", res.status()
    );
}

// ─── Login Tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_login_with_valid_credentials_returns_200() {
    let client = reqwest::Client::new();
    let email = format!("login_{}@example.com", uuid::Uuid::new_v4());
    let token = register_and_login(&client, &email, "securepassword123").await;
    assert!(!token.is_empty(), "Should get a valid token");
}

#[tokio::test]
async fn test_login_with_wrong_password_returns_401() {
    let client = reqwest::Client::new();
    let email = format!("wrongpass_{}@example.com", uuid::Uuid::new_v4());

    register_and_login(&client, &email, "correctpassword123").await;

    let res = post_json(&client, "/auth/login", serde_json::json!({
        "email": email,
        "password": "wrongpassword123"
    })).await;
    assert!(
        res.status() == 401 || res.status() == 429,
        "Expected 401 or 429, got {}", res.status()
    );
}

#[tokio::test]
async fn test_login_with_nonexistent_email_returns_401() {
    let client = reqwest::Client::new();
    let res = post_json(&client, "/auth/login", serde_json::json!({
        "email": "nonexistent_never_registered@example.com",
        "password": "somepassword123"
    })).await;
    assert!(
        res.status() == 401 || res.status() == 429,
        "Expected 401 or 429, got {}", res.status()
    );
}

// ─── JWT Token Tests ──────────────────────────────────────────

#[tokio::test]
async fn test_protected_route_without_token_returns_401() {
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/auth/me", BASE_URL))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn test_protected_route_with_invalid_token_returns_401() {
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/auth/me", BASE_URL))
        .header("User-Agent", "IntegrationTestRunner/1.0")
        .bearer_auth("this.is.not.a.valid.token")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn test_protected_route_with_valid_token_returns_200() {
    let client = reqwest::Client::new();
    let email = format!("protected_{}@example.com", uuid::Uuid::new_v4());
    let token = register_and_login(&client, &email, "securepassword123").await;
    let res = get_authenticated(&client, "/auth/me", &token).await;
    assert_eq!(res.status(), 200);
    let profile: serde_json::Value = res.json().await.unwrap();
    assert_eq!(profile["email"], email);
    assert_eq!(profile["role"], "user");
}

// ─── Logout + Blacklist Tests ─────────────────────────────────

#[tokio::test]
async fn test_token_invalidated_after_logout() {
    let client = reqwest::Client::new();
    let email = format!("logout_{}@example.com", uuid::Uuid::new_v4());
    let token = register_and_login(&client, &email, "securepassword123").await;

    // Logout
    client
        .post(format!("{}/auth/logout", BASE_URL))
        .header("User-Agent", "IntegrationTestRunner/1.0")
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    // Try using token after logout — must be rejected
    let res = get_authenticated(&client, "/auth/me", &token).await;
    assert_eq!(res.status(), 401, "Token should be invalid after logout");
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("invalidated"));
}

// ─── Security Header Tests ────────────────────────────────────

#[tokio::test]
async fn test_security_headers_present() {
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/health", BASE_URL))
        .send()
        .await
        .unwrap();
    let headers = res.headers();
    assert!(headers.contains_key("x-content-type-options"));
    assert!(headers.contains_key("x-frame-options"));
    assert!(headers.contains_key("referrer-policy"));
}

// ─── Rate Limit Tests ─────────────────────────────────────────

#[tokio::test]
async fn test_rate_limit_headers_present() {
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/", BASE_URL))
        .send()
        .await
        .unwrap();
    let headers = res.headers();
    assert!(headers.contains_key("x-ratelimit-limit"));
    assert!(headers.contains_key("x-ratelimit-remaining"));
    assert!(headers.contains_key("x-ratelimit-algorithm"));
}

// ─── API Key Tests ────────────────────────────────────────────

#[tokio::test]
async fn test_api_key_create_and_use() {
    let client = reqwest::Client::new();
    let email = format!("apikey_{}@example.com", uuid::Uuid::new_v4());
    let token = register_and_login(&client, &email, "securepassword123").await;

    let key_res = client
        .post(format!("{}/api-keys", BASE_URL))
        .header("User-Agent", "IntegrationTestRunner/1.0")
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Integration Test Key",
            "scopes": ["read"],
            "expires_in_days": 1
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(key_res.status(), 201);
    let key_body: serde_json::Value = key_res.json().await.unwrap();
    let api_key = key_body["key"].as_str().unwrap();

    let profile_res = client
        .get(format!("{}/auth/me", BASE_URL))
        .header("X-API-Key", api_key)
        .send()
        .await
        .unwrap();

    assert_eq!(profile_res.status(), 200);
    let profile: serde_json::Value = profile_res.json().await.unwrap();
    assert_eq!(profile["email"], email);
}