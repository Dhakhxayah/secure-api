// Fuzz Tests
// Throw random and malicious inputs at every endpoint
// Verify the server NEVER crashes — always returns a proper HTTP error
//
// Run with: cargo test --test fuzz_tests

const BASE_URL: &str = "http://localhost:3000";

// Collection of malicious payloads to test against
fn get_malicious_payloads() -> Vec<&'static str> {
    vec![
        // SQL Injection
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --",
        "1; DELETE FROM users",

        // XSS
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<iframe src='javascript:alert(1)'>",

        // Path Traversal
        "../../etc/passwd",
        "../../../windows/system32",
        "....//....//etc/passwd",

        // Null Bytes
        "test\0injection",
        "\x00admin",

        // Unicode Attacks
        "ａｄｍｉｎ",  // full-width chars
        "admin\u{200B}", // zero-width space

        // Oversized inputs (truncated here, generated in test)
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",

        // Format String
        "%s%s%s%s%s",
        "%x%x%x%x",

        // Empty / Whitespace
        "",
        "   ",
        "\n\n\n",
        "\t\t\t",
    ]
}

// Helper to send a POST request
async fn post_json(
    client: &reqwest::Client,
    path: &str,
    body: serde_json::Value,
) -> u16 {
    match client
        .post(format!("{}{}", BASE_URL, path))
        .header("Content-Type", "application/json")
        .header("User-Agent", "FuzzTester/1.0")
        .json(&body)
        .send()
        .await
    {
        Ok(res) => res.status().as_u16(),
        Err(_) => 0, // 0 means connection failed / server crashed
    }
}

// ─── Register Endpoint Fuzz ───────────────────────────────────

#[tokio::test]
async fn fuzz_register_email_field() {
    let client = reqwest::Client::new();
    let payloads = get_malicious_payloads();

    for payload in payloads {
        let status = post_json(&client, "/auth/register", serde_json::json!({
            "email": payload,
            "password": "normalpassword123"
        })).await;

        assert_ne!(
            status, 0,
            "Server crashed or refused connection on email payload: {:?}", payload
        );
        assert_ne!(
            status, 500,
            "Server returned 500 on email payload: {:?}", payload
        );

        // Should always be a client error (4xx) not server error (5xx)
        assert!(
            status >= 400 && status < 500 || status == 201 || status == 409,
            "Unexpected status {} for payload: {:?}", status, payload
        );
    }
}

#[tokio::test]
async fn fuzz_register_password_field() {
    let client = reqwest::Client::new();
    let payloads = get_malicious_payloads();

    for payload in payloads {
        let status = post_json(&client, "/auth/register", serde_json::json!({
            "email": "fuzz@test.com",
            "password": payload
        })).await;

        assert_ne!(status, 0, "Server crashed on password payload: {:?}", payload);
        assert_ne!(status, 500, "Server 500 on password payload: {:?}", payload);
    }
}

// ─── Login Endpoint Fuzz ──────────────────────────────────────

#[tokio::test]
async fn fuzz_login_email_field() {
    let client = reqwest::Client::new();
    let payloads = get_malicious_payloads();

    for payload in payloads {
        let status = post_json(&client, "/auth/login", serde_json::json!({
            "email": payload,
            "password": "normalpassword123"
        })).await;

        assert_ne!(status, 0, "Server crashed on login email: {:?}", payload);
        assert_ne!(status, 500, "Server 500 on login email: {:?}", payload);
    }
}

#[tokio::test]
async fn fuzz_login_password_field() {
    let client = reqwest::Client::new();
    let payloads = get_malicious_payloads();

    for payload in payloads {
        let status = post_json(&client, "/auth/login", serde_json::json!({
            "email": "fuzz@test.com",
            "password": payload
        })).await;

        assert_ne!(status, 0, "Server crashed on login password: {:?}", payload);
        assert_ne!(status, 500, "Server 500 on login password: {:?}", payload);
    }
}

// ─── Random Input Fuzz ────────────────────────────────────────

#[tokio::test]
async fn fuzz_random_json_bodies() {
    use rand::Rng;
    let client = reqwest::Client::new();
    let mut rng = rand::thread_rng();

    let endpoints = ["/auth/register", "/auth/login"];

    for endpoint in &endpoints {
        for _ in 0..20 {
            // Generate random string of random length
            let len = rng.gen_range(0..200);
            let random_string: String = (0..len)
                .map(|_| rng.gen_range(32u8..127u8) as char)
                .collect();

            let status = post_json(&client, endpoint, serde_json::json!({
                "email": random_string,
                "password": random_string
            })).await;

            assert_ne!(
                status, 0,
                "Server crashed on random input to {}", endpoint
            );
            assert_ne!(
                status, 500,
                "Server returned 500 on random input to {}", endpoint
            );
        }
    }
}

#[tokio::test]
async fn fuzz_oversized_inputs() {
    let client = reqwest::Client::new();

    // Generate very large strings
    let large_string = "A".repeat(10_000);
    let huge_string = "B".repeat(100_000);

    let payloads = vec![large_string.as_str(), huge_string.as_str()];

    for payload in payloads {
        let status = post_json(&client, "/auth/register", serde_json::json!({
            "email": payload,
            "password": payload
        })).await;

        // Should reject — not crash
        assert_ne!(status, 0, "Server crashed on oversized input");
        assert_ne!(status, 500, "Server 500 on oversized input");
    }
}

#[tokio::test]
async fn fuzz_wrong_content_types() {
    let client = reqwest::Client::new();

    // Send plain text instead of JSON
    let res = client
        .post(format!("{}/auth/register", BASE_URL))
        .header("Content-Type", "text/plain")
        .body("not json at all")
        .send()
        .await
        .unwrap();

    assert_ne!(res.status().as_u16(), 500, "Server 500 on wrong content type");

    // Send XML instead of JSON
    let res = client
        .post(format!("{}/auth/register", BASE_URL))
        .header("Content-Type", "application/xml")
        .body("<user><email>test</email></user>")
        .send()
        .await
        .unwrap();

    assert_ne!(res.status().as_u16(), 500, "Server 500 on XML input");
}

#[tokio::test]
async fn fuzz_missing_fields() {
    let client = reqwest::Client::new();

    // Missing password
    let status = post_json(&client, "/auth/register", serde_json::json!({
        "email": "test@example.com"
    })).await;
    assert_ne!(status, 500, "Server 500 on missing password field");

    // Missing email
    let status = post_json(&client, "/auth/register", serde_json::json!({
        "password": "somepassword"
    })).await;
    assert_ne!(status, 500, "Server 500 on missing email field");

    // Empty body
    let res = client
        .post(format!("{}/auth/register", BASE_URL))
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_ne!(res.status().as_u16(), 500, "Server 500 on empty JSON");

    // Completely empty body
    let res = client
        .post(format!("{}/auth/register", BASE_URL))
        .header("Content-Type", "application/json")
        .body("")
        .send()
        .await
        .unwrap();
    assert_ne!(res.status().as_u16(), 500, "Server 500 on empty body");
}