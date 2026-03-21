// HTML Sanitization using ammonia
// Strips all dangerous HTML tags and attributes
// Protects against XSS (Cross-Site Scripting) attacks

// WHY THIS MATTERS:
// If a user submits "<script>steal(document.cookie)</script>" as their name
// and you store it without sanitizing, every browser that renders that name
// will execute the script and steal cookies of logged-in users.
// ammonia strips all HTML tags, leaving only plain text.
#[allow(dead_code)]
pub fn sanitize_html(input: &str) -> String {
    // ammonia::clean strips ALL HTML by default
    // Returns plain text with all tags removed
    ammonia::clean(input)
}

pub fn sanitize_email(email: &str) -> String {
    // Emails should never contain HTML
    // Strip tags and trim whitespace
    let cleaned = ammonia::clean(email);
    cleaned.trim().to_lowercase()
}

// Validate and sanitize a general text field
// max_length: maximum allowed characters
pub fn sanitize_text(input: &str, max_length: usize) -> Result<String, String> {
    // Check length first before sanitizing
    if input.len() > max_length {
        return Err(format!(
            "Input too long. Maximum {} characters allowed.",
            max_length
        ));
    }

    // Strip HTML tags
    let cleaned = ammonia::clean(input);

    // Check for null bytes — used in some injection attacks
    if cleaned.contains('\0') {
        return Err("Invalid characters in input".to_string());
    }

    Ok(cleaned)
}

// Check if a string looks like an XSS attempt
// Used for logging suspicious requests
pub fn looks_like_xss(input: &str) -> bool {
    let input_lower = input.to_lowercase();
    let xss_patterns = [
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "onclick=",
        "eval(",
        "document.cookie",
        "window.location",
        "<iframe",
        "<img",
    ];

    xss_patterns.iter().any(|pattern| input_lower.contains(pattern))
}

#[cfg(test)]
mod sanitize_tests {
    use super::*;

    #[test]
    fn test_script_tag_stripped() {
        let input = "<script>alert('xss')</script>Hello";
        let result = sanitize_html(input);
        assert!(!result.contains("<script>"));
        assert!(result.contains("Hello"));
    }

    #[test]
    fn test_javascript_protocol_stripped() {
        let input = "<a href='javascript:steal()'>click</a>";
        let result = sanitize_html(input);
        assert!(!result.contains("javascript:"));
    }

    #[test]
    fn test_plain_text_unchanged() {
        let input = "Hello, I am a normal user";
        let result = sanitize_html(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_email_lowercased() {
        let input = "Test@Example.COM";
        let result = sanitize_email(input);
        assert_eq!(result, "test@example.com");
    }

    #[test]
    fn test_text_too_long_rejected() {
        let input = "a".repeat(300);
        let result = sanitize_text(&input, 255);
        assert!(result.is_err());
    }

    #[test]
    fn test_xss_detection() {
        assert!(looks_like_xss("<script>alert(1)</script>"));
        assert!(looks_like_xss("javascript:void(0)"));
        assert!(!looks_like_xss("Hello world"));
    }
}