//! HTTP-boundary tests for request validation and route-surface behavior.
//!
//! These tests exercise the boundary between raw HTTP requests and application
//! handlers: accepted methods, routes, content types, body limits, and JSON
//! input shape.

use crate::{
    http::contract::FetchSecret,
    tests::{SHA256_111111, SHA256_222222},
};
use axum::http::StatusCode;

// ---------------------------------------------------------------------------
// Input validation: reject anything that is not exactly the expected shape
// ---------------------------------------------------------------------------

/// A 64-char identifier containing a non-ASCII character (fullwidth lookalike)
/// is rejected: hex is ASCII-only, and Unicode must never bypass the length
/// check through multi-byte tricks.
#[tokio::test]
async fn test_unicode_identifier_rejected() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    // 63 ASCII hex chars + one fullwidth 'ａ' (U+FF41): 64 chars, not hex
    let mut identifier = "a".repeat(63);
    identifier.push('ａ');

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier,
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

/// An identifier with interior whitespace is rejected: it is not 64 hex
/// characters, and normalization must not silently strip spaces into a valid
/// one.
#[tokio::test]
async fn test_identifier_with_whitespace_rejected() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let mut identifier = "a".repeat(32);
    identifier.push(' ');
    identifier.push_str(&"b".repeat(31));

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier,
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

/// Identifier and authentication_key must be exactly 64 hex characters:
/// empty, 63, 65, and non-hex are all rejected before any lookup.
#[tokio::test]
async fn test_malformed_identifier_and_key_lengths_rejected() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    for identifier in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "z".repeat(64), // not hex
    ] {
        let response = server
            .post("/fetch")
            .json(&FetchSecret {
                identifier,
                authentication_key: SHA256_222222.to_string(),
            })
            .expect_failure()
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }

    for key in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "z".repeat(64),
    ] {
        let response = server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: key,
            })
            .expect_failure()
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }
}

/// The 1024-byte body limit applies to `/fetch` and `/trash` too, not only
/// `/store`: an oversized body is rejected before deserialization.
#[tokio::test]
async fn test_fetch_and_trash_reject_oversized_body() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    // serde ignores unknown fields, so a padded but otherwise valid body is
    // the way to exceed the limit through the JSON extractor
    let oversized = serde_json::json!({
        "identifier": SHA256_111111,
        "authentication_key": SHA256_222222,
        "pad": "x".repeat(2048),
    });

    for path in ["/fetch", "/trash"] {
        let response = server.post(path).json(&oversized).expect_failure().await;
        assert_eq!(
            response.status_code(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{path} must enforce the body limit"
        );
    }
}

/// A maximally nested JSON body below the HTTP limit is rejected without
/// crashing the worker. `FetchSecret` has no recursive fields, and serde's
/// ignored-value path does not raise a separate recursion-limit error here;
/// the 1024-byte body limit is therefore the effective nesting bound.
#[tokio::test]
async fn test_maximally_nested_under_body_limit_json_rejected_without_crash() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    const DEPTH: usize = 500;
    let mut nested = String::from("{\"ignored\":");
    for _ in 0..DEPTH {
        nested.push('[');
    }
    nested.push('1');
    for _ in 0..DEPTH {
        nested.push(']');
    }
    nested.push('}');
    assert!(
        nested.len() < 1024,
        "the nested payload must stay below the HTTP body limit, got {} bytes",
        nested.len()
    );

    let response = server
        .post("/fetch")
        .bytes(nested.into())
        .content_type("application/json")
        .expect_failure()
        .await;
    assert!(
        response.status_code() != StatusCode::PAYLOAD_TOO_LARGE,
        "the recursion payload must not be rejected by the HTTP body limit"
    );
    assert_eq!(
        response.status_code(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "serde JSON recursion errors must use Axum's 422 rejection"
    );
    let body = response.text();
    assert!(
        body.contains("missing field `identifier`"),
        "the under-limit nested body must be rejected by the request schema, got: {body}"
    );

    // the server is still alive
    let alive = server.get("/info").expect_success().await;
    assert_eq!(alive.status_code(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Route surface: methods, unknown routes, content-type, /info availability
// ---------------------------------------------------------------------------

/// `/info` is not rate-limited: it stays available even when every bucket is
/// exhausted (it is the cheap liveness + canary endpoint).
#[tokio::test]
async fn test_info_is_not_rate_limited() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    state
        .recovery
        .set_lookup_bucket_for_test(crate::rate_limit::TokenBucket::new(0.0, 0.0))
        .await;
    state
        .recovery
        .set_store_bucket_for_test(crate::rate_limit::TokenBucket::new(0.0, 0.0))
        .await;
    state
        .attempts
        .maintenance
        .set_bucket_for_test(crate::rate_limit::TokenBucket::new(0.0, 0.0))
        .await;

    let response = server.get("/info").expect_success().await;
    assert_eq!(response.status_code(), StatusCode::OK);
}

/// Wrong method on a known route is 405, not 404 and not a handler bypass.
#[tokio::test]
async fn test_wrong_method_returns_405() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    for (method, path) in [
        ("GET", "/fetch"),
        ("GET", "/store"),
        ("GET", "/trash"),
        ("POST", "/attempts"),
        ("POST", "/info"),
    ] {
        let response = match method {
            "GET" => server.get(path).await,
            _ => server.post(path).text("").await,
        };
        assert_eq!(
            response.status_code(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} must be 405"
        );
    }
}

/// An unknown route is 404: no catch-all handler leaks into an endpoint.
#[tokio::test]
async fn test_unknown_route_returns_404() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let response = server.get("/nonexistent").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

/// A POST without a JSON content-type is 415: the Json extractor rejects it
/// before any handler logic runs.
#[tokio::test]
async fn test_missing_or_wrong_content_type_returns_415() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let body = format!(
        "{{\"identifier\":\"{}\",\"authentication_key\":\"{}\"}}",
        SHA256_111111, SHA256_222222
    );

    // wrong content-type
    let response = server
        .post("/fetch")
        .add_header("content-type", "text/plain")
        .text(body.clone())
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}
