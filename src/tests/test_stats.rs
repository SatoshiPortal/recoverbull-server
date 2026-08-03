use crate::{
    models::{FetchSecret, StatEntry, StoreSecret},
    tests::{BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222},
    utils::sha256_hex,
};
use axum::http::StatusCode;

#[tokio::test]
async fn test_stats_publish_hashed_identifier_with_bruteforce_info() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let fetch_wrong_authentication_key = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: NOT_PASSWORD_HASH.to_string(),
    };

    // two failed attempts
    for _ in 0..2 {
        let response = server
            .post("/fetch")
            .json(&fetch_wrong_authentication_key)
            .expect_failure()
            .await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    let response = server.get("/stats").expect_success().await;
    let body = response.text();
    let stats = response.json::<Vec<StatEntry>>();

    // the raw identifier must never leak
    assert!(!body.contains(SHA256_111111));

    assert_eq!(stats.len(), 1);
    let expected_id_hash = sha256_hex(&hex::decode(SHA256_111111).unwrap());
    assert_eq!(stats[0].id_hash, expected_id_hash);
    assert_eq!(stats[0].attempts, 2);
}

#[tokio::test]
async fn test_fetch_success_reports_and_resets_failed_attempts() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    server.post("/store").json(&store).expect_success().await;

    // two failed attempts
    for _ in 0..2 {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: NOT_PASSWORD_HASH.to_string(),
            })
            .expect_failure()
            .await;
    }

    // successful fetch reports the failed attempts
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;
    let body = response.json::<serde_json::Value>();
    assert_eq!(body["failed_attempts"], 2);

    // the counter has been reset: stats are empty again
    let response = server.get("/stats").expect_success().await;
    let stats = response.json::<Vec<StatEntry>>();
    assert_eq!(stats.len(), 0);

    // a subsequent successful fetch reports zero failed attempts
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;
    let body = response.json::<serde_json::Value>();
    assert_eq!(body["failed_attempts"], 0);
}
