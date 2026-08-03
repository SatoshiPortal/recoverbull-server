use crate::{
    models::{FetchSecret, StatEntry},
    tests::{NOT_PASSWORD_HASH, SHA256_111111},
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
