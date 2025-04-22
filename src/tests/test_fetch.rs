use crate::{
    models::{ResponseFailedAttempt, FetchSecret, Secret, StoreSecret},
    tests::{
        BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222,
        SHA256_CONCAT_111111_222222,
    },
};
use axum::http::StatusCode;

#[tokio::test]
async fn test_fetch_success() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };

    server.post("/store").json(&store).expect_success().await;

    let fetch = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    };

    let response = server.post("/fetch").json(&fetch).expect_success().await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let secret = response.json::<Secret>();
    assert_eq!(secret.id, SHA256_CONCAT_111111_222222);
    assert_eq!(secret.encrypted_secret, BASE64_ENCRYPTED_SECRET);
}

#[tokio::test]
async fn test_fetch_key_failure_invalid_hash_for_format_identifier() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let fetch = &FetchSecret {
        identifier: "not_a_hash".to_string(),
        authentication_key: SHA256_111111.to_string(),
    };

    let response = server.post("/fetch").json(&fetch).expect_failure().await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_fetch_failure_invalid_hash_format_for_authentication_key() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let fetch = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: "not_a_hash".to_string(),
    };

    let response = server.post("/fetch").json(&fetch).expect_failure().await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_fetch_rate_limit_enforced_and_reset_after_cooldown() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    println!("\n\nThis test takes {} seconds to be executed", state.rate_limit_cooldown.num_seconds());

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };

    server.post("/store").json(&store).expect_success().await;

    let fetch_wrong_authentication_key = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: NOT_PASSWORD_HASH.to_string(), // this should make the fetchy fail
    };

    // trigger rate limit by attempting many fail attempts
    for i in 0..state.rate_limit_max_failed_attempts {
        let response = server
            .post("/fetch")
            .json(&fetch_wrong_authentication_key)
            .expect_failure()
            .await;
        
        let failed_attempt = response.json::<ResponseFailedAttempt>();
        assert_eq!(failed_attempt.attempts, i+1);
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

        println!("attempts: {} | code: {}", failed_attempt.attempts, response.status_code());
    }
    
    // trigger the rate_limit_cooldown
    let response = server
        .post("/fetch")
        .json(&fetch_wrong_authentication_key)
        .expect_failure()
        .await;

    let failed_attempt = response.json::<ResponseFailedAttempt>();
    assert_eq!(failed_attempt.attempts, state.rate_limit_max_failed_attempts);
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);

    println!("attempts: {} | code: {}", failed_attempt.attempts, response.status_code());
    
    let rate_limit_cooldown = state.rate_limit_cooldown.num_seconds() as u64;
    println!("\rWaiting… {} seconds rate_limit_cooldown", rate_limit_cooldown);
    std::thread::sleep(std::time::Duration::from_secs(rate_limit_cooldown));

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;

    let secret = response.json::<Secret>();
    
    println!("code: {} | key: {}", response.status_code(), secret.encrypted_secret);

    assert_eq!(secret.id, SHA256_CONCAT_111111_222222);
    assert_eq!(secret.encrypted_secret, BASE64_ENCRYPTED_SECRET);

    // ensure the entry is not in the map anymore
    let identifier_rate_limit = state.identifier_rate_limit.lock().await;
    assert_eq!(identifier_rate_limit.contains_key(SHA256_111111), false);
}
