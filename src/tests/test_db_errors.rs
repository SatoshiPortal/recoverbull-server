use crate::{
    http::contract::FetchSecret,
    recovery::identifiers::identifier_hash,
    storage::sqlite::Secret,
    tests::{SHA256_111111, SHA256_222222},
};
use axum::http::StatusCode;
use diesel::RunQueryDsl;

#[test]
fn test_connection_setup_failure_is_opaque_and_non_panicking() {
    let error = crate::storage::sqlite::establish_connection(
        "/path/that/does/not/exist/recoverbull.sqlite3".to_owned(),
    )
    .err()
    .expect("invalid database path must fail closed");
    assert_eq!(error, crate::storage::sqlite::ConnectionSetupError::Open);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_bounded_concurrent_connection_setup_and_write_diagnostics() {
    const ROUNDS: usize = 4;
    const CONCURRENCY: usize = 256;
    let (database_url, _guard) = crate::config::unique_test_database();
    let mut state = crate::app::init();
    state
        .recovery
        .set_database_url_for_test(database_url.clone());
    state.recovery.initialize_for_test().unwrap();

    let mut setup_errors = std::collections::BTreeMap::new();
    let mut write_errors = 0;
    for round in 0..ROUNDS {
        let mut tasks = Vec::with_capacity(CONCURRENCY);
        for index in 0..CONCURRENCY {
            let database_url = database_url.clone();
            tasks.push(tokio::task::spawn_blocking(move || {
                let connection = crate::storage::sqlite::establish_connection(database_url);
                let Ok(mut connection) = connection else {
                    return (connection.err(), true);
                };
                let secret = Secret {
                    id: format!("stress-{round}-{index}"),
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    encrypted_secret: "AA==".to_owned(),
                };
                (
                    None,
                    crate::storage::sqlite::write(&mut connection, &secret).is_err(),
                )
            }));
        }
        for task in tasks {
            let (setup_error, write_error) = task.await.unwrap();
            if let Some(error) = setup_error {
                *setup_errors.entry(error).or_insert(0usize) += 1;
            }
            write_errors += usize::from(write_error);
        }
    }

    assert!(
        setup_errors.is_empty(),
        "connection setup failures by static stage: {setup_errors:?}"
    );
    assert_eq!(
        write_errors, 0,
        "writes must not fail in the bounded diagnostic"
    );
}

#[tokio::test]
async fn test_handlers_return_generic_500_when_connection_setup_fails() {
    let mut state = crate::app::init();
    state.storage.initialize().unwrap();
    state
        .recovery
        .set_database_url_for_test("/path/that/does/not/exist/recoverbull.sqlite3".to_owned());
    let server = axum_test::TestServer::new(crate::router::new(state.clone())).unwrap();

    let store = server
        .post("/store")
        .json(&serde_json::json!({
            "identifier": SHA256_111111,
            "authentication_key": SHA256_222222,
            "encrypted_secret": crate::tests::BASE64_ENCRYPTED_SECRET,
        }))
        .await;
    assert_eq!(store.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

    let fetch = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_owned(),
            authentication_key: SHA256_222222.to_owned(),
        })
        .await;
    assert_eq!(fetch.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(state.attempts.ledger.lock_for_test().await.is_empty());
    assert_eq!(state.observability.counters.flush().database_error, 2);
}

/// A database failure must not be confused with wrong credentials:
/// the handler must respond 500 (not 401) and must not consume rate-limit
/// attempts, otherwise transient database trouble burns the user's
/// recovery attempts and locks them out.
#[tokio::test]
async fn test_database_error_returns_500_without_consuming_attempts() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    // Force every subsequent query to fail: drop the table out from under
    // the server. Database initialization is tested separately.
    let mut connection =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
    diesel::sql_query("DROP TABLE secret")
        .execute(&mut connection)
        .expect("failed to drop table");

    let fetch = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    };

    // More requests than max_failed_attempts: none may be 401 or 429.
    for _ in 0..(state.attempts.policy.max_attempts() + 2) {
        let response = server.post("/fetch").json(fetch).await;
        assert_eq!(
            response.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "database errors must be reported as 500, not as invalid credentials"
        );
    }

    // No rate-limit entry may remain: attempts were refunded.
    let identifier_rate_limit = state.attempts.ledger.lock_for_test().await;
    assert!(!identifier_rate_limit.contains_key(&identifier_hash(SHA256_111111).unwrap()));
}
