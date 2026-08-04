use crate::{
    models::FetchSecret,
    tests::{SHA256_111111, SHA256_222222},
};
use axum::http::StatusCode;
use diesel::RunQueryDsl;

/// A database failure must not be confused with wrong credentials:
/// the handler must respond 500 (not 401) and must not consume rate-limit
/// attempts, otherwise transient database trouble burns the user's
/// recovery attempts and locks them out.
#[tokio::test]
async fn test_database_error_returns_500_without_consuming_attempts() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    // Force every subsequent query to fail: drop the table out from under
    // the server. init_db recreates it on the next test (IF NOT EXISTS).
    let mut connection = crate::database::establish_connection(state.clone().database_url);
    diesel::sql_query("DROP TABLE secret")
        .execute(&mut connection)
        .expect("failed to drop table");

    let fetch = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    };

    // More requests than max_failed_attempts: none may be 401 or 429.
    for _ in 0..(state.rate_limit_max_failed_attempts + 2) {
        let response = server.post("/fetch").json(fetch).await;
        assert_eq!(
            response.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "database errors must be reported as 500, not as invalid credentials"
        );
    }

    // No rate-limit entry may remain: attempts were refunded.
    let identifier_rate_limit = state.identifier_rate_limit.lock().await;
    assert!(!identifier_rate_limit.contains_key(SHA256_111111));
}
