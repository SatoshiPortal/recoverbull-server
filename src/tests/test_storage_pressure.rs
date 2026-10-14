//! AUD-2026-10-01: `/store` must not reveal whether a `secret_id` exists when
//! storage can no longer be written. Two guards: a store for an existing row
//! is a real write (so storage pressure refuses it like a new row), and the
//! first storage failure latches `/store` closed with a uniform `503`.

use crate::tests::{distinct_authentication_key, BASE64_ENCRYPTED_SECRET, SHA256_111111};
use axum::http::StatusCode;
use diesel::{sql_query, QueryableByName, RunQueryDsl};

#[derive(QueryableByName)]
struct DataVersion {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    value: i32,
}

/// `PRAGMA data_version` changes on a connection only when another connection
/// commits a modification. A no-op `INSERT … ON CONFLICT DO NOTHING` would
/// leave it unchanged, which is exactly the storage-free path the oracle
/// needs.
fn data_version(connection: &mut diesel::SqliteConnection) -> i32 {
    sql_query("SELECT data_version AS value FROM pragma_data_version")
        .get_result::<DataVersion>(connection)
        .unwrap()
        .value
}

async fn store(
    server: &axum_test::TestServer,
    authentication_key: &str,
) -> axum_test::TestResponse {
    server
        .post("/store")
        .json(&serde_json::json!({
            "identifier": SHA256_111111,
            "authentication_key": authentication_key,
            "encrypted_secret": BASE64_ENCRYPTED_SECRET,
        }))
        .await
}

#[tokio::test]
async fn test_store_of_an_existing_secret_id_is_a_real_write() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let mut observer =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
    let key = distinct_authentication_key(1);

    assert_eq!(
        store(&server, &key).await.status_code(),
        StatusCode::CREATED
    );
    let after_first = data_version(&mut observer);

    assert_eq!(
        store(&server, &key).await.status_code(),
        StatusCode::CREATED
    );
    assert_ne!(
        data_version(&mut observer),
        after_first,
        "storing an existing secret_id must commit a write, otherwise it needs \
         no storage and succeeds exactly when a new secret_id cannot"
    );
}

#[tokio::test]
async fn test_store_latches_closed_after_a_storage_failure() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let existing = distinct_authentication_key(1);
    let fresh = distinct_authentication_key(2);
    assert_eq!(
        store(&server, &existing).await.status_code(),
        StatusCode::CREATED
    );
    assert!(!state.recovery.storage_pressure_for_test());

    // Make the next write fail the way a full or damaged volume would: the
    // operation runs but cannot be committed.
    let mut connection =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
    sql_query("ALTER TABLE secret RENAME TO secret_gone")
        .execute(&mut connection)
        .unwrap();
    assert_eq!(
        store(&server, &fresh).await.status_code(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(state.recovery.storage_pressure_for_test());

    // Storage is writable again, but the process stays closed: an attacker
    // who can fill the disk must not get one more existence answer per
    // probe, and the operator must look before stores resume.
    sql_query("ALTER TABLE secret_gone RENAME TO secret")
        .execute(&mut connection)
        .unwrap();
    for key in [&existing, &fresh] {
        let response = store(&server, key).await;
        assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.header("retry-after"), "60");
    }

    // Reads are unaffected: recovery keeps working on a full disk.
    let fetch = server
        .post("/fetch")
        .json(&serde_json::json!({
            "identifier": SHA256_111111,
            "authentication_key": existing,
        }))
        .await;
    assert_eq!(fetch.status_code(), StatusCode::OK);

    let counters = state.counters.flush();
    assert_eq!(counters.database_error, 1);
    assert_eq!(counters.store_storage_pressure, 2);
}

/// A locked database is contention, not storage pressure: it must stay a
/// retryable `503` and must not latch `/store` closed.
#[tokio::test]
async fn test_a_locked_database_does_not_latch_store_closed() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let mut holder =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
    sql_query("PRAGMA busy_timeout = 0")
        .execute(&mut holder)
        .unwrap();
    sql_query("BEGIN IMMEDIATE").execute(&mut holder).unwrap();

    let response = store(&server, &distinct_authentication_key(1)).await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.header("retry-after"), "1");
    assert!(!state.recovery.storage_pressure_for_test());

    sql_query("ROLLBACK").execute(&mut holder).unwrap();
    assert_eq!(
        store(&server, &distinct_authentication_key(1))
            .await
            .status_code(),
        StatusCode::CREATED
    );
    let counters = state.counters.flush();
    assert_eq!(counters.database_busy, 1);
    assert_eq!(counters.store_storage_pressure, 0);
}

/// Below the free-space reserve every store is refused before any database
/// work, so the answer depends on free space alone, never on the row.
#[tokio::test]
async fn test_store_is_refused_below_the_reserve_whether_or_not_the_row_exists() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let existing = distinct_authentication_key(1);
    let fresh = distinct_authentication_key(2);
    assert_eq!(
        store(&server, &existing).await.status_code(),
        StatusCode::CREATED
    );

    state.recovery.set_free_space_for_test(63 * 1024 * 1024);
    for key in [&existing, &fresh] {
        let response = store(&server, key).await;
        assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.header("retry-after"), "60");
    }
    assert!(
        !state.recovery.storage_pressure_for_test(),
        "the reserve refuses without latching: stores resume once space is freed"
    );
    assert_eq!(state.counters.flush().store_storage_pressure, 2);

    state.recovery.set_free_space_for_test(65 * 1024 * 1024);
    assert_eq!(
        store(&server, &fresh).await.status_code(),
        StatusCode::CREATED
    );
}

/// `STORAGE_RESERVE_MB=0` disables the reserve.
#[tokio::test]
async fn test_reserve_can_be_disabled() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    state.recovery.set_free_space_for_test(0);
    state.recovery.set_storage_reserve_for_test(0);
    assert_eq!(
        store(&server, &distinct_authentication_key(1))
            .await
            .status_code(),
        StatusCode::CREATED
    );
}
