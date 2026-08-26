#[test]
fn test_application_connection_enables_secure_delete() {
    use diesel::{QueryableByName, RunQueryDsl};

    #[derive(QueryableByName)]
    struct PragmaValue {
        #[diesel(sql_type = diesel::sql_types::Integer)]
        value: i32,
    }
    let state = crate::env::init();
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let mut connection = crate::storage::sqlite::establish_connection(state.database_url).unwrap();
    let value = diesel::sql_query("SELECT secure_delete AS value FROM pragma_secure_delete")
        .get_result::<PragmaValue>(&mut connection)
        .unwrap();
    assert_eq!(value.value, 1);
}

#[test]
fn test_application_connection_uses_patched_sqlite_and_wal() {
    use diesel::{QueryableByName, RunQueryDsl};

    #[derive(QueryableByName)]
    struct TextValue {
        #[diesel(sql_type = diesel::sql_types::Text)]
        value: String,
    }
    let state = crate::env::init();
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let mut connection = crate::storage::sqlite::establish_connection(state.database_url).unwrap();
    let version = diesel::sql_query("SELECT sqlite_version() AS value")
        .get_result::<TextValue>(&mut connection)
        .unwrap();
    assert!(crate::storage::sqlite::sqlite_version_at_least_for_test(
        &version.value
    ));
    let mode = diesel::sql_query("SELECT journal_mode AS value FROM pragma_journal_mode")
        .get_result::<TextValue>(&mut connection)
        .unwrap();
    assert_eq!(mode.value, "wal");
}

#[test]
fn test_sqlite_version_comparator_boundaries() {
    assert!(!crate::storage::sqlite::sqlite_version_at_least_for_test(
        "3.51.2"
    ));
    assert!(crate::storage::sqlite::sqlite_version_at_least_for_test(
        "3.51.3"
    ));
    assert!(crate::storage::sqlite::sqlite_version_at_least_for_test(
        "3.52.0"
    ));
    assert!(!crate::storage::sqlite::sqlite_version_at_least_for_test(
        "not-a-version"
    ));
}

#[test]
fn test_memory_database_fails_closed_when_wal_is_unavailable() {
    assert_eq!(
        crate::storage::sqlite::establish_connection(":memory:".to_owned())
            .err()
            .expect("in-memory SQLite must fail the WAL check"),
        crate::storage::sqlite::ConnectionSetupError::Wal
    );
}
