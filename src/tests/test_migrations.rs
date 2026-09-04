use diesel::{sql_query, Connection, QueryableByName, RunQueryDsl, SqliteConnection};

fn connection() -> SqliteConnection {
    SqliteConnection::establish(":memory:").expect("failed to create in-memory database")
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    value: i64,
}

#[test]
fn empty_database_gets_secret_and_ledger() {
    let mut connection = connection();
    crate::storage::sqlite::run_migrations(&mut connection).unwrap();

    assert_eq!(
        sql_query("SELECT COUNT(*) AS value FROM secret")
            .get_result::<Count>(&mut connection)
            .unwrap()
            .value,
        0
    );
    assert_eq!(
        sql_query("SELECT COUNT(*) AS value FROM __diesel_schema_migrations")
            .get_result::<Count>(&mut connection)
            .unwrap()
            .value,
        1
    );
}

#[test]
fn migrations_are_idempotent() {
    let mut connection = connection();
    crate::storage::sqlite::run_migrations(&mut connection).unwrap();
    crate::storage::sqlite::run_migrations(&mut connection).unwrap();

    assert_eq!(
        sql_query("SELECT COUNT(*) AS value FROM __diesel_schema_migrations")
            .get_result::<Count>(&mut connection)
            .unwrap()
            .value,
        1
    );
}

#[test]
fn exact_legacy_table_is_adopted_without_touching_data() {
    let mut connection = connection();
    sql_query("CREATE TABLE secret (id TEXT PRIMARY KEY NOT NULL, created_at TEXT NOT NULL, encrypted_secret TEXT NOT NULL)")
        .execute(&mut connection)
        .unwrap();
    sql_query("INSERT INTO secret VALUES ('id', 'time', 'cipher')")
        .execute(&mut connection)
        .unwrap();

    crate::storage::sqlite::run_migrations(&mut connection).unwrap();

    let row = sql_query("SELECT id, created_at, encrypted_secret FROM secret")
        .get_result::<SecretRow>(&mut connection)
        .unwrap();
    assert_eq!(row.id, "id");
    assert_eq!(row.created_at, "time");
    assert_eq!(row.encrypted_secret, "cipher");
    let version: String = sql_query("SELECT version FROM __diesel_schema_migrations")
        .get_result::<Version>(&mut connection)
        .unwrap()
        .version;
    assert_eq!(version, "0001");
}

#[derive(QueryableByName)]
struct Version {
    #[diesel(sql_type = diesel::sql_types::Text)]
    version: String,
}

#[derive(QueryableByName)]
struct SecretRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    created_at: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    encrypted_secret: String,
}

#[test]
fn incompatible_legacy_table_is_rejected() {
    let mut connection = connection();
    sql_query("CREATE TABLE secret (id TEXT PRIMARY KEY NOT NULL, created_at TEXT NOT NULL, extra TEXT NOT NULL)")
        .execute(&mut connection)
        .unwrap();

    let error = crate::storage::sqlite::run_migrations(&mut connection).unwrap_err();
    assert!(error.to_string().contains("incompatible schema"));
}

fn ledger_with_initial_version(connection: &mut SqliteConnection) {
    sql_query(
        "CREATE TABLE __diesel_schema_migrations (\
         version VARCHAR(50) PRIMARY KEY NOT NULL,\
         run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
    )
    .execute(connection)
    .unwrap();
    sql_query("INSERT INTO __diesel_schema_migrations (version) VALUES ('0001')")
        .execute(connection)
        .unwrap();
}

/// A Diesel ledger that already records migration `0001` makes Diesel skip
/// it. That record must not be trusted over the schema it claims to
/// describe: a database with the ledger but no `secret` table (a partial
/// restore, a manual edit) used to initialize successfully and then fail
/// every request with `500`.
#[test]
fn recorded_migration_without_secret_table_is_rejected() {
    let mut connection = connection();
    ledger_with_initial_version(&mut connection);

    let error = crate::storage::sqlite::run_migrations(&mut connection).unwrap_err();
    assert!(
        error.to_string().contains("secret table"),
        "startup must fail closed on a missing secret table: {error}"
    );
}

/// Same ledger, with a `secret` table whose columns do not match migration
/// `0001`: the schema postcondition is checked unconditionally, not only on
/// the pre-Diesel adoption path.
#[test]
fn recorded_migration_with_incompatible_secret_table_is_rejected() {
    let mut connection = connection();
    ledger_with_initial_version(&mut connection);
    sql_query("CREATE TABLE secret (id TEXT PRIMARY KEY NOT NULL, wrong TEXT)")
        .execute(&mut connection)
        .unwrap();

    let error = crate::storage::sqlite::run_migrations(&mut connection).unwrap_err();
    assert!(
        error.to_string().contains("incompatible schema"),
        "startup must fail closed on an incompatible secret table: {error}"
    );
}

/// The exact schema with a valid ledger is the normal restart path and must
/// keep passing the postcondition.
#[test]
fn recorded_migration_with_exact_secret_table_is_accepted() {
    let mut connection = connection();
    ledger_with_initial_version(&mut connection);
    sql_query("CREATE TABLE secret (id TEXT PRIMARY KEY NOT NULL, created_at TEXT NOT NULL, encrypted_secret TEXT NOT NULL)")
        .execute(&mut connection)
        .unwrap();

    crate::storage::sqlite::run_migrations(&mut connection).unwrap();
}

/// End to end through `initialize()` on a real file: after the table is
/// dropped underneath a migrated database, startup must report a migration
/// failure instead of logging "database initialized".
#[tokio::test]
async fn initialize_fails_closed_when_the_secret_table_is_missing() {
    let (_server, state) = crate::tests::test_server::new_test_server().await;
    let mut connection =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
    sql_query("DROP TABLE secret")
        .execute(&mut connection)
        .unwrap();

    assert_eq!(
        state.storage.initialize(),
        Err(crate::storage::sqlite::ConnectionSetupError::Migration)
    );
}

/// AUD-05: `check-database` must validate an already-initialized database and
/// refuse to manufacture one. An empty or truncated file has no `secret`
/// table and must be rejected before any migration runs, so a brand-new file
/// is never reported as a valid backup.
#[test]
fn check_database_refuses_an_uninitialized_file() {
    let (url, _guard) = crate::config::unique_test_database();
    std::fs::File::create(&url).unwrap();
    assert_eq!(
        crate::storage::sqlite::check_database(url.clone()),
        Err(crate::storage::sqlite::ConnectionSetupError::Uninitialized)
    );
    let mut connection = SqliteConnection::establish(&url).unwrap();
    let tables = sql_query(
        "SELECT COUNT(*) AS value FROM sqlite_master WHERE type='table' \
         AND name IN ('secret','__diesel_schema_migrations')",
    )
    .get_result::<Count>(&mut connection)
    .unwrap()
    .value;
    assert_eq!(
        tables, 0,
        "check-database must not create tables in the file it inspects"
    );
}

/// A genuinely initialized database still passes the check.
#[test]
fn check_database_accepts_an_initialized_file() {
    let (url, _guard) = crate::config::unique_test_database();
    crate::storage::sqlite::initialize_database(url.clone()).unwrap();
    crate::storage::sqlite::check_database(url).expect("an initialized database must pass");
}
