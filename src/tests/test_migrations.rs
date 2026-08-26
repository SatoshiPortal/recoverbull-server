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
