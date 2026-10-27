//! Exercise literal relative filenames through the real CLI, in a child cwd.

use diesel::{sql_query, Connection, QueryableByName, RunQueryDsl, SqliteConnection};
use std::{os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = Self(std::env::temp_dir().join(format!(
            "recoverbull-backup-cli-{}-{nonce}",
            std::process::id()
        )));
        std::fs::create_dir(&directory.0).unwrap();
        directory
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn backup_keeps_a_relative_file_colon_name_and_owner_only_permissions() {
    let directory = TestDirectory::new();
    let source = directory.0.join("source.sqlite3");
    let mut connection = SqliteConnection::establish(source.to_str().unwrap()).unwrap();
    sql_query("CREATE TABLE evidence(value TEXT NOT NULL)")
        .execute(&mut connection)
        .unwrap();
    sql_query("INSERT INTO evidence VALUES ('synthetic fixture')")
        .execute(&mut connection)
        .unwrap();
    drop(connection);

    let result = Command::new(env!("CARGO_BIN_EXE_recoverbull"))
        .current_dir(&directory.0)
        .arg("backup")
        .arg(&source)
        // Keep this relative: /tmp/.../file:odd.sqlite3 cannot trigger URI parsing.
        .arg("file:odd.sqlite3")
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    assert!(!directory.0.join("odd.sqlite3").exists());
    let destination = directory.0.join("file:odd.sqlite3");
    let metadata = destination.metadata().unwrap();
    assert!(metadata.len() > 0, "the requested backup must not be empty");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    // Open the absolute path here so verification cannot itself interpret a URI.
    let mut copy = SqliteConnection::establish(destination.to_str().unwrap()).unwrap();
    #[derive(QueryableByName)]
    struct Evidence {
        #[diesel(sql_type = diesel::sql_types::Text)]
        value: String,
    }
    let row = sql_query("SELECT value FROM evidence")
        .get_result::<Evidence>(&mut copy)
        .unwrap();
    assert_eq!(row.value, "synthetic fixture");
}

fn initialized_database(path: &std::path::Path) {
    let mut connection = SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    sql_query(
        "CREATE TABLE secret (id TEXT PRIMARY KEY NOT NULL, created_at TEXT NOT NULL, \
         encrypted_secret TEXT NOT NULL)",
    )
    .execute(&mut connection)
    .unwrap();
    sql_query(
        "INSERT INTO secret VALUES ('synthetic-id', 'synthetic-time', 'synthetic-ciphertext')",
    )
    .execute(&mut connection)
    .unwrap();
}

fn check_database(directory: &TestDirectory, filename: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_recoverbull"))
        .current_dir(&directory.0)
        .arg("check-database")
        .arg(filename)
        .output()
        .unwrap()
}

#[test]
fn check_database_checks_the_literal_file_colon_name_without_migrating_its_sibling() {
    let directory = TestDirectory::new();
    let literal = directory.0.join("file:odd.sqlite3");
    let sibling = directory.0.join("odd.sqlite3");
    initialized_database(&sibling);
    let mut unrelated = SqliteConnection::establish(literal.to_str().unwrap()).unwrap();
    sql_query("CREATE TABLE evidence(value TEXT NOT NULL)")
        .execute(&mut unrelated)
        .unwrap();
    drop(unrelated);

    let result = check_database(&directory, "file:odd.sqlite3");
    assert!(
        !result.status.success(),
        "the literal uninitialized file must fail even beside a valid sibling: {result:?}"
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("no secret table"));
    #[derive(QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        value: i64,
    }
    let mut sibling = SqliteConnection::establish(sibling.to_str().unwrap()).unwrap();
    let migrated = sql_query(
        "SELECT COUNT(*) AS value FROM sqlite_master WHERE name = '__diesel_schema_migrations'",
    )
    .get_result::<Count>(&mut sibling)
    .unwrap();
    assert_eq!(
        migrated.value, 0,
        "an unrelated sibling must not be migrated"
    );
}

#[test]
fn check_database_accepts_an_initialized_literal_file_colon_name() {
    let directory = TestDirectory::new();
    initialized_database(&directory.0.join("file:odd.sqlite3"));
    std::fs::write(directory.0.join("odd.sqlite3"), b"unrelated non-database").unwrap();

    let result = check_database(&directory, "file:odd.sqlite3");
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        std::fs::read(directory.0.join("odd.sqlite3")).unwrap(),
        b"unrelated non-database"
    );
}
