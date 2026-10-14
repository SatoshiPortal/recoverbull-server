//! `recoverbull backup`: a consistent, owner-only copy that never overwrites,
//! never follows a link, and never migrates. These replace the Python backup
//! tool's tests now that the server binary does the copy itself.

use crate::storage::sqlite::{backup_database, check_database, BackupError};
use diesel::{sql_query, Connection, QueryableByName, RunQueryDsl, SqliteConnection};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    value: i64,
}

fn count(connection: &mut SqliteConnection, sql: &str) -> i64 {
    sql_query(sql)
        .get_result::<Count>(connection)
        .unwrap()
        .value
}

/// A destination path that does not exist yet; the guard removes it later.
fn fresh_destination() -> (PathBuf, std::sync::Arc<crate::config::TestDatabaseGuard>) {
    let (path, guard) = crate::config::unique_test_database();
    (PathBuf::from(path), guard)
}

/// A server-initialized source whose last rows live only in its `-wal`: the
/// writer keeps the connection open with automatic checkpoints off.
fn source_with_rows_in_wal() -> (
    PathBuf,
    std::sync::Arc<crate::config::TestDatabaseGuard>,
    SqliteConnection,
) {
    let (url, guard) = crate::config::unique_test_database();
    crate::storage::sqlite::initialize_database(url.clone()).unwrap();
    let mut writer = SqliteConnection::establish(&url).unwrap();
    sql_query("PRAGMA wal_autocheckpoint = 0")
        .execute(&mut writer)
        .unwrap();
    sql_query(
        "INSERT INTO secret (id, created_at, encrypted_secret) \
         VALUES ('wal-row', '2026-01-01T00:00:00Z', 'AA==')",
    )
    .execute(&mut writer)
    .unwrap();
    assert!(
        Path::new(&format!("{url}-wal")).metadata().unwrap().len() > 0,
        "the fixture row must still be in the WAL"
    );
    (PathBuf::from(url), guard, writer)
}

#[test]
fn test_backup_copies_rows_still_in_the_wal_into_an_owner_only_file() {
    let (source, _source_guard, _writer) = source_with_rows_in_wal();
    let (destination, _destination_guard) = fresh_destination();

    backup_database(&source, &destination).unwrap();

    let mode = destination.metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let mut copy = SqliteConnection::establish(destination.to_str().unwrap()).unwrap();
    assert_eq!(
        count(
            &mut copy,
            "SELECT COUNT(*) AS value FROM secret WHERE id = 'wal-row'"
        ),
        1
    );
}

#[test]
fn test_backup_never_overwrites_or_follows_a_link() {
    let (source, _source_guard, _writer) = source_with_rows_in_wal();

    let (existing, _existing_guard) = fresh_destination();
    std::fs::write(&existing, b"keep me").unwrap();
    assert_eq!(
        backup_database(&source, &existing),
        Err(BackupError::DestinationExists)
    );
    assert_eq!(std::fs::read(&existing).unwrap(), b"keep me");

    // A link planted where a sidecar of the destination would go.
    let (linked, _linked_guard) = fresh_destination();
    let target = PathBuf::from(format!("{}-target", linked.display()));
    std::fs::write(&target, b"not yours").unwrap();
    std::os::unix::fs::symlink(&target, format!("{}-wal", linked.display())).unwrap();
    assert_eq!(
        backup_database(&source, &linked),
        Err(BackupError::DestinationExists)
    );
    assert!(!linked.exists());
    assert_eq!(std::fs::read(&target).unwrap(), b"not yours");
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_file(format!("{}-wal", linked.display()));
}

#[test]
fn test_backup_refuses_a_missing_or_non_database_source_and_leaves_nothing() {
    let (destination, _guard) = fresh_destination();
    assert_eq!(
        backup_database(Path::new("/nonexistent/recoverbull.sqlite3"), &destination),
        Err(BackupError::SourceMissing)
    );

    let (garbage, _garbage_guard) = fresh_destination();
    std::fs::write(&garbage, vec![b'x'; 4096]).unwrap();
    assert_eq!(
        backup_database(&garbage, &destination),
        Err(BackupError::Copy)
    );
    assert!(
        !destination.exists(),
        "a failed copy must not look like a backup"
    );
}

/// The copy keeps the source's schema: a pre-ledger database stays one, so
/// the copy of an older database still opens with the version that wrote
/// it. `check-database` is the step that adopts and migrates.
#[test]
fn test_backup_does_not_migrate_and_check_database_adopts_the_copy() {
    let (legacy, _legacy_guard) = crate::config::unique_test_database();
    let mut connection = SqliteConnection::establish(&legacy).unwrap();
    sql_query(include_str!("../../migrations/0001_schema/up.sql"))
        .execute(&mut connection)
        .unwrap();
    drop(connection);
    let (destination, _guard) = fresh_destination();

    backup_database(Path::new(&legacy), &destination).unwrap();

    let mut copy = SqliteConnection::establish(destination.to_str().unwrap()).unwrap();
    assert_eq!(
        count(
            &mut copy,
            "SELECT COUNT(*) AS value FROM sqlite_master \
             WHERE name = '__diesel_schema_migrations'"
        ),
        0,
        "backup must not create the migration ledger"
    );
    drop(copy);
    check_database(destination.to_str().unwrap().to_owned()).unwrap();
}

/// `?`, `#` and `%` are URI syntax for SQLite; a path containing them must
/// still name the file, not a query string or an escape.
#[test]
fn test_backup_handles_uri_characters_in_paths() {
    let (source, _source_guard, _writer) = source_with_rows_in_wal();
    let directory = std::env::temp_dir().join(format!(
        "recoverbull-test-{}-odd ?#%41 name",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let odd_source = directory.join("source ?#%41.sqlite3");
    let destination = directory.join("copy ?#%41.sqlite3");
    backup_database(&source, &odd_source).unwrap();

    backup_database(&odd_source, &destination).unwrap();

    let mut copy = SqliteConnection::establish(destination.to_str().unwrap()).unwrap();
    assert_eq!(count(&mut copy, "SELECT COUNT(*) AS value FROM secret"), 1);
    let _ = std::fs::remove_dir_all(&directory);
}
