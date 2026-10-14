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

    // A dangling link planted at the destination itself: O_EXCL refuses it,
    // so nothing is created at the link's target.
    let (dangling, _dangling_guard) = fresh_destination();
    let elsewhere = PathBuf::from(format!("{}-elsewhere", dangling.display()));
    std::os::unix::fs::symlink(&elsewhere, &dangling).unwrap();
    assert_eq!(
        backup_database(&source, &dangling),
        Err(BackupError::DestinationExists)
    );
    assert!(!elsewhere.exists());
    let _ = std::fs::remove_file(&dangling);
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
        Err(BackupError::SourceNotADatabase)
    );
    assert!(
        !destination.exists(),
        "a failed copy must not look like a backup"
    );
}

/// A destination named like a sidecar of another database is refused even
/// when nothing is there yet: a stopped server's `db-wal` would be read as
/// its journal on the next start.
#[test]
fn test_backup_refuses_a_sidecar_name_as_destination() {
    let (source, _source_guard, _writer) = source_with_rows_in_wal();
    let (other, _other_guard) = fresh_destination();
    for suffix in ["-wal", "-shm", "-journal"] {
        let destination = PathBuf::from(format!("{}{suffix}", other.display()));
        assert_eq!(
            backup_database(&source, &destination),
            Err(BackupError::DestinationIsASidecar)
        );
        assert!(!destination.exists());
    }
    // The source's own sidecar, which exists while a writer is open, is
    // refused as existing, and left alone.
    let own_wal = PathBuf::from(format!("{}-wal", source.display()));
    let before = std::fs::read(&own_wal).unwrap();
    assert!(backup_database(&source, &own_wal).is_err());
    assert_eq!(std::fs::read(&own_wal).unwrap(), before);
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

/// SQLite would copy an empty file as an empty database and call it a
/// success: the one mistake a cron job must not be able to make. A
/// destination that cannot be created is named as such, not blamed on the
/// source.
#[test]
fn test_backup_refuses_an_empty_source_and_names_an_uncreatable_destination() {
    let (destination, _guard) = fresh_destination();
    let (empty, _empty_guard) = fresh_destination();
    std::fs::write(&empty, b"").unwrap();
    assert_eq!(
        backup_database(&empty, &destination),
        Err(BackupError::SourceNotADatabase)
    );
    assert!(!destination.exists());

    let (source, _source_guard, _writer) = source_with_rows_in_wal();
    let missing_dir = PathBuf::from(format!(
        "{}-no-such-dir/copy.sqlite3",
        destination.display()
    ));
    assert_eq!(
        backup_database(&source, &missing_dir),
        Err(BackupError::DestinationCreate)
    );
}

/// Every connection diesel opens has URI filenames enabled, so a bare
/// destination starting with `file:` used to be parsed as a URI: the 0600
/// placeholder went under the literal name and the real copy elsewhere with
/// the umask mode, verified against the placeholder.
#[test]
fn test_backup_treats_a_file_colon_destination_as_a_plain_name() {
    let (source, _source_guard, _writer) = source_with_rows_in_wal();
    let directory =
        std::env::temp_dir().join(format!("recoverbull-test-{}-uri", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let destination = directory.join("file:odd.sqlite3");
    let elsewhere = directory.join("odd.sqlite3");

    backup_database(&source, &destination).unwrap();

    assert!(
        !elsewhere.exists(),
        "the copy must not land at the URI's target"
    );
    let mode = destination.metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert!(
        destination.metadata().unwrap().len() > 0,
        "the copy must be the named file"
    );
    let mut copy = SqliteConnection::establish(destination.to_str().unwrap()).unwrap();
    assert_eq!(count(&mut copy, "SELECT COUNT(*) AS value FROM secret"), 1);
    let _ = std::fs::remove_dir_all(&directory);
}
