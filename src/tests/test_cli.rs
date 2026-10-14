//! Exit codes of the operator commands in `cli::run`.

use crate::cli::{run, Command};
use std::path::PathBuf;

#[test]
fn test_check_database_exit_codes() {
    let (url, _guard) = crate::config::unique_test_database();
    let missing = Command::CheckDatabase {
        database: PathBuf::from("/nonexistent/recoverbull.sqlite3"),
    };
    assert_eq!(run(missing), 1);
    let (garbage, _garbage_guard) = crate::config::unique_test_database();
    std::fs::write(&garbage, b"not a database at all, just some text").unwrap();
    assert_eq!(
        run(Command::CheckDatabase {
            database: PathBuf::from(&garbage),
        }),
        1
    );
    crate::storage::sqlite::initialize_database(url.clone()).unwrap();
    assert_eq!(
        run(Command::CheckDatabase {
            database: PathBuf::from(&url),
        }),
        0
    );
}

#[test]
fn test_backup_exit_codes() {
    let (source, _source_guard) = crate::config::unique_test_database();
    let (destination, _destination_guard) = crate::config::unique_test_database();
    let backup = || Command::Backup {
        source: PathBuf::from(&source),
        destination: PathBuf::from(&destination),
    };
    assert_eq!(run(backup()), 1, "a missing source fails");
    crate::storage::sqlite::initialize_database(source.clone()).unwrap();
    assert_eq!(run(backup()), 0);
    assert_eq!(run(backup()), 1, "an existing destination is refused");
}
