//! Exercise literal relative filenames through the real CLI, in a child cwd.

use diesel::{sql_query, Connection, QueryableByName, RunQueryDsl, SqliteConnection};
use std::{os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

struct TestDirectory(PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn backup_keeps_a_relative_file_colon_name_and_owner_only_permissions() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = TestDirectory(std::env::temp_dir().join(format!(
        "recoverbull-backup-cli-{}-{nonce}",
        std::process::id()
    )));
    std::fs::create_dir(&directory.0).unwrap();
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
