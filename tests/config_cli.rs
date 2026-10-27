//! Validate startup configuration through the real CLI in isolated child processes.

use std::{
    net::TcpListener,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Command, Output},
};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "recoverbull-config-cli-{}-{nonce}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }

    fn config(&self, server_address: &str) -> String {
        format!(
            "DATABASE_URL={}\nSERVER_ADDRESS={server_address}\n\
             SECRET_MAX_LENGTH=128\nCANARY=synthetic-config-fixture\n\
             RATE_LIMIT_COOLDOWN=1440\nRATE_LIMIT_MAX_ATTEMPTS=3\n",
            self.0.join("synthetic.sqlite3").display()
        )
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_recoverbull"));
        command.current_dir(&self.0).env_clear();
        command
    }

    fn assert_no_database(&self) {
        for suffix in ["", "-wal", "-shm"] {
            assert!(
                !self.0.join(format!("synthetic.sqlite3{suffix}")).exists(),
                "configuration validation must not create SQLite files"
            );
        }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_configuration_error(output: &Output, setting: &str) {
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(setting),
        "{output:?}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("configuration: ok"),
        "{output:?}"
    );
}

#[test]
fn malformed_dotenv_cannot_silently_discard_a_later_security_limit() {
    let directory = TestDirectory::new();
    let required = directory.config("127.0.0.1:3001");
    let path = directory.0.join(".env");
    std::fs::write(
        &path,
        format!("{required}RATE_LIMIT_MAX_IDENTIFIERS=1000\n"),
    )
    .unwrap();
    let control = directory.command().arg("check-config").output().unwrap();
    assert!(control.status.success(), "{control:?}");

    // All required values precede the error, so ignoring the parse error used
    // to accept the default capacity instead of the stricter setting below it.
    let private_marker = "SYNTHETIC_MALFORMED_VALUE_MUST_NOT_BE_LOGGED";
    std::fs::write(
        &path,
        format!("{required}BROKEN {private_marker}\nRATE_LIMIT_MAX_IDENTIFIERS=1000\n"),
    )
    .unwrap();
    let result = directory.command().arg("check-config").output().unwrap();
    assert_configuration_error(&result, ".env");
    assert!(
        !String::from_utf8_lossy(&result.stderr).contains(private_marker),
        "dotenv errors must not expose the offending line"
    );
    directory.assert_no_database();
}

#[test]
fn unreadable_dotenv_is_not_ignored_when_process_configuration_is_complete() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join(".env"), b"CANARY=\xff\n").unwrap();
    let result = environment_only_command(&directory, "127.0.0.1:3001")
        .arg("check-config")
        .output()
        .unwrap();
    assert_configuration_error(&result, ".env");
    directory.assert_no_database();
}

fn environment_only_command(directory: &TestDirectory, server_address: &str) -> Command {
    let mut command = directory.command();
    command
        .env("DATABASE_URL", directory.0.join("synthetic.sqlite3"))
        .env("SERVER_ADDRESS", server_address)
        .env("SECRET_MAX_LENGTH", "128")
        .env("CANARY", "synthetic-config-fixture")
        .env("RATE_LIMIT_COOLDOWN", "1440")
        .env("RATE_LIMIT_MAX_ATTEMPTS", "3")
        .env("RATE_LIMIT_MAX_IDENTIFIERS", "1000");
    command
}

#[test]
fn check_config_accepts_environment_only_without_binding_the_listener() {
    let directory = TestDirectory::new();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let result = environment_only_command(&directory, &occupied.local_addr().unwrap().to_string())
        .arg("check-config")
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    assert!(!directory.0.join(".env").exists());
    directory.assert_no_database();
}

#[test]
fn process_environment_still_takes_precedence_over_dotenv() {
    let directory = TestDirectory::new();
    std::fs::write(
        directory.0.join(".env"),
        directory.config("127.0.0.1:70000"),
    )
    .unwrap();
    let result = environment_only_command(&directory, "127.0.0.1:3001")
        .arg("check-config")
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    directory.assert_no_database();
}
