//! Command line of the `recoverbull` binary: the operator commands and their
//! exit codes. With no command, `main` starts the server.

use std::path::PathBuf;

/// RecoverBull key server. Without a command, starts the server with the
/// configuration from `.env` (in the working directory or a parent of it)
/// and the environment.
#[derive(clap::Parser)]
#[command(name = "recoverbull", version)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(clap::Subcommand)]
pub(crate) enum Command {
    /// Validate the configuration the server would start with.
    ///
    /// Reads `.env` from the working directory or a parent of it, then the
    /// environment, and applies every startup check without starting
    /// anything. Run it from the data directory, as the service does. The memory limit it compares
    /// the identifier capacity against is this process's cgroup, not the
    /// service unit's.
    CheckConfig,
    /// Validate a database with the server's own startup checks.
    ///
    /// Applies pending migrations to it, so run it on a restored or imported
    /// copy, never on an archived backup.
    CheckDatabase {
        /// Literal SQLite file path to check (not a SQLite URI).
        database: PathBuf,
    },
    /// Copy a database consistently, even while the server is running.
    ///
    /// One snapshot, rows still in the `-wal` included, readable by its owner
    /// only, verified with `integrity_check`. The copy is never migrated and
    /// nothing is ever overwritten. Write it into a directory only you can
    /// write to.
    Backup {
        /// SQLite file to copy.
        source: PathBuf,
        /// New file to write; refused if it, or a sidecar, already exists.
        destination: PathBuf,
    },
}

pub(crate) fn parse() -> Cli {
    <Cli as clap::Parser>::parse()
}

/// Runs an operator command and returns the process exit code. None of them
/// loads more than it needs: `check-database` and `backup` read no
/// configuration, and no command binds a listener.
pub(crate) fn run(command: Command) -> i32 {
    match command {
        Command::CheckConfig => match crate::config::init() {
            Ok(_) => {
                println!("configuration: ok");
                0
            }
            Err(error) => {
                eprintln!("configuration error: {error}");
                1
            }
        },
        Command::CheckDatabase { database } => {
            if !database.is_file() {
                eprintln!("database check failed: path is not an existing file");
                return 1;
            }
            let Some(database_url) = database.to_str() else {
                eprintln!("database check failed: path is not valid UTF-8");
                return 1;
            };
            match crate::storage::sqlite::check_database(database_url.to_owned()) {
                Ok(()) => {
                    println!("database check: ok");
                    0
                }
                Err(error) => {
                    eprintln!("database check failed: {error}");
                    1
                }
            }
        }
        Command::Backup {
            source,
            destination,
        } => match crate::storage::sqlite::backup_database(&source, &destination) {
            Ok(()) => {
                println!("backup: ok");
                0
            }
            Err(error) => {
                eprintln!("backup failed: {error}");
                1
            }
        },
    }
}
