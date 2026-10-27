//! SQLite persistence implementation; Diesel remains confined to this module.
//!
//! Initialization verifies `secure_delete` and WAL, while leased operations
//! retain their permit through blocking work and trash uses an immediate
//! transaction.

use crate::config::StorageConfig;
use crate::schema::secret::dsl::*;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use diesel::prelude::*;
use diesel::sql_query;
use diesel::{
    Connection, ExpressionMethods, OptionalExtension, QueryDsl, QueryableByName, RunQueryDsl,
    SqliteConnection,
};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

#[derive(Insertable, Queryable, Selectable)]
#[diesel(table_name = crate::schema::secret)]
/// Diesel row and insert shape for the opaque secret table.
pub(crate) struct Secret {
    pub(crate) id: String,
    pub(crate) created_at: String,
    pub(crate) encrypted_secret: String,
}

#[derive(Clone)]
/// Concrete database runtime; recovery receives only opaque operations.
pub(crate) struct SqliteStorage {
    database_url: String,
    database_semaphore: Arc<Semaphore>,
    #[cfg(test)]
    test_database_guard: Arc<crate::config::TestDatabaseGuard>,
}

/// Opaque lease transferred to a blocking worker; its permit is held until
/// the synchronous operation returns.
pub(crate) struct SqliteOperation {
    database_url: String,
    permit: OwnedSemaphorePermit,
    #[cfg(test)]
    test_database_guard: Arc<crate::config::TestDatabaseGuard>,
}

#[derive(Clone)]
/// Insert value passed from recovery without exposing Diesel types upstream.
pub(crate) struct NewStoredSecret {
    pub(crate) id: String,
    pub(crate) created_at: String,
    pub(crate) encrypted_secret: String,
}

#[derive(Clone)]
/// Non-Diesel value returned across the storage/recovery boundary.
pub(crate) struct StoredSecret {
    pub(crate) id: String,
    pub(crate) created_at: String,
    pub(crate) encrypted_secret: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Opaque storage failure categories safe for domain and HTTP mapping.
pub(crate) enum StorageError {
    /// No lease before the deadline, or SQLite reported the database locked:
    /// transient pressure, retry later.
    Busy,
    /// The database file could not be opened or checked.
    Connection,
    /// The operation itself failed: full or unwritable storage, a damaged
    /// file, or any other non-transient SQLite error.
    Database,
}

/// SQLite reports contention as an error like any other; it is the one
/// failure a client should simply retry rather than the operator investigate.
/// Covers SQLITE_BUSY ("database is locked"), SQLITE_LOCKED ("database table
/// is locked"), SQLITE_PROTOCOL ("locking protocol", a rare wal-index retry
/// exhaustion) and SQLITE_INTERRUPT.
fn classify_database_error(error: &diesel::result::Error) -> StorageError {
    const TRANSIENT: [&str; 4] = ["locked", "busy", "locking protocol", "interrupted"];
    match error {
        diesel::result::Error::DatabaseError(_, info)
            if TRANSIENT
                .iter()
                .any(|needle| info.message().contains(needle)) =>
        {
            StorageError::Busy
        }
        _ => StorageError::Database,
    }
}

impl SqliteStorage {
    /// Creates storage and its bounded shared database semaphore.
    pub(crate) fn from_config(config: StorageConfig) -> Self {
        Self {
            database_url: config.database_url,
            database_semaphore: Arc::new(Semaphore::new(config.database_max_concurrency)),
            #[cfg(test)]
            test_database_guard: config.test_database_guard,
        }
    }

    /// The directory holding the database, where free space decides whether
    /// a store may proceed.
    pub(crate) fn data_directory(&self) -> std::path::PathBuf {
        let path = std::path::Path::new(&self.database_url);
        match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => std::path::PathBuf::from("."),
        }
    }

    pub(crate) async fn acquire(&self) -> Result<SqliteOperation, StorageError> {
        let permit = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            self.database_semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| StorageError::Busy)?
        .map_err(|_| StorageError::Busy)?;
        Ok(SqliteOperation {
            database_url: self.database_url.clone(),
            permit,
            #[cfg(test)]
            test_database_guard: self.test_database_guard.clone(),
        })
    }

    pub(crate) fn initialize(&self) -> Result<(), ConnectionSetupError> {
        initialize_database(self.database_url.clone())
    }

    #[cfg(test)]
    pub(crate) fn set_semaphore_for_test(&mut self, semaphore: Arc<Semaphore>) {
        self.database_semaphore = semaphore;
    }

    #[cfg(test)]
    pub(crate) fn set_database_url_for_test(&mut self, database_url: String) {
        self.database_url = database_url;
    }
    #[cfg(test)]
    pub(crate) fn database_url_for_test(&self) -> String {
        self.database_url.clone()
    }
    #[cfg(test)]
    pub(crate) fn database_semaphore_for_test(&self) -> Arc<Semaphore> {
        self.database_semaphore.clone()
    }
}

/// Why `recoverbull backup` refused or failed. No variant carries database
/// content: the message is safe for an operator's terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackupError {
    /// The source is not an existing regular file.
    SourceMissing,
    /// The source does not carry the SQLite header: an empty file (which
    /// SQLite would copy as an empty database) or some other file.
    SourceNotADatabase,
    /// The destination could not be created: missing directory, no
    /// permission, or a name that is not valid UTF-8.
    DestinationCreate,
    /// The destination, or one of its SQLite sidecars, already exists (a
    /// symlink included): a backup never overwrites or follows a link.
    DestinationExists,
    /// The destination is named like a SQLite sidecar (`-wal`, `-shm`,
    /// `-journal`): writing a database there would be read as another
    /// database's journal.
    DestinationIsASidecar,
    /// The source could not be opened read-only.
    Open,
    /// SQLite could not produce the copy (not a database, unreadable, full
    /// destination volume).
    Copy,
    /// The copy was written but fails `PRAGMA integrity_check`.
    Integrity,
}

/// The 16 bytes every SQLite database starts with.
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// Whether the file starts with the SQLite header. `Ok(false)` for an empty
/// file, which SQLite would silently treat as a new database.
fn has_sqlite_header(path: &std::path::Path) -> std::io::Result<bool> {
    let mut header = [0u8; 16];
    let read = std::fs::File::open(path)
        .and_then(|mut file| std::io::Read::read(&mut file, &mut header))?;
    Ok(read == header.len() && &header == SQLITE_HEADER)
}

/// SQLite URI path escaping: `%`, `?` and `#` would otherwise be read as an
/// escape, the query string, or a fragment. Every connection diesel opens
/// has `SQLITE_OPEN_URI` set, so a bare path starting with `file:` would be
/// parsed as a URI too; passing every path through this keeps SQLite on the
/// file this code checked.
fn sqlite_uri_path(path: &std::path::Path) -> Option<String> {
    let path = path.to_str()?;
    let mut escaped = String::with_capacity(path.len());
    for character in path.chars() {
        match character {
            '%' => escaped.push_str("%25"),
            '?' => escaped.push_str("%3f"),
            '#' => escaped.push_str("%23"),
            other => escaped.push(other),
        }
    }
    Some(escaped)
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SourceMissing => "the source is not an existing file",
            Self::SourceNotADatabase => "the source is empty or is not an SQLite database",
            Self::DestinationCreate => "the destination could not be created",
            Self::DestinationExists => {
                "the destination, or one of its -wal/-shm/-journal sidecars, already exists"
            }
            Self::DestinationIsASidecar => {
                "the destination name ends in -wal, -shm or -journal: that is another database's sidecar"
            }
            Self::Open => "the source could not be opened read-only",
            Self::Copy => {
                "SQLite could not copy the source (not a database, unreadable, or no space)"
            }
            Self::Integrity => "the copy failed SQLite's integrity check",
        })
    }
}

/// Writes a consistent copy of `source` to the new file `destination`, safe
/// while the server is running. The source is opened read-only and copied
/// with `VACUUM INTO`, which reads one transaction-consistent snapshot,
/// including rows still in its `-wal` file, and writes a compact,
/// self-contained database. Any schema is copied as it is: nothing is
/// migrated, so the copy of an older database still opens with the version
/// that wrote it; `check_database` is the step that migrates.
///
/// The destination is created atomically (`O_EXCL`, so an existing file or a
/// planted link makes it fail) with mode 0600 before any byte is written, so
/// it is never readable by others and never overwrites anything. SQLite's own
/// journal for the copy goes next to it, so the destination directory must be
/// one only the caller can write to.
pub(crate) fn backup_database(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), BackupError> {
    use std::os::unix::fs::OpenOptionsExt;

    if !source.is_file() {
        return Err(BackupError::SourceMissing);
    }
    if !has_sqlite_header(source).map_err(|_| BackupError::Open)? {
        return Err(BackupError::SourceNotADatabase);
    }
    let destination_name = destination.to_string_lossy();
    if ["-wal", "-shm", "-journal"]
        .iter()
        .any(|suffix| destination_name.ends_with(suffix))
    {
        return Err(BackupError::DestinationIsASidecar);
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut candidate = destination.as_os_str().to_owned();
        candidate.push(suffix);
        if std::fs::symlink_metadata(&candidate).is_ok() {
            return Err(BackupError::DestinationExists);
        }
    }
    let source_uri = sqlite_uri_path(source).ok_or(BackupError::Open)?;
    let destination_uri = sqlite_uri_path(destination).ok_or(BackupError::DestinationCreate)?;

    // `VACUUM INTO` accepts an empty existing file, which lets the file be
    // created here with the right mode and no race with a later link.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
    {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(BackupError::DestinationExists)
        }
        Err(_) => return Err(BackupError::DestinationCreate),
    }

    let copied = SqliteConnection::establish(&format!("file:{source_uri}?mode=ro"))
        .map_err(|_| BackupError::Open)
        .and_then(|mut connection| {
            sql_query("PRAGMA busy_timeout = 5000;")
                .execute(&mut connection)
                .map_err(|_| BackupError::Open)?;
            sql_query("VACUUM INTO ?")
                .bind::<diesel::sql_types::Text, _>(format!("file:{destination_uri}"))
                .execute(&mut connection)
                .map_err(|_| BackupError::Copy)?;
            Ok(())
        });
    if let Err(error) = copied {
        // A refused or partial copy must not look like a backup.
        let _ = std::fs::remove_file(destination);
        return Err(error);
    }

    #[derive(QueryableByName)]
    struct IntegrityCheck {
        #[diesel(sql_type = diesel::sql_types::Text)]
        integrity_check: String,
    }
    let mut copy = SqliteConnection::establish(&format!("file:{destination_uri}?mode=ro"))
        .map_err(|_| BackupError::Integrity)?;
    let verdict = sql_query("PRAGMA integrity_check")
        .load::<IntegrityCheck>(&mut copy)
        .map_err(|_| BackupError::Integrity)?;
    if verdict.len() != 1 || verdict[0].integrity_check != "ok" {
        return Err(BackupError::Integrity);
    }
    Ok(())
}

/// Validates an already-initialized database for the restore drill.
///
/// A restore drill points `recoverbull check-database` at a RESTORED copy, which
/// already carries the schema of the live database it was backed up from. An
/// empty or truncated file has no `secret` table; letting the shared
/// initialization create one would report a brand-new or damaged file as a
/// valid backup (AUD-05). This path therefore refuses an uninitialized file
/// before any migration runs, so the check can only ever validate a real
/// database and never manufacture one. It still runs the full startup
/// initialization afterwards (idempotent migrations, schema postcondition, WAL
/// setup) on the restored copy, as the drill documents. The input is a literal
/// filename, unlike the server's `DATABASE_URL`.
pub(crate) fn check_database(database_path: String) -> Result<(), ConnectionSetupError> {
    // SQLite opens any file and fails only on first read, at whichever
    // pragma runs first; the header says up front whether this is a database
    // at all. An empty file is left to the uninitialized check below.
    let path = std::path::Path::new(&database_path);
    let is_empty = path.metadata().map(|m| m.len() == 0).unwrap_or(false);
    if !is_empty && !has_sqlite_header(path).map_err(|_| ConnectionSetupError::Open)? {
        return Err(ConnectionSetupError::NotADatabase);
    }
    let escaped_path = sqlite_uri_path(path).ok_or(ConnectionSetupError::Open)?;
    let database_url = format!("file:{escaped_path}?mode=rw");
    let mut probe = establish_connection_without_wal_check(database_url.clone())?;
    let initialized =
        table_exists(&mut probe, "secret").map_err(|_| ConnectionSetupError::NotADatabase)?;
    if !initialized {
        return Err(ConnectionSetupError::Uninitialized);
    }
    drop(probe);
    initialize_database(database_url)
}

/// Applies the exact database initialization used by server startup.
///
/// The restore drill invokes this through `recoverbull check-database` on the
/// restored copy, so the server's own migrations, not a separate schema
/// approximation, decide whether this application can open and migrate it.
pub(crate) fn initialize_database(database_url: String) -> Result<(), ConnectionSetupError> {
    let mut connection = establish_connection_without_wal_check(database_url)?;
    verify_sqlite_runtime(&mut connection)?;
    run_migrations(&mut connection).map_err(|_| ConnectionSetupError::Migration)?;
    sql_query("PRAGMA journal_mode = WAL;")
        .execute(&mut connection)
        .map_err(|_| ConnectionSetupError::Wal)?;
    let journal_mode = sql_query("SELECT journal_mode AS value FROM pragma_journal_mode")
        .load::<PragmaText>(&mut connection)
        .map_err(|_| ConnectionSetupError::Wal)?
        .into_iter()
        .next()
        .ok_or(ConnectionSetupError::Wal)?;
    if journal_mode.value != "wal" {
        return Err(ConnectionSetupError::Wal);
    }
    tracing::info!(target: "security", "database initialized");
    Ok(())
}

impl SqliteOperation {
    /// Inserts idempotently while retaining the opaque lease until completion.
    pub(crate) fn store(self, new_secret: NewStoredSecret) -> Result<(), StorageError> {
        let _permit = self.permit;
        #[cfg(test)]
        let _test_database_guard = self.test_database_guard;
        let mut connection =
            establish_connection(self.database_url).map_err(|_| StorageError::Connection)?;
        write(
            &mut connection,
            &Secret {
                id: new_secret.id,
                created_at: new_secret.created_at,
                encrypted_secret: new_secret.encrypted_secret,
            },
        )
        .map_err(|error| classify_database_error(&error))
    }

    /// Reads without deleting the stored row.
    pub(crate) fn fetch(self, secret_id: String) -> Result<Option<StoredSecret>, StorageError> {
        self.lookup(secret_id, false)
    }

    /// Reads and deletes the row in one immediate transaction.
    pub(crate) fn trash(self, secret_id: String) -> Result<Option<StoredSecret>, StorageError> {
        self.lookup(secret_id, true)
    }

    fn lookup(self, secret_id: String, trash: bool) -> Result<Option<StoredSecret>, StorageError> {
        let _permit = self.permit;
        #[cfg(test)]
        let _test_database_guard = self.test_database_guard;
        let mut connection =
            establish_connection(self.database_url).map_err(|_| StorageError::Connection)?;
        let row = if trash {
            read_and_trash_secret_by_id(&mut connection, &secret_id)
        } else {
            read_secret_by_id(&mut connection, &secret_id)
        }
        .map_err(|error| classify_database_error(&error))?;
        Ok(row.map(|row| StoredSecret {
            id: row.id,
            created_at: row.created_at,
            encrypted_secret: row.encrypted_secret,
        }))
    }
}

/// Embedded schema migrations applied during startup.
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!();
const INITIAL_MIGRATION_VERSION: &str = "0001";
/// Minimum SQLite runtime version required by the service.
pub const MINIMUM_SQLITE_VERSION: &str = "3.53.2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Startup failures for SQLite capability, migration, and journal checks.
pub enum ConnectionSetupError {
    Open,
    Version,
    BusyTimeout,
    SecureDelete,
    SecureDeleteVerification,
    Wal,
    Migration,
    /// The `check-database` target is not an SQLite file (wrong header) or
    /// its schema cannot be read. Distinct from `Migration` so a restore
    /// drill on a garbage file is not reported as a schema problem.
    NotADatabase,
    /// The `check-database` restore-drill target has no `secret` table, so it
    /// is not an initialized database. Only the check path returns this: normal
    /// startup deliberately creates the schema on a fresh `DATABASE_URL`.
    Uninitialized,
}

impl std::fmt::Display for ConnectionSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Open => "the database file could not be opened",
            Self::Version => "the bundled SQLite is older than the minimum this server requires",
            Self::BusyTimeout => "the busy timeout could not be set",
            Self::SecureDelete => "secure_delete could not be enabled",
            Self::SecureDeleteVerification => "secure_delete is not in effect",
            Self::Wal => "the database is not in WAL mode",
            Self::Migration => "the migrations failed or the secret table does not match them",
            Self::NotADatabase => "the file is not an SQLite database",
            Self::Uninitialized => "the file has no secret table: not an initialized database",
        })
    }
}

#[derive(QueryableByName)]
struct SecretColumn {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    column_type: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    not_null: i32,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    primary_key: i32,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    default_value: Option<String>,
}

/// The `secret` columns migration `0001` creates, in `pragma_table_info`
/// order: `(name, type, notnull, pk, dflt_value)`.
const EXPECTED_SECRET_COLUMNS: [(&str, &str, i32, i32, Option<&str>); 3] = [
    ("id", "TEXT", 1, 1, None),
    ("created_at", "TEXT", 1, 0, None),
    ("encrypted_secret", "TEXT", 1, 0, None),
];

/// Checks that the live `secret` table has exactly the columns of migration
/// `0001`. This is the storage postcondition every query in this module
/// relies on, and it is checked against the table itself rather than against
/// Diesel's ledger: the ledger records that a migration ran, not that the
/// schema it produced is still there.
fn validate_secret_schema(
    connection: &mut SqliteConnection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !table_exists(connection, "secret")? {
        return Err("secret table is missing".into());
    }
    let columns = sql_query(
        "SELECT name, type AS column_type, \"notnull\" AS not_null, \
         pk AS primary_key, dflt_value AS default_value \
         FROM pragma_table_info('secret') ORDER BY cid",
    )
    .load::<SecretColumn>(connection)?;
    let exact = columns.len() == EXPECTED_SECRET_COLUMNS.len()
        && columns
            .iter()
            .zip(EXPECTED_SECRET_COLUMNS)
            .all(|(column, expected)| {
                (
                    column.name.as_str(),
                    column.column_type.as_str(),
                    column.not_null,
                    column.primary_key,
                    column.default_value.as_deref(),
                ) == expected
            });
    if !exact {
        return Err("secret table has an incompatible schema".into());
    }
    Ok(())
}

/// Runs embedded migrations, adopting an exact pre-Diesel `secret` table when
/// necessary, then verifies the resulting schema unconditionally.
///
/// Adoption creates only Diesel's ledger and never creates or changes
/// `secret`; it can be removed once every database has been adopted. The
/// final validation is what makes a pre-existing ledger safe to trust: a
/// database whose ledger already records `0001` makes Diesel skip the
/// migration, so without it a missing or incompatible `secret` table (a
/// partial restore, a manual edit) would pass startup and fail every request.
pub fn run_migrations(
    connection: &mut SqliteConnection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let secret_exists = table_exists(connection, "secret")?;
    let ledger_exists = table_exists(connection, "__diesel_schema_migrations")?;

    if secret_exists && !ledger_exists {
        validate_secret_schema(connection).map_err(|error| format!("legacy {error}"))?;

        connection.transaction(|connection| {
            sql_query(
                "CREATE TABLE __diesel_schema_migrations (\
                 version VARCHAR(50) PRIMARY KEY NOT NULL,\
                 run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP\
                 )",
            )
            .execute(connection)?;
            sql_query("INSERT INTO __diesel_schema_migrations (version) VALUES (?)")
                .bind::<diesel::sql_types::Text, _>(INITIAL_MIGRATION_VERSION)
                .execute(connection)?;
            Ok::<_, diesel::result::Error>(())
        })?;
    }

    connection.run_pending_migrations(MIGRATIONS)?;
    validate_secret_schema(connection)
}

fn table_exists(
    connection: &mut SqliteConnection,
    table_name: &str,
) -> Result<bool, diesel::result::Error> {
    #[derive(QueryableByName)]
    struct TableName {
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
    }

    Ok(
        sql_query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind::<diesel::sql_types::Text, _>(table_name)
            .load::<TableName>(connection)?
            .into_iter()
            .next()
            .map(|table_name_row| table_name_row.name)
            .is_some(),
    )
}

#[derive(QueryableByName)]
struct PragmaText {
    #[diesel(sql_type = diesel::sql_types::Text)]
    value: String,
}

fn sqlite_version_at_least(version: &str, minimum: &str) -> bool {
    let parse = |value: &str| {
        value
            .split('.')
            .map(|part| part.parse::<u32>().ok())
            .collect::<Option<Vec<_>>>()
    };
    let (Some(actual), Some(required)) = (parse(version), parse(minimum)) else {
        return false;
    };
    actual.cmp(&required) != std::cmp::Ordering::Less
}

fn verify_sqlite_runtime(connection: &mut SqliteConnection) -> Result<(), ConnectionSetupError> {
    let version = sql_query("SELECT sqlite_version() AS value")
        .get_result::<PragmaText>(connection)
        .map_err(|_| ConnectionSetupError::Version)?;
    if sqlite_version_at_least(&version.value, MINIMUM_SQLITE_VERSION) {
        Ok(())
    } else {
        Err(ConnectionSetupError::Version)
    }
}

#[cfg(test)]
pub(crate) fn sqlite_version_at_least_for_test(version: &str) -> bool {
    sqlite_version_at_least(version, MINIMUM_SQLITE_VERSION)
}

fn establish_connection_without_wal_check(
    database_url: String,
) -> Result<SqliteConnection, ConnectionSetupError> {
    let mut connection =
        SqliteConnection::establish(&database_url).map_err(|_| ConnectionSetupError::Open)?;
    // busy_timeout is per-connection: without it, concurrent writers in WAL
    // mode fail immediately with SQLITE_BUSY instead of waiting.
    sql_query("PRAGMA busy_timeout = 5000;")
        .execute(&mut connection)
        .map_err(|_| ConnectionSetupError::BusyTimeout)?;
    sql_query("PRAGMA secure_delete = ON;")
        .execute(&mut connection)
        .map_err(|_| ConnectionSetupError::SecureDelete)?;
    #[derive(QueryableByName)]
    struct PragmaValue {
        #[diesel(sql_type = diesel::sql_types::Integer)]
        value: i32,
    }
    let secure_delete = sql_query("SELECT secure_delete AS value FROM pragma_secure_delete")
        .get_result::<PragmaValue>(&mut connection)
        .map_err(|_| ConnectionSetupError::SecureDeleteVerification)?;
    if secure_delete.value != 1 {
        return Err(ConnectionSetupError::SecureDeleteVerification);
    }
    Ok(connection)
}

/// Opens a worker connection and rejects runtimes that are not in WAL mode.
pub fn establish_connection(
    database_url: String,
) -> Result<SqliteConnection, ConnectionSetupError> {
    let mut connection = establish_connection_without_wal_check(database_url)?;
    let journal_mode = sql_query("SELECT journal_mode AS value FROM pragma_journal_mode")
        .load::<PragmaText>(&mut connection)
        .map_err(|_| ConnectionSetupError::Wal)?
        .into_iter()
        .next()
        .ok_or(ConnectionSetupError::Wal)?;
    if journal_mode.value != "wal" {
        return Err(ConnectionSetupError::Wal);
    }
    Ok(connection)
}

/// Inserts a secret without revealing whether its identifier already exists.
pub fn write(
    connection: &mut SqliteConnection,
    new_secret: &Secret,
) -> Result<(), diesel::result::Error> {
    connection.immediate_transaction(|connection| {
        // ON CONFLICT DO NOTHING: storing is idempotent. The response must not
        // reveal whether the secret_id already exists, otherwise /store becomes
        // an unthrottled authentication_key oracle (a 403 would confirm a
        // correct guess without ever touching the fetch rate-limit).
        diesel::insert_into(crate::schema::secret::table)
            .values(new_secret)
            .on_conflict_do_nothing()
            .execute(connection)?;
        // AUD-2026-10-01: a no-op insert needs no storage, so when the file
        // can no longer grow a store for an existing row would still succeed
        // while a new one fails. Rewriting the row unconditionally makes both
        // cases a real write that must reach the WAL, so storage pressure
        // refuses them alike. The values do not change.
        diesel::update(secret.filter(id.eq(&new_secret.id)))
            .set((id.eq(&new_secret.id), created_at.eq(created_at)))
            .execute(connection)?;
        Ok(())
    })
}

/// Reads one row, preserving database errors distinct from a missing row.
pub fn read_secret_by_id(
    connection: &mut SqliteConnection,
    secret_id: &str,
) -> Result<Option<Secret>, diesel::result::Error> {
    // Err (SQLITE_BUSY, I/O error, ...) must stay distinguishable from
    // Ok(None): a database failure is not a wrong credential and must never
    // consume a rate-limit attempt.
    secret
        .filter(id.eq(secret_id))
        .first::<Secret>(connection)
        .optional()
}

/// Atomically reads and deletes one row using SQLite's immediate transaction.
pub fn read_and_trash_secret_by_id(
    connection: &mut SqliteConnection,
    secret_id: &str,
) -> Result<Option<Secret>, diesel::result::Error> {
    connection.immediate_transaction(|connection| {
        let stored_secret = read_secret_by_id(connection, secret_id)?;
        let Some(stored_secret) = stored_secret else {
            return Ok(None);
        };

        let deleted = diesel::delete(secret.filter(id.eq(secret_id))).execute(connection)?;
        if deleted != 1 {
            return Err(diesel::result::Error::NotFound);
        }

        Ok(Some(stored_secret))
    })
}
