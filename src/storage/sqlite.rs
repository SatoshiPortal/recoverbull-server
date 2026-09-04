//! SQLite persistence implementation; Diesel remains confined to this module.
//!
//! Initialization verifies `secure_delete` and WAL, while leased operations
//! retain their permit through blocking work and trash uses an immediate
//! transaction.

use crate::schema::secret::dsl::*;

use crate::config::StorageConfig;
use crate::schema::secret::*;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Opaque storage failure categories safe for domain and HTTP mapping.
pub(crate) enum StorageError {
    Connection,
    Database,
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

    pub(crate) async fn acquire(&self) -> Result<SqliteOperation, StorageError> {
        let permit = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            self.database_semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| StorageError::Connection)?
        .map_err(|_| StorageError::Connection)?;
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

/// Validates an already-initialized database for the restore drill.
///
/// A restore drill points `keychain check-database` at a RESTORED copy, which
/// already carries the schema of the live database it was backed up from. An
/// empty or truncated file has no `secret` table; letting the shared
/// initialization create one would report a brand-new or damaged file as a
/// valid backup (AUD-05). This path therefore refuses an uninitialized file
/// before any migration runs, so the check can only ever validate a real
/// database and never manufacture one. It still runs the full startup
/// initialization afterwards (idempotent migrations, schema postcondition, WAL
/// setup) on the restored copy, as the drill documents.
pub(crate) fn check_database(database_url: String) -> Result<(), ConnectionSetupError> {
    let mut probe = establish_connection_without_wal_check(database_url.clone())?;
    let initialized =
        table_exists(&mut probe, "secret").map_err(|_| ConnectionSetupError::Migration)?;
    drop(probe);
    if !initialized {
        return Err(ConnectionSetupError::Uninitialized);
    }
    initialize_database(database_url)
}

/// Applies the exact database initialization used by server startup.
///
/// The restore drill invokes this through `keychain check-database` on the
/// restored copy, so an independent Python schema approximation cannot be
/// the final authority on whether this application can open and migrate it.
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
        .map_err(|_| StorageError::Database)
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
        .map_err(|_| StorageError::Database)?;
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
pub const MINIMUM_SQLITE_VERSION: &str = "3.51.3";

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
    /// The `check-database` restore-drill target has no `secret` table, so it
    /// is not an initialized database. Only the check path returns this: normal
    /// startup deliberately creates the schema on a fresh `DATABASE_URL`.
    Uninitialized,
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
    // ON CONFLICT DO NOTHING: storing is idempotent. The response must not
    // reveal whether the secret_id already exists, otherwise /store becomes
    // an unthrottled authentication_key oracle (a 403 would confirm a
    // correct guess without ever touching the fetch rate-limit).
    diesel::insert_into(crate::schema::secret::table)
        .values(new_secret)
        .on_conflict_do_nothing()
        .execute(connection)
        .map(|_| ())
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
