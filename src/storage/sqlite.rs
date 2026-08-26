use crate::schema::secret::dsl::*;

use crate::schema::secret::*;
use crate::AppState;

use diesel::prelude::*;
use diesel::sql_query;
use diesel::{
    Connection, ExpressionMethods, OptionalExtension, QueryDsl, QueryableByName, RunQueryDsl,
    SqliteConnection,
};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

#[derive(Insertable, Queryable, Selectable)]
#[diesel(table_name = crate::schema::secret)]
pub(crate) struct Secret {
    pub(crate) id: String,
    pub(crate) created_at: String,
    pub(crate) encrypted_secret: String,
}

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!();
const INITIAL_MIGRATION_VERSION: &str = "0001";
pub const MINIMUM_SQLITE_VERSION: &str = "3.51.3";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConnectionSetupError {
    Open,
    Version,
    BusyTimeout,
    SecureDelete,
    SecureDeleteVerification,
    Wal,
    Migration,
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

pub fn try_init_db(state: AppState) -> Result<(), ConnectionSetupError> {
    let mut connection = establish_connection_without_wal_check(state.database_url)?;
    verify_sqlite_runtime(&mut connection)?;
    run_migrations(&mut connection).map_err(|_| ConnectionSetupError::Migration)?;

    // enable WAL mode to allow replication with litestream
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

/// Runs embedded migrations, adopting an exact pre-Diesel `secret` table when
/// necessary. Adoption creates only Diesel's ledger and never creates or
/// changes `secret`; it can be removed once every database has been adopted.
pub fn run_migrations(
    connection: &mut SqliteConnection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let secret_exists = table_exists(connection, "secret")?;
    let ledger_exists = table_exists(connection, "__diesel_schema_migrations")?;

    if secret_exists && !ledger_exists {
        let columns = sql_query(
            "SELECT name, type AS column_type, \"notnull\" AS not_null, \
             pk AS primary_key, dflt_value AS default_value \
             FROM pragma_table_info('secret') ORDER BY cid",
        )
        .load::<SecretColumn>(connection)?;
        let expected = [
            ("id", "TEXT", 1, 1, None),
            ("created_at", "TEXT", 1, 0, None),
            ("encrypted_secret", "TEXT", 1, 0, None),
        ];
        let exact = columns.len() == expected.len()
            && columns.iter().zip(expected).all(|(column, expected)| {
                (
                    column.name.as_str(),
                    column.column_type.as_str(),
                    column.not_null,
                    column.primary_key,
                    column.default_value.as_deref(),
                ) == expected
            });
        if !exact {
            return Err("legacy secret table has an incompatible schema".into());
        }

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
    Ok(())
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
