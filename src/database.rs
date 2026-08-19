use crate::schema::secret::dsl::*;

use crate::AppState;
use crate::{models::Secret, schema::secret::*};

use diesel::sql_query;
use diesel::{
    Connection, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection,
};

pub fn init_db(state: AppState) {
    let mut connection = establish_connection(state.database_url);
    let create_table_query = "
        CREATE TABLE IF NOT EXISTS secret (
            id TEXT PRIMARY KEY NOT NULL,
            created_at TEXT NOT NULL,
            encrypted_secret TEXT NOT NULL
        );
    ";
    sql_query(create_table_query)
        .execute(&mut connection)
        .expect("Error creating table");

    // enable WAL mode to allow replication with litestream
    sql_query("PRAGMA journal_mode = WAL;")
        .execute(&mut connection)
        .expect("Failed to enable WAL mode");
}

pub fn establish_connection(database_url: String) -> SqliteConnection {
    let mut connection =
        SqliteConnection::establish(&database_url).expect("Error connecting to database");
    // busy_timeout is per-connection: without it, concurrent writers in WAL
    // mode fail immediately with SQLITE_BUSY instead of waiting.
    sql_query("PRAGMA busy_timeout = 5000;")
        .execute(&mut connection)
        .expect("Failed to set busy_timeout");
    connection
}

pub fn write(connection: &mut SqliteConnection, new_secret: &Secret) -> bool {
    // ON CONFLICT DO NOTHING: storing is idempotent. The response must not
    // reveal whether the secret_id already exists, otherwise /store becomes
    // an unthrottled authentication_key oracle (a 403 would confirm a
    // correct guess without ever touching the fetch rate-limit).
    diesel::insert_into(crate::schema::secret::table)
        .values(new_secret)
        .on_conflict_do_nothing()
        .execute(connection)
        .is_ok()
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
