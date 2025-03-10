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
    sql_query("PRAGMA journal_mode = WAL;").execute(&mut connection).expect("Failed to enable WAL mode");
}

pub fn establish_connection(database_url: String) -> SqliteConnection {
    SqliteConnection::establish(&database_url).expect("Error connecting to database")
}

pub fn write(connection: &mut SqliteConnection, new_secret: &Secret) -> Option<bool> {
    match diesel::insert_into(crate::schema::secret::table)
        .values(new_secret)
        .execute(connection)
    {
        Ok(_) => Some(true),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => None, // Duplicate
        Err(_) => Some(false),
    }
}

pub fn read_secret_by_id(connection: &mut SqliteConnection, secret_id: &str) -> Option<Secret> {
    match secret
        .filter(id.eq(secret_id))
        .first::<Secret>(connection)
        .optional()
    {
        Ok(Some(found_secret)) => Some(found_secret),
        Ok(None) => None,
        Err(_) => None,
    }
}

pub fn trash(connection: &mut SqliteConnection, secret_id: &str) -> bool {
    match diesel::delete(secret.filter(id.eq(secret_id))).execute(connection) {
        Ok(deleted_count) if deleted_count > 0 => true,
        Ok(_) => false,
        Err(_) => false,
    }
}
