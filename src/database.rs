use crate::schema::key::dsl::*;

use crate::{
    models::Key,
    schema::key::{id, secret},
};

use diesel::sql_query;
use diesel::{
    Connection, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection,
};
use dotenv::dotenv;
use std::env;

pub fn init_db() {
    let mut connection = establish_connection();
    let create_table_query = "
        CREATE TABLE IF NOT EXISTS key (
            id TEXT PRIMARY KEY NOT NULL,
            created_at TEXT NOT NULL,
            secret TEXT NOT NULL,
            private TEXT NOT NULL
        );
    ";
    sql_query(create_table_query)
        .execute(&mut connection)
        .expect("Error creating table");
}

pub fn establish_connection() -> SqliteConnection {
    dotenv().ok();
    let database_url: String = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url).expect("Error connecting to database")
}

pub fn write_key(connection: &mut SqliteConnection, new_key: &Key) -> Option<bool> {
    match diesel::insert_into(crate::schema::key::table)
        .values(new_key)
        .execute(connection)
    {
        Ok(_) => Some(true),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => None,
        Err(_) => Some(false),
    }
}

pub fn read_key_by_id_and_secret(
    connection: &mut SqliteConnection,
    key_id: &str,
    secret_hash: &str,
) -> Option<Key> {
    key.filter(id.eq(key_id))
        .filter(secret.eq(secret_hash))
        .first::<Key>(connection)
        .optional()
        .expect("Error reading key")
}
