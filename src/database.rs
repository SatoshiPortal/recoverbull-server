use crate::schema::key::dsl::*;

use crate::{models::Key, schema::key::*};

use diesel::sql_query;
use diesel::{
    Connection, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection,
};
use std::env;

pub fn init_db() {
    let mut connection = establish_connection();
    let create_table_query = "
        CREATE TABLE IF NOT EXISTS key (
            id TEXT PRIMARY KEY NOT NULL,
            created_at TEXT NOT NULL,
            backup_key TEXT NOT NULL
        );
    ";
    sql_query(create_table_query)
        .execute(&mut connection)
        .expect("Error creating table");
}

pub fn establish_connection() -> SqliteConnection {
    let database_url;
    if cfg!(test) {
        database_url = env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");
    } else {
        database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    }
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
        )) => None, // Duplicate
        Err(_) => Some(false),
    }
}

pub fn read_key_by_id(connection: &mut SqliteConnection, key_id: &str) -> Option<Key> {
    match key
        .filter(id.eq(key_id))
        .first::<Key>(connection)
        .optional()
    {
        Ok(Some(found_key)) => Some(found_key),
        Ok(None) => None,
        Err(_) => None,
    }
}
