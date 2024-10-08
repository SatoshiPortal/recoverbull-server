use crate::schema::key::dsl::*;

use crate::{
    models::Key,
    schema::key::{id, secret},
};

use diesel::{
    Connection, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection,
};
use dotenv::dotenv;
use std::env;
pub fn establish_connection() -> SqliteConnection {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url).expect("Error connecting to database")
}

pub fn write_key(connection: &mut SqliteConnection, new_key: &Key) {
    diesel::insert_into(crate::schema::key::table)
        .values(new_key)
        .execute(connection)
        .expect("Error writing new key");
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
