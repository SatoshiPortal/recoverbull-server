use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct StoreKey {
    pub secret_hash: String,
    pub backup_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct FetchKey {
    pub backup_key_hash: String,
    pub secret_hash: String,
}

#[derive(Insertable, Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::key)]
pub struct Key {
    pub id: String,
    pub created_at: String,
    pub backup_key: String,
}
