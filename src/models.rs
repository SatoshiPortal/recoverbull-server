use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct StoreKey {
    pub secret_hash: String,
    pub backup_key: String,
}

#[derive(Deserialize)]
pub struct FetchKey {
    pub id: String,
    pub secret_hash: String,
}

#[derive(Insertable, Serialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::key)]
pub struct Key {
    pub id: String,
    pub created_at: String,
    pub secret: String,
    pub private: String,
}
