use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EncryptedRequest {
    pub public_key: String,
    pub encrypted_body: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedResponse {
    pub encrypted_response: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    pub timestamp: i64,
    pub cooldown: i64,
    pub secret_max_length: usize,
    pub canary: String,
}

#[derive(Serialize, Deserialize)]
pub struct StoreSecret {
    pub identifier: String,
    pub authentication_key: String,
    pub encrypted_secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct FetchSecret {
    pub identifier: String,
    pub authentication_key: String,
}

#[derive(Insertable, Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::secret)]
pub struct Secret {
    pub id: String,
    pub created_at: String,
    pub encrypted_secret: String,
}
