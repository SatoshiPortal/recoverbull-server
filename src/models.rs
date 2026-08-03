use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Info {
    pub secret_max_length: usize,
    pub canary: String,
    pub rate_limit_cooldown: u64,
    pub rate_limit_max_failed_attempts: u8,
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

#[derive(Clone)]
pub struct RateLimitInfo {
    pub last_request: chrono::DateTime<chrono::Utc>,
    pub attempts: u8,
}

#[derive(Serialize, Deserialize)]
pub struct ResponseFailedAttempt{
    pub error: String,
    pub requested_at:  chrono::DateTime<chrono::Utc>,
    pub rate_limit_cooldown: i64,
    pub attempts: u8,
}

#[derive(Serialize, Deserialize)]
pub struct StatEntry {
    /// SHA-256 of the raw identifier bytes, so clients can recognize their
    /// own identifier without exposing it (pre-image resistance).
    pub id_hash: String,
    pub attempts: u8,
    pub last_failed_at: chrono::DateTime<chrono::Utc>,
}