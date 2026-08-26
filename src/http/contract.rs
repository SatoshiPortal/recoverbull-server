use serde::Serialize;

use crate::models::AttemptStatus;

#[derive(Serialize)]
pub(crate) struct LookupSuccessResponse {
    pub(crate) id: String,
    pub(crate) created_at: String,
    pub(crate) encrypted_secret: String,
    pub(crate) attempt_status: AttemptStatus,
}
