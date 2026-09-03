pub mod test_adversarial;
pub mod test_attempts;
pub mod test_audit_claims;
pub mod test_concurrency;
pub mod test_config;
pub mod test_contract;
pub mod test_db_errors;
pub mod test_distinct_candidates;
pub mod test_fetch;
pub mod test_http_boundary;
pub mod test_info;
pub mod test_logging;
pub mod test_migrations;
pub mod test_privacy;
pub mod test_rate_limit;
pub mod test_secure_delete;
pub mod test_server;
pub mod test_store;
pub mod test_timing;
pub mod test_trash;

static SHA256_111111: &str = "bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a";
static SHA256_222222: &str = "4cc8f4d609b717356701c57a03e737e5ac8fe885da8c7163d3de47e01849c635";
static SHA256_CONCAT_111111_222222: &str =
    "dd1d9109d8404436efc6d86bf1eb9f292f884d935b0ba0d22eb44ce8421ded19";
static NOT_PASSWORD_HASH: &str = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
static BASE64_ENCRYPTED_SECRET: &str = "4a1dl1T8cxcP2pnvxwYWDwm/I68vVd9oWMY0nTOmBSNbonEN/mfBjkPWkSNlxjWacsS2lRVzoGUQ4guZArKf415dLvbObReqWNtzmA4vaB9/feJapmgWAssVI9EbhJFf";

pub(crate) fn distinct_candidate(index: usize) -> String {
    format!("{:064x}", index + 1)
}

/// A monotonic reading `age` in the past. Expiry reads the monotonic clock, so
/// a test that synthesizes an already-expired entry must back-date this value
/// as well as the published wall-clock timestamps. Underflow on a
/// just-booted host falls back to the present, which makes such a test fail
/// loudly rather than pass for the wrong reason.
pub(crate) fn monotonic_age(age: std::time::Duration) -> tokio::time::Instant {
    tokio::time::Instant::now()
        .checked_sub(age)
        .unwrap_or_else(tokio::time::Instant::now)
}
