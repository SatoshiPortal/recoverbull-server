use crate::env::{
    canary_file_state, unique_test_database, validate_capacity, validate_config,
    validate_snapshot_ttl, validate_token_bucket, CanaryFileState, MAX_DATABASE_CONCURRENCY,
    MAX_RATE_LIMIT_IDENTIFIERS,
};

#[test]
fn test_validate_config_accepts_valid_values() {
    assert!(validate_config(1440, 128, 3).is_ok());
    assert!(validate_config(1, 1, 1).is_ok());
}

#[test]
fn test_validate_config_rejects_non_positive_cooldown() {
    // a zero or negative cooldown silently disables rate-limiting:
    // the cooldown check is always elapsed, so attempts are never blocked
    assert!(validate_config(0, 128, 3).is_err());
    assert!(validate_config(-1, 128, 3).is_err());
    assert!(validate_config(i64::MIN, 128, 3).is_err());
}

#[test]
fn test_validate_config_rejects_absurdly_large_cooldown() {
    // chrono::TimeDelta::minutes panics on out-of-range values
    assert!(validate_config(525_601, 128, 3).is_err());
    assert!(validate_config(i64::MAX, 128, 3).is_err());
    assert!(validate_config(525_600, 128, 3).is_ok());
}

#[test]
fn test_validate_config_rejects_zero_secret_max_length() {
    assert!(validate_config(1440, 0, 3).is_err());
}

#[test]
fn test_validate_config_rejects_zero_max_attempts() {
    assert!(validate_config(1440, 128, 0).is_err());
}

#[test]
fn test_database_guard_removes_database_and_sqlite_sidecars_after_last_clone() {
    let (database_url, guard) = unique_test_database();
    let database = std::path::PathBuf::from(&database_url);
    let wal = std::path::PathBuf::from(format!("{database_url}-wal"));
    let shm = std::path::PathBuf::from(format!("{database_url}-shm"));
    std::fs::write(&database, b"database").unwrap();
    std::fs::write(&wal, b"wal").unwrap();
    std::fs::write(&shm, b"shm").unwrap();

    let clone = guard.clone();
    drop(guard);
    assert!(database.exists());
    assert!(wal.exists());
    assert!(shm.exists());

    drop(clone);
    assert!(!database.exists());
    assert!(!wal.exists());
    assert!(!shm.exists());
}

#[test]
fn test_validate_capacity_accepts_valid_values() {
    assert!(validate_capacity(100_000, 16).is_ok());
    assert!(validate_capacity(1, 1).is_ok());
    assert!(validate_capacity(MAX_RATE_LIMIT_IDENTIFIERS, MAX_DATABASE_CONCURRENCY).is_ok());
}

#[test]
fn test_validate_capacity_rejects_zero() {
    // a zero capacity disables the protection entirely
    assert!(validate_capacity(0, 16).is_err());
    assert!(validate_capacity(100_000, 0).is_err());
}

#[test]
fn test_validate_capacity_rejects_absurdly_large_values() {
    // beyond the bounds, the memory/concurrency protections are silently
    // disabled: the server must refuse to start instead
    assert!(validate_capacity(MAX_RATE_LIMIT_IDENTIFIERS + 1, 16).is_err());
    assert!(validate_capacity(usize::MAX, 16).is_err());
    assert!(validate_capacity(100_000, MAX_DATABASE_CONCURRENCY + 1).is_err());
    assert!(validate_capacity(100_000, usize::MAX).is_err());
}

#[test]
fn test_canary_file_state_reads_and_unquotes() {
    let path = unique_temp_path("canary_reads");
    std::fs::write(&path, "OTHER=value\nCANARY='🐦‍⬛'\n").unwrap();
    match canary_file_state(&path) {
        CanaryFileState::Value(value) => assert_eq!(value, "🐦‍⬛"),
        _ => panic!("expected the file canary value"),
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn test_canary_file_state_distinguishes_removal_from_unavailable() {
    let path = unique_temp_path("canary_removed");
    // a file that parses but holds no CANARY key: deliberate removal,
    // which is the warrant-canary compromise signal
    std::fs::write(&path, "OTHER=value\n").unwrap();
    assert!(matches!(canary_file_state(&path), CanaryFileState::Removed));
    std::fs::remove_file(&path).ok();

    // a missing file is an ops error, not a signal
    assert!(matches!(
        canary_file_state(&path),
        CanaryFileState::Unavailable
    ));
}

#[test]
fn test_validate_token_bucket_accepts_valid_values() {
    assert!(validate_token_bucket("STORE", 10.0, 2.0).is_ok());
    // a zero refill rate is a valid, deliberately strict bucket
    assert!(validate_token_bucket("STORE", 1.0, 0.0).is_ok());
}

#[test]
fn test_validate_token_bucket_rejects_sub_token_bursts() {
    assert!(validate_token_bucket("STORE", 0.5, 0.0).is_err());
}

#[test]
fn test_validate_token_bucket_rejects_f64_max() {
    assert!(validate_token_bucket("STORE", f64::MAX, 0.0).is_err());
}

#[test]
fn test_validate_token_bucket_rejects_zero_burst() {
    // a zero burst means the bucket can never hold a single token
    assert!(validate_token_bucket("STORE", 0.0, 2.0).is_err());
}

#[test]
fn test_validate_token_bucket_rejects_negative_burst() {
    assert!(validate_token_bucket("STORE", -1.0, 2.0).is_err());
}

#[test]
fn test_validate_token_bucket_rejects_negative_refill() {
    assert!(validate_token_bucket("STORE", 10.0, -1.0).is_err());
}

#[test]
fn test_validate_token_bucket_rejects_nan() {
    assert!(validate_token_bucket("STORE", f64::NAN, 2.0).is_err());
    assert!(validate_token_bucket("STORE", 10.0, f64::NAN).is_err());
}

#[test]
fn test_validate_token_bucket_rejects_infinity() {
    assert!(validate_token_bucket("STORE", f64::INFINITY, 2.0).is_err());
    assert!(validate_token_bucket("STORE", 10.0, f64::INFINITY).is_err());
    assert!(validate_token_bucket("STORE", f64::NEG_INFINITY, 2.0).is_err());
}

#[test]
fn test_validate_snapshot_ttl_accepts_valid_values() {
    assert!(validate_snapshot_ttl(1).is_ok());
    assert!(validate_snapshot_ttl(60).is_ok());
    assert!(validate_snapshot_ttl(u64::MAX).is_ok());
}

#[test]
fn test_validate_snapshot_ttl_rejects_zero() {
    // a zero TTL forces a fresh snapshot computation on every request,
    // defeating the point of caching
    assert!(validate_snapshot_ttl(0).is_err());
}

fn unique_temp_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "keychain-test-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
