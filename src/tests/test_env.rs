use crate::env::{
    canary_file_state, validate_capacity, validate_config, CanaryFileState,
    MAX_DATABASE_CONCURRENCY, MAX_RATE_LIMIT_IDENTIFIERS,
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
fn test_validate_config_rejects_zero_max_failed_attempts() {
    assert!(validate_config(1440, 128, 0).is_err());
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
    assert!(matches!(
        canary_file_state(&path),
        CanaryFileState::Removed
    ));
    std::fs::remove_file(&path).ok();

    // a missing file is an ops error, not a signal
    assert!(matches!(
        canary_file_state(&path),
        CanaryFileState::Unavailable
    ));
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
