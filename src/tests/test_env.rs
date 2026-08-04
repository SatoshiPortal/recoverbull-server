use crate::env::validate_config;

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
