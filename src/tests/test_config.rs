use crate::config::{
    canary_file_state, estimated_peak_memory_bytes, max_identifiers_within_budget,
    unique_test_database, validate_capacity, validate_config, validate_snapshot_ttl,
    validate_token_bucket, CanaryFileState, DEFAULT_MEMORY_BUDGET_MB, MAX_DATABASE_CONCURRENCY,
    PROCESS_MEMORY_RESERVE_BYTES, RATE_LIMIT_BYTES_PER_CANDIDATE, RATE_LIMIT_BYTES_PER_IDENTIFIER,
};

/// The documented production budget, in bytes.
const DEFAULT_BUDGET: usize = DEFAULT_MEMORY_BUDGET_MB * 1024 * 1024;

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
    // the documented production configuration
    assert!(validate_capacity(100_000, 16, 3, DEFAULT_BUDGET).is_ok());
    assert!(validate_capacity(1, 1, 1, DEFAULT_BUDGET).is_ok());
    assert!(validate_capacity(1, MAX_DATABASE_CONCURRENCY, 255, DEFAULT_BUDGET).is_ok());
}

#[test]
fn test_validate_capacity_rejects_zero() {
    // a zero capacity disables the protection entirely
    assert!(validate_capacity(0, 16, 3, DEFAULT_BUDGET).is_err());
    assert!(validate_capacity(100_000, 0, 3, DEFAULT_BUDGET).is_err());
}

#[test]
fn test_validate_capacity_rejects_absurdly_large_values() {
    // beyond the bounds, the memory/concurrency protections are silently
    // disabled: the server must refuse to start instead
    assert!(validate_capacity(usize::MAX, 16, 3, DEFAULT_BUDGET).is_err());
    assert!(validate_capacity(100_000, MAX_DATABASE_CONCURRENCY + 1, 3, DEFAULT_BUDGET).is_err());
    assert!(validate_capacity(100_000, usize::MAX, 3, DEFAULT_BUDGET).is_err());
}

/// The capacity that used to be the hard ceiling is rejected under the
/// documented budget. It was justified by a per-entry cost an order of
/// magnitude too low, so it admitted the very memory-exhaustion kill the
/// ceiling claimed to prevent: about 15 GB of peak against `MemoryMax=512M`.
#[test]
fn test_validate_capacity_rejects_the_former_ten_million_ceiling() {
    let former_ceiling = 10_000_000;
    assert!(validate_capacity(former_ceiling, 16, 3, DEFAULT_BUDGET).is_err());
    let peak = estimated_peak_memory_bytes(former_ceiling, 3).expect("the estimate fits usize");
    assert!(
        peak > 14 * 1024 * 1024 * 1024,
        "the former ceiling must be shown to cost more than 14 GiB, got {peak} bytes"
    );
}

/// The bound moves with `RATE_LIMIT_MAX_ATTEMPTS`, because a retained
/// CandidateTag is a 64-character String and an entry holds up to the
/// configured budget of them. The former fixed ceiling ignored this entirely.
#[test]
fn test_validate_capacity_tracks_the_candidate_budget() {
    let capacity = 200_000;
    assert!(
        validate_capacity(capacity, 16, 3, DEFAULT_BUDGET).is_ok(),
        "200,000 identifiers at 3 candidates must fit the default budget"
    );
    assert!(
        validate_capacity(capacity, 16, 255, DEFAULT_BUDGET).is_err(),
        "the same capacity at the u8 candidate ceiling must not fit"
    );
    assert!(
        max_identifiers_within_budget(255, DEFAULT_BUDGET)
            < max_identifiers_within_budget(3, DEFAULT_BUDGET),
        "a larger candidate budget must lower the admissible capacity"
    );
}

/// A capacity may be raised, but only by declaring the budget that pays for
/// it: the guard rail states a startup error instead of deferring to the OOM
/// killer.
#[test]
fn test_validate_capacity_follows_an_explicitly_raised_budget() {
    let capacity = 2_000_000;
    assert!(validate_capacity(capacity, 16, 3, DEFAULT_BUDGET).is_err());
    let needed = estimated_peak_memory_bytes(capacity, 3).expect("the estimate fits usize");
    let declared = needed + PROCESS_MEMORY_RESERVE_BYTES;
    assert!(
        validate_capacity(capacity, 16, 3, declared).is_ok(),
        "a budget covering the estimate plus the reserve must be accepted"
    );
}

/// The boundary is exact on both sides, so the accepted maximum is really
/// the largest capacity that fits.
#[test]
fn test_validate_capacity_boundary_is_exact() {
    let max = max_identifiers_within_budget(3, DEFAULT_BUDGET);
    assert!(
        validate_capacity(max, 16, 3, DEFAULT_BUDGET).is_ok(),
        "the reported maximum ({max}) must be accepted"
    );
    assert!(
        validate_capacity(max + 1, 16, 3, DEFAULT_BUDGET).is_err(),
        "one identifier past the reported maximum must be refused"
    );
}

/// A budget that does not even cover the process reserve is a
/// misconfiguration, not a very small map.
#[test]
fn test_validate_capacity_rejects_a_budget_under_the_process_reserve() {
    assert!(validate_capacity(1, 16, 3, PROCESS_MEMORY_RESERVE_BYTES).is_err());
    assert!(validate_capacity(1, 16, 3, 0).is_err());
    assert!(validate_capacity(1, 16, 3, PROCESS_MEMORY_RESERVE_BYTES + 1024 * 1024).is_ok());
}

/// The estimate saturates instead of wrapping: an overflowing product must
/// never be mistaken for a capacity that fits.
#[test]
fn test_estimated_peak_memory_does_not_wrap() {
    assert_eq!(estimated_peak_memory_bytes(usize::MAX, 255), None);
    assert!(validate_capacity(usize::MAX, 16, 255, usize::MAX).is_err());
    assert_eq!(
        estimated_peak_memory_bytes(1, 0),
        Some(RATE_LIMIT_BYTES_PER_IDENTIFIER)
    );
    assert_eq!(
        estimated_peak_memory_bytes(2, 1),
        Some(2 * (RATE_LIMIT_BYTES_PER_IDENTIFIER + RATE_LIMIT_BYTES_PER_CANDIDATE))
    );
}

/// The per-entry constants stay at or above what a release build measured,
/// so the model cannot silently drift back to an optimistic value: 100,000
/// entries at 3 candidates measured 117 MB of peak RSS, and the model must
/// not predict less than that.
#[test]
fn test_capacity_model_is_not_optimistic_against_the_measurement() {
    let measured_peak_bytes = 117_051_392usize;
    let modelled = estimated_peak_memory_bytes(100_000, 3).expect("the estimate fits usize");
    assert!(
        modelled >= measured_peak_bytes,
        "the model ({modelled} bytes) must not predict less than the measured peak ({measured_peak_bytes} bytes)"
    );
    // and the documented production configuration must still fit the budget
    assert!(validate_capacity(100_000, 16, 3, DEFAULT_BUDGET).is_ok());
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

/// cgroup limit files: `max` (v2) and the v1 sentinel both mean "no limit",
/// and anything unparsable must degrade to "no limit" rather than to a bogus
/// ceiling that would refuse a legitimate capacity.
#[test]
fn test_parse_memory_limit_recognizes_unlimited_forms() {
    use crate::config::parse_memory_limit;

    assert_eq!(parse_memory_limit("536870912\n"), Some(536_870_912));
    assert_eq!(parse_memory_limit("  268435456  "), Some(268_435_456));

    assert_eq!(parse_memory_limit("max\n"), None, "cgroup v2 spells it max");
    assert_eq!(
        parse_memory_limit("9223372036854771712\n"),
        None,
        "cgroup v1 writes a sentinel near i64::MAX"
    );
    assert_eq!(parse_memory_limit(""), None);
    assert_eq!(parse_memory_limit("not-a-number"), None);
    assert_eq!(
        parse_memory_limit("0"),
        None,
        "a zero limit is not a budget"
    );
}

/// The enforced limit wins whenever it is lower than the declared budget.
/// Declaring 512 MiB while the cgroup enforces 256 MiB must not authorize a
/// capacity sized for 512 MiB: that is the memory-exhaustion kill this check
/// exists to prevent, and a declared value drifts out of sync with the unit
/// file exactly when an operator lowers `MemoryMax`.
#[test]
fn test_effective_budget_takes_the_enforced_limit_when_lower() {
    use crate::config::effective_memory_budget_bytes;

    let declared = DEFAULT_BUDGET;
    let lower = 256 * 1024 * 1024;
    let higher = 2048 * 1024 * 1024;

    assert_eq!(
        effective_memory_budget_bytes(declared, Some(lower)),
        lower,
        "a lower enforced limit must override the declared budget"
    );
    assert_eq!(
        effective_memory_budget_bytes(declared, Some(higher)),
        declared,
        "a higher enforced limit must not raise the declared budget"
    );
    assert_eq!(
        effective_memory_budget_bytes(declared, None),
        declared,
        "no discoverable limit falls back to the declared budget"
    );
}

/// End to end: the documented default capacity fits a 512 MiB budget, and the
/// same capacity is refused once the enforced limit is the binding constraint.
#[test]
fn test_capacity_is_refused_against_a_lower_enforced_limit() {
    use crate::config::effective_memory_budget_bytes;

    let enforced = 128 * 1024 * 1024;
    let budget = effective_memory_budget_bytes(DEFAULT_BUDGET, Some(enforced));
    assert_eq!(budget, enforced);
    assert!(
        validate_capacity(100_000, 16, 3, DEFAULT_BUDGET).is_ok(),
        "the default capacity fits the declared budget"
    );
    assert!(
        validate_capacity(100_000, 16, 3, budget).is_err(),
        "the same capacity must be refused once the enforced limit binds"
    );
}

/// Detection is best-effort and must never panic or invent a limit, whatever
/// the host looks like: this machine may run under cgroup v2, v1, or neither.
#[test]
fn test_detected_memory_limit_is_best_effort() {
    if let Some(limit) = crate::config::detected_memory_limit_bytes() {
        assert!(limit > 0, "a reported limit must be positive");
    }
}
