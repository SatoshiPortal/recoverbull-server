use chrono::Duration;
use dotenvy::dotenv;
use std::{collections::HashMap, env, fmt::Display, str::FromStr, sync::Arc};
use tokio::sync::{Mutex, Semaphore};

use crate::AppState;

fn optional_env<T>(name: &str, default: T) -> T
where
    T: FromStr,
    T::Err: Display,
{
    match env::var(name) {
        Ok(value) => value.parse().unwrap_or_else(|error| {
            eprintln!("Error: {name} has an invalid value: {error}");
            std::process::exit(1);
        }),
        Err(env::VarError::NotPresent) => default,
        Err(error) => {
            eprintln!("Error: cannot read {name}: {error}");
            std::process::exit(1);
        }
    }
}

/// Builds a database path unique to this call, under the OS temp directory.
/// Every test calls `env::init()`, so each test gets its own SQLite file:
/// without this, all tests shared a single file and ran into each other's
/// data under `cargo test`'s parallel execution.
#[cfg(test)]
pub(crate) struct TestDatabaseGuard {
    path: std::path::PathBuf,
}

#[cfg(test)]
impl Drop for TestDatabaseGuard {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let path = if suffix.is_empty() {
                self.path.clone()
            } else {
                std::path::PathBuf::from(format!("{}{}", self.path.display(), suffix))
            };
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
pub(crate) fn unique_test_database() -> (String, Arc<TestDatabaseGuard>) {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "recoverbull-test-{}-{}-{}.sqlite3",
        std::process::id(),
        count,
        nanos
    ));
    let url = path.to_string_lossy().into_owned();
    (url, Arc::new(TestDatabaseGuard { path }))
}

/// Validates the security-critical configuration values.
///
/// A non-positive rate-limit cooldown would silently disable rate-limiting
/// entirely (the cooldown check would always be elapsed), and a zero
/// max_attempts or secret_max_length makes the service unusable.
/// The server must refuse to start rather than run degraded.
pub fn validate_config(
    rate_limit_cooldown: i64,
    secret_max_length: usize,
    rate_limit_max_failed_attempts: u8,
) -> Result<(), String> {
    if rate_limit_cooldown <= 0 {
        return Err(format!(
            "RATE_LIMIT_COOLDOWN must be greater than 0, got {}",
            rate_limit_cooldown
        ));
    }
    // chrono::TimeDelta panics on out-of-range values; keep the cooldown
    // within a sane range (at most one year in minutes).
    if rate_limit_cooldown > 525_600 {
        return Err(format!(
            "RATE_LIMIT_COOLDOWN must be at most 525600 minutes (1 year), got {}",
            rate_limit_cooldown
        ));
    }
    if secret_max_length == 0 {
        return Err("SECRET_MAX_LENGTH must be greater than 0".to_string());
    }
    if rate_limit_max_failed_attempts == 0 {
        return Err("RATE_LIMIT_MAX_FAILED_ATTEMPTS must be at least 1".to_string());
    }
    Ok(())
}

/// Upper bound for the in-memory rate-limit map. Each entry costs roughly
/// 150-180 bytes; the planned worst case is the 100,000 default (~20 MB).
/// 10 million entries (~2 GB) is already absurd for this service — beyond
/// that, the operator is better served by a startup error than by a silent
/// memory-exhaustion kill.
pub const MAX_RATE_LIMIT_IDENTIFIERS: usize = 10_000_000;

/// Upper bound for concurrent SQLite blocking operations. SQLite serializes
/// writers anyway and tokio's blocking pool defaults to 512 threads, so
/// anything beyond 1024 permits cannot be exercised and only hides
/// misconfiguration.
pub const MAX_DATABASE_CONCURRENCY: usize = 1024;

/// Validates the resource-capacity configuration values. Zero disables the
/// protection entirely; absurdly large values disable it silently. The
/// server must refuse to start rather than run unbounded.
pub fn validate_capacity(
    rate_limit_max_identifiers: usize,
    database_max_concurrency: usize,
) -> Result<(), String> {
    if rate_limit_max_identifiers == 0 || rate_limit_max_identifiers > MAX_RATE_LIMIT_IDENTIFIERS {
        return Err(format!(
            "RATE_LIMIT_MAX_IDENTIFIERS must be between 1 and {}, got {}",
            MAX_RATE_LIMIT_IDENTIFIERS, rate_limit_max_identifiers
        ));
    }
    if database_max_concurrency == 0 || database_max_concurrency > MAX_DATABASE_CONCURRENCY {
        return Err(format!(
            "DATABASE_MAX_CONCURRENCY must be between 1 and {}, got {}",
            MAX_DATABASE_CONCURRENCY, database_max_concurrency
        ));
    }
    Ok(())
}

/// Validates a token-bucket configuration (burst capacity and refill rate).
///
/// The burst must be finite and strictly positive, or the bucket could never
/// hold any token. The refill rate must be finite and non-negative (zero
/// disables refilling but is otherwise a valid, deliberately strict bucket).
pub fn validate_token_bucket(name: &str, burst: f64, refill: f64) -> Result<(), String> {
    if !burst.is_finite() || burst <= 0.0 {
        return Err(format!(
            "{name}_RATE_LIMIT_BURST must be finite and > 0, got {burst}"
        ));
    }
    if !refill.is_finite() || refill < 0.0 {
        return Err(format!(
            "{name}_RATE_LIMIT_REFILL_PER_SECOND must be finite and >= 0, got {refill}"
        ));
    }
    Ok(())
}

/// Validates the `/attempts` snapshot TTL: zero would force a fresh snapshot
/// computation on every request, defeating the point of caching.
pub fn validate_snapshot_ttl(seconds: u64) -> Result<(), String> {
    if seconds == 0 {
        return Err("ATTEMPTS_SNAPSHOT_TTL_SECONDS must be greater than 0".to_string());
    }
    Ok(())
}

/// Live state of the warrant canary in the dotenv file.
pub enum CanaryFileState {
    /// The file holds a CANARY key (possibly an empty value).
    Value(String),
    /// The file parses but holds no CANARY key: the operator deliberately
    /// removed the warrant canary — this IS the compromise signal and must
    /// not be masked by a fallback.
    Removed,
    /// The file is missing or unreadable: an ops error, not a signal.
    /// Callers fall back to the startup value to avoid a false alarm.
    Unavailable,
}

/// Re-reads the canary state from the dotenv file, so an operator can update
/// or remove the warrant canary by editing the file without restarting the
/// server (env::var alone would never see the edit: dotenvy loads the file
/// only at startup).
pub fn canary_file_state(path: &std::path::Path) -> CanaryFileState {
    let Ok(iter) = dotenvy::from_path_iter(path) else {
        return CanaryFileState::Unavailable;
    };
    for item in iter {
        match item {
            Ok((key, value)) if key == "CANARY" => return CanaryFileState::Value(value),
            Ok(_) => continue,
            Err(_) => return CanaryFileState::Unavailable,
        }
    }
    CanaryFileState::Removed
}

/// Cached result of the last successful `canary_file_state` parse, keyed by
/// the file metadata it was read under. `value` mirrors `CanaryFileState`,
/// collapsed to an `Option` since `Unavailable` is never cached (there is
/// nothing stable to key it on, and it must always fall back to the
/// startup value rather than to stale cached content).
pub struct CachedCanary {
    modified: std::time::SystemTime,
    len: u64,
    value: Option<String>,
}

/// Same contract as `canary_file_state`, but skips re-parsing the dotenv
/// file when its metadata (modification time and length) is unchanged since
/// the last read. `/info` has no rate limit by design, so without this cache
/// every request would re-read and re-parse the file from disk.
pub fn canary_file_state_cached(
    path: &std::path::Path,
    cache: &mut Option<CachedCanary>,
) -> CanaryFileState {
    let Ok(metadata) = std::fs::metadata(path) else {
        return CanaryFileState::Unavailable;
    };
    let modified = metadata
        .modified()
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let len = metadata.len();

    if let Some(cached) = cache.as_ref() {
        if cached.modified == modified && cached.len == len {
            return match &cached.value {
                Some(value) => CanaryFileState::Value(value.clone()),
                None => CanaryFileState::Removed,
            };
        }
    }

    let state = canary_file_state(path);
    match &state {
        CanaryFileState::Value(value) => {
            *cache = Some(CachedCanary {
                modified,
                len,
                value: Some(value.clone()),
            });
        }
        CanaryFileState::Removed => {
            *cache = Some(CachedCanary {
                modified,
                len,
                value: None,
            });
        }
        // The file vanished or became unreadable between the metadata call
        // above and the parse: leave the previous cache entry untouched.
        CanaryFileState::Unavailable => {}
    }
    state
}

pub fn init() -> AppState {
    // Whether CANARY comes from the process environment must be known before
    // dotenv loads the file: dotenvy never overrides an existing variable.
    // An environment-provided canary is authoritative (file edits are
    // ignored); a file-provided canary follows the file at request time.
    let canary_from_env = env::var("CANARY").is_ok();
    // dotenv() returns the path of the file it loaded, which may be in a
    // parent directory: keep it as the live canary source.
    let dotenv_path = dotenv().ok();

    let server_addr: String = env::var("SERVER_ADDRESS").expect("SERVER_ADDRESS must be set");
    let rate_limit_cooldown =
        env::var("RATE_LIMIT_COOLDOWN").expect("RATE_LIMIT_COOLDOWN must be set");
    let secret_max_length = env::var("SECRET_MAX_LENGTH").expect("SECRET_MAX_LENGTH must be set");
    let canary = env::var("CANARY").expect("CANARY must be set");
    let (rate_limit_max_failed_attempts_name, rate_limit_max_failed_attempts) = match env::var(
        "RATE_LIMIT_MAX_FAILED_ATTEMPTS",
    ) {
        Ok(value) => ("RATE_LIMIT_MAX_FAILED_ATTEMPTS", value),
        Err(env::VarError::NotPresent) => match env::var("RATE_LIMIT_MAX_FAILED_ATTEMPTS") {
            Ok(value) => {
                #[cfg(not(test))]
                eprintln!(
                        "Warning: RATE_LIMIT_MAX_FAILED_ATTEMPTS is deprecated; use RATE_LIMIT_MAX_FAILED_ATTEMPTS"
                    );
                ("RATE_LIMIT_MAX_FAILED_ATTEMPTS", value)
            }
            Err(env::VarError::NotPresent) => panic!("RATE_LIMIT_MAX_FAILED_ATTEMPTS must be set"),
            Err(error) => panic!("cannot read RATE_LIMIT_MAX_FAILED_ATTEMPTS: {error}"),
        },
        Err(error) => panic!("cannot read RATE_LIMIT_MAX_FAILED_ATTEMPTS: {error}"),
    };

    #[cfg(test)]
    let (database_url, test_database_guard) = {
        // TEST_DATABASE_URL is fully optional and, if set, deliberately
        // ignored here: every call must get its own unique path so that
        // tests never share a database file, including under cargo test's
        // parallel execution within the same process.
        unique_test_database()
    };
    #[cfg(not(test))]
    let database_url = { env::var("DATABASE_URL").expect("DATABASE_URL must be set") };

    let rate_limit_cooldown = match rate_limit_cooldown.parse::<i64>() {
        Ok(number) => number,
        Err(e) => {
            println!("Error: RATE_LIMIT_COOLDOWN must be a integer: {}", e);
            std::process::exit(1);
        }
    };

    let secret_max_length = match secret_max_length.parse::<usize>() {
        Ok(number) => number,
        Err(e) => {
            println!("Error: SECRET_MAX_LENGTH must be a usize: {}", e);
            std::process::exit(1);
        }
    };

    let rate_limit_max_failed_attempts = match rate_limit_max_failed_attempts.parse::<u8>() {
        Ok(number) => number,
        Err(e) => {
            println!("Error: {rate_limit_max_failed_attempts_name} must be a u8: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = validate_config(
        rate_limit_cooldown,
        secret_max_length,
        rate_limit_max_failed_attempts,
    ) {
        println!("Error: {}", e);
        std::process::exit(1);
    }

    // Global write damper (optional, with defaults). Behind an onion
    // service per-IP limiting is useless, so the bucket is global.
    let store_rate_limit_burst: f64 = optional_env("STORE_RATE_LIMIT_BURST", 10.0);
    let store_rate_limit_refill: f64 = optional_env("STORE_RATE_LIMIT_REFILL_PER_SECOND", 2.0);
    if let Err(e) = validate_token_bucket("STORE", store_rate_limit_burst, store_rate_limit_refill)
    {
        println!("Error: {e}");
        std::process::exit(1);
    }

    // A second global bucket bounds identifier spraying and database reads.
    // It is deliberately independent from the per-identifier security budget.
    let lookup_rate_limit_burst: f64 = optional_env("LOOKUP_RATE_LIMIT_BURST", 100.0);
    let lookup_rate_limit_refill: f64 = optional_env("LOOKUP_RATE_LIMIT_REFILL_PER_SECOND", 5.0);
    if let Err(e) =
        validate_token_bucket("LOOKUP", lookup_rate_limit_burst, lookup_rate_limit_refill)
    {
        println!("Error: {e}");
        std::process::exit(1);
    }

    let rate_limit_max_identifiers = optional_env("RATE_LIMIT_MAX_IDENTIFIERS", 100_000usize);
    let database_max_concurrency = optional_env("DATABASE_MAX_CONCURRENCY", 16usize);
    if let Err(e) = validate_capacity(rate_limit_max_identifiers, database_max_concurrency) {
        println!("Error: {}", e);
        std::process::exit(1);
    }

    // `/attempts` serves a cached snapshot; this third bucket bounds direct
    // cache-bypass traffic without consuming lookup tokens needed for
    // recovery. The reverse-proxy cache absorbs the normal read volume.
    let attempts_rate_limit_burst: f64 = optional_env("ATTEMPTS_RATE_LIMIT_BURST", 20.0);
    let attempts_rate_limit_refill: f64 =
        optional_env("ATTEMPTS_RATE_LIMIT_REFILL_PER_SECOND", 2.0);
    if let Err(e) = validate_token_bucket(
        "ATTEMPTS",
        attempts_rate_limit_burst,
        attempts_rate_limit_refill,
    ) {
        println!("Error: {e}");
        std::process::exit(1);
    }

    let attempts_snapshot_ttl_seconds = optional_env("ATTEMPTS_SNAPSHOT_TTL_SECONDS", 60u64);
    if let Err(e) = validate_snapshot_ttl(attempts_snapshot_ttl_seconds) {
        println!("Error: {e}");
        std::process::exit(1);
    }

    AppState {
        server_address: server_addr,
        database_url,
        #[cfg(test)]
        _test_database_guard: test_database_guard,
        canary,
        canary_from_env,
        canary_path: dotenv_path.unwrap_or_else(|| std::path::PathBuf::from(".env")),
        canary_cache: Arc::new(Mutex::new(None)),
        rate_limit_cooldown: Duration::minutes(rate_limit_cooldown as i64),
        identifier_rate_limit: Arc::new(Mutex::new(HashMap::new())),
        secret_max_length,
        rate_limit_max_failed_attempts,
        store_token_bucket: Arc::new(Mutex::new(crate::rate_limit::TokenBucket::new(
            store_rate_limit_burst,
            store_rate_limit_refill,
        ))),
        lookup_token_bucket: Arc::new(Mutex::new(crate::rate_limit::TokenBucket::new(
            lookup_rate_limit_burst,
            lookup_rate_limit_refill,
        ))),
        attempts_token_bucket: Arc::new(Mutex::new(crate::rate_limit::TokenBucket::new(
            attempts_rate_limit_burst,
            attempts_rate_limit_refill,
        ))),
        rate_limit_max_identifiers,
        database_semaphore: Arc::new(Semaphore::new(database_max_concurrency)),
        attempts_collection_started_at: chrono::Utc::now(),
        attempts_snapshot: Arc::new(Mutex::new(None)),
        attempts_snapshot_ttl: std::time::Duration::from_secs(attempts_snapshot_ttl_seconds),
    }
}
