//! Environment loading, validation, and typed configuration passed to owners.
//!
//! Initialization reads required values, applies compatibility fallbacks, then
//! validates limits in dependency order before constructing subsystem configs.

use dotenvy::dotenv;
#[cfg(test)]
use std::sync::Arc;
use std::{env, fmt::Display, str::FromStr};

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
/// Every test calls `app::init()`, so each test gets its own SQLite file:
/// without this, all tests shared a single file and ran into each other's
/// data under `cargo test`'s parallel execution.
#[cfg(test)]
/// Test-only lifetime guard for an isolated SQLite database and its sidecars;
/// `cfg(test)` excludes this parallel-test seam from release builds.
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
/// Test-only unique database allocation; each guard removes SQLite sidecars on drop.
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
    rate_limit_max_attempts: u8,
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
    if rate_limit_max_attempts == 0 {
        return Err("RATE_LIMIT_MAX_ATTEMPTS must be at least 1".to_string());
    }
    Ok(())
}

/// Peak process bytes one rate-limit entry costs, excluding the part that
/// scales with the candidate budget.
///
/// Measured, not estimated: a release build filling the ledger and then
/// building one `/attempts` snapshot costs 1121-1254 peak bytes per entry
/// between 10,000 and 100,000 entries at `RATE_LIMIT_MAX_ATTEMPTS=3`
/// (100,000 entries reached 117 MB peak RSS, with a 4.01 MB gzip body — the
/// same gzip size the audit recorded in the README). The constant is rounded
/// up so the model stays conservative.
///
/// It covers the map slot, the 64-byte `id_hash` allocation, the snapshot
/// projection, the JSON serialization buffer and its growth, and the gzip
/// encoder. See `docs/DEPLOYMENT.md` for the measurement procedure.
pub const RATE_LIMIT_BYTES_PER_IDENTIFIER: usize = 1_100;

/// Peak process bytes each retained CandidateTag adds to an entry.
///
/// A CandidateTag is a 64-character `String` in a per-entry `HashMap`, so an
/// entry's cost grows with `RATE_LIMIT_MAX_ATTEMPTS`: measured at 147 bytes
/// per candidate between 10 and 255 candidates, rounded up here. Ignoring
/// this term is what made the previous fixed ceiling meaningless — at the
/// u8 maximum budget an entry costs about 38 kB, not a few hundred bytes.
pub const RATE_LIMIT_BYTES_PER_CANDIDATE: usize = 150;

/// Process memory the capacity model deliberately leaves unclaimed: the base
/// process, SQLite connections and page cache, Tokio worker stacks, and the
/// serving path. The budget an operator declares is the whole-process limit
/// (their cgroup `MemoryMax`), so the identifier map may only use what
/// remains after this reserve.
pub const PROCESS_MEMORY_RESERVE_BYTES: usize = 64 * 1024 * 1024;

/// Default whole-process memory budget, aligned with `MemoryMax=512M` in
/// `deploy/systemd/recoverbull.service`.
pub const DEFAULT_MEMORY_BUDGET_MB: usize = 512;

/// cgroup v1 writes this sentinel instead of a word for "no limit"; v2 writes
/// the literal `max`. Anything at or above it is not a real limit.
const CGROUP_V1_UNLIMITED: usize = 0x7FFF_FFFF_FFFF_F000;

/// Parses one cgroup memory-limit file, returning `None` when it declares no
/// limit. `max` is the cgroup v2 spelling; v1 uses a sentinel close to
/// `i64::MAX`. Unparsable content is treated as "no limit" so an unexpected
/// kernel format degrades to the operator's declared budget rather than to a
/// bogus ceiling.
pub fn parse_memory_limit(raw: &str) -> Option<usize> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "max" {
        return None;
    }
    match raw.parse::<usize>() {
        Ok(limit) if limit > 0 && limit < CGROUP_V1_UNLIMITED => Some(limit),
        _ => None,
    }
}

/// Returns the smallest memory limit the kernel will actually enforce on this
/// process, or `None` when none is discoverable.
///
/// A limit set on any ancestor applies too, so the v2 hierarchy is walked from
/// this process's own cgroup up to the root and the minimum is kept. Every
/// read is best-effort: an unreadable or absent file simply contributes no
/// constraint.
pub fn detected_memory_limit_bytes() -> Option<usize> {
    let own = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let mut limit: Option<usize> = None;
    let mut consider = |path: std::path::PathBuf| {
        if let Some(found) = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| parse_memory_limit(&raw))
        {
            limit = Some(limit.map_or(found, |current: usize| current.min(found)));
        }
    };

    for line in own.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(_id), Some(controllers), Some(cgroup_path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let relative = cgroup_path.trim_start_matches('/');
        if controllers.is_empty() {
            // cgroup v2: one unified hierarchy, and an ancestor's limit binds.
            let mut current = std::path::PathBuf::from("/sys/fs/cgroup");
            consider(current.join("memory.max"));
            for component in relative.split('/').filter(|part| !part.is_empty()) {
                current.push(component);
                consider(current.join("memory.max"));
            }
        } else if controllers.split(',').any(|name| name == "memory") {
            // cgroup v1: the memory controller has its own mount point.
            consider(
                std::path::Path::new("/sys/fs/cgroup/memory")
                    .join(relative)
                    .join("memory.limit_in_bytes"),
            );
        }
    }
    limit
}

/// Combines the operator's declared budget with the enforced limit.
///
/// The smaller wins. Declaring 512 MiB while the cgroup enforces 256 MiB must
/// not authorize a capacity sized for 512 MiB — that is exactly the
/// memory-exhaustion kill the check exists to prevent, and a declared value
/// cannot be trusted to stay synchronized with the unit file.
pub fn effective_memory_budget_bytes(
    declared_bytes: usize,
    detected_bytes: Option<usize>,
) -> usize {
    match detected_bytes {
        Some(detected) => declared_bytes.min(detected),
        None => declared_bytes,
    }
}

/// Upper bound for concurrent SQLite blocking operations. SQLite serializes
/// writers anyway and tokio's blocking pool defaults to 512 threads, so
/// anything beyond 1024 permits cannot be exercised and only hides
/// misconfiguration.
pub const MAX_DATABASE_CONCURRENCY: usize = 1024;

/// Estimated peak bytes for a capacity and candidate budget, or `None` when
/// the product overflows `usize` (which is itself over any real budget).
pub fn estimated_peak_memory_bytes(
    rate_limit_max_identifiers: usize,
    rate_limit_max_attempts: u8,
) -> Option<usize> {
    RATE_LIMIT_BYTES_PER_CANDIDATE
        .checked_mul(usize::from(rate_limit_max_attempts))?
        .checked_add(RATE_LIMIT_BYTES_PER_IDENTIFIER)?
        .checked_mul(rate_limit_max_identifiers)
}

/// Largest capacity whose estimated peak fits the declared budget.
pub fn max_identifiers_within_budget(
    rate_limit_max_attempts: u8,
    memory_budget_bytes: usize,
) -> usize {
    let per_entry = RATE_LIMIT_BYTES_PER_IDENTIFIER.saturating_add(
        RATE_LIMIT_BYTES_PER_CANDIDATE.saturating_mul(usize::from(rate_limit_max_attempts)),
    );
    memory_budget_bytes
        .saturating_sub(PROCESS_MEMORY_RESERVE_BYTES)
        .checked_div(per_entry)
        .unwrap_or(0)
}

/// Validates the resource-capacity configuration against an explicit memory
/// budget.
///
/// Zero disables a protection entirely. An oversized capacity used to be
/// rejected against a fixed 10,000,000-entry ceiling justified by a
/// per-entry cost that was low by an order of magnitude, so the ceiling
/// admitted configurations that produce exactly the silent
/// memory-exhaustion kill it claimed to prevent — 10,000,000 entries cost
/// about 15 GB at the documented candidate budget, not the ~2 GB claimed,
/// against a 512 MB `MemoryMax`. The bound is therefore derived from the
/// operator's declared budget and the measured per-entry cost, and it
/// accounts for `RATE_LIMIT_MAX_ATTEMPTS`, which the fixed ceiling ignored.
pub fn validate_capacity(
    rate_limit_max_identifiers: usize,
    database_max_concurrency: usize,
    rate_limit_max_attempts: u8,
    memory_budget_bytes: usize,
) -> Result<(), String> {
    if rate_limit_max_identifiers == 0 {
        return Err(format!(
            "RATE_LIMIT_MAX_IDENTIFIERS must be at least 1, got {}",
            rate_limit_max_identifiers
        ));
    }
    if database_max_concurrency == 0 || database_max_concurrency > MAX_DATABASE_CONCURRENCY {
        return Err(format!(
            "DATABASE_MAX_CONCURRENCY must be between 1 and {}, got {}",
            MAX_DATABASE_CONCURRENCY, database_max_concurrency
        ));
    }
    let reserve_mb = PROCESS_MEMORY_RESERVE_BYTES / (1024 * 1024);
    let available = memory_budget_bytes
        .checked_sub(PROCESS_MEMORY_RESERVE_BYTES)
        .filter(|available| *available > 0)
        .ok_or_else(|| {
            format!(
                "RATE_LIMIT_MEMORY_BUDGET_MB must exceed the {} MiB process reserve, got {} MiB",
                reserve_mb,
                memory_budget_bytes / (1024 * 1024)
            )
        })?;
    estimated_peak_memory_bytes(rate_limit_max_identifiers, rate_limit_max_attempts)
        .filter(|required| *required <= available)
        .ok_or_else(|| {
            format!(
                "RATE_LIMIT_MAX_IDENTIFIERS={} with RATE_LIMIT_MAX_ATTEMPTS={} needs about {} MiB \
                 at snapshot peak, over the {} MiB available from an effective memory budget of \
                 {} MiB (the lower of RATE_LIMIT_MEMORY_BUDGET_MB and the enforced cgroup limit) \
                 after the {} MiB process reserve; lower the capacity to at most {}, lower the \
                 candidate budget, or raise both the cgroup limit and the declared budget",
                rate_limit_max_identifiers,
                rate_limit_max_attempts,
                estimated_peak_memory_bytes(rate_limit_max_identifiers, rate_limit_max_attempts)
                    .map_or("more than usize::MAX".to_string(), |bytes| (bytes
                        / (1024 * 1024))
                        .to_string()),
                available / (1024 * 1024),
                memory_budget_bytes / (1024 * 1024),
                reserve_mb,
                max_identifiers_within_budget(rate_limit_max_attempts, memory_budget_bytes),
            )
        })?;
    Ok(())
}

/// Validates a token-bucket configuration (burst capacity and refill rate).
///
/// The burst must be finite and at least one token. It must also survive the
/// first subtraction in f64 without rounding back to the original capacity.
/// The refill rate must be finite and non-negative (zero disables refilling but
/// is otherwise a valid, deliberately strict bucket).
pub fn validate_token_bucket(name: &str, burst: f64, refill: f64) -> Result<(), String> {
    if !burst.is_finite() || burst < 1.0 || burst - 1.0 == burst {
        return Err(format!(
            "{name}_RATE_LIMIT_BURST must be finite, represent at least one token, and change after consuming one token, got {burst}"
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

#[derive(Clone)]
/// Storage settings, including the bounded database concurrency owner.
pub(crate) struct StorageConfig {
    pub(crate) database_url: String,
    pub(crate) database_max_concurrency: usize,
    #[cfg(test)]
    pub(crate) test_database_guard: Arc<TestDatabaseGuard>,
}

#[derive(Clone)]
/// Recovery validation and global bucket settings.
pub(crate) struct RecoveryConfig {
    pub(crate) store_rate_limit_burst: f64,
    pub(crate) store_rate_limit_refill: f64,
    pub(crate) lookup_rate_limit_burst: f64,
    pub(crate) lookup_rate_limit_refill: f64,
    pub(crate) secret_max_length: usize,
}

#[derive(Clone)]
/// Attempt admission, map-capacity, and snapshot-cache settings.
pub(crate) struct AttemptsConfig {
    pub(crate) rate_limit_cooldown_minutes: i64,
    pub(crate) rate_limit_max_attempts: u8,
    pub(crate) rate_limit_max_identifiers: usize,
    pub(crate) attempts_rate_limit_burst: f64,
    pub(crate) attempts_rate_limit_refill: f64,
    pub(crate) snapshot_ttl: std::time::Duration,
}

#[derive(Clone)]
/// `/info` canary settings, including whether the process environment wins.
pub(crate) struct InfoConfig {
    pub(crate) canary: String,
    pub(crate) canary_from_env: bool,
    pub(crate) canary_path: std::path::PathBuf,
}

#[derive(Clone)]
/// Fully parsed and validated configuration used to build application state.
pub(crate) struct ValidatedConfig {
    pub(crate) server_address: String,
    pub(crate) storage: StorageConfig,
    pub(crate) recovery: RecoveryConfig,
    pub(crate) attempts: AttemptsConfig,
    pub(crate) info: InfoConfig,
}

/// Loads environment and dotenv configuration, validates every configured
/// bound, and returns the values consumed by the application owners.
pub fn init() -> ValidatedConfig {
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
    let (rate_limit_max_attempts_name, rate_limit_max_attempts) = match env::var(
        "RATE_LIMIT_MAX_ATTEMPTS",
    ) {
        Ok(value) => ("RATE_LIMIT_MAX_ATTEMPTS", value),
        Err(env::VarError::NotPresent) => match env::var("RATE_LIMIT_MAX_FAILED_ATTEMPTS") {
            Ok(value) => {
                #[cfg(not(test))]
                eprintln!(
                        "Warning: RATE_LIMIT_MAX_FAILED_ATTEMPTS is deprecated; use RATE_LIMIT_MAX_ATTEMPTS"
                    );
                ("RATE_LIMIT_MAX_FAILED_ATTEMPTS", value)
            }
            Err(env::VarError::NotPresent) => panic!("RATE_LIMIT_MAX_ATTEMPTS must be set"),
            Err(error) => panic!("cannot read RATE_LIMIT_MAX_FAILED_ATTEMPTS: {error}"),
        },
        Err(error) => panic!("cannot read RATE_LIMIT_MAX_ATTEMPTS: {error}"),
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

    let rate_limit_max_attempts = match rate_limit_max_attempts.parse::<u8>() {
        Ok(number) => number,
        Err(e) => {
            println!("Error: {rate_limit_max_attempts_name} must be a u8: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = validate_config(
        rate_limit_cooldown,
        secret_max_length,
        rate_limit_max_attempts,
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
    // The capacity bound is derived from a declared whole-process budget, so
    // an over-budget capacity fails at startup instead of being killed by the
    // cgroup once the map fills and a snapshot is built.
    let memory_budget_mb: usize =
        optional_env("RATE_LIMIT_MEMORY_BUDGET_MB", DEFAULT_MEMORY_BUDGET_MB);
    let declared_budget_bytes = memory_budget_mb.saturating_mul(1024 * 1024);
    // The declared budget is a statement of intent; the cgroup limit is what
    // the kernel will enforce. Trusting the declaration alone would leave the
    // check useless for an operator who lowered MemoryMax without lowering
    // the budget.
    let detected_limit_bytes = detected_memory_limit_bytes();
    let memory_budget_bytes =
        effective_memory_budget_bytes(declared_budget_bytes, detected_limit_bytes);
    #[cfg(not(test))]
    if let Some(detected) = detected_limit_bytes {
        if detected < declared_budget_bytes {
            eprintln!(
                "Warning: the enforced cgroup memory limit ({} MiB) is below \
                 RATE_LIMIT_MEMORY_BUDGET_MB ({} MiB); sizing capacity against the \
                 enforced limit",
                detected / (1024 * 1024),
                memory_budget_mb
            );
        }
    }
    if let Err(e) = validate_capacity(
        rate_limit_max_identifiers,
        database_max_concurrency,
        rate_limit_max_attempts,
        memory_budget_bytes,
    ) {
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

    ValidatedConfig {
        server_address: server_addr,
        storage: StorageConfig {
            database_url,
            database_max_concurrency,
            #[cfg(test)]
            test_database_guard,
        },
        recovery: RecoveryConfig {
            store_rate_limit_burst,
            store_rate_limit_refill,
            lookup_rate_limit_burst,
            lookup_rate_limit_refill,
            secret_max_length,
        },
        attempts: AttemptsConfig {
            rate_limit_cooldown_minutes: rate_limit_cooldown,
            rate_limit_max_attempts,
            rate_limit_max_identifiers,
            attempts_rate_limit_burst,
            attempts_rate_limit_refill,
            snapshot_ttl: std::time::Duration::from_secs(attempts_snapshot_ttl_seconds),
        },
        info: InfoConfig {
            canary,
            canary_from_env,
            canary_path: dotenv_path.unwrap_or_else(|| std::path::PathBuf::from(".env")),
        },
    }
}
