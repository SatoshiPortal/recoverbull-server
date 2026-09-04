//! Application state assembly and the shared runtime owners used by every route.
//!
//! The state is intentionally composed from cloneable handles: cloning the
//! outer value shares semaphores, ledgers, counters, and cancellation-aware
//! workers rather than duplicating their limits or mutable collections.

use crate::{
    attempts::{AttemptsPolicy, AttemptsState},
    config::ValidatedConfig,
    observability::SecurityCounters,
    recovery::service::RecoveryService,
    storage::sqlite::SqliteStorage,
};
#[cfg(test)]
use std::ops::Deref;
use std::{path::PathBuf, sync::Arc};

/// How long a canary value read from the dotenv file is reused.
///
/// The canary is a signal a human acts on over hours or days, so re-reading
/// the file on every `/info` request bought nothing and made the only
/// unbucketed public route do filesystem work per request — which is why it
/// needed a dedicated permit and a blocking worker to stay safe. One read
/// per interval removes both. `/info` advertises the remaining freshness, so
/// a proxy or client cache cannot stack a second staleness window on top of
/// this one.
pub(crate) const CANARY_REREAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Clone)]
/// State needed by `/info`, including the canary source and its freshness.
pub(crate) struct InfoState {
    canary: String,
    canary_from_env: bool,
    canary_path: Arc<std::sync::RwLock<PathBuf>>,
    /// Last resolved canary and when it was read, or `None` before the first
    /// read. Guarded by a `std::sync::Mutex` because the critical section is
    /// a clone and never spans an await.
    cached_canary: Arc<std::sync::Mutex<Option<(String, std::time::Instant)>>>,
    canary_reread_interval: std::time::Duration,
    secret_max_length: usize,
    policy: AttemptsPolicy,
    counters: Arc<SecurityCounters>,
}

#[derive(Clone)]
/// Public server settings retained separately from subsystem configuration.
pub(crate) struct AppConfig {
    /// Loopback listener address configured for the process.
    pub(crate) server_address: String,
}

#[derive(Clone)]
/// Complete application graph shared with Axum handlers by clone-on-state.
pub(crate) struct AppState {
    components: AppComponents,
}

/// Internal application graph. Its fields are visible only to test builds so
/// production handlers cannot bypass the narrow AppState capability methods.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct AppComponents {
    pub(crate) config: AppConfig,
    pub(crate) storage: SqliteStorage,
    pub(crate) recovery: RecoveryService,
    pub(crate) attempts: AttemptsState,
    pub(crate) info: InfoState,
    pub(crate) counters: Arc<SecurityCounters>,
}

#[cfg(not(test))]
#[derive(Clone)]
struct AppComponents {
    config: AppConfig,
    storage: SqliteStorage,
    recovery: RecoveryService,
    attempts: AttemptsState,
    info: InfoState,
    counters: Arc<SecurityCounters>,
}

#[cfg(test)]
impl Deref for AppState {
    type Target = AppComponents;

    /// Explicit test-only access to component seams; no production equivalent exists.
    fn deref(&self) -> &Self::Target {
        &self.components
    }
}

#[cfg(test)]
impl std::ops::DerefMut for AppState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.components
    }
}

/// Composes the shared application owners from validated configuration.
pub(crate) fn build(config: ValidatedConfig) -> AppState {
    // Each subsystem is built once; clones below share ownership handles so
    // handlers, detached recovery work, and background tasks observe one state.
    let storage = SqliteStorage::from_config(config.storage);
    let attempts = AttemptsState::new(config.attempts);
    let counters = Arc::new(SecurityCounters::default());
    let info = InfoState::new(
        &config.info,
        config.recovery.secret_max_length,
        attempts.policy(),
        counters.clone(),
    );
    let recovery = RecoveryService::new(
        config.recovery,
        attempts.clone(),
        storage.clone(),
        counters.clone(),
    );
    AppState {
        components: AppComponents {
            config: AppConfig {
                server_address: config.server_address,
            },
            storage,
            recovery,
            attempts,
            info,
            counters,
        },
    }
}

impl AppState {
    /// Returns the validated listener address without exposing configuration
    /// or subsystem ownership to request handlers.
    pub(crate) fn server_address(&self) -> &str {
        &self.components.config.server_address
    }

    /// Performs the startup-only SQLite capability and migration checks.
    pub(crate) fn initialize_storage(
        &self,
    ) -> Result<(), crate::storage::sqlite::ConnectionSetupError> {
        self.components.storage.initialize()
    }

    /// Clones the aggregate counter owner for the HTTP layer.
    pub(crate) fn counters(&self) -> Arc<SecurityCounters> {
        self.components.counters.clone()
    }

    /// Starts the fixed-window aggregate security counter reporter.
    pub(crate) fn spawn_security_reporter(&self, period: std::time::Duration) {
        crate::observability::counters::spawn_reporter(self.components.counters.clone(), period);
    }

    /// Starts the production wipe task and returns its lifecycle handle.
    pub(crate) fn spawn_production_wiper(&self) -> tokio::task::JoinHandle<()> {
        crate::attempts::maintenance::spawn_production_wiper(
            self.components.attempts.ledger.clone(),
            self.components.attempts.snapshot.clone(),
        )
    }

    /// Returns the only capability available to store/fetch/trash handlers.
    pub(crate) fn recovery_service(&self) -> &RecoveryService {
        &self.components.recovery
    }

    /// Returns the read-only operational information capability for `/info`.
    pub(crate) fn info_state(&self) -> &InfoState {
        &self.components.info
    }

    /// Applies the global telemetry request bucket and records rejection using
    /// aggregate counters, without exposing either owner to the handler. A
    /// rejection carries the bucket's own backoff estimate.
    pub(crate) async fn attempts_request_admission(&self) -> crate::rate_limit::BucketDecision {
        let decision = self
            .components
            .attempts
            .maintenance
            .try_consume_request()
            .await;
        if matches!(decision, crate::rate_limit::BucketDecision::Rejected { .. }) {
            self.components.counters.attempts_rate_limited();
        }
        decision
    }

    /// Builds or clones the public telemetry representation behind its domain
    /// boundary, without exposing the admission ledger to the handler. A
    /// failed build is counted here: `/attempts` carries a negative signal, so
    /// its failure must reach the unconditional counter window rather than
    /// only the quota-bounded per-request diagnostics.
    pub(crate) async fn attempts_snapshot(
        &self,
    ) -> Result<crate::attempts::snapshot::AttemptsSnapshotCache, ()> {
        let result = self
            .components
            .attempts
            .snapshot
            .snapshot_for_request(
                &self.components.attempts.ledger,
                self.components.attempts.policy.cooldown(),
            )
            .await;
        if result.is_err() {
            self.components.counters.attempts_snapshot_failed();
        }
        result
    }

    /// Returns the cache lifetime remaining for an emitted snapshot.
    pub(crate) fn attempts_max_age(&self, created_at: std::time::Instant) -> u64 {
        self.components
            .attempts
            .snapshot
            .remaining_max_age(created_at)
    }

    /// Returns the current telemetry collection boundary for `/info`.
    pub(crate) async fn attempts_collection_started_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.components
            .attempts
            .snapshot
            .collection_started_at()
            .await
    }
}

#[cfg(test)]
/// Test-only state constructor; this seam is excluded from release builds.
pub(crate) fn init() -> AppState {
    build(crate::config::init())
}

impl InfoState {
    /// Creates the information view while sharing policy and counters.
    fn new(
        config: &crate::config::InfoConfig,
        secret_max_length: usize,
        policy: AttemptsPolicy,
        counters: Arc<SecurityCounters>,
    ) -> Self {
        Self {
            canary: config.canary.clone(),
            canary_from_env: config.canary_from_env,
            canary_path: Arc::new(std::sync::RwLock::new(config.canary_path.clone())),
            cached_canary: Arc::new(std::sync::Mutex::new(None)),
            canary_reread_interval: CANARY_REREAD_INTERVAL,
            secret_max_length,
            policy,
            counters,
        }
    }
    /// Returns the authoritative process canary, or the dotenv canary read at
    /// most once per interval, applying the documented fallback semantics.
    ///
    /// The file semantics are the signal and do not change: a `CANARY` key
    /// serves its value, a readable file without that key serves an empty
    /// string (the deliberate compromise signal, never masked by the
    /// fallback), and an unreadable file serves the startup value and counts
    /// `canary_unavailable`. What changed is only how often the file is
    /// consulted.
    pub(crate) fn current_canary(&self) -> String {
        if self.canary_from_env {
            return self.canary.clone();
        }
        if let Some(fresh) = self.fresh_canary() {
            return fresh;
        }
        let path = self.canary_path.read().expect("canary path lock").clone();
        let value = match crate::config::canary_file_state(&path) {
            crate::config::CanaryFileState::Value(value) => value,
            crate::config::CanaryFileState::Removed => String::new(),
            crate::config::CanaryFileState::Unavailable => {
                self.counters.canary_unavailable();
                self.canary.clone()
            }
        };
        *self.cached_canary.lock().expect("canary cache lock") =
            Some((value.clone(), std::time::Instant::now()));
        value
    }

    /// Returns the cached canary while it is inside the re-read interval, and
    /// the freshness a response may advertise.
    fn fresh_canary(&self) -> Option<String> {
        let cached = self.cached_canary.lock().expect("canary cache lock");
        cached
            .as_ref()
            .filter(|(_, read_at)| read_at.elapsed() < self.canary_reread_interval)
            .map(|(value, _)| value.clone())
    }

    /// Seconds a client may reuse an `/info` response: what remains of the
    /// canary's freshness, so caching cannot make the signal older than one
    /// re-read interval. Zero when the process canary is authoritative,
    /// because then only a restart can change it.
    pub(crate) fn canary_max_age(&self) -> u64 {
        if self.canary_from_env {
            return 0;
        }
        let elapsed = self
            .cached_canary
            .lock()
            .expect("canary cache lock")
            .as_ref()
            .map(|(_, read_at)| read_at.elapsed())
            .unwrap_or(self.canary_reread_interval);
        self.canary_reread_interval
            .saturating_sub(elapsed)
            .as_secs()
    }
    /// Returns the configured maximum encrypted payload length.
    pub(crate) fn secret_max_length(&self) -> usize {
        self.secret_max_length
    }
    /// Returns the shared attempts policy view used by `/info`.
    pub(crate) fn policy(&self) -> &AttemptsPolicy {
        &self.policy
    }
    #[cfg(test)]
    /// Test-only observation seam; excluded from release builds.
    pub(crate) fn canary_for_test(&self) -> &str {
        &self.canary
    }
    #[cfg(test)]
    /// Test-only canary-source seam; excluded from release builds.
    pub(crate) fn set_canary_from_env_for_test(&mut self, value: bool) {
        self.canary_from_env = value;
    }
    #[cfg(test)]
    /// Test-only canary-path seam; excluded from release builds.
    pub(crate) fn set_canary_path_for_test(&self, path: PathBuf) {
        *self.canary_path.write().unwrap() = path;
    }
    #[cfg(test)]
    /// Test-only freshness seam: zero re-reads the file on every request, so
    /// a test can assert the file semantics without waiting out the
    /// production interval. Excluded from release builds.
    pub(crate) fn set_canary_reread_interval_for_test(&mut self, interval: std::time::Duration) {
        self.canary_reread_interval = interval;
    }
}
