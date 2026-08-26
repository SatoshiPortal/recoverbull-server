use crate::{
    attempts::{AttemptsPolicy, AttemptsState},
    config::ValidatedConfig,
    observability::ObservabilityState,
    recovery::service::RecoveryService,
    storage::sqlite::SqliteStorage,
};
#[cfg(test)]
use std::ops::Deref;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub(crate) struct InfoState {
    canary: String,
    canary_from_env: bool,
    canary_path: Arc<std::sync::RwLock<PathBuf>>,
    canary_read_semaphore: Arc<Semaphore>,
    secret_max_length: usize,
    policy: AttemptsPolicy,
    counters: Arc<crate::observability::SecurityCounters>,
}

#[derive(Clone)]
pub(crate) struct AppConfig {
    pub(crate) server_address: String,
}

#[derive(Clone)]
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
    pub(crate) observability: ObservabilityState,
}

#[cfg(not(test))]
#[derive(Clone)]
struct AppComponents {
    config: AppConfig,
    storage: SqliteStorage,
    recovery: RecoveryService,
    attempts: AttemptsState,
    info: InfoState,
    observability: ObservabilityState,
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
    let storage = SqliteStorage::from_config(config.storage);
    let attempts = AttemptsState::new(config.attempts);
    let observability = ObservabilityState::new();
    let info = InfoState::new(
        &config.info,
        config.recovery.secret_max_length,
        attempts.policy(),
        observability.counters.clone(),
    );
    let recovery = RecoveryService::new(
        config.recovery,
        attempts.clone(),
        storage.clone(),
        observability.counters.clone(),
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
            observability,
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

    /// Clones the privacy-safe state consumed by the HTTP diagnostics adapter.
    pub(crate) fn request_diagnostics_state(&self) -> ObservabilityState {
        self.components.observability.clone()
    }

    /// Starts the fixed-window aggregate security counter reporter.
    pub(crate) fn spawn_security_reporter(&self, period: std::time::Duration) {
        crate::observability::counters::spawn_reporter(
            self.components.observability.clone(),
            period,
        );
    }

    /// Starts expiry maintenance without exposing the ledger to the process
    /// entry point or to request handlers.
    pub(crate) fn spawn_attempts_sweeper(&self) {
        crate::attempts::maintenance::spawn_sweeper(
            self.components.attempts.ledger.clone(),
            self.components.attempts.policy.cooldown(),
        );
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
    /// aggregate counters, without exposing either owner to the handler.
    pub(crate) async fn attempts_request_admitted(&self) -> bool {
        let admitted = self
            .components
            .attempts
            .maintenance
            .try_consume_request()
            .await;
        if !admitted {
            self.components
                .observability
                .counters
                .attempts_rate_limited();
        }
        admitted
    }

    /// Builds or clones the public telemetry representation behind its domain
    /// boundary, without exposing the admission ledger to the handler.
    pub(crate) async fn attempts_snapshot(
        &self,
    ) -> Result<crate::attempts::snapshot::AttemptsSnapshotCache, ()> {
        self.components
            .attempts
            .snapshot
            .snapshot_for_request(
                &self.components.attempts.ledger,
                self.components.attempts.policy.cooldown(),
            )
            .await
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
pub(crate) fn init() -> AppState {
    build(crate::config::init())
}

impl InfoState {
    fn new(
        config: &crate::config::InfoConfig,
        secret_max_length: usize,
        policy: AttemptsPolicy,
        counters: Arc<crate::observability::SecurityCounters>,
    ) -> Self {
        Self {
            canary: config.canary.clone(),
            canary_from_env: config.canary_from_env,
            canary_path: Arc::new(std::sync::RwLock::new(config.canary_path.clone())),
            canary_read_semaphore: Arc::new(Semaphore::new(1)),
            secret_max_length,
            policy,
            counters,
        }
    }
    pub(crate) async fn current_canary(&self) -> String {
        if self.canary_from_env {
            return self.canary.clone();
        }
        let permit = match self.canary_read_semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return self.canary.clone(),
        };
        let path = self.canary_path.read().expect("canary path lock").clone();
        let state = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            crate::config::canary_file_state(&path)
        })
        .await
        .unwrap_or(crate::config::CanaryFileState::Unavailable);
        match state {
            crate::config::CanaryFileState::Value(value) => value,
            crate::config::CanaryFileState::Removed => String::new(),
            crate::config::CanaryFileState::Unavailable => {
                self.counters.canary_unavailable();
                self.canary.clone()
            }
        }
    }
    pub(crate) fn secret_max_length(&self) -> usize {
        self.secret_max_length
    }
    pub(crate) fn policy(&self) -> &AttemptsPolicy {
        &self.policy
    }
    #[cfg(test)]
    pub(crate) fn canary_for_test(&self) -> &str {
        &self.canary
    }
    #[cfg(test)]
    pub(crate) fn set_canary_from_env_for_test(&mut self, value: bool) {
        self.canary_from_env = value;
    }
    #[cfg(test)]
    pub(crate) fn set_canary_path_for_test(&self, path: PathBuf) {
        *self.canary_path.write().unwrap() = path;
    }
    #[cfg(test)]
    pub(crate) fn canary_read_semaphore_for_test(&self) -> Arc<Semaphore> {
        self.canary_read_semaphore.clone()
    }
    #[cfg(test)]
    pub(crate) fn set_canary_read_semaphore_for_test(&mut self, semaphore: Arc<Semaphore>) {
        self.canary_read_semaphore = semaphore;
    }
}
