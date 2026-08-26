//! Recovery use cases between HTTP extraction and concrete storage.

use super::identifiers::{generate_secret_id, identifier_hash, is_256bits_hex_hash};
use crate::{
    attempts::AttemptsState,
    attempts::{
        ledger::{Admission, LookupOutcome, ReservationGuard},
        AttemptStatus,
    },
    config::RecoveryConfig,
    observability::SecurityCounters,
    rate_limit::TokenBucket,
    storage::sqlite::{NewStoredSecret, SqliteStorage, StorageError, StoredSecret},
};
use base64::Engine;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Primitive store input crossing the HTTP/recovery boundary.
pub(crate) struct StoreCommand {
    /// HTTP identifier, canonicalized before admission.
    pub(crate) identifier: String,
    /// HTTP authentication key, canonicalized before derivation.
    pub(crate) authentication_key: String,
    /// Base64-encoded encrypted payload; `created_at` is generated internally.
    pub(crate) encrypted_secret: String,
}

/// Primitive lookup input crossing the HTTP/recovery boundary.
pub(crate) struct LookupCommand {
    /// HTTP identifier supplied for candidate derivation.
    pub(crate) identifier: String,
    /// HTTP authentication key supplied for candidate derivation.
    pub(crate) authentication_key: String,
}

#[derive(Clone, Copy)]
/// Selects read-only fetch or transactional destructive trash semantics.
pub(crate) enum LookupKind {
    Fetch,
    /// Destructive lookup: the storage operation reads and deletes in one transaction.
    Trash,
}

pub(crate) enum StoreResult {
    /// The secret was accepted and written idempotently.
    Stored,
    /// Input failed validation, with a client-safe explanation.
    Invalid(String),
    /// The global store bucket had no token.
    GlobalOverload,
    /// A database lease could not be acquired before its deadline.
    DatabaseBusy,
    /// The detached database operation failed.
    DatabaseError,
}

/// Domain outcomes mapped by handlers to deliberately coarse HTTP responses.
pub(crate) enum LookupResult {
    /// Input failed canonical hash validation.
    Invalid,
    /// The global lookup bucket had no token.
    GlobalOverload,
    /// The identifier map reached its configured capacity.
    Capacity,
    /// An identical candidate is currently being processed.
    Pending,
    RateLimited {
        count: u8,
        requested_at: DateTime<Utc>,
        retry_after_secs: u64,
        cooldown_minutes: i64,
    },
    DatabaseBusy,
    DatabaseError,
    Completed {
        /// Secret when credentials matched; `None` is a uniform miss.
        secret: Option<StoredSecret>,
        /// Attempt counters for the current candidate window.
        attempt_status: AttemptStatus,
        /// Time at which this lookup was admitted.
        requested_at: DateTime<Utc>,
        /// Configured retry window in minutes.
        cooldown_minutes: i64,
    },
}

#[derive(Clone)]
/// Owns recovery orchestration while keeping HTTP and Diesel outside the
/// domain boundary; detached workers retain cancellation responsibility.
pub(crate) struct RecoveryService {
    store_bucket: Arc<Mutex<TokenBucket>>,
    lookup_bucket: Arc<Mutex<TokenBucket>>,
    attempts: AttemptsState,
    storage: SqliteStorage,
    counters: Arc<SecurityCounters>,
    max_secret_length: usize,
}

impl RecoveryService {
    /// Builds recovery owners while keeping Axum and Diesel at their boundaries.
    pub(crate) fn new(
        config: RecoveryConfig,
        attempts: AttemptsState,
        storage: SqliteStorage,
        counters: Arc<SecurityCounters>,
    ) -> Self {
        Self {
            store_bucket: Arc::new(Mutex::new(TokenBucket::new(
                config.store_rate_limit_burst,
                config.store_rate_limit_refill,
            ))),
            lookup_bucket: Arc::new(Mutex::new(TokenBucket::new(
                config.lookup_rate_limit_burst,
                config.lookup_rate_limit_refill,
            ))),
            attempts,
            storage,
            counters,
            max_secret_length: config.secret_max_length,
        }
    }

    /// Validates and canonicalizes a store command, applies the global write
    /// limit, and transfers an opaque storage lease to blocking work.
    pub(crate) async fn store(&self, request: StoreCommand) -> StoreResult {
        let authentication_key = request.authentication_key.to_lowercase();
        let identifier = request.identifier.to_lowercase();
        let encrypted_secret = request.encrypted_secret;
        if !is_256bits_hex_hash(&identifier) || !is_256bits_hex_hash(&authentication_key) {
            self.counters.store_rejected();
            return StoreResult::Invalid(
                "identifier or authentication_key are not 256 bits HEX hashes".to_owned(),
            );
        }
        if encrypted_secret.is_empty() {
            self.counters.store_rejected();
            return StoreResult::Invalid("encrypted_secret is empty".to_owned());
        }
        if encrypted_secret.len() > self.max_secret_length {
            self.counters.store_rejected();
            return StoreResult::Invalid(format!(
                "encrypted_secret length exceeds the limit {}",
                self.max_secret_length
            ));
        }
        if !is_base64(&encrypted_secret) {
            self.counters.store_rejected();
            return StoreResult::Invalid("encrypted_secret should be base64 encoded".to_owned());
        }
        if !self.store_bucket.lock().await.try_consume() {
            self.counters.store_rejected();
            return StoreResult::GlobalOverload;
        }
        let secret = NewStoredSecret {
            id: generate_secret_id(&identifier, &authentication_key),
            created_at: Utc::now().to_rfc3339(),
            encrypted_secret,
        };
        // Validation and global admission precede the database lease. Once the
        // lease is moved into the detached worker, cancellation cannot abandon
        // the operation or its accounting.
        let operation = match self.storage.acquire().await {
            Ok(operation) => operation,
            Err(_) => {
                self.counters.database_busy();
                return StoreResult::DatabaseBusy;
            }
        };
        let counters = self.counters.clone();
        // The outer task owns the counter update so dropping the handler future
        // cannot cancel the operation after its permit was transferred.
        let task = tokio::spawn(async move {
            match tokio::task::spawn_blocking(move || operation.store(secret)).await {
                Ok(Ok(())) => {
                    counters.store_accepted();
                    StoreResult::Stored
                }
                Ok(Err(_)) => {
                    counters.database_error();
                    StoreResult::DatabaseError
                }
                Err(_) => {
                    counters.database_error();
                    StoreResult::DatabaseError
                }
            }
        });
        match task.await {
            Ok(result) => result,
            Err(_) => {
                self.counters.database_error();
                StoreResult::DatabaseError
            }
        }
    }

    #[cfg(test)]
    /// Test-only map-capacity seam; excluded from release builds.
    pub(crate) fn set_max_identifiers_for_test(&mut self, max: usize) {
        self.attempts.policy.set_max_identifiers_for_test(max);
    }

    #[cfg(test)]
    /// Test-only attempt-limit seam; excluded from release builds.
    pub(crate) fn set_max_attempts_for_test(&mut self, max: u8) {
        self.attempts.policy.set_max_attempts_for_test(max);
    }

    #[cfg(test)]
    /// Test-only database semaphore seam; excluded from release builds.
    pub(crate) fn set_database_semaphore_for_test(
        &mut self,
        semaphore: Arc<tokio::sync::Semaphore>,
    ) {
        self.storage.set_semaphore_for_test(semaphore);
    }

    #[cfg(test)]
    /// Test-only database URL seam; excluded from release builds.
    pub(crate) fn set_database_url_for_test(&mut self, database_url: String) {
        self.storage.set_database_url_for_test(database_url);
    }
    #[cfg(test)]
    /// Test-only semaphore observation seam; excluded from release builds.
    pub(crate) fn database_semaphore_for_test(&self) -> Arc<tokio::sync::Semaphore> {
        self.storage.database_semaphore_for_test()
    }
    #[cfg(test)]
    /// Test-only initialization seam; excluded from release builds.
    pub(crate) fn initialize_for_test(
        &self,
    ) -> Result<(), crate::storage::sqlite::ConnectionSetupError> {
        self.storage.initialize()
    }
    #[cfg(test)]
    /// Test-only store-bucket seam; excluded from release builds.
    pub(crate) async fn set_store_bucket_for_test(&self, bucket: TokenBucket) {
        *self.store_bucket.lock().await = bucket;
    }
    #[cfg(test)]
    /// Test-only lookup-bucket seam; excluded from release builds.
    pub(crate) async fn set_lookup_bucket_for_test(&self, bucket: TokenBucket) {
        *self.lookup_bucket.lock().await = bucket;
    }
    #[cfg(test)]
    /// Test-only configuration observation seam; excluded from release builds.
    pub(crate) fn max_secret_length(&self) -> usize {
        self.max_secret_length
    }

    /// Admits a fetch or trash candidate and returns a transport-neutral
    /// outcome after bounded storage work and ledger finalization.
    pub(crate) async fn lookup(&self, request: LookupCommand, kind: LookupKind) -> LookupResult {
        let identifier = request.identifier.to_lowercase();
        let authentication_key = request.authentication_key.to_lowercase();
        if !is_256bits_hex_hash(&identifier) || !is_256bits_hex_hash(&authentication_key) {
            return LookupResult::Invalid;
        }
        if !self.lookup_bucket.lock().await.try_consume() {
            self.counters.lookup_rate_limited();
            return LookupResult::GlobalOverload;
        }
        let id_hash = identifier_hash(&identifier).expect("validated hex identifier");
        let candidate = generate_secret_id(&identifier, &authentication_key);
        let requested_at = Utc::now();
        // Lookup proceeds through global throttling, ledger admission, a
        // bounded SQLite lease, then generation finalization and counters.
        let admission = self
            .attempts
            .ledger
            .admit(
                id_hash.clone(),
                candidate.clone(),
                requested_at,
                self.attempts.policy.max_attempts(),
                self.attempts.policy.max_identifiers(),
                self.attempts.policy.cooldown(),
            )
            .await;
        match admission {
            Admission::Saturated {} => {
                self.counters.lookup_map_capacity();
                LookupResult::Capacity
            }
            Admission::RateLimited {
                count,
                last_candidate_at,
            } => {
                self.counters.lookup_target_lockout();
                let retry_after_secs = (last_candidate_at + self.attempts.policy.cooldown()
                    - requested_at)
                    .num_seconds()
                    .max(1) as u64;
                LookupResult::RateLimited {
                    count,
                    requested_at: last_candidate_at,
                    retry_after_secs,
                    cooldown_minutes: self.attempts.policy.cooldown().num_minutes(),
                }
            }
            Admission::Pending => {
                self.counters.lookup_rate_limited();
                LookupResult::Pending
            }
            Admission::Replay {
                status,
                generation: _generation,
            } => {
                self.run_lookup(None, id_hash, candidate, requested_at, status, kind)
                    .await
            }
            Admission::New {
                status,
                generation,
                reservation,
            } => {
                self.run_lookup(
                    Some((generation, reservation)),
                    id_hash,
                    candidate,
                    requested_at,
                    status,
                    kind,
                )
                .await
            }
        }
    }

    async fn run_lookup(
        &self,
        reservation: Option<(DateTime<Utc>, ReservationGuard)>,
        id_hash: String,
        candidate: String,
        requested_at: DateTime<Utc>,
        attempt_status: AttemptStatus,
        kind: LookupKind,
    ) -> LookupResult {
        let (generation, mut reservation) = match reservation {
            Some(value) => (Some(value.0), Some(value.1)),
            None => (None, None),
        };
        // A detached task receives both the opaque permit and reservation
        // finalization responsibility; only its JoinHandle is awaited here.
        let operation = match self.storage.acquire().await {
            Ok(operation) => operation,
            Err(_) => {
                if let Some(guard) = reservation.as_mut() {
                    guard.refund().await;
                }
                self.counters.database_busy();
                return LookupResult::DatabaseBusy;
            }
        };
        let task_ledger = self.attempts.ledger.clone();
        let task_counters = self.counters.clone();
        let task_id_hash = id_hash.clone();
        let task_candidate = candidate.clone();
        let operation_candidate = task_candidate.clone();
        // Once this task is spawned, it owns the lease, blocking operation and
        // generation finalization even if the HTTP handler is cancelled.
        let task = tokio::spawn(async move {
            let database_result = tokio::task::spawn_blocking(move || match kind {
                LookupKind::Fetch => operation.fetch(operation_candidate.clone()),
                LookupKind::Trash => operation.trash(operation_candidate.clone()),
            })
            .await;
            let final_result = match database_result {
                Ok(result) => result,
                Err(_) => Err(StorageError::Database),
            };
            if let Some(generation) = generation {
                let outcome = match &final_result {
                    Ok(Some(_)) => LookupOutcome::Hit,
                    Ok(None) => LookupOutcome::Miss,
                    Err(_) => LookupOutcome::Error,
                };
                task_ledger
                    .finalize(&task_id_hash, &task_candidate, generation, outcome)
                    .await;
            }
            match &final_result {
                Ok(Some(_)) => {
                    task_counters.lookup_accepted();
                    if matches!(kind, LookupKind::Trash) {
                        task_counters.trash_hit();
                    } else {
                        task_counters.fetch_hit();
                    }
                }
                Ok(None) => {
                    task_counters.lookup_accepted();
                    if matches!(kind, LookupKind::Trash) {
                        task_counters.trash_miss();
                    } else {
                        task_counters.fetch_miss();
                    }
                }
                Err(_) => task_counters.database_error(),
            }
            final_result
        });
        if let Some(guard) = reservation.take() {
            guard.transfer();
        }
        let result = match task.await {
            Ok(result) => result,
            Err(_) => {
                if let Some(generation) = generation {
                    self.attempts
                        .ledger
                        .refund(&id_hash, &candidate, generation)
                        .await;
                }
                self.counters.database_error();
                return LookupResult::DatabaseError;
            }
        };
        match result {
            Ok(secret) => LookupResult::Completed {
                secret,
                attempt_status,
                requested_at,
                cooldown_minutes: self.attempts.policy.cooldown().num_minutes(),
            },
            Err(_) => LookupResult::DatabaseError,
        }
    }
}

fn is_base64(input: &str) -> bool {
    if !input.len().is_multiple_of(4) {
        return false;
    }
    base64::prelude::BASE64_STANDARD.decode(input).is_ok()
}
