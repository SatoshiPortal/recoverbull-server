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
    rate_limit::{BucketDecision, TokenBucket},
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
    /// HTTP identifier supplied for secret_id derivation.
    pub(crate) identifier: String,
    /// HTTP authentication key supplied for secret_id derivation.
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
    /// The global store bucket had no token; the backoff is the bucket's
    /// own estimate of its next token.
    GlobalOverload { retry_after_secs: u64 },
    /// A database lease could not be acquired before its deadline.
    DatabaseBusy,
    /// The detached database operation failed.
    DatabaseError,
}

/// Domain outcomes mapped by handlers to deliberately coarse HTTP responses.
pub(crate) enum LookupResult {
    /// Input failed canonical hash validation.
    Invalid,
    /// The global lookup bucket had no token; the backoff is the bucket's
    /// own estimate of its next token.
    GlobalOverload {
        retry_after_secs: u64,
    },
    /// The identifier map reached its configured capacity.
    Capacity,
    /// An identical secret_id is currently being processed.
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
        /// Attempt counters for the current secret_id window.
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
        if let BucketDecision::Rejected { retry_after_secs } =
            self.store_bucket.lock().await.try_consume()
        {
            self.counters.store_rejected();
            return StoreResult::GlobalOverload { retry_after_secs };
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

    /// Admits a fetch or trash secret_id and returns a transport-neutral
    /// outcome after bounded storage work and ledger finalization.
    pub(crate) async fn lookup(&self, request: LookupCommand, kind: LookupKind) -> LookupResult {
        let identifier = request.identifier.to_lowercase();
        let authentication_key = request.authentication_key.to_lowercase();
        if !is_256bits_hex_hash(&identifier) || !is_256bits_hex_hash(&authentication_key) {
            return LookupResult::Invalid;
        }
        if let BucketDecision::Rejected { retry_after_secs } =
            self.lookup_bucket.lock().await.try_consume()
        {
            self.counters.lookup_rate_limited();
            return LookupResult::GlobalOverload { retry_after_secs };
        }
        let id_hash = identifier_hash(&identifier).expect("validated hex identifier");
        let secret_id = generate_secret_id(&identifier, &authentication_key);
        let requested_at = Utc::now();
        // Lookup proceeds through global throttling, ledger admission, a
        // bounded SQLite lease, then generation finalization and counters.
        let admission = self
            .attempts
            .ledger
            .admit(
                id_hash.clone(),
                secret_id.clone(),
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
                last_secret_id_at,
            } => {
                self.counters.lookup_target_lockout();
                let retry_after_secs = (last_secret_id_at + self.attempts.policy.cooldown()
                    - requested_at)
                    .num_seconds()
                    .max(1) as u64;
                LookupResult::RateLimited {
                    count,
                    requested_at: last_secret_id_at,
                    retry_after_secs,
                    cooldown_minutes: self.attempts.policy.cooldown().num_minutes(),
                }
            }
            Admission::Pending => {
                self.counters.lookup_rate_limited();
                LookupResult::Pending
            }
            Admission::Replay { status, generation } => {
                self.run_lookup(
                    generation,
                    None,
                    id_hash,
                    secret_id,
                    requested_at,
                    status,
                    kind,
                )
                .await
            }
            Admission::New {
                status,
                generation,
                reservation,
            } => {
                self.run_lookup(
                    generation,
                    Some(reservation),
                    id_hash,
                    secret_id,
                    requested_at,
                    status,
                    kind,
                )
                .await
            }
        }
    }

    /// Runs the storage operation for an admitted secret_id. `reservation` is
    /// `Some` for a new secret_id and `None` for a committed replay; the
    /// generation is carried in both cases so that a replayed `/trash` can
    /// forget its `secret_id` without touching a replacement window.
    #[allow(clippy::too_many_arguments)]
    async fn run_lookup(
        &self,
        generation: DateTime<Utc>,
        mut reservation: Option<ReservationGuard>,
        id_hash: String,
        secret_id: String,
        requested_at: DateTime<Utc>,
        attempt_status: AttemptStatus,
        kind: LookupKind,
    ) -> LookupResult {
        let reserved = reservation.is_some();
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
        let task_secret_id = secret_id.clone();
        let operation_secret_id = task_secret_id.clone();
        // Once this task is spawned, it owns the lease, blocking operation and
        // generation finalization even if the HTTP handler is cancelled.
        let task = tokio::spawn(async move {
            let database_result = tokio::task::spawn_blocking(move || match kind {
                LookupKind::Fetch => operation.fetch(operation_secret_id.clone()),
                LookupKind::Trash => operation.trash(operation_secret_id.clone()),
            })
            .await;
            let final_result = match database_result {
                Ok(result) => result,
                Err(_) => Err(StorageError::Database),
            };
            let outcome = match (&final_result, kind) {
                (Ok(Some(_)), LookupKind::Trash) => LookupOutcome::Deleted,
                (Ok(Some(_)), LookupKind::Fetch) => LookupOutcome::Hit,
                (Ok(None), _) => LookupOutcome::Miss,
                (Err(_), _) => LookupOutcome::Error,
            };
            if reserved {
                task_ledger
                    .finalize(&task_id_hash, &task_secret_id, generation, outcome)
                    .await;
            } else if outcome == LookupOutcome::Deleted {
                // A committed replay that deleted the row: the `secret_id` must not
                // stay recognizable after the deletion it authenticated.
                task_ledger
                    .forget_committed(&task_id_hash, &task_secret_id, generation)
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
                if reserved {
                    self.attempts
                        .ledger
                        .refund(&id_hash, &secret_id, generation)
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
