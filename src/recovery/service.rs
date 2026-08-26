//! Recovery use cases between HTTP extraction and concrete storage.

use super::identifiers::{generate_secret_id, identifier_hash, is_256bits_hex_hash};
use crate::{
    attempts::{
        ledger::{Admission, AttemptsLedgerState, LookupOutcome, ReservationGuard},
        AttemptStatus,
    },
    rate_limit::TokenBucket,
    security_counters::SecurityCounters,
    storage::sqlite::{NewStoredSecret, SqliteStorage, StorageError, StoredSecret},
};
use base64::Engine;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Primitive store input crossing the HTTP/recovery boundary.
pub(crate) struct StoreCommand {
    pub(crate) identifier: String,
    pub(crate) authentication_key: String,
    pub(crate) encrypted_secret: String,
}

/// Primitive lookup input crossing the HTTP/recovery boundary.
pub(crate) struct LookupCommand {
    pub(crate) identifier: String,
    pub(crate) authentication_key: String,
}

#[derive(Clone, Copy)]
pub(crate) enum LookupKind {
    Fetch,
    /// Destructive lookup: the storage operation reads and deletes in one transaction.
    Trash,
}

pub(crate) enum StoreResult {
    Stored,
    Invalid(String),
    GlobalOverload,
    DatabaseBusy,
    DatabaseError,
}

pub(crate) enum LookupResult {
    Invalid,
    GlobalOverload,
    Capacity,
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
        secret: Option<StoredSecret>,
        attempt_status: AttemptStatus,
        requested_at: DateTime<Utc>,
        cooldown_minutes: i64,
    },
}

#[derive(Clone)]
/// Owns recovery orchestration while keeping HTTP and Diesel outside the
/// domain boundary; detached workers retain cancellation responsibility.
pub(crate) struct RecoveryService {
    store_bucket: Arc<Mutex<TokenBucket>>,
    lookup_bucket: Arc<Mutex<TokenBucket>>,
    ledger: AttemptsLedgerState,
    storage: SqliteStorage,
    counters: Arc<SecurityCounters>,
    max_secret_length: usize,
    cooldown: chrono::TimeDelta,
    max_attempts: u8,
    max_identifiers: usize,
}

impl RecoveryService {
    pub(crate) fn new(
        store_bucket: Arc<Mutex<TokenBucket>>,
        lookup_bucket: Arc<Mutex<TokenBucket>>,
        ledger: AttemptsLedgerState,
        storage: SqliteStorage,
        counters: Arc<SecurityCounters>,
        max_secret_length: usize,
        cooldown: chrono::TimeDelta,
        max_attempts: u8,
        max_identifiers: usize,
    ) -> Self {
        Self {
            store_bucket,
            lookup_bucket,
            ledger,
            storage,
            counters,
            max_secret_length,
            cooldown,
            max_attempts,
            max_identifiers,
        }
    }

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
    pub(crate) fn set_max_identifiers_for_test(&mut self, max: usize) {
        self.max_identifiers = max;
    }

    #[cfg(test)]
    pub(crate) fn set_max_attempts_for_test(&mut self, max: u8) {
        self.max_attempts = max;
    }

    #[cfg(test)]
    pub(crate) fn set_database_semaphore_for_test(
        &mut self,
        semaphore: Arc<tokio::sync::Semaphore>,
    ) {
        self.storage.set_semaphore_for_test(semaphore);
    }

    #[cfg(test)]
    pub(crate) fn set_database_url_for_test(&mut self, database_url: String) {
        self.storage.set_database_url_for_test(database_url);
    }

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
        let admission = self
            .ledger
            .admit(
                id_hash.clone(),
                candidate.clone(),
                requested_at,
                self.max_attempts,
                self.max_identifiers,
                self.cooldown,
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
                let retry_after_secs = (last_candidate_at + self.cooldown - requested_at)
                    .num_seconds()
                    .max(1) as u64;
                LookupResult::RateLimited {
                    count,
                    requested_at: last_candidate_at,
                    retry_after_secs,
                    cooldown_minutes: self.cooldown.num_minutes(),
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
        let task_ledger = self.ledger.clone();
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
                    self.ledger.refund(&id_hash, &candidate, generation).await;
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
                cooldown_minutes: self.cooldown.num_minutes(),
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
