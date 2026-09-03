//! `/attempts` admission throttling and retention tasks.

use super::{ledger::AttemptsLedgerState, snapshot::AttemptsSnapshotState};
use crate::rate_limit::TokenBucket;
use chrono::TimeDelta;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Owns the attempts-only request bucket; store and lookup buckets remain
/// owned by their callers through the generic `TokenBucket` type.
#[derive(Clone)]
pub(crate) struct AttemptsMaintenanceState {
    request_bucket: Arc<Mutex<TokenBucket>>,
}

impl AttemptsMaintenanceState {
    /// Creates the independent `/attempts` request bucket.
    pub(crate) fn new(capacity: f64, refill_per_second: f64) -> Self {
        Self {
            request_bucket: Arc::new(Mutex::new(TokenBucket::new(capacity, refill_per_second))),
        }
    }

    /// Attempts to consume one telemetry request token.
    pub(crate) async fn try_consume_request(&self) -> bool {
        self.request_bucket.lock().await.try_consume()
    }

    #[cfg(test)]
    /// Test-only bucket replacement for deterministic rate-limit assertions.
    pub(crate) async fn set_bucket_for_test(&self, bucket: TokenBucket) {
        *self.request_bucket.lock().await = bucket;
    }
}

const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// Production interval for the global in-memory telemetry wipe.
pub(crate) const PRODUCTION_GLOBAL_WIPE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

/// Clears expired ledger entries without retaining locks across logging.
pub(crate) async fn sweep_expired_identifiers(ledger: &AttemptsLedgerState, cooldown: TimeDelta) {
    ledger.retain_active(cooldown).await;
}

/// Clears identifiers, resets collection time, and invalidates the cache.
/// The owner preserves `cache -> map -> timestamp`; deadlines are explicit so
/// sweep and wipe work cannot hold locks while logging.
pub(crate) async fn wipe_identifier_rate_limit(
    ledger: &AttemptsLedgerState,
    snapshot: &AttemptsSnapshotState,
) {
    let count = snapshot
        .clear_and_reset_collection(ledger, chrono::Utc::now())
        .await;
    tracing::info!(target: "security", count, "daily telemetry wipe completed");
}

/// Computes the first wipe deadline without an immediate startup wipe.
pub(crate) fn global_wiper_first_deadline(
    now: tokio::time::Instant,
    period: std::time::Duration,
) -> tokio::time::Instant {
    now + period
}

/// Owns the detached periodic wiper task; the caller must retain its handle
/// and fail closed if it exits unexpectedly.
/// Spawns the detached periodic wipe task with the supplied deadline period.
pub(crate) fn spawn_global_wiper(
    ledger: AttemptsLedgerState,
    snapshot: AttemptsSnapshotState,
    period: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval_at(
            global_wiper_first_deadline(tokio::time::Instant::now(), period),
            period,
        );
        loop {
            interval.tick().await;
            wipe_identifier_rate_limit(&ledger, &snapshot).await;
        }
    })
}

/// Spawns the detached ten-minute expiry sweeper.
pub(crate) fn spawn_sweeper(ledger: AttemptsLedgerState, cooldown: TimeDelta) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            sweep_expired_identifiers(&ledger, cooldown).await;
        }
    });
}

/// Spawns the production daily wipe task.
pub(crate) fn spawn_production_wiper(
    ledger: AttemptsLedgerState,
    snapshot: AttemptsSnapshotState,
) -> tokio::task::JoinHandle<()> {
    spawn_global_wiper(ledger, snapshot, PRODUCTION_GLOBAL_WIPE_INTERVAL)
}
