//! Attempt-domain values shared by lookup admission and telemetry.

use crate::config::AttemptsConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicI64, AtomicU8, AtomicUsize},
    Arc,
};

#[derive(Clone, Serialize, Deserialize)]
/// JSON-compatible attempt counters and hour-precision window timestamps.
pub(crate) struct AttemptStatus {
    /// The initial telemetry contract distinguishes candidate counters from
    /// request-counting semantics.
    pub(crate) version: u8,
    /// Total distinct candidates in the current window.
    pub(crate) total_attempts: u8,
    pub(crate) failed_attempts: u8,
    pub(crate) remaining_attempts: u8,
    pub(crate) total_requests: u64,
    pub(crate) window_started_at: DateTime<Utc>,
    /// Distinct candidate immediately preceding this request, if any.
    pub(crate) previous_attempt_at: Option<DateTime<Utc>>,
    pub(crate) resets_at: DateTime<Utc>,
}

pub(crate) mod ledger;
pub(crate) mod maintenance;
pub(crate) mod snapshot;

#[derive(Clone)]
/// Immutable-in-production policy handles shared by admission and `/info`.
/// Atomics exist solely so cfg(test) seams can adjust one shared policy.
pub(crate) struct AttemptsPolicy {
    cooldown_minutes: Arc<AtomicI64>,
    max_attempts: Arc<AtomicU8>,
    max_identifiers: Arc<AtomicUsize>,
}
impl AttemptsPolicy {
    /// Constructs policy atomics from validated startup configuration.
    fn new(config: &AttemptsConfig) -> Self {
        Self {
            cooldown_minutes: Arc::new(AtomicI64::new(config.rate_limit_cooldown_minutes)),
            max_attempts: Arc::new(AtomicU8::new(config.rate_limit_max_attempts)),
            max_identifiers: Arc::new(AtomicUsize::new(config.rate_limit_max_identifiers)),
        }
    }
    /// Returns the immutable production cooldown value.
    pub(crate) fn cooldown(&self) -> chrono::TimeDelta {
        chrono::TimeDelta::minutes(
            self.cooldown_minutes
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }
    /// Returns the maximum distinct candidates per identifier.
    pub(crate) fn max_attempts(&self) -> u8 {
        self.max_attempts.load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Returns the maximum number of identifiers retained in memory.
    pub(crate) fn max_identifiers(&self) -> usize {
        self.max_identifiers
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    /// Test-only policy seam; excluded from release builds.
    pub(crate) fn set_max_attempts_for_test(&self, value: u8) {
        self.max_attempts
            .store(value, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(test)]
    /// Test-only map-capacity seam; excluded from release builds.
    pub(crate) fn set_max_identifiers_for_test(&self, value: usize) {
        self.max_identifiers
            .store(value, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(test)]
    /// Test-only cooldown seam; excluded from release builds.
    pub(crate) fn set_cooldown_for_test(&self, value: chrono::TimeDelta) {
        self.cooldown_minutes
            .store(value.num_minutes(), std::sync::atomic::Ordering::Relaxed);
    }
}

#[derive(Clone)]
/// Shared attempt subsystem: policy, admission ledger, snapshot, and jobs.
pub(crate) struct AttemptsState {
    pub(crate) policy: AttemptsPolicy,
    pub(crate) ledger: ledger::AttemptsLedgerState,
    pub(crate) snapshot: snapshot::AttemptsSnapshotState,
    pub(crate) maintenance: maintenance::AttemptsMaintenanceState,
}
impl AttemptsState {
    /// Creates all attempt owners from validated configuration.
    pub(crate) fn new(config: AttemptsConfig) -> Self {
        Self {
            policy: AttemptsPolicy::new(&config),
            ledger: ledger::AttemptsLedgerState::new(),
            snapshot: snapshot::AttemptsSnapshotState::new(config.snapshot_ttl),
            maintenance: maintenance::AttemptsMaintenanceState::new(
                config.attempts_rate_limit_burst,
                config.attempts_rate_limit_refill,
            ),
        }
    }
    /// Clones the shared policy handles without copying mutable state.
    pub(crate) fn policy(&self) -> AttemptsPolicy {
        self.policy.clone()
    }
}
