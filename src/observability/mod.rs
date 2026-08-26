//! Privacy-preserving counters and quota-controlled request diagnostics.
pub(crate) mod counters;
pub(crate) mod diagnostic;

use std::sync::Arc;

pub(crate) use counters::SecurityCounters;
pub(crate) use diagnostic::LogQuota;

#[derive(Clone)]
/// Shared observability owners cloned by handlers and background reporters.
pub(crate) struct ObservabilityState {
    pub(crate) counters: Arc<SecurityCounters>,
    pub(crate) log_quota: Arc<LogQuota>,
}

impl ObservabilityState {
    /// Creates fresh counters and independent diagnostic quotas.
    pub(crate) fn new() -> Self {
        Self {
            counters: Arc::new(SecurityCounters::default()),
            log_quota: diagnostic::new_quota(),
        }
    }
}
