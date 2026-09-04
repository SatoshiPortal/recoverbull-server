//! Saturating security counters and their fixed-shape reporting snapshot.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Default)]
/// Concurrent counters that never wrap on overflow.
pub struct SecurityCounters {
    store_accepted: AtomicU64,
    store_rejected: AtomicU64,
    lookup_accepted: AtomicU64,
    lookup_rate_limited: AtomicU64,
    lookup_target_lockout: AtomicU64,
    lookup_map_capacity: AtomicU64,
    fetch_hit: AtomicU64,
    fetch_miss: AtomicU64,
    trash_hit: AtomicU64,
    trash_miss: AtomicU64,
    attempts_rate_limited: AtomicU64,
    /// Snapshot builds that failed to produce a representation. Emitted in
    /// the unconditional five-minute window, so a broken telemetry subsystem
    /// is visible even when per-request diagnostics are starved or off.
    attempts_snapshot_failed: AtomicU64,
    /// Requests the router cut at its timeout. Every `503` this server
    /// returns is counted somewhere, because none of them is ever logged.
    request_timeout: AtomicU64,
    database_busy: AtomicU64,
    database_error: AtomicU64,
    timing_floor_overrun: AtomicU64,
    canary_unavailable: AtomicU64,
}

fn saturating_increment(counter: &AtomicU64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current == u64::MAX {
            return;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(next) => current = next,
        }
    }
}

macro_rules! counter_methods {
    ($($name:ident),+ $(,)?) => { $(
        /// Increments this metric with saturation at `u64::MAX`.
        pub fn $name(&self) { saturating_increment(&self.$name); }
    )+ };
}

impl SecurityCounters {
    counter_methods!(
        store_accepted,
        store_rejected,
        lookup_accepted,
        lookup_rate_limited,
        lookup_target_lockout,
        lookup_map_capacity,
        fetch_hit,
        fetch_miss,
        trash_hit,
        trash_miss,
        attempts_rate_limited,
        attempts_snapshot_failed,
        request_timeout,
        database_busy,
        database_error,
        timing_floor_overrun,
        canary_unavailable,
    );

    #[cfg(test)]
    pub(crate) fn set_database_error_for_test(&self, value: u64) {
        self.database_error.store(value, Ordering::Relaxed);
    }

    /// Resets one reporting window and returns its fixed-shape values.
    pub fn flush(&self) -> CounterSnapshot {
        CounterSnapshot {
            store_accepted: self.store_accepted.swap(0, Ordering::Relaxed),
            store_rejected: self.store_rejected.swap(0, Ordering::Relaxed),
            lookup_accepted: self.lookup_accepted.swap(0, Ordering::Relaxed),
            lookup_rate_limited: self.lookup_rate_limited.swap(0, Ordering::Relaxed),
            lookup_target_lockout: self.lookup_target_lockout.swap(0, Ordering::Relaxed),
            lookup_map_capacity: self.lookup_map_capacity.swap(0, Ordering::Relaxed),
            fetch_hit: self.fetch_hit.swap(0, Ordering::Relaxed),
            fetch_miss: self.fetch_miss.swap(0, Ordering::Relaxed),
            trash_hit: self.trash_hit.swap(0, Ordering::Relaxed),
            trash_miss: self.trash_miss.swap(0, Ordering::Relaxed),
            attempts_rate_limited: self.attempts_rate_limited.swap(0, Ordering::Relaxed),
            attempts_snapshot_failed: self.attempts_snapshot_failed.swap(0, Ordering::Relaxed),
            request_timeout: self.request_timeout.swap(0, Ordering::Relaxed),
            database_busy: self.database_busy.swap(0, Ordering::Relaxed),
            database_error: self.database_error.swap(0, Ordering::Relaxed),
            timing_floor_overrun: self.timing_floor_overrun.swap(0, Ordering::Relaxed),
            canary_unavailable: self.canary_unavailable.swap(0, Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
/// Values atomically drained from one reporting window.
pub struct CounterSnapshot {
    pub store_accepted: u64,
    pub store_rejected: u64,
    pub lookup_accepted: u64,
    pub lookup_rate_limited: u64,
    pub lookup_target_lockout: u64,
    pub lookup_map_capacity: u64,
    pub fetch_hit: u64,
    pub fetch_miss: u64,
    pub trash_hit: u64,
    pub trash_miss: u64,
    pub attempts_rate_limited: u64,
    pub attempts_snapshot_failed: u64,
    pub request_timeout: u64,
    pub database_busy: u64,
    pub database_error: u64,
    pub timing_floor_overrun: u64,
    pub canary_unavailable: u64,
}

/// Spawns a detached reporter that drains counters at each bounded interval.
pub(crate) fn spawn_reporter(counters: Arc<SecurityCounters>, period: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        loop {
            interval.tick().await;
            report_once(&counters);
        }
    });
}

/// Drains and emits one privacy-safe counter window. This line is emitted at
/// `info` unconditionally and is the only aggregate view of activity, so a
/// signal that must survive log-volume pressure belongs in a counter here
/// rather than in a per-request line.
pub(crate) fn report_once(counters: &SecurityCounters) {
    let snapshot = counters.flush();
    tracing::info!(
        target: "security_counters",
        store_accepted = snapshot.store_accepted,
        store_rejected = snapshot.store_rejected,
        lookup_accepted = snapshot.lookup_accepted,
        lookup_rate_limited = snapshot.lookup_rate_limited,
        lookup_target_lockout = snapshot.lookup_target_lockout,
        lookup_map_capacity = snapshot.lookup_map_capacity,
        fetch_hit = snapshot.fetch_hit,
        fetch_miss = snapshot.fetch_miss,
        trash_hit = snapshot.trash_hit,
        trash_miss = snapshot.trash_miss,
        attempts_rate_limited = snapshot.attempts_rate_limited,
        attempts_snapshot_failed = snapshot.attempts_snapshot_failed,
        request_timeout = snapshot.request_timeout,
        database_busy = snapshot.database_busy,
        database_error = snapshot.database_error,
        timing_floor_overrun = snapshot.timing_floor_overrun,
        canary_unavailable = snapshot.canary_unavailable,
        "security counter window"
    );
}
