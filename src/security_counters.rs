use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::AppState;

#[derive(Default)]
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
    database_busy: AtomicU64,
    database_error: AtomicU64,
    timing_floor_overrun: AtomicU64,
    canary_unavailable: AtomicU64,
    diagnostic_logs_emitted: AtomicU64,
    diagnostic_logs_suppressed: AtomicU64,
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
        database_busy,
        database_error,
        timing_floor_overrun,
        canary_unavailable,
        diagnostic_logs_emitted,
        diagnostic_logs_suppressed,
    );

    #[cfg(test)]
    pub(crate) fn set_database_error_for_test(&self, value: u64) {
        self.database_error.store(value, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn set_diagnostic_logs_for_test(&self, emitted: u64, suppressed: u64) {
        self.diagnostic_logs_emitted
            .store(emitted, Ordering::Relaxed);
        self.diagnostic_logs_suppressed
            .store(suppressed, Ordering::Relaxed);
    }

    /// Resets one reporting window and returns fixed, dimensionless fields.
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
            database_busy: self.database_busy.swap(0, Ordering::Relaxed),
            database_error: self.database_error.swap(0, Ordering::Relaxed),
            timing_floor_overrun: self.timing_floor_overrun.swap(0, Ordering::Relaxed),
            canary_unavailable: self.canary_unavailable.swap(0, Ordering::Relaxed),
            diagnostic_logs_emitted: self.diagnostic_logs_emitted.swap(0, Ordering::Relaxed),
            diagnostic_logs_suppressed: self.diagnostic_logs_suppressed.swap(0, Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
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
    pub database_busy: u64,
    pub database_error: u64,
    pub timing_floor_overrun: u64,
    pub canary_unavailable: u64,
    pub diagnostic_logs_emitted: u64,
    pub diagnostic_logs_suppressed: u64,
}

pub(crate) fn spawn_reporter(state: AppState, period: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        loop {
            interval.tick().await;
            report_once(&state);
        }
    });
}

pub(crate) fn report_once(state: &AppState) {
    let snapshot = state.security_counters.flush();
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
        database_busy = snapshot.database_busy,
        database_error = snapshot.database_error,
        timing_floor_overrun = snapshot.timing_floor_overrun,
        canary_unavailable = snapshot.canary_unavailable,
        diagnostic_logs_emitted = snapshot.diagnostic_logs_emitted,
        diagnostic_logs_suppressed = snapshot.diagnostic_logs_suppressed,
        "security counter window"
    );
}
