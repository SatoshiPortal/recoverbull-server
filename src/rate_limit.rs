use crate::AppState;

/// A simple global token bucket, used to dampen unauthenticated writes.
/// Behind an onion service every connection arrives from 127.0.0.1, so
/// per-IP limiting is useless: the bucket is deliberately global. It slows
/// database growth; it is not a wall — legitimate backup flows need a
/// couple of writes each and never notice it.
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_second: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_second: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_second,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Refills the tokens elapsed since the last call, then tries to
    /// consume one. Returns false when the bucket is empty.
    pub fn try_consume(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// How often the sweeper removes expired rate-limit entries.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// Production interval for the global in-memory telemetry wipe.
pub const PRODUCTION_GLOBAL_WIPE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

/// Clears all identifiers and candidate tags and starts a fresh collection.
/// The lock order is shared with `/attempts`: snapshot, map, timestamp.
pub async fn wipe_identifier_rate_limit(state: &AppState) {
    let mut snapshot = state.attempts_snapshot.lock().await;
    let count = state
        .identifier_rate_limit
        .clear_and_reset_collection(&state.attempts_collection_started_at, chrono::Utc::now())
        .await;
    *snapshot = None;
    drop(snapshot);
    tracing::info!(target: "security", count, "daily telemetry wipe completed");
}

pub(crate) fn global_wiper_first_deadline(
    now: tokio::time::Instant,
    period: std::time::Duration,
) -> tokio::time::Instant {
    now + period
}

pub fn spawn_global_wiper(
    state: AppState,
    period: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval_at(
            global_wiper_first_deadline(tokio::time::Instant::now(), period),
            period,
        );
        loop {
            interval.tick().await;
            wipe_identifier_rate_limit(&state).await;
        }
    })
}

/// Removes the hashed rate-limit entries whose last candidate is older than the
/// cooldown. Entries are only meaningful within the cooldown window; keeping
/// them longer would grow memory unboundedly and retain identifiers for no
/// security benefit (the whitepaper asks identifiers to be wiped daily).
pub async fn sweep_expired_identifiers(state: &AppState) {
    let now = chrono::Utc::now();
    state
        .identifier_rate_limit
        .retain_active(now, state.rate_limit_cooldown)
        .await;
}

/// Spawns the background task that sweeps expired rate-limit entries, so
/// identifiers are forgotten after the cooldown even if they are never
/// requested again.
pub fn spawn_sweeper(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            sweep_expired_identifiers(&state).await;
        }
    });
}

pub fn spawn_production_wiper(state: AppState) -> tokio::task::JoinHandle<()> {
    spawn_global_wiper(state, PRODUCTION_GLOBAL_WIPE_INTERVAL)
}
