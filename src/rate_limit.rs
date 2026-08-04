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
    last_refill: chrono::DateTime<chrono::Utc>,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_second: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_second,
            last_refill: chrono::Utc::now(),
        }
    }

    /// Refills the tokens elapsed since the last call, then tries to
    /// consume one. Returns false when the bucket is empty.
    pub fn try_consume(&mut self) -> bool {
        let now = chrono::Utc::now();
        let elapsed =
            now.signed_duration_since(self.last_refill).num_milliseconds() as f64 / 1000.0;
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

/// Removes the rate-limit entries whose last request is older than the
/// cooldown. Entries are only meaningful within the cooldown window; keeping
/// them longer would grow memory unboundedly and retain identifiers for no
/// security benefit (the whitepaper asks identifiers to be wiped daily).
pub async fn sweep_expired_identifiers(state: &AppState) {
    let now = chrono::Utc::now();
    let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
    let before = identifier_rate_limit.len();
    identifier_rate_limit.retain(|_, info| {
        now.signed_duration_since(info.last_request) <= state.rate_limit_cooldown
    });
    let remaining = identifier_rate_limit.len();
    // Log discipline: counts only, never identifiers.
    tracing::info!(swept = before - remaining, remaining, "rate-limit sweep");
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
