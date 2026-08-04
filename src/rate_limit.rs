use crate::AppState;

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
