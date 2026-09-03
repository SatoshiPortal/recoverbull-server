//! Request diagnostics with privacy-preserving IDs and separate log quotas.

use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::observability::{ObservabilityState, SecurityCounters};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum QuotaClass {
    ServerError,
    Detail,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Separate token buckets limiting server-error and detail diagnostics.
pub(crate) struct LogQuota {
    server_error: Mutex<Bucket>,
    detail: Mutex<Bucket>,
}

impl LogQuota {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            server_error: Mutex::new(Bucket {
                tokens: 10.0,
                last: now,
            }),
            detail: Mutex::new(Bucket {
                tokens: 10.0,
                last: now,
            }),
        }
    }

    fn allow(&self, class: QuotaClass) -> bool {
        let bucket = match class {
            QuotaClass::ServerError => &self.server_error,
            QuotaClass::Detail => &self.detail,
        };
        let Ok(mut bucket) = bucket.lock() else {
            return false;
        };

        let now = Instant::now();
        bucket.tokens = (bucket.tokens + now.duration_since(bucket.last).as_secs_f64()).min(10.0);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub(crate) fn new_quota() -> Arc<LogQuota> {
    Arc::new(LogQuota::new())
}

/// Generates a process-local opaque request identifier for diagnostics.
pub(crate) fn request_id() -> String {
    let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(pid.to_le_bytes());
    hasher.update(sequence.to_le_bytes());
    hasher.update(nanos.to_le_bytes());
    hex::encode(hasher.finalize())
}

/// Maps only known paths to the diagnostic route allowlist.
pub(crate) fn route_kind(path: &str) -> &'static str {
    match path {
        "/store" => "store",
        "/fetch" => "fetch",
        "/trash" => "trash",
        "/info" => "info",
        "/attempts" => "attempts",
        _ => "other",
    }
}

/// Maps known HTTP methods while collapsing others to `other`.
pub(crate) fn method_kind(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        _ => "other",
    }
}

/// Reduces elapsed time to a non-sensitive fixed bucket.
pub(crate) fn duration_bucket(duration: Duration) -> &'static str {
    match duration {
        d if d < Duration::from_millis(500) => "lt500ms",
        d if d < Duration::from_secs(1) => "500ms_1s",
        d if d < Duration::from_secs(5) => "1s_5s",
        _ => "gte5s",
    }
}

/// Maps a status to its category **and** its quota class in one decision.
///
/// The two must never disagree, so they are derived from a single match rather
/// than the class being inferred from the category string. Only this table
/// decides what reaches the WARN-level budget, and getting it wrong is
/// expensive in both directions:
///
/// - `3xx` is `success`, not the unexpected-status fallback. `304` is the
///   *success* path of a conditional `GET /attempts`, which the README tells
///   clients to use; routing it to the server-error budget made benign polling
///   raise false alarms and starve the budget genuine `500`s need.
/// - `408`/`429`/`503` stay `Detail` even though `503 >= 500`. Overload
///   responses are the most frequent failures under load, and promoting them
///   to WARN would reintroduce the same starvation from the other side.
///
/// Every status this service can actually return (`200`, `201`, `202`, `304`,
/// `400`, `401`, `404`, `405`, `408`, `413`, `415`, `422`, `429`, `500`,
/// `503`) is covered by an explicit arm, so the fallback is unreachable from a
/// client and can safely keep server-error visibility for a genuine anomaly.
fn classify(status: u16) -> (&'static str, QuotaClass) {
    match status {
        408 | 429 | 503 => ("overload", QuotaClass::Detail),
        200..=399 => ("success", QuotaClass::Detail),
        400..=499 => ("client_error", QuotaClass::Detail),
        500..=599 => ("server_error", QuotaClass::ServerError),
        _ => ("server_error", QuotaClass::ServerError),
    }
}

#[cfg(test)]
/// Test-only view of the category half of `classify`; production reads both
/// halves together so they cannot drift apart. Excluded from release builds.
pub(crate) fn status_category(status: u16) -> &'static str {
    classify(status).0
}

#[cfg(test)]
/// Test-only view of the quota routing: `true` when a status spends the
/// WARN-level server-error budget. Excluded from release builds.
pub(crate) fn spends_server_error_budget(status: u16) -> bool {
    matches!(classify(status).1, QuotaClass::ServerError)
}

struct DiagnosticEvent<'a> {
    request_id: &'a str,
    route: &'static str,
    method: &'static str,
    status: u16,
    category: &'static str,
    duration: &'static str,
}

fn emit(
    quota: &LogQuota,
    counters: &SecurityCounters,
    class: QuotaClass,
    event: DiagnosticEvent<'_>,
) {
    // Only the allowlisted route/method/category dimensions reach logs; quota
    // decisions are made before emission and are reflected in counters.
    let level_enabled = match class {
        QuotaClass::ServerError => {
            tracing::enabled!(target: "request_diagnostics", tracing::Level::WARN)
        }
        QuotaClass::Detail => {
            tracing::enabled!(target: "request_diagnostics", tracing::Level::DEBUG)
        }
    };
    if !level_enabled {
        return;
    }

    if quota.allow(class) {
        counters.diagnostic_logs_emitted();
        match class {
            QuotaClass::ServerError => tracing::warn!(
                target: "request_diagnostics",
                request_id = event.request_id,
                route = event.route,
                method = event.method,
                status = event.status,
                category = event.category,
                duration_bucket = event.duration,
                "request completed"
            ),
            QuotaClass::Detail => tracing::debug!(
                target: "request_diagnostics",
                request_id = event.request_id,
                route = event.route,
                method = event.method,
                status = event.status,
                category = event.category,
                duration_bucket = event.duration,
                "request completed"
            ),
        }
    } else {
        counters.diagnostic_logs_suppressed();
    }
}

/// Emits one quota-controlled diagnostic event from transport-neutral values.
pub(crate) fn record(
    state: &ObservabilityState,
    request_id: &str,
    route: &'static str,
    method: &'static str,
    status: u16,
    duration: Duration,
) {
    let (category, class) = classify(status);
    emit(
        &state.log_quota,
        &state.counters,
        class,
        DiagnosticEvent {
            request_id,
            route,
            method,
            status,
            category,
            duration: duration_bucket(duration),
        },
    );
}
