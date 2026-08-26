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

/// Maps status codes to the bounded diagnostic category set.
pub(crate) fn status_category(status: u16) -> &'static str {
    match status {
        408 | 429 | 503 => "overload",
        200..=299 => "success",
        400..=499 => "client_error",
        500..=599 => "server_error",
        _ => "server_error",
    }
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
    let category = status_category(status);
    let class = if category == "server_error" {
        QuotaClass::ServerError
    } else {
        QuotaClass::Detail
    };
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
