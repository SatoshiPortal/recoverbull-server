use std::{io::Write, sync::Arc};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use flate2::{write::GzEncoder, Compression};

use crate::{
    models::{error_body, retry_after_response, AttemptEntry, AttemptsSnapshot},
    utils::{sha256_hex, truncate_to_hour},
    AppState, AttemptsSnapshotCache,
};

/// Small fixed advisory backoff for the global attempts-telemetry bucket:
/// there is no cooldown deadline to derive here, only "try again shortly".
const GLOBAL_OVERLOAD_RETRY_AFTER_SECS: u64 = 1;

/// Public lookup telemetry.
///
/// Publishes the identifiers currently rate-limited for fetch/trash lookups,
/// hashed with SHA-256 over the raw identifier bytes so that:
/// - a client can recognize its own identifier (it knows the raw value),
/// - nobody else can recover a raw identifier from the list (pre-image
///   resistance), which keeps the list useless for griefing or lockout.
///
/// Entries live in the same in-memory map as the rate-limiter, so they
/// expire with it (cooldown reset or server reboot): no persistence.
///
/// The snapshot is serialized and gzip-compressed at most once per TTL
/// window, then served as immutable shared bytes: request volume never
/// multiplies full-map serialization work. The body is always gzip — there
/// is no uncompressed variant, which keeps one representation, one ETag and
/// one cache entry.
pub async fn get_attempts(State(state): State<AppState>, headers: HeaderMap) -> Response {
    {
        let mut bucket = state.attempts_token_bucket.lock().await;
        if !bucket.try_consume() {
            state.security_counters.attempts_rate_limited();
            return retry_after_response(
                StatusCode::SERVICE_UNAVAILABLE,
                GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
                "Too many attempts telemetry requests, retry later",
            );
        }
    }

    let mut cached = state.attempts_snapshot.lock().await;
    if cached
        .as_ref()
        .is_none_or(|snapshot| snapshot.created_at.elapsed() >= state.attempts_snapshot_ttl)
    {
        match build_snapshot(&state).await {
            Ok(snapshot) => *cached = Some(snapshot),
            Err(response) => return response,
        }
    }

    let snapshot = cached.as_ref().expect("snapshot was initialized");
    let etag = snapshot.etag.clone();
    let body = snapshot.gzip_body.as_ref().clone();
    let max_age = remaining_max_age(snapshot.created_at, state.attempts_snapshot_ttl);
    drop(cached);

    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|candidate| {
                let candidate = candidate.trim();
                // RFC 9110: If-None-Match uses the weak comparison function,
                // so a weak validator W/"…" matches our strong ETag.
                let candidate = candidate.strip_prefix("W/").unwrap_or(candidate);
                candidate == "*" || candidate == etag
            })
        });

    let mut response = if not_modified {
        Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_ENCODING, "gzip")
            .body(Body::from(body))
    }
    .expect("static attempts response headers are valid");

    let response_headers = response.headers_mut();
    response_headers.insert(
        header::CACHE_CONTROL,
        format!("public, max-age={max_age}").parse().unwrap(),
    );
    response_headers.insert(header::ETAG, etag.parse().unwrap());
    response
}

/// Collects the current entries under the rate-limit lock, then serializes
/// and compresses on a blocking thread after releasing it. flate2 writes a
/// zero mtime in the gzip header, so identical content produces identical
/// bytes and a stable ETag across rebuilds.
async fn build_snapshot(state: &AppState) -> Result<AttemptsSnapshotCache, Response> {
    let now = chrono::Utc::now();
    let mut entries: Vec<AttemptEntry> = {
        let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
        identifier_rate_limit.retain(|_, info| {
            now.signed_duration_since(info.last_candidate_at) <= state.rate_limit_cooldown
        });
        identifier_rate_limit
            .iter()
            .map(|(id_hash, info)| AttemptEntry {
                id_hash: id_hash.clone(),
                total_attempts: info.candidate_count(),
                failed_attempts: info.failed_candidates,
                total_requests: info.total_requests,
                window_started_at: truncate_to_hour(info.window_started_at),
                last_attempt_at: truncate_to_hour(info.last_request_at),
            })
            .collect()
        // lock dropped here
    };

    // Sorting happens after the lock guard above goes out of scope: this is
    // the same `identifier_rate_limit` mutex that every `/fetch` and
    // `/trash` request must acquire to reserve an attempt, so holding it
    // through an O(n log n) sort over up to 100k entries would inject
    // latency into that user-facing recovery path on every TTL window.
    // Deterministic ordering (identical activity must produce identical
    // bytes so the ETag only changes when the activity does) does not
    // require the lock, only a stable snapshot of the data.
    entries.sort_by(|a, b| a.id_hash.cmp(&b.id_hash));

    let collection_started_at = *state.attempts_collection_started_at.lock().await;
    let payload = AttemptsSnapshot {
        version: 1,
        collection_started_at: truncate_to_hour(collection_started_at),
        entries,
    };

    let built = tokio::task::spawn_blocking(move || -> std::io::Result<AttemptsSnapshotCache> {
        let raw = serde_json::to_vec(&payload).expect("attempts snapshot is serializable");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
        encoder.write_all(&raw)?;
        let gzip = encoder.finish()?;
        Ok(AttemptsSnapshotCache {
            etag: format!("\"{}\"", sha256_hex(&gzip)),
            gzip_body: Arc::new(Bytes::from(gzip)),
            created_at: std::time::Instant::now(),
        })
    })
    .await;

    match built {
        Ok(Ok(snapshot)) => Ok(snapshot),
        Ok(Err(_error)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("Internal server error")),
        )
            .into_response()),
        Err(_error) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("Internal server error")),
        )
            .into_response()),
    }
}

/// Remaining snapshot freshness, rounded up to the next second so clients
/// never cache past the rebuild. Never zero: a zero max-age would let some
/// caches treat the body as immediately stale and hammer the origin.
fn remaining_max_age(created_at: std::time::Instant, ttl: std::time::Duration) -> u64 {
    let remaining = ttl.saturating_sub(created_at.elapsed());
    (remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0)).max(1)
}
