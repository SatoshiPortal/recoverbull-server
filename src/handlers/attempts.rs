use std::{io::Write, sync::Arc};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use flate2::{write::GzEncoder, Compression};
use serde_json::json;

use crate::{
    models::{AttemptEntry, AttemptsSnapshot},
    utils::{sha256_hex, truncate_to_hour},
    AppState, AttemptsSnapshotCache,
};

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
            tracing::warn!("attempts telemetry rate-limit exceeded");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "Too many attempts telemetry requests, retry later"})),
            )
                .into_response();
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
            value
                .split(',')
                .any(|candidate| candidate.trim() == "*" || candidate.trim() == etag)
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
    let entries = {
        let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
        identifier_rate_limit.retain(|_, info| {
            now.signed_duration_since(info.last_request) <= state.rate_limit_cooldown
        });
        let mut entries: Vec<AttemptEntry> = identifier_rate_limit
            .iter()
            .map(|(id_hash, info)| AttemptEntry {
                id_hash: id_hash.clone(),
                total_attempts: info.attempts,
                failed_attempts: info.failed_attempts,
                window_started_at: truncate_to_hour(info.window_started_at),
                last_attempt_at: truncate_to_hour(info.last_request),
            })
            .collect();
        // deterministic ordering: identical activity must produce identical
        // bytes so the ETag only changes when the activity does
        entries.sort_by(|a, b| a.id_hash.cmp(&b.id_hash));
        entries
    };

    let payload = AttemptsSnapshot {
        version: 1,
        collection_started_at: truncate_to_hour(state.attempts_collection_started_at),
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
        Ok(Err(error)) => {
            tracing::error!(error = %error, "failed to compress attempts snapshot");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            )
                .into_response())
        }
        Err(error) => {
            tracing::error!(error = %error, "attempts snapshot task panicked");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            )
                .into_response())
        }
    }
}

/// Remaining snapshot freshness, rounded up to the next second so clients
/// never cache past the rebuild. Never zero: a zero max-age would let some
/// caches treat the body as immediately stale and hammer the origin.
fn remaining_max_age(created_at: std::time::Instant, ttl: std::time::Duration) -> u64 {
    let remaining = ttl.saturating_sub(created_at.elapsed());
    (remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0)).max(1)
}
