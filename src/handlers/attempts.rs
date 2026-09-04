//! `/attempts` telemetry snapshot extraction and conditional response mapping.

use crate::{
    http::error::{error_body, retry_after_response},
    AppState,
};
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

/// Public lookup telemetry.
///
/// Publishes *every* identifier with an active fetch/trash entry, not only
/// the saturated ones: a single admitted secret_id creates an entry, and the
/// entry is published until it expires. The count of published entries is
/// therefore the live size of the rate-limit map, and its ratio to the
/// `max_attempt_identifiers` advertised by `/info` is the aggregate
/// map-pressure signal (see the map-filling accepted risk in SECURITY.md).
///
/// Identifiers are hashed with SHA-256 over the raw identifier bytes so that:
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
    if let crate::rate_limit::BucketDecision::Rejected { retry_after_secs } =
        state.attempts_request_admission().await
    {
        return retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            retry_after_secs,
            "Too many attempts telemetry requests, retry later",
        );
    }

    let snapshot = match state.attempts_snapshot().await {
        Ok(snapshot) => snapshot,
        Err(()) => return *internal_error(),
    };
    let etag = snapshot.etag.clone();
    let body = axum::body::Bytes::from_owner(snapshot.gzip_body.clone());
    let max_age = state.attempts_max_age(snapshot.created_at);

    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|secret_id| {
                let secret_id = secret_id.trim();
                // RFC 9110: If-None-Match uses the weak comparison function,
                // so a weak validator W/"…" matches our strong ETag.
                let secret_id = secret_id.strip_prefix("W/").unwrap_or(secret_id);
                secret_id == "*" || secret_id == etag
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

fn internal_error() -> Box<Response> {
    Box::new(
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("Internal server error")),
        )
            .into_response(),
    )
}
