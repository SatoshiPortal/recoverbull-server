//! Axum route graph and security middleware ordering.
//!
//! The timing floor is applied to sensitive POST routes, while diagnostics,
//! timeout, and body limits wrap the graph without holding locks during sleep.

use axum::{
    extract::{DefaultBodyLimit, Request},
    middleware::{from_fn, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    app::AppState,
    handlers::{attempts, fetch, info, store},
};

// No CORS layers: clients are native apps reaching the server over Tor,
// not browsers. Allowing any origin would let any web page conscript its
// visitors' browsers into calling this API.
/// Builds the production router with the production timing floor.
pub fn new(app_state: AppState) -> Router {
    new_with_response_delay(app_state, PRODUCTION_MIN_RESPONSE_DELAY)
}

/// Production floor for POST requests matching the sensitive lookup routes,
/// including requests rejected during extraction.
pub const PRODUCTION_MIN_RESPONSE_DELAY: Duration = Duration::from_millis(500);

/// Production bound on the total duration of one request, including body
/// reads: a client dribbling its request byte by byte (slow-loris) sees it
/// expire. Header reads happen before the service and remain a proxy concern.
pub const PRODUCTION_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds the router with an explicit floor so timing behavior can be tested
/// without making the ordinary test suite sleep for the production floor.
pub(crate) fn new_with_response_delay(app_state: AppState, response_delay: Duration) -> Router {
    new_with_limits(app_state, response_delay, PRODUCTION_REQUEST_TIMEOUT)
}

/// Builds the router with both time bounds explicit, so the timeout response
/// can be tested without waiting for the production value.
pub(crate) fn new_with_limits(
    app_state: AppState,
    response_delay: Duration,
    request_timeout: Duration,
) -> Router {
    let security_counters = app_state.counters();
    let timeout_counters = app_state.counters();

    let sensitive_routes = Router::new()
        .route("/store", post(store::store_secret))
        .route("/fetch", post(fetch::fetch_secret))
        .route("/trash", post(fetch::trash_secret))
        // route_layer limits this middleware to matched routes. The method
        // check additionally keeps GET/HEAD 405 responses out of the floor.
        .route_layer(from_fn(move |request, next| {
            minimum_response_delay(request, next, response_delay, security_counters.clone())
        }))
        .with_state(app_state.clone());

    let public_routes = Router::new()
        .route("/info", get(info::get_info))
        .route("/attempts", get(attempts::get_attempts))
        .with_state(app_state.clone());

    sensitive_routes
        .merge(public_routes)
        // Layers are applied outside-in: diagnostics observes the final
        // response (including a timeout's 503) and tags it with a request
        // ID, the timeout bounds the request, and body limits precede JSON.
        // The body limit is the bound
        // `SECRET_MAX_LENGTH` is validated against at startup.
        .layer(DefaultBodyLimit::max(crate::config::MAX_REQUEST_BODY_BYTES))
        .layer(from_fn(move |request, next| {
            request_timeout_middleware(request, next, request_timeout, timeout_counters.clone())
        }))
        .layer(from_fn(diagnostic_middleware))
}

/// Advisory backoff for an expired request: there is no deadline to derive,
/// only "the server could not finish in time, try again shortly".
const REQUEST_TIMEOUT_RETRY_AFTER_SECS: u64 = 1;

/// Bounds one request's total duration, body reads included, and answers an
/// expired request with the contractual service-pressure response.
///
/// Clients classify by status only, and the documented meaning of `503` is
/// "back off and retry using `Retry-After`". A request the server could not
/// finish in time is exactly that, whatever the cause (slow storage, a held
/// lock, a dribbled body), so it must not surface as the framework's bare
/// `408 Request Timeout` with an empty body: that status is outside the
/// documented set, and a client following the README is not told to retry
/// it. Dropping the inner future cancels the handler, which refunds any
/// reservation not yet transferred to detached storage work. Diagnostics
/// wrap this layer and therefore record the final `503`.
async fn request_timeout_middleware(
    request: Request,
    next: Next,
    timeout: Duration,
    counters: Arc<crate::observability::SecurityCounters>,
) -> Response {
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_elapsed) => {
            // A `503` is never logged per request, so it must be counted.
            counters.request_timeout();
            crate::http::error::retry_after_response(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                REQUEST_TIMEOUT_RETRY_AFTER_SECS,
                "Request timed out, retry later",
            )
        }
    }
}

/// Tags every response with a server-generated request ID and logs the one
/// diagnostic this server keeps: a server error.
async fn diagnostic_middleware(mut request: Request, next: Next) -> Response {
    // A client-supplied value must not reach handlers or influence diagnostics.
    request.headers_mut().remove("x-request-id");
    let request_id = crate::observability::diagnostic::request_id();
    let route = crate::observability::diagnostic::route_kind(request.uri().path());
    let mut response = next.run(request).await;
    crate::observability::diagnostic::record(&request_id, route, response.status().as_u16());
    if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

#[cfg(test)]
/// Test-only zero-delay router constructor; excluded from release builds.
pub(crate) fn new_for_tests(app_state: AppState) -> Router {
    new_with_response_delay(app_state, Duration::ZERO)
}

#[cfg(test)]
/// Test-only constructor with a short request timeout; excluded from release
/// builds.
pub(crate) fn new_for_tests_with_timeout(app_state: AppState, request_timeout: Duration) -> Router {
    new_with_limits(app_state, Duration::ZERO, request_timeout)
}

async fn minimum_response_delay(
    request: Request,
    next: Next,
    floor: Duration,
    security_counters: Arc<crate::observability::SecurityCounters>,
) -> Response {
    if request.method() != axum::http::Method::POST {
        return next.run(request).await;
    }

    let started = Instant::now();
    let response = next.run(request).await;
    let elapsed = started.elapsed();
    if elapsed > floor {
        security_counters.timing_floor_overrun();
    }
    tokio::time::sleep(floor.saturating_sub(elapsed)).await;
    #[cfg(test)]
    let mut response = response;
    #[cfg(test)]
    response.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-recoverbull-test-sensitive-post-delay"),
        axum::http::HeaderValue::from_static("1"),
    );
    response
}
