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

/// Builds the router with an explicit floor so timing behavior can be tested
/// without making the ordinary test suite sleep for the production floor.
pub(crate) fn new_with_response_delay(app_state: AppState, response_delay: Duration) -> Router {
    // Bound the total request duration, including body reads: a client
    // dribbling its request byte by byte (slow-loris) sees it expire.
    // Header reads happen before the service and remain a proxy concern.
    let timeout = tower_http::timeout::TimeoutLayer::new(Duration::from_secs(30));
    let security_counters = app_state.request_diagnostics_state().counters.clone();

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
        // response, timeout bounds the request, and body limits precede JSON.
        // Legitimate JSON requests are below 320 bytes. Keep modest headroom
        // while rejecting oversized bodies before deserialization.
        .layer(DefaultBodyLimit::max(1024))
        .layer(timeout)
        .layer(from_fn(move |request, next| {
            diagnostic_middleware(app_state.request_diagnostics_state(), request, next)
        }))
}

/// Adapts Axum requests and responses to the transport-neutral diagnostics API.
async fn diagnostic_middleware(
    state: crate::observability::ObservabilityState,
    mut request: Request,
    next: Next,
) -> Response {
    // A client-supplied value must not reach handlers or influence diagnostics.
    request.headers_mut().remove("x-request-id");
    let request_id = crate::observability::diagnostic::request_id();
    let route = crate::observability::diagnostic::route_kind(request.uri().path());
    let method = crate::observability::diagnostic::method_kind(request.method().as_str());
    let started = Instant::now();
    let mut response = next.run(request).await;
    crate::observability::diagnostic::record(
        &state,
        &request_id,
        route,
        method,
        response.status().as_u16(),
        started.elapsed(),
    );
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
