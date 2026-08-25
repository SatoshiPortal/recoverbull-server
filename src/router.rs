use axum::{
    extract::{DefaultBodyLimit, Request, State},
    middleware::{from_fn, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    handlers::{
        attempts,
        fetch::{self, LookupOperation},
        info, store,
    },
    models::FetchSecret,
    AppState,
};

// No CORS layers: clients are native apps reaching the server over Tor,
// not browsers. Allowing any origin would let any web page conscript its
// visitors' browsers into calling this API.
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
    let security_counters = app_state.security_counters.clone();

    let sensitive_routes = Router::new()
        .route("/store", post(store::store_secret))
        .route(
            "/fetch",
            post(|state: State<AppState>, json: Json<FetchSecret>| {
                fetch::lookup_secret(state, json, LookupOperation::Fetch)
            }),
        )
        .route(
            "/trash",
            post(|state: State<AppState>, json: Json<FetchSecret>| {
                fetch::lookup_secret(state, json, LookupOperation::Trash)
            }),
        )
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
        // Legitimate JSON requests are below 320 bytes. Keep modest headroom
        // while rejecting oversized bodies before deserialization.
        .layer(DefaultBodyLimit::max(1024))
        .layer(timeout)
        .layer(from_fn(move |request, next| {
            crate::diagnostic::middleware(app_state.clone(), request, next)
        }))
}

#[cfg(test)]
pub(crate) fn new_for_tests(app_state: AppState) -> Router {
    new_with_response_delay(app_state, Duration::ZERO)
}

async fn minimum_response_delay(
    request: Request,
    next: Next,
    floor: Duration,
    security_counters: Arc<crate::security_counters::SecurityCounters>,
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
