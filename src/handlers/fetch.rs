use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::database::{establish_connection, read_and_trash_secret_by_id, read_secret_by_id};
use crate::models::{AttemptStatus, FetchSecret, RateLimitInfo, ResponseFailedAttempt};
use crate::utils::{generate_secret_id, identifier_hash, is_256bits_hex_hash};

use crate::AppState;

const DATABASE_PERMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Gives back one reserved attempt. Split from the locking so the same
/// logic can run under an async lock on the normal paths and under a
/// `try_lock` from a synchronous `Drop`.
fn refund_in_map(
    identifier_rate_limit: &mut std::collections::HashMap<String, RateLimitInfo>,
    identifier_hash: &str,
) {
    let should_remove = match identifier_rate_limit.get_mut(identifier_hash) {
        Some(info) => {
            info.attempts = info.attempts.saturating_sub(1);
            info.attempts == 0 && info.failed_attempts == 0
        }
        None => false,
    };
    if should_remove {
        identifier_rate_limit.remove(identifier_hash);
    }
}

async fn refund_attempt(state: &AppState, identifier_hash: &str) {
    let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
    refund_in_map(&mut identifier_rate_limit, identifier_hash);
}

/// RAII guard armed the moment an attempt reservation succeeds
/// (`info.attempts += 1`), so that reservation and refund can never drift
/// apart because of cancellation. Between arming and an explicit `disarm()`
/// on a path that legitimately consumes the attempt, the handler future
/// awaits the database semaphore and a blocking DB task. If the future is
/// dropped anywhere in that window - an axum route timeout, a client
/// disconnect, a server shutdown - none of the existing error branches run,
/// so without this guard the reservation would never be refunded and a
/// legitimate user would silently lose part of their attempt budget without
/// a single password ever being checked.
///
/// `Drop` is synchronous and cannot `.await`, but the rate-limit map lives
/// behind a `tokio::sync::Mutex`, whose lock is only obtainable with an
/// `.await`. Blocking the runtime thread inside `Drop` to wait for that
/// lock (e.g. via a hand-rolled spin loop) would stall every other task on
/// the same worker, so that is not an option either. Instead the refund is
/// delegated to a detached task: `Drop` calls `tokio::spawn`, which only
/// requires an active Tokio runtime handle - always the case here, since
/// this guard is only ever constructed and dropped from within the async
/// `fetch_secret` handler, which itself runs on the Tokio runtime. The
/// spawned task is independent of the guard's lifetime: cancelling or
/// dropping the handler future does not cancel the refund task, so the
/// refund is guaranteed to eventually run to completion instead of being
/// silently lost.
struct AttemptReservationGuard {
    state: AppState,
    identifier_hash: String,
    armed: bool,
}

impl AttemptReservationGuard {
    fn new(state: AppState, identifier_hash: String) -> Self {
        Self {
            state,
            identifier_hash,
            armed: true,
        }
    }

    /// Marks the reservation as legitimately consumed on this path: the
    /// attempt must stay counted and no refund must happen.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AttemptReservationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let identifier_hash = std::mem::take(&mut self.identifier_hash);

        // Uncontended is the overwhelmingly common case: refund right here so
        // the map is consistent the instant the cancelled future is dropped,
        // with no scheduling window during which the attempt still looks
        // consumed.
        if let Ok(mut identifier_rate_limit) = self.state.identifier_rate_limit.try_lock() {
            refund_in_map(&mut identifier_rate_limit, &identifier_hash);
            return;
        }

        // Contended: fall back to a detached task rather than blocking this
        // runtime thread. The refund is deferred, never dropped.
        let state = self.state.clone();
        tokio::spawn(async move {
            refund_attempt(&state, &identifier_hash).await;
        });
    }
}

pub async fn fetch_secret(
    State(state): State<AppState>,
    Json(request): Json<FetchSecret>,
    is_trashing_secret: bool,
) -> (StatusCode, Json<Value>) {
    // canonicalize hex inputs: "AB…" and "ab…" are the same logical value
    // and must map to the same record and the same rate-limit entry
    let identifier = &request.identifier.to_lowercase();
    let authentication_key = &request.authentication_key.to_lowercase();

    if !is_256bits_hex_hash(identifier) || !is_256bits_hex_hash(authentication_key) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "identifier or authentication_key are not 256 bits HEX hashes",
            })),
        );
    }

    // Keep only a one-way tag in the rate-limit state. This is also the tag
    // clients use to recognize their entry in `/stats`.
    let identifier_hash = identifier_hash(identifier).expect("validated hex identifier");

    // Per-IP limits are meaningless behind Tor, so bound aggregate lookup
    // work before allocating per-identifier state or touching SQLite.
    {
        let mut bucket = state.lookup_token_bucket.lock().await;
        if !bucket.try_consume() {
            tracing::warn!("global lookup rate-limit exceeded");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "Too many lookup requests, retry later"})),
            );
        }
    }

    let current_time: chrono::DateTime<chrono::Utc> = chrono::Utc::now();

    // The rate-limit check and the attempt reservation are atomic: the entry
    // is checked and incremented under the same lock, so concurrent requests
    // cannot all pass the check before anyone increments.
    let reservation = {
        let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;

        // entries expire once the cooldown has elapsed
        if identifier_rate_limit
            .get(&identifier_hash)
            .is_some_and(|info| {
                current_time.signed_duration_since(info.last_request) > state.rate_limit_cooldown
            })
        {
            identifier_rate_limit.remove(&identifier_hash);
        }

        let is_new_identifier = !identifier_rate_limit.contains_key(&identifier_hash);
        if is_new_identifier && identifier_rate_limit.len() >= state.rate_limit_max_identifiers {
            identifier_rate_limit.retain(|_, info| {
                current_time.signed_duration_since(info.last_request) <= state.rate_limit_cooldown
            });
        }

        if is_new_identifier && identifier_rate_limit.len() >= state.rate_limit_max_identifiers {
            None
        } else {
            let info = identifier_rate_limit
                .entry(identifier_hash.clone())
                .or_insert(RateLimitInfo {
                    window_started_at: current_time,
                    last_request: current_time,
                    attempts: 0,
                    failed_attempts: 0,
                });

            if info.attempts >= state.rate_limit_max_failed_attempts {
                Some(Err((info.attempts, info.last_request)))
            } else {
                let previous_attempt_at = (info.attempts > 0).then_some(info.last_request);
                info.attempts += 1;
                info.last_request = current_time;
                let attempt_status = AttemptStatus {
                    total_attempts: info.attempts,
                    failed_attempts: info.failed_attempts,
                    remaining_attempts: state
                        .rate_limit_max_failed_attempts
                        .saturating_sub(info.attempts),
                    window_started_at: info.window_started_at,
                    previous_attempt_at,
                    resets_at: info.last_request + state.rate_limit_cooldown,
                };
                Some(Ok((attempt_status, info.last_request)))
            }
        }
    };

    let Some(reservation) = reservation else {
        tracing::warn!("identifier rate-limit capacity exhausted");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Rate-limit capacity exhausted, retry later"})),
        );
    };

    let (attempt_status, last_request) = match reservation {
        Ok(admitted) => admitted,
        Err((attempts, last_request)) => {
            tracing::warn!("rate-limit lockout");
            let response = json!({
                "error": "Too many attempts",
                "requested_at": last_request,
                "rate_limit_cooldown": state.rate_limit_cooldown.num_minutes(),
                "attempts": attempts,
            });
            return (StatusCode::TOO_MANY_REQUESTS, Json(response));
        }
    };
    let attempt_number = attempt_status.total_attempts;

    // Armed now, right as the reservation above becomes real: from this
    // point on, either a code path below explicitly disarms it because the
    // attempt is legitimately consumed, or the future gets cancelled and
    // `Drop` refunds it. See `AttemptReservationGuard` for why the refund
    // itself must be detached from `Drop`.
    let mut attempt_guard = AttemptReservationGuard::new(state.clone(), identifier_hash.clone());

    let database_permit = match tokio::time::timeout(
        DATABASE_PERMIT_TIMEOUT,
        state.database_semaphore.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) | Err(_) => {
            // Refund here synchronously (not via the guard's detached task)
            // to keep this already-covered error path's behavior and timing
            // unchanged; disarm first so `Drop` does not refund a second time.
            attempt_guard.disarm();
            refund_attempt(&state, &identifier_hash).await;
            tracing::warn!("database concurrency limit exceeded");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Database busy, retry later"})),
            );
        }
    };

    // re-generate the key_id
    let key_id = generate_secret_id(identifier, authentication_key);

    // look in db for this key_id, outside the rate-limit lock and on a
    // blocking thread: diesel is synchronous and must not stall the async
    // workers. Trash uses an immediate transaction so only one concurrent
    // caller can read and delete a secret.
    let database_url = state.database_url.clone();
    let key_id_for_db = key_id.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _database_permit = database_permit;
        let mut connection = establish_connection(database_url);
        if is_trashing_secret {
            read_and_trash_secret_by_id(&mut connection, &key_id_for_db)
        } else {
            read_secret_by_id(&mut connection, &key_id_for_db)
        }
    })
    .await;

    let result = match task {
        Ok(result) => result,
        Err(error) => {
            attempt_guard.disarm();
            refund_attempt(&state, &identifier_hash).await;
            tracing::error!(error = %error, "database task panicked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            );
        }
    };

    match result {
        Err(e) => {
            // A database error is not a wrong credential: respond 500 and
            // refund the attempt reserved above so transient database
            // trouble cannot burn a user's rate-limit attempts.
            // Log discipline: the diesel error carries the SQLite message
            // only — never log identifiers, keys or request bodies.
            tracing::error!(error = %e, "database error on fetch");
            attempt_guard.disarm();
            refund_attempt(&state, &identifier_hash).await;

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            )
        }

        Ok(Some(key)) => {
            // The lookup completed and the attempt is legitimately consumed:
            // no refund, whatever the outcome below.
            attempt_guard.disarm();

            // A database hit does not prove ownership: an unauthenticated
            // caller may have planted the row through `/store`. Therefore a
            // successful lookup must not reset or discount the security
            // counter. The attempt counters captured at reservation time are
            // reported so the client can detect lookups it did not make —
            // including hits on planted rows, which never count as failures.
            let code = if is_trashing_secret {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            };

            tracing::info!(
                attempts = attempt_status.total_attempts,
                failed_attempts = attempt_status.failed_attempts,
                is_trash = is_trashing_secret,
                "secret released"
            );

            let mut response = json!(&key);
            response["attempt_status"] = json!(attempt_status);

            (code, Json(response))
        }

        Ok(None) => {
            // The lookup completed and the attempt is legitimately consumed:
            // no refund, this is the wrong-credential path itself.
            attempt_guard.disarm();

            // target brute-force mitigation
            // If the entry is not found:
            // - The key has been deleted by the user
            // - The key_id doesn't exists for the provided identifier + authentication_key
            let failed_attempts = {
                let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
                identifier_rate_limit
                    .get_mut(&identifier_hash)
                    .map(|info| {
                        info.failed_attempts = info.failed_attempts.saturating_add(1);
                        info.failed_attempts
                    })
                    .unwrap_or(0)
            };
            tracing::info!(attempt_number, failed_attempts, "failed fetch attempt");
            let response = json!(ResponseFailedAttempt {
                error: "Invalid identifier/authentication_key".to_owned(),
                requested_at: last_request,
                rate_limit_cooldown: state.rate_limit_cooldown.num_minutes(),
                attempts: attempt_number,
            });

            (StatusCode::UNAUTHORIZED, Json(response))
        }
    }
}
