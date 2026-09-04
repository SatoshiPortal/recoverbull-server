//! The single request diagnostic this server keeps, plus its request ID.

use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    sync::{
        atomic::{AtomicU64, Ordering},
        LazyLock,
    },
};

/// Per-process key for request IDs, drawn from the operating system once.
///
/// A bare counter would be an activity oracle: any client could subtract two
/// IDs it received and learn how many requests the server handled in
/// between, which no endpoint publishes today. Hashing the counter under a
/// process-local random key keeps IDs unique and comparable inside one log
/// without exposing that delta.
static REQUEST_ID_KEY: LazyLock<RandomState> = LazyLock::new(RandomState::new);
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Returns an opaque, process-local request identifier.
pub(crate) fn request_id() -> String {
    let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut hasher = REQUEST_ID_KEY.build_hasher();
    hasher.write_u64(sequence);
    format!("{:016x}", hasher.finish())
}

/// Maps only known paths to the diagnostic route allowlist. A path is never
/// logged as text: an unknown one collapses to `other`, so a client cannot
/// place its own bytes in a log line through the request target.
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

/// The pressure status this server returns for every kind of overload. It is
/// the one `5xx` a client can trigger at will, so it is counted in the
/// five-minute window and never logged.
const PRESSURE_STATUS: u16 = 503;

/// Logs one WARN line for a server error, and nothing for anything else.
///
/// The policy is two sentences: **a server error leaves one line, and a
/// `503` leaves none because it is pressure, counted in the unconditional
/// five-minute window instead.** In practice that means a genuine `500`, from
/// a database failure or a failed snapshot build — neither of which a client
/// can provoke at volume.
///
/// It replaces a per-request event system with two token-bucket quota
/// classes and a status-to-category table, about 500 lines that produced the
/// one defect they were meant to bound: `304` was misfiled into the WARN
/// class, so ordinary conditional polling raised false alarms and starved
/// the budget a genuine `500` needed. The `503` exception is what the quota
/// really bought — without it an exhausted bucket writes one line per
/// rejected request — and stating it as a rule costs one comparison instead
/// of two buckets. Volume control for what remains belongs to the log daemon
/// (see `docs/DEPLOYMENT.md`), which already rate-limits per service.
pub(crate) fn record(request_id: &str, route: &'static str, status: u16) {
    if status < 500 || status == PRESSURE_STATUS {
        return;
    }
    tracing::warn!(
        target: "request_diagnostics",
        request_id,
        route,
        status,
        "request failed"
    );
}
