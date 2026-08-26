//! Candidate state and per-identifier counters owned by the attempts domain.

use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateState {
    Pending,
    Committed,
}

/// The already-derived `secret_id`/`key_id`; raw authentication material is
/// never retained in rate-limit state.
pub(crate) type CandidateTag = String;

#[derive(Clone)]
pub(crate) struct RateLimitInfo {
    pub(crate) window_started_at: DateTime<Utc>,
    pub(crate) last_candidate_at: DateTime<Utc>,
    pub(crate) last_request_at: DateTime<Utc>,
    pub(crate) candidates: HashMap<CandidateTag, CandidateState>,
    pub(crate) failed_candidates: u8,
    pub(crate) total_requests: u64,
}

impl RateLimitInfo {
    pub(crate) fn new(now: DateTime<Utc>) -> Self {
        Self {
            window_started_at: now,
            last_candidate_at: now,
            last_request_at: now,
            candidates: HashMap::new(),
            failed_candidates: 0,
            total_requests: 0,
        }
    }

    pub(crate) fn candidate_count(&self) -> u8 {
        self.candidates
            .len()
            .try_into()
            .expect("candidate map cannot exceed the configured u8 bound")
    }
}
