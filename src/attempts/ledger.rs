//! Candidate admission, reservation ownership and Pending/Committed FSM.

use super::AttemptStatus;
use chrono::{DateTime, TimeDelta, Utc};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
#[cfg(test)]
use tokio::sync::MutexGuard;

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

#[derive(Clone)]
/// Cloneable owner of the identifier map and its Pending/Committed transitions.
pub(crate) struct AttemptsLedgerState {
    map: Arc<Mutex<HashMap<String, RateLimitInfo>>>,
}

#[derive(Clone, Copy)]
pub(crate) enum LookupOutcome {
    Hit,
    Miss,
    Error,
}

pub(crate) enum Admission {
    New {
        status: AttemptStatus,
        generation: DateTime<Utc>,
        reservation: ReservationGuard,
    },
    Replay {
        status: AttemptStatus,
        generation: DateTime<Utc>,
    },
    Pending,
    Saturated {},
    RateLimited {
        count: u8,
        last_candidate_at: DateTime<Utc>,
    },
}

impl AttemptsLedgerState {
    pub(crate) fn new() -> Self {
        Self {
            map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) async fn admit(
        &self,
        id_hash: String,
        candidate: String,
        requested_at: DateTime<Utc>,
        max: u8,
        max_identifiers: usize,
        cooldown: TimeDelta,
    ) -> Admission {
        let mut map = self.map.lock().await;
        if map.get(&id_hash).is_some_and(|info| {
            requested_at.signed_duration_since(info.last_candidate_at) > cooldown
        }) {
            map.remove(&id_hash);
        }
        if !map.contains_key(&id_hash) && map.len() >= max_identifiers {
            map.retain(|_, info| {
                requested_at.signed_duration_since(info.last_candidate_at) <= cooldown
            });
            if map.len() >= max_identifiers {
                return Admission::Saturated {};
            }
        }
        let info = map
            .entry(id_hash.clone())
            .or_insert_with(|| RateLimitInfo::new(requested_at));
        info.total_requests = info.total_requests.saturating_add(1);
        info.last_request_at = requested_at;
        if info.candidate_count() >= max {
            return Admission::RateLimited {
                count: info.candidate_count(),
                last_candidate_at: info.last_candidate_at,
            };
        }
        match info.candidates.get(&candidate).copied() {
            Some(CandidateState::Pending) => Admission::Pending,
            Some(CandidateState::Committed) => Admission::Replay {
                status: attempt_status(info, max, None, cooldown),
                generation: info.window_started_at,
            },
            None => {
                let previous = (info.candidate_count() > 0).then_some(info.last_candidate_at);
                info.candidates
                    .insert(candidate.clone(), CandidateState::Pending);
                info.last_candidate_at = requested_at;
                let generation = info.window_started_at;
                Admission::New {
                    status: attempt_status(info, max, previous, cooldown),
                    generation,
                    reservation: ReservationGuard::new(
                        self.clone(),
                        id_hash,
                        candidate,
                        generation,
                    ),
                }
            }
        }
    }

    pub(crate) async fn finalize(
        &self,
        id_hash: &str,
        candidate: &str,
        generation: DateTime<Utc>,
        outcome: LookupOutcome,
    ) {
        let mut map = self.map.lock().await;
        let remove_identifier = {
            let Some(info) = map.get_mut(id_hash) else {
                return;
            };
            if info.window_started_at != generation
                || info.candidates.get(candidate) != Some(&CandidateState::Pending)
            {
                return;
            }
            match outcome {
                LookupOutcome::Hit | LookupOutcome::Miss => {
                    info.candidates
                        .insert(candidate.to_owned(), CandidateState::Committed);
                    if matches!(outcome, LookupOutcome::Miss) {
                        info.failed_candidates = info.failed_candidates.saturating_add(1);
                    }
                    false
                }
                LookupOutcome::Error => {
                    info.candidates.remove(candidate);
                    info.candidates.is_empty()
                }
            }
        };
        if remove_identifier {
            map.remove(id_hash);
        }
    }

    pub(crate) async fn refund(&self, id_hash: &str, candidate: &str, generation: DateTime<Utc>) {
        let mut map = self.map.lock().await;
        remove_pending(&mut map, id_hash, candidate, generation);
    }

    pub(crate) async fn snapshot_entries(&self) -> Vec<(String, RateLimitInfo)> {
        self.map
            .lock()
            .await
            .iter()
            .map(|(id, info)| (id.clone(), info.clone()))
            .collect()
    }

    pub(crate) async fn retain_active(&self, now: DateTime<Utc>, cooldown: TimeDelta) {
        self.map
            .lock()
            .await
            .retain(|_, info| now.signed_duration_since(info.last_candidate_at) <= cooldown);
    }

    /// Clears the ledger and resets the collection timestamp while retaining
    /// the map lock across both operations. The caller must already hold the
    /// snapshot lock: this transitional API preserves the pre-Commit-8 order
    /// `snapshot -> map -> timestamp` until timestamp ownership moves here.
    pub(crate) async fn clear_and_reset_collection(
        &self,
        collection_started_at: &Mutex<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> usize {
        let mut map = self.map.lock().await;
        let count = map.len();
        map.clear();
        let mut started_at = collection_started_at.lock().await;
        *started_at = now;
        count
    }

    #[cfg(test)]
    /// Sole test seam for constructing synthetic ledger state.
    pub(crate) async fn lock_for_test(&self) -> MutexGuard<'_, HashMap<String, RateLimitInfo>> {
        self.map.lock().await
    }
}

fn attempt_status(
    info: &RateLimitInfo,
    max: u8,
    previous: Option<DateTime<Utc>>,
    cooldown: TimeDelta,
) -> AttemptStatus {
    let count = info.candidate_count();
    AttemptStatus {
        version: 1,
        total_attempts: count,
        failed_attempts: info.failed_candidates,
        remaining_attempts: max.saturating_sub(count),
        total_requests: info.total_requests,
        window_started_at: info.window_started_at,
        previous_attempt_at: previous,
        resets_at: info.last_candidate_at + cooldown,
    }
}

fn remove_pending(
    map: &mut HashMap<String, RateLimitInfo>,
    id_hash: &str,
    candidate: &str,
    generation: DateTime<Utc>,
) {
    let remove_identifier = map.get_mut(id_hash).is_some_and(|info| {
        if info.window_started_at == generation
            && info.candidates.get(candidate) == Some(&CandidateState::Pending)
        {
            info.candidates.remove(candidate);
        }
        info.window_started_at == generation && info.candidates.is_empty()
    });
    if remove_identifier {
        map.remove(id_hash);
    }
}

#[must_use = "a reservation must stay alive until SQLite responsibility is transferred"]
/// Owns one Pending reservation until it is finalized, refunded, or transferred.
pub(crate) struct ReservationGuard {
    state: AttemptsLedgerState,
    id_hash: String,
    candidate: String,
    generation: DateTime<Utc>,
    armed: bool,
}

impl ReservationGuard {
    fn new(
        state: AttemptsLedgerState,
        id_hash: String,
        candidate: String,
        generation: DateTime<Utc>,
    ) -> Self {
        Self {
            state,
            id_hash,
            candidate,
            generation,
            armed: true,
        }
    }

    pub(crate) async fn refund(&mut self) {
        if self.armed {
            self.state
                .refund(&self.id_hash, &self.candidate, self.generation)
                .await;
            self.disarm();
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ReservationGuard {
    /// Drop cannot await. It tries the mutex immediately and spawns cleanup if
    /// another operation owns it, preserving exactly-once refund ownership.
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let state = self.state.clone();
        let id_hash = std::mem::take(&mut self.id_hash);
        let candidate = std::mem::take(&mut self.candidate);
        let generation = self.generation;
        let map = state.map.clone();
        if let Ok(mut map) = map.try_lock() {
            remove_pending(&mut map, &id_hash, &candidate, generation);
        } else {
            tokio::spawn(async move {
                state.refund(&id_hash, &candidate, generation).await;
            });
        };
    }
}
