//! Candidate admission, reservation ownership and Pending/Committed FSM.

use super::AttemptStatus;
use chrono::{DateTime, TimeDelta, Utc};
use std::{collections::HashMap, sync::Arc};
#[cfg(test)]
use tokio::sync::MutexGuard;
use tokio::{sync::Mutex, time::Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
/// Lifecycle of a derived candidate in the admission state machine.
pub(crate) enum CandidateState {
    Pending,
    Committed,
}

/// The already-derived `secret_id`/`key_id`; raw authentication material is
/// never retained in rate-limit state.
pub(crate) type CandidateTag = String;

#[derive(Clone)]
/// Per-identifier counters and candidate states retained during cooldown.
pub(crate) struct RateLimitInfo {
    /// Generation token for detached finalization, and a published timestamp.
    /// Deliberately wall-clock: `finalize` and `refund` compare it to the
    /// value a request captured at admission, and clients read it.
    pub(crate) window_started_at: DateTime<Utc>,
    pub(crate) last_candidate_at: DateTime<Utc>,
    pub(crate) last_request_at: DateTime<Utc>,
    /// Monotonic twin of `last_candidate_at`, and the *only* value the expiry
    /// decision reads. `CLOCK_REALTIME` is settable: a forward jump larger
    /// than the cooldown would otherwise expire every entry at once and reset
    /// every per-identifier budget, which is exactly the state an attacker
    /// wants. Public timestamps stay wall-clock so clients keep absolute
    /// values they can display.
    pub(crate) last_candidate_instant: Instant,
    pub(crate) candidates: HashMap<CandidateTag, CandidateState>,
    pub(crate) failed_candidates: u8,
    pub(crate) total_requests: u64,
}

impl RateLimitInfo {
    /// Starts an empty window at `now`, pairing the published wall-clock
    /// timestamps with the monotonic reading expiry compares against.
    pub(crate) fn new(now: DateTime<Utc>) -> Self {
        Self {
            window_started_at: now,
            last_candidate_at: now,
            last_request_at: now,
            last_candidate_instant: Instant::now(),
            candidates: HashMap::new(),
            failed_candidates: 0,
            total_requests: 0,
        }
    }

    #[cfg(test)]
    /// Test-only: back-dates the monotonic expiry clock so a test can build an
    /// entry that expiry already considers stale, without sleeping. Tests that
    /// assert on published values must back-date the wall-clock fields too.
    pub(crate) fn set_monotonic_age_for_test(&mut self, age: std::time::Duration) {
        self.last_candidate_instant = Instant::now()
            .checked_sub(age)
            .expect("test monotonic back-date stays within the process clock");
    }

    pub(crate) fn candidate_count(&self) -> u8 {
        self.candidates
            .len()
            .try_into()
            .expect("candidate map cannot exceed the configured u8 bound")
    }
}

/// One ledger entry projected to exactly what the public snapshot publishes.
///
/// Plain data by design: it holds no `CandidateTag`, so a snapshot build can
/// never serialize one, and the projection cost per entry is independent of
/// the configured candidate budget.
pub(crate) struct AttemptsLedgerEntry {
    pub(crate) id_hash: String,
    pub(crate) candidate_count: u8,
    pub(crate) failed_candidates: u8,
    pub(crate) total_requests: u64,
    pub(crate) window_started_at: DateTime<Utc>,
    pub(crate) last_candidate_at: DateTime<Utc>,
}

#[derive(Clone)]
/// Cloneable owner of the identifier map and its Pending/Committed transitions.
pub(crate) struct AttemptsLedgerState {
    map: Arc<Mutex<HashMap<String, RateLimitInfo>>>,
}

#[derive(Clone, Copy)]
/// Database result used to finalize or refund a pending reservation.
pub(crate) enum LookupOutcome {
    Hit,
    Miss,
    Error,
}

/// Result of ordered identifier/candidate admission under the ledger lock.
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
    /// Creates an empty ledger.
    pub(crate) fn new() -> Self {
        Self {
            map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Performs expiry, capacity, request accounting, saturation, and candidate
    /// membership checks atomically under the ledger lock, in that order.
    pub(crate) async fn admit(
        &self,
        id_hash: String,
        candidate: String,
        requested_at: DateTime<Utc>,
        max: u8,
        max_identifiers: usize,
        cooldown: TimeDelta,
    ) -> Admission {
        // Admission order is deliberate: expire the target, evict stale
        // identifiers before rejecting capacity, count the request, enforce
        // candidate limits, then distinguish Pending, Replay, and New.
        let mut map = self.map.lock().await;
        // Expiry reads the monotonic clock only; `requested_at` remains the
        // published wall-clock timestamp for this admission.
        let now = Instant::now();
        if map
            .get(&id_hash)
            .is_some_and(|info| is_expired(info, now, cooldown))
        {
            map.remove(&id_hash);
        }
        if !map.contains_key(&id_hash) && map.len() >= max_identifiers {
            map.retain(|_, info| !is_expired(info, now, cooldown));
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
                info.last_candidate_instant = now;
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

    /// Commits a hit or miss, or refunds an error, only while the candidate is
    /// still Pending in the same generation.
    pub(crate) async fn finalize(
        &self,
        id_hash: &str,
        candidate: &str,
        generation: DateTime<Utc>,
        outcome: LookupOutcome,
    ) {
        // Generation and Pending checks prevent a late worker from changing a
        // newer cooldown window or committing a reservation twice.
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

    /// Removes a still-pending candidate only when its generation matches.
    pub(crate) async fn refund(&self, id_hash: &str, candidate: &str, generation: DateTime<Utc>) {
        let mut map = self.map.lock().await;
        remove_pending(&mut map, id_hash, candidate, generation);
    }

    /// Projects entries for snapshot work, releasing the map lock immediately.
    ///
    /// The projection is deliberate: the public snapshot publishes counters and
    /// timestamps only, so copying `RateLimitInfo` wholesale would clone every
    /// entry's `CandidateTag` set — one `HashMap` allocation plus one 64-byte
    /// `String` per retained candidate — to build a payload that never reads a
    /// CandidateTag. Projecting under the lock keeps the snapshot's peak cost
    /// proportional to the number of identifiers instead of the number of
    /// candidates, and shortens the map lock that gates `/fetch` and `/trash`
    /// admission.
    pub(crate) async fn snapshot_entries(&self) -> Vec<AttemptsLedgerEntry> {
        self.map
            .lock()
            .await
            .iter()
            .map(|(id, info)| AttemptsLedgerEntry {
                id_hash: id.clone(),
                candidate_count: info.candidate_count(),
                failed_candidates: info.failed_candidates,
                total_requests: info.total_requests,
                window_started_at: info.window_started_at,
                last_candidate_at: info.last_candidate_at,
            })
            .collect()
    }

    /// Drops identifiers whose last distinct candidate is outside cooldown.
    ///
    /// Takes no wall-clock argument on purpose: retention is an expiry
    /// decision, and expiry reads the monotonic clock.
    pub(crate) async fn retain_active(&self, cooldown: TimeDelta) {
        let now = Instant::now();
        self.map
            .lock()
            .await
            .retain(|_, info| !is_expired(info, now, cooldown));
    }

    /// Clears all entries and advances collection time while preserving the
    /// `snapshot -> map -> timestamp` lock order used by the snapshot owner.
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

/// The single expiry decision, on the monotonic clock.
///
/// `saturating_duration_since` keeps a reading that is not in the past from
/// expiring an entry, and a cooldown that cannot be represented as a
/// `std::time::Duration` (only possible if it were negative, which startup
/// validation rejects) retains the entry: keeping a budget is the
/// fail-closed direction.
fn is_expired(info: &RateLimitInfo, now: Instant, cooldown: TimeDelta) -> bool {
    match cooldown.to_std() {
        Ok(cooldown) => now.saturating_duration_since(info.last_candidate_instant) > cooldown,
        Err(_) => false,
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
    /// Creates an armed guard whose drop path refunds the Pending candidate.
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

    /// Explicitly refunds the reservation before transferring responsibility.
    pub(crate) async fn refund(&mut self) {
        if self.armed {
            self.state
                .refund(&self.id_hash, &self.candidate, self.generation)
                .await;
            self.armed = false;
        }
    }

    /// Transfers finalization responsibility and consumes the guard.
    pub(crate) fn transfer(mut self) {
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
