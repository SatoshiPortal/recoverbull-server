//! Admission of derived `secret_id` values, reservation ownership, and the
//! Pending/Committed state machine.
//!
//! A `secret_id` is the value
//! `SHA256(lowerhex(identifier) || lowerhex(authentication_key))` a client
//! presents to `/fetch` or `/trash`.

use super::AttemptStatus;
use chrono::{DateTime, TimeDelta, Utc};
use std::{collections::HashMap, sync::Arc};
#[cfg(test)]
use tokio::sync::MutexGuard;
use tokio::{sync::Mutex, time::Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
/// Lifecycle of a derived `secret_id` in the admission state machine.
pub(crate) enum SecretIdState {
    Pending,
    Committed,
}

/// The already-derived `secret_id`/`key_id`; raw authentication material is
/// never retained in rate-limit state.
pub(crate) type SecretId = String;

#[derive(Clone)]
/// Per-identifier counters and secret_id states retained during cooldown.
pub(crate) struct RateLimitInfo {
    /// Generation token for detached finalization, and a published timestamp.
    /// Deliberately wall-clock: `finalize` and `refund` compare it to the
    /// value a request captured at admission, and clients read it.
    pub(crate) window_started_at: DateTime<Utc>,
    pub(crate) last_secret_id_at: DateTime<Utc>,
    pub(crate) last_request_at: DateTime<Utc>,
    /// Monotonic twin of `last_secret_id_at`, and the *only* value the expiry
    /// decision reads. `CLOCK_REALTIME` is settable: a forward jump larger
    /// than the cooldown would otherwise expire every entry at once and reset
    /// every per-identifier budget, which is exactly the state an attacker
    /// wants. Public timestamps stay wall-clock so clients keep absolute
    /// values they can display.
    pub(crate) last_secret_id_instant: Instant,
    /// The `secret_id` values still recognizable in this window, each either
    /// `Pending` or replayable for free as `Committed`.
    pub(crate) secret_ids: HashMap<SecretId, SecretIdState>,
    /// Slots consumed by `secret_id` values deliberately forgotten: a
    /// successful `/trash` deletes the row and forgets the `secret_id` that found it,
    /// so presenting that secret_id again is a new secret_id like any other.
    /// Keeping it would make its replay free and its counter stable,
    /// which told a Backup File holder which PIN had been used for the
    /// deletion. The slot stays consumed so the deletion never refunds budget.
    pub(crate) forgotten_slots: u8,
    pub(crate) failed_secret_ids: u8,
    pub(crate) total_requests: u64,
}

impl RateLimitInfo {
    /// Starts an empty window at `now`, pairing the published wall-clock
    /// timestamps with the monotonic reading expiry compares against.
    pub(crate) fn new(now: DateTime<Utc>) -> Self {
        Self {
            window_started_at: now,
            last_secret_id_at: now,
            last_request_at: now,
            last_secret_id_instant: Instant::now(),
            secret_ids: HashMap::new(),
            forgotten_slots: 0,
            failed_secret_ids: 0,
            total_requests: 0,
        }
    }

    #[cfg(test)]
    /// Test-only: back-dates the monotonic expiry clock so a test can build an
    /// entry that expiry already considers stale, without sleeping. Tests that
    /// assert on published values must back-date the wall-clock fields too.
    pub(crate) fn set_monotonic_age_for_test(&mut self, age: std::time::Duration) {
        self.last_secret_id_instant = Instant::now()
            .checked_sub(age)
            .expect("test monotonic back-date stays within the process clock");
    }

    /// Slots consumed in this window: the recognizable secret_ids plus the
    /// forgotten ones. Admission refuses at `max`, so the sum fits a `u8`.
    pub(crate) fn consumed_slots(&self) -> u8 {
        self.secret_ids
            .len()
            .saturating_add(usize::from(self.forgotten_slots))
            .try_into()
            .expect("secret_id map cannot exceed the configured u8 bound")
    }
}

/// One ledger entry projected to exactly what the public snapshot publishes.
///
/// Plain data by design: it holds no `SecretId`, so a snapshot build can
/// never serialize one, and the projection cost per entry is independent of
/// the configured secret_id budget.
pub(crate) struct AttemptsLedgerEntry {
    pub(crate) id_hash: String,
    pub(crate) consumed_slots: u8,
    pub(crate) failed_secret_ids: u8,
    pub(crate) total_requests: u64,
    pub(crate) window_started_at: DateTime<Utc>,
    pub(crate) last_secret_id_at: DateTime<Utc>,
}

#[derive(Clone)]
/// Cloneable owner of the identifier map and its Pending/Committed transitions.
pub(crate) struct AttemptsLedgerState {
    map: Arc<Mutex<HashMap<String, RateLimitInfo>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// Database result used to finalize or refund a pending reservation.
pub(crate) enum LookupOutcome {
    /// The row exists and was read.
    Hit,
    /// The row existed and was deleted: the secret_id is committed as a
    /// consumed slot but its `secret_id` is forgotten (see `forgotten_slots`).
    Deleted,
    Miss,
    Error,
}

/// Result of ordered identifier/secret_id admission under the ledger lock.
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
        last_secret_id_at: DateTime<Utc>,
    },
}

impl AttemptsLedgerState {
    /// Creates an empty ledger.
    pub(crate) fn new() -> Self {
        Self {
            map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Performs expiry, capacity, request accounting, saturation, and secret_id
    /// membership checks atomically under the ledger lock, in that order.
    pub(crate) async fn admit(
        &self,
        id_hash: String,
        secret_id: String,
        requested_at: DateTime<Utc>,
        max: u8,
        max_identifiers: usize,
        cooldown: TimeDelta,
    ) -> Admission {
        // Admission order is deliberate: expire the target, evict stale
        // identifiers before rejecting capacity, count the request, enforce
        // secret_id limits, then distinguish Pending, Replay, and New.
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
        if info.consumed_slots() >= max {
            return Admission::RateLimited {
                count: info.consumed_slots(),
                last_secret_id_at: info.last_secret_id_at,
            };
        }
        match info.secret_ids.get(&secret_id).copied() {
            Some(SecretIdState::Pending) => Admission::Pending,
            Some(SecretIdState::Committed) => Admission::Replay {
                status: attempt_status(info, max, None, cooldown),
                generation: info.window_started_at,
            },
            None => {
                let previous = (info.consumed_slots() > 0).then_some(info.last_secret_id_at);
                info.secret_ids
                    .insert(secret_id.clone(), SecretIdState::Pending);
                info.last_secret_id_at = requested_at;
                info.last_secret_id_instant = now;
                let generation = info.window_started_at;
                Admission::New {
                    status: attempt_status(info, max, previous, cooldown),
                    generation,
                    reservation: ReservationGuard::new(
                        self.clone(),
                        id_hash,
                        secret_id,
                        generation,
                    ),
                }
            }
        }
    }

    /// Commits a hit or miss, or refunds an error, only while the secret_id is
    /// still Pending in the same generation.
    pub(crate) async fn finalize(
        &self,
        id_hash: &str,
        secret_id: &str,
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
                || info.secret_ids.get(secret_id) != Some(&SecretIdState::Pending)
            {
                return;
            }
            match outcome {
                LookupOutcome::Hit | LookupOutcome::Miss => {
                    info.secret_ids
                        .insert(secret_id.to_owned(), SecretIdState::Committed);
                    if matches!(outcome, LookupOutcome::Miss) {
                        info.failed_secret_ids = info.failed_secret_ids.saturating_add(1);
                    }
                    false
                }
                LookupOutcome::Deleted => {
                    forget_secret_id(info, secret_id);
                    false
                }
                LookupOutcome::Error => {
                    info.secret_ids.remove(secret_id);
                    is_blank(info)
                }
            }
        };
        if remove_identifier {
            map.remove(id_hash);
        }
    }

    /// Forgets a `Committed` `secret_id` whose replay deleted the
    /// row, only in the same generation. The slot stays consumed. A replay
    /// carries no reservation, so this is the only ledger transition a
    /// replayed `/trash` performs; the generation check keeps a late worker
    /// from touching a replacement window.
    pub(crate) async fn forget_committed(
        &self,
        id_hash: &str,
        secret_id: &str,
        generation: DateTime<Utc>,
    ) {
        let mut map = self.map.lock().await;
        let Some(info) = map.get_mut(id_hash) else {
            return;
        };
        if info.window_started_at != generation
            || info.secret_ids.get(secret_id) != Some(&SecretIdState::Committed)
        {
            return;
        }
        forget_secret_id(info, secret_id);
    }

    /// Removes a still-pending secret_id only when its generation matches.
    pub(crate) async fn refund(&self, id_hash: &str, secret_id: &str, generation: DateTime<Utc>) {
        let mut map = self.map.lock().await;
        remove_pending(&mut map, id_hash, secret_id, generation);
    }

    /// Projects entries for snapshot work, releasing the map lock immediately.
    ///
    /// The projection is deliberate: the public snapshot publishes counters and
    /// timestamps only, so copying `RateLimitInfo` wholesale would clone every
    /// entry's `SecretId` set — one `HashMap` allocation plus one 64-byte
    /// `String` per retained secret_id — to build a payload that never reads a
    /// SecretId. Projecting under the lock keeps the snapshot's peak cost
    /// proportional to the number of identifiers instead of the number of
    /// secret_ids, and shortens the map lock that gates `/fetch` and `/trash`
    /// admission.
    pub(crate) async fn snapshot_entries(&self) -> Vec<AttemptsLedgerEntry> {
        self.map
            .lock()
            .await
            .iter()
            .map(|(id, info)| AttemptsLedgerEntry {
                id_hash: id.clone(),
                consumed_slots: info.consumed_slots(),
                failed_secret_ids: info.failed_secret_ids,
                total_requests: info.total_requests,
                window_started_at: info.window_started_at,
                last_secret_id_at: info.last_secret_id_at,
            })
            .collect()
    }

    /// Drops identifiers whose last distinct secret_id is outside cooldown.
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
        Ok(cooldown) => now.saturating_duration_since(info.last_secret_id_instant) > cooldown,
        Err(_) => false,
    }
}

fn attempt_status(
    info: &RateLimitInfo,
    max: u8,
    previous: Option<DateTime<Utc>>,
    cooldown: TimeDelta,
) -> AttemptStatus {
    let count = info.consumed_slots();
    AttemptStatus {
        version: 1,
        total_attempts: count,
        failed_attempts: info.failed_secret_ids,
        remaining_attempts: max.saturating_sub(count),
        total_requests: info.total_requests,
        window_started_at: info.window_started_at,
        previous_attempt_at: previous,
        resets_at: info.last_secret_id_at + cooldown,
    }
}

fn remove_pending(
    map: &mut HashMap<String, RateLimitInfo>,
    id_hash: &str,
    secret_id: &str,
    generation: DateTime<Utc>,
) {
    let remove_identifier = map.get_mut(id_hash).is_some_and(|info| {
        if info.window_started_at == generation
            && info.secret_ids.get(secret_id) == Some(&SecretIdState::Pending)
        {
            info.secret_ids.remove(secret_id);
        }
        info.window_started_at == generation && is_blank(info)
    });
    if remove_identifier {
        map.remove(id_hash);
    }
}

/// Converts a recognizable secret_id into a consumed, unrecognizable slot.
fn forget_secret_id(info: &mut RateLimitInfo, secret_id: &str) {
    if info.secret_ids.remove(secret_id).is_some() {
        info.forgotten_slots = info.forgotten_slots.saturating_add(1);
    }
}

/// An entry with no recognizable secret_id and no consumed slot holds no
/// budget and may be dropped after a refund. A forgotten slot is still
/// budget, so an entry keeping one must survive.
fn is_blank(info: &RateLimitInfo) -> bool {
    info.secret_ids.is_empty() && info.forgotten_slots == 0
}

#[must_use = "a reservation must stay alive until SQLite responsibility is transferred"]
/// Owns one Pending reservation until it is finalized, refunded, or transferred.
pub(crate) struct ReservationGuard {
    state: AttemptsLedgerState,
    id_hash: String,
    secret_id: String,
    generation: DateTime<Utc>,
    armed: bool,
}

impl ReservationGuard {
    /// Creates an armed guard whose drop path refunds the Pending secret_id.
    fn new(
        state: AttemptsLedgerState,
        id_hash: String,
        secret_id: String,
        generation: DateTime<Utc>,
    ) -> Self {
        Self {
            state,
            id_hash,
            secret_id,
            generation,
            armed: true,
        }
    }

    /// Explicitly refunds the reservation before transferring responsibility.
    pub(crate) async fn refund(&mut self) {
        if self.armed {
            self.state
                .refund(&self.id_hash, &self.secret_id, self.generation)
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
        let secret_id = std::mem::take(&mut self.secret_id);
        let generation = self.generation;
        let map = state.map.clone();
        if let Ok(mut map) = map.try_lock() {
            remove_pending(&mut map, &id_hash, &secret_id, generation);
        } else {
            tokio::spawn(async move {
                state.refund(&id_hash, &secret_id, generation).await;
            });
        };
    }
}
