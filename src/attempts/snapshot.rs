//! Serialized attempt snapshot values and their public timestamp precision.

use crate::{attempts::ledger::AttemptsLedgerState, digest::sha256_hex};
use chrono::DurationRound;
use flate2::{write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::sync::{watch, Mutex};

/// Immutable gzip snapshot shared by all requests until the TTL expires.
#[derive(Clone)]
pub(crate) struct AttemptsSnapshotCache {
    /// Transport-neutral shared ownership; Axum converts this at the HTTP boundary.
    pub(crate) gzip_body: Arc<[u8]>,
    pub(crate) etag: String,
    pub(crate) created_at: Instant,
}

type AttemptsBuildReceiver = watch::Receiver<Option<Result<AttemptsSnapshotCache, ()>>>;

type AttemptsBuildSlot = Arc<Mutex<Option<AttemptsBuildReceiver>>>;

/// Releases the single-flight slot when a build task ends, on every path
/// including an unwind.
///
/// The slot must not outlive its build task. A slot still holding the
/// receiver of a task that died without sending makes every later
/// `/attempts` request clone that receiver, observe a dropped sender, and
/// return `500` — permanently, because a new build is only started when the
/// slot is empty. Clearing on `Drop` bounds that failure to the requests
/// already waiting on the dead build.
struct BuildSlotGuard {
    build: AttemptsBuildSlot,
}

impl Drop for BuildSlotGuard {
    /// Drop cannot await, so it releases the slot immediately when the lock is
    /// free and defers to a task when another operation owns it.
    fn drop(&mut self) {
        if let Ok(mut slot) = self.build.try_lock() {
            *slot = None;
        } else {
            let build = self.build.clone();
            tokio::spawn(async move {
                *build.lock().await = None;
            });
        }
    }
}

#[cfg(test)]
#[derive(Default)]
/// Test-only single-flight probe; cfg(test) excludes synchronization controls
/// from release builds.
pub(crate) struct AttemptsBuildProbe {
    pub(crate) started: std::sync::atomic::AtomicUsize,
    pub(crate) hold: std::sync::atomic::AtomicBool,
    pub(crate) released: std::sync::atomic::AtomicBool,
    pub(crate) started_notify: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
    /// Forces the build task to unwind before it can publish a result, so a
    /// test can prove the single-flight slot is still released.
    pub(crate) panic_before_send: std::sync::atomic::AtomicBool,
    /// Where the build pauses so a test can interleave a real wipe with a
    /// build that already holds a pre-wipe copy of the ledger. Zero pauses
    /// nowhere; see the `PAUSE_*` constants for the two positions.
    pub(crate) pause_point: std::sync::atomic::AtomicU8,
    pub(crate) paused_notify: tokio::sync::Notify,
    pub(crate) resume: tokio::sync::Notify,
}

#[cfg(test)]
/// Pause after the ledger has been projected, before the collection marker
/// is read: a wipe here leaves the build holding pre-wipe entries and about
/// to read the post-wipe marker.
pub(crate) const PAUSE_AFTER_LEDGER_COPY: u8 = 1;

#[cfg(test)]
/// Pause after both the entries and the collection marker were read, right
/// before the blocking serialization.
pub(crate) const PAUSE_AFTER_COLLECTION_READ: u8 = 2;

#[cfg(test)]
impl AttemptsBuildProbe {
    async fn pause_at(&self, point: u8) {
        if self.pause_point.load(Ordering::SeqCst) == point {
            self.paused_notify.notify_one();
            self.resume.notified().await;
        }
    }
}

/// Outcome of one build attempt, decided under the cache lock.
enum BuildOutcome {
    /// The snapshot was built from the current collection and is now cached.
    Published(AttemptsSnapshotCache),
    /// A wipe ran between the ledger copy and publication: the copy holds
    /// pre-wipe entries and was discarded without touching the cache.
    Stale,
    /// Serialization or compression failed.
    Failed,
}

/// How many times a build task retries after a wipe made its copy stale.
/// Wipes are 24 hours apart, so one retry is only ever exercised by tests.
const STALE_BUILD_RETRIES: usize = 1;

#[derive(Clone)]
/// Shared cache, single-flight watcher, collection clock, and TTL.
pub(crate) struct AttemptsSnapshotState {
    cache: Arc<Mutex<Option<AttemptsSnapshotCache>>>,
    build: AttemptsBuildSlot,
    collection_started_at: Arc<Mutex<chrono::DateTime<chrono::Utc>>>,
    /// Generation of the in-memory collection, advanced by every wipe under
    /// the cache lock. A build captures it before copying the ledger and may
    /// publish only if it is unchanged when the cache lock is next taken, so
    /// a copy made before a wipe can never be served after it. This is the
    /// retention boundary the wipe promises; without it, the wipe merely
    /// invalidated the cache and a build already in flight refilled it with
    /// purged entries.
    wipe_epoch: Arc<AtomicU64>,
    ttl: std::time::Duration,
    #[cfg(test)]
    probe: Arc<AttemptsBuildProbe>,
}

impl AttemptsSnapshotState {
    /// Creates an empty cache with a fixed validated TTL.
    pub(crate) fn new(ttl: std::time::Duration) -> Self {
        Self {
            cache: Arc::new(Mutex::new(None)),
            build: Arc::new(Mutex::new(None)),
            collection_started_at: Arc::new(Mutex::new(chrono::Utc::now())),
            wipe_epoch: Arc::new(AtomicU64::new(0)),
            ttl,
            #[cfg(test)]
            probe: Arc::new(AttemptsBuildProbe::default()),
        }
    }

    /// Returns the UTC start of the current telemetry collection window.
    pub(crate) async fn collection_started_at(&self) -> chrono::DateTime<chrono::Utc> {
        *self.collection_started_at.lock().await
    }

    /// Returns a fresh-or-cached immutable gzip snapshot for one request.
    pub(crate) async fn snapshot_for_request(
        &self,
        ledger: &AttemptsLedgerState,
        cooldown: chrono::TimeDelta,
    ) -> Result<AttemptsSnapshotCache, ()> {
        // Fast path clones O(1) `Arc<[u8]>`; the expensive map copy and gzip work
        // happen outside the cache and build mutexes.
        {
            let cached = self.cache.lock().await;
            if let Some(snapshot) = cached.as_ref() {
                if snapshot.created_at.elapsed() < self.ttl {
                    return Ok(snapshot.clone());
                }
            }
        }
        // `watch` makes all concurrent callers observe one build (single
        // flight), while the TTL bounds how long its immutable result lives.
        let mut build_slot = self.build.lock().await;
        let mut receiver = if let Some(receiver) = build_slot.as_ref() {
            receiver.clone()
        } else {
            let (sender, receiver) = watch::channel(None);
            *build_slot = Some(receiver.clone());
            let snapshot_state = self.clone();
            let ledger = ledger.clone();
            tokio::spawn(async move {
                // The guard lives in an inner scope so it drops *before*
                // `sender`, on the success path and while unwinding alike. A
                // waiter therefore never observes a failed build while the
                // slot it would have to replace is still occupied.
                let result = {
                    let _slot = BuildSlotGuard {
                        build: snapshot_state.build.clone(),
                    };
                    let mut result = Err(());
                    for _ in 0..=STALE_BUILD_RETRIES {
                        match snapshot_state.build_and_publish(&ledger, cooldown).await {
                            BuildOutcome::Published(snapshot) => {
                                result = Ok(snapshot);
                                break;
                            }
                            // Rebuild from the post-wipe ledger rather than
                            // fail every waiter for a benign race.
                            BuildOutcome::Stale => continue,
                            BuildOutcome::Failed => break,
                        }
                    }
                    result
                };
                let _ = sender.send(Some(result));
            });
            receiver
        };
        drop(build_slot);
        receiver.changed().await.map_err(|_| ())?;
        let result = match receiver.borrow().clone() {
            Some(result) => result,
            None => Err(()),
        };
        result
    }

    /// Builds from the current collection and publishes only if no wipe ran
    /// in between. The epoch is compared under the cache lock, which the
    /// wipe holds while advancing it, so the check and the publication are
    /// one atomic decision.
    async fn build_and_publish(
        &self,
        ledger: &AttemptsLedgerState,
        cooldown: chrono::TimeDelta,
    ) -> BuildOutcome {
        let epoch = self.wipe_epoch.load(Ordering::SeqCst);
        let Ok(snapshot) = self.build(ledger, cooldown).await else {
            return BuildOutcome::Failed;
        };
        let mut cache = self.cache.lock().await;
        if self.wipe_epoch.load(Ordering::SeqCst) != epoch {
            return BuildOutcome::Stale;
        }
        *cache = Some(snapshot.clone());
        BuildOutcome::Published(snapshot)
    }

    async fn build(
        &self,
        ledger: &AttemptsLedgerState,
        cooldown: chrono::TimeDelta,
    ) -> Result<AttemptsSnapshotCache, ()> {
        #[cfg(test)]
        {
            self.probe.started.fetch_add(1, Ordering::SeqCst);
            self.probe.started_notify.notify_one();
            if self.probe.hold.load(Ordering::SeqCst) && !self.probe.released.load(Ordering::SeqCst)
            {
                self.probe.release.notified().await;
            }
            if self.probe.panic_before_send.load(Ordering::SeqCst) {
                panic!("attempts build probe: forced unwind before send");
            }
        }
        ledger.retain_active(cooldown).await;
        let projected = ledger.snapshot_entries().await;
        #[cfg(test)]
        self.probe.pause_at(PAUSE_AFTER_LEDGER_COPY).await;
        let mut entries: Vec<AttemptEntry> = projected
            .into_iter()
            .map(|entry| AttemptEntry {
                id_hash: entry.id_hash,
                total_attempts: entry.candidate_count,
                failed_attempts: entry.failed_candidates,
                total_requests: entry.total_requests,
                window_started_at: truncate_to_hour(entry.window_started_at),
                last_attempt_at: truncate_to_hour(entry.last_candidate_at),
            })
            .collect();
        entries.sort_by(|a, b| a.id_hash.cmp(&b.id_hash));
        let collection_started_at = truncate_to_hour(self.collection_started_at().await);
        #[cfg(test)]
        self.probe.pause_at(PAUSE_AFTER_COLLECTION_READ).await;
        let payload = AttemptsSnapshot {
            version: 1,
            collection_started_at,
            entries,
        };
        tokio::task::spawn_blocking(move || {
            let raw = serde_json::to_vec(&payload).expect("attempts snapshot is serializable");
            let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
            encoder.write_all(&raw).map_err(|_| ())?;
            let gzip = encoder.finish().map_err(|_| ())?;
            Ok(AttemptsSnapshotCache {
                etag: format!("\"{}\"", sha256_hex(&gzip)),
                gzip_body: Arc::from(gzip.into_boxed_slice()),
                created_at: Instant::now(),
            })
        })
        .await
        .map_err(|_| ())?
    }

    /// Wipes ledger telemetry and invalidates the cached representation.
    pub(crate) async fn clear_and_reset_collection(
        &self,
        ledger: &AttemptsLedgerState,
        now: chrono::DateTime<chrono::Utc>,
    ) -> usize {
        let mut cache = self.cache.lock().await;
        let count = ledger
            .clear_and_reset_collection(&self.collection_started_at, now)
            .await;
        // Advanced under the cache lock: any build that copied the ledger
        // before this point observes the change when it tries to publish.
        self.wipe_epoch.fetch_add(1, Ordering::SeqCst);
        *cache = None;
        count
    }

    /// Computes a positive HTTP cache lifetime remaining under the TTL.
    pub(crate) fn remaining_max_age(&self, created_at: Instant) -> u64 {
        let remaining = self.ttl.saturating_sub(created_at.elapsed());
        (remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0)).max(1)
    }

    #[cfg(test)]
    pub(crate) fn probe(&self) -> &AttemptsBuildProbe {
        &self.probe
    }

    #[cfg(test)]
    /// Test-only TTL control for deterministic rebuild tests.
    pub(crate) fn set_ttl_for_test(&mut self, ttl: std::time::Duration) {
        self.ttl = ttl;
    }

    #[cfg(test)]
    /// Test-only cache observation for wipe assertions.
    pub(crate) async fn is_cached_for_test(&self) -> bool {
        self.cache.lock().await.is_some()
    }
}

#[derive(Serialize, Deserialize)]
/// One privacy-preserving identifier entry in the HTTP snapshot.
pub(crate) struct AttemptEntry {
    /// SHA-256 of the raw identifier bytes, so clients can recognize their
    /// own identifier without exposing it (pre-image resistance).
    pub(crate) id_hash: String,
    /// Total distinct candidates in the current cooldown window.
    pub(crate) total_attempts: u8,
    pub(crate) failed_attempts: u8,
    pub(crate) total_requests: u64,
    /// Hour-truncated: exact timestamps would ease correlation.
    pub(crate) window_started_at: chrono::DateTime<chrono::Utc>,
    /// Compatibility field name; this is the hour-truncated last distinct
    /// candidate timestamp, never the timestamp of a replay request.
    pub(crate) last_attempt_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize)]
/// Versioned `/attempts` payload; timestamps are intentionally hour-truncated.
pub(crate) struct AttemptsSnapshot {
    pub(crate) version: u8,
    /// Hour-truncated start of the in-memory collection. A changed value
    /// tells clients to reset their baseline after startup or global wipe.
    pub(crate) collection_started_at: chrono::DateTime<chrono::Utc>,
    pub(crate) entries: Vec<AttemptEntry>,
}

/// Truncates a UTC timestamp to the precision promised by the telemetry API.
pub(crate) fn truncate_to_hour(
    timestamp: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    timestamp
        .duration_trunc(chrono::Duration::hours(1))
        .expect("hour truncation of a valid timestamp")
}
