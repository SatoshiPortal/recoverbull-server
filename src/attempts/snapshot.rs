//! Serialized attempt snapshot values and their public timestamp precision.

use crate::{attempts::ledger::AttemptsLedgerState, digest::sha256_hex};
use chrono::DurationRound;
use flate2::{write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use std::{io::Write, sync::Arc, time::Instant};
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
}

#[derive(Clone)]
/// Shared cache, single-flight watcher, collection clock, and TTL.
pub(crate) struct AttemptsSnapshotState {
    cache: Arc<Mutex<Option<AttemptsSnapshotCache>>>,
    build: Arc<Mutex<Option<AttemptsBuildReceiver>>>,
    collection_started_at: Arc<Mutex<chrono::DateTime<chrono::Utc>>>,
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
                let result = snapshot_state.build(&ledger, cooldown).await;
                if let Ok(snapshot) = &result {
                    *snapshot_state.cache.lock().await = Some(snapshot.clone());
                }
                let _ = sender.send(Some(result));
                *snapshot_state.build.lock().await = None;
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

    async fn build(
        &self,
        ledger: &AttemptsLedgerState,
        cooldown: chrono::TimeDelta,
    ) -> Result<AttemptsSnapshotCache, ()> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            self.probe.started.fetch_add(1, Ordering::SeqCst);
            self.probe.started_notify.notify_one();
            if self.probe.hold.load(Ordering::SeqCst) && !self.probe.released.load(Ordering::SeqCst)
            {
                self.probe.release.notified().await;
            }
        }
        let now = chrono::Utc::now();
        ledger.retain_active(now, cooldown).await;
        let mut entries: Vec<AttemptEntry> = ledger
            .snapshot_entries()
            .await
            .into_iter()
            .map(|(id_hash, info)| AttemptEntry {
                id_hash,
                total_attempts: info.candidate_count(),
                failed_attempts: info.failed_candidates,
                total_requests: info.total_requests,
                window_started_at: truncate_to_hour(info.window_started_at),
                last_attempt_at: truncate_to_hour(info.last_candidate_at),
            })
            .collect();
        entries.sort_by(|a, b| a.id_hash.cmp(&b.id_hash));
        let payload = AttemptsSnapshot {
            version: 1,
            collection_started_at: truncate_to_hour(self.collection_started_at().await),
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
