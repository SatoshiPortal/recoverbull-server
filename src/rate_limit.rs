//! Global token-bucket implementation for unauthenticated request damping.

use std::time::Instant;

/// Smallest backoff ever advertised. A rounded-up estimate below one second
/// would tell a client to retry immediately at the boundary. A bucket without
/// refill has no deadline at all and gets this advisory value; startup
/// refuses such a configuration, so that case is reachable only from a test.
const ADVISORY_RETRY_AFTER_SECS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Outcome of one admission attempt, decided under the bucket owner's lock.
pub enum BucketDecision {
    /// One token was consumed.
    Consumed,
    /// The bucket was empty. `retry_after_secs` is the server's estimate, at
    /// the moment of refusal and from the same state, of when one token will
    /// exist: the missing fraction of a token divided by the refill rate,
    /// rounded up, never below one second. It is an estimate, not a
    /// reservation; a concurrent request may take the token first.
    Rejected { retry_after_secs: u64 },
}

/// A simple global token bucket, used to dampen unauthenticated writes.
/// Behind an onion service every connection arrives from 127.0.0.1, so
/// per-IP limiting is useless: the bucket is deliberately global. It slows
/// database growth; it is not a wall — legitimate backup flows need a
/// couple of writes each and never notice it.
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_second: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Creates a full bucket with the configured capacity and refill rate.
    pub fn new(capacity: f64, refill_per_second: f64) -> Self {
        Self::new_at(capacity, refill_per_second, Instant::now())
    }

    /// Creates a full bucket whose clock starts at `now`. Production passes
    /// the current instant through `new`; tests inject one so refill can be
    /// exercised exactly, without sleeping.
    pub fn new_at(capacity: f64, refill_per_second: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_second,
            last_refill: now,
        }
    }

    /// Refills the tokens elapsed since the last call, then tries to
    /// consume one.
    pub fn try_consume(&mut self) -> BucketDecision {
        self.try_consume_at(Instant::now())
    }

    /// Refills the tokens elapsed between the last call and `now`, then tries
    /// to consume one. The decision and its backoff are computed from the same
    /// state, so a handler never re-reads a bucket that may have changed.
    pub fn try_consume_at(&mut self, now: Instant) -> BucketDecision {
        // A reading older than the last refill (impossible on the monotonic
        // clock, but harmless) contributes nothing and does not rewind.
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        self.last_refill = self.last_refill.max(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            BucketDecision::Consumed
        } else {
            BucketDecision::Rejected {
                retry_after_secs: self.retry_after_secs(),
            }
        }
    }

    /// Seconds until the current deficit refills, rounded up and floored at
    /// the advisory minimum. Startup rejects a non-positive configured rate,
    /// so the guard below only covers a bucket built directly by a test.
    fn retry_after_secs(&self) -> u64 {
        if self.refill_per_second <= 0.0 {
            return ADVISORY_RETRY_AFTER_SECS;
        }
        let deficit = (1.0 - self.tokens).max(0.0);
        let seconds = (deficit / self.refill_per_second).ceil();
        if seconds.is_finite() {
            // `as` saturates, so an absurd estimate stays an integer.
            (seconds as u64).max(ADVISORY_RETRY_AFTER_SECS)
        } else {
            ADVISORY_RETRY_AFTER_SECS
        }
    }
}
