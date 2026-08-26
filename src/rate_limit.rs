//! Global token-bucket implementation for unauthenticated request damping.
//!
/// A simple global token bucket, used to dampen unauthenticated writes.
/// Behind an onion service every connection arrives from 127.0.0.1, so
/// per-IP limiting is useless: the bucket is deliberately global. It slows
/// database growth; it is not a wall — legitimate backup flows need a
/// couple of writes each and never notice it.
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_second: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    /// Creates a full bucket with the configured capacity and refill rate.
    pub fn new(capacity: f64, refill_per_second: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_second,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Refills the tokens elapsed since the last call, then tries to
    /// consume one. Returns false when the bucket is empty.
    pub fn try_consume(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
