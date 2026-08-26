//! Shared digest primitives used by recovery identifiers and telemetry.

use sha2::{Digest, Sha256};

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
