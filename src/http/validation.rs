//! HTTP input validation owned by the request boundary.

use base64::{prelude::BASE64_STANDARD, Engine};

pub(crate) fn is_base64(input: &str) -> bool {
    if !input.len().is_multiple_of(4) {
        return false;
    }
    BASE64_STANDARD.decode(input).is_ok()
}
