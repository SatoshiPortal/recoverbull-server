//! Canonical identifier validation and secret-ID derivation.

use crate::digest::sha256_hex;

fn is_hex(input: &str) -> bool {
    input.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_length(length: usize, input: &str) -> bool {
    input.len() == length
}

pub(crate) fn is_256bits_hex_hash(input: &str) -> bool {
    is_length(64, input) && is_hex(input)
}

pub(crate) fn identifier_hash(identifier: &str) -> Option<String> {
    hex::decode(identifier).ok().map(|raw| sha256_hex(&raw))
}

pub(crate) fn generate_secret_id(identifier: &str, authentication_key: &str) -> String {
    let mut identifier_and_authentication_key = Vec::new();
    identifier_and_authentication_key.extend_from_slice(identifier.as_bytes());
    identifier_and_authentication_key.extend_from_slice(authentication_key.as_bytes());

    sha256_hex(&identifier_and_authentication_key)
}
