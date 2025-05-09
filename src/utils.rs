use base64::{prelude::BASE64_STANDARD, Engine};
use sha2::{Digest, Sha256};

fn is_hex(input: &str) -> bool {
    input.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_base64(input: &str) -> bool {
    if input.len() % 4 != 0 {
        return false;
    }
    BASE64_STANDARD.decode(input).is_ok()
}

fn is_length(length: usize, input: &str) -> bool {
    input.len() == length
}

pub fn is_256bits_hex_hash(input: &str) -> bool {
    is_length(64, input) && is_hex(input)
}

pub fn generate_secret_id(identifier: &str, authentication_key: &str) -> String {
    let mut identifier_and_authentication_key = Vec::new();
    identifier_and_authentication_key.extend_from_slice(identifier.as_bytes());
    identifier_and_authentication_key.extend_from_slice(authentication_key.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&identifier_and_authentication_key);

    let secret_id = hasher.finalize();
    hex::encode(secret_id)
}
