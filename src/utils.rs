pub fn is_sha256_hash(input: &str) -> bool {
    if input.len() != 64 || !input.chars().all(|c| c.is_digit(16)) {
        return false;
    }
    return true;
}
