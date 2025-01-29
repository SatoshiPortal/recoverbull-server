use chrono::Duration;
use dotenv::dotenv;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, env, sync::Arc};
use tokio::sync::Mutex;

use crate::AppState;

fn is_hex(input: &str) -> bool {
    input.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_length(length: usize, input: &str) -> bool {
    input.len() == length
}

pub fn is_sha256_hash(input: &str) -> bool {
     is_length(64, input) && is_hex(input) 
}

pub fn init() -> AppState {
    dotenv().ok();

    let keychain_addr: String = env::var("KEYCHAIN_ADDRESS").expect("KEYCHAIN_ADDRESS must be set");
    let request_cooldown = env::var("REQUEST_COOLDOWN").expect("REQUEST_COOLDOWN must be set");

    let database_url;
    if cfg!(test) {
        database_url = env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");
    } else {
        database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    }

    let cooldown = match request_cooldown.parse::<i64>() {
        Ok(number) => number,
        Err(e) => {
            println!("Error: REQUEST_COOLDOWN must be a integer: {}", e);
            std::process::exit(1);
        }
    };

    return AppState {
        keychain_address: keychain_addr,
        database_url: database_url,
        cooldown: Duration::minutes(cooldown),
        key_access_time: Arc::new(Mutex::new(HashMap::new())),
    };
}

pub fn generate_secret_id(identifier: &String, authentication_key: &String) -> String {
    let mut identifier_and_authentication_key = Vec::new();
    identifier_and_authentication_key.extend_from_slice(&identifier.as_bytes());
    identifier_and_authentication_key.extend_from_slice(&authentication_key.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&identifier_and_authentication_key);

    let secret_id = hasher.finalize();
    return hex::encode(secret_id);
}
