use chrono::Duration;
use dotenv::dotenv;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, env, sync::Arc};
use tokio::sync::Mutex;

use crate::AppState;

pub fn is_sha256_hash(input: &str) -> bool {
    if input.len() != 64 || !input.chars().all(|c| c.is_digit(16)) {
        return false;
    }
    return true;
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

pub fn generate_key_id(backup_id: &String, secret_hash: &String) -> String {
    let mut backup_id_and_secret_hash = Vec::new();
    backup_id_and_secret_hash.extend_from_slice(&backup_id.as_bytes());
    backup_id_and_secret_hash.extend_from_slice(&secret_hash.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&backup_id_and_secret_hash);

    let key_id = hasher.finalize();
    return hex::encode(key_id);
}
