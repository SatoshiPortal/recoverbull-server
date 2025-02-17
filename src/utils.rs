use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::Duration;
use dotenv::dotenv;
use nostr::key::Keys;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, env, sync::Arc};
use tokio::sync::Mutex;

use crate::AppState;

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

pub fn init() -> AppState {
    dotenv().ok();

    let server_addr: String = env::var("SERVER_ADDRESS").expect("SERVER_ADDRESS must be set");
    let request_cooldown = env::var("REQUEST_COOLDOWN").expect("REQUEST_COOLDOWN must be set");
    let secret_max_length = env::var("SECRET_MAX_LENGTH").expect("SECRET_MAX_LENGTH must be set");
    env::var("CANARY").expect("CANARY must be set");
    get_secret_key_from_dotenv(); // Check if SECRET_KEY is set

    println!("SERVER PUBKEY: {}", get_test_server_public_key());

    let database_url = if cfg!(test) {
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set")
    } else {
        env::var("DATABASE_URL").expect("DATABASE_URL must be set")
    };

    let cooldown = match request_cooldown.parse::<i64>() {
        Ok(number) => number,
        Err(e) => {
            println!("Error: REQUEST_COOLDOWN must be a integer: {}", e);
            std::process::exit(1);
        }
    };

    let secret_max_length = match secret_max_length.parse::<usize>() {
        Ok(number) => number,
        Err(e) => {
            println!("Error: SECRET_MAX_LENGTH must be a usize: {}", e);
            std::process::exit(1);
        }
    };

    AppState {
        server_address: server_addr,
        database_url,
        cooldown: Duration::minutes(cooldown),
        identifier_access_time: Arc::new(Mutex::new(HashMap::new())),
        secret_max_length,
    }
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

pub fn get_secret_key_from_dotenv() -> String {
    env::var("SECRET_KEY").expect("SECRET_KEY must be set")
}

pub fn get_test_server_public_key() -> String {
    let secret_key_from_dotenv = get_secret_key_from_dotenv();
    let keys = Keys::parse(&secret_key_from_dotenv).unwrap();
    keys.public_key().to_hex()
}

