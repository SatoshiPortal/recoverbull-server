use chrono::Duration;
use dotenv::dotenv;
use std::{collections::HashMap, env, sync::Arc};
use tokio::sync::Mutex;

use crate::AppState;

pub fn init() -> AppState {
    dotenv().ok();

    let server_addr: String = env::var("SERVER_ADDRESS").expect("SERVER_ADDRESS must be set");
    let rate_limit_cooldown = env::var("RATE_LIMIT_COOLDOWN").expect("RATE_LIMIT_COOLDOWN must be set");
    let secret_max_length = env::var("SECRET_MAX_LENGTH").expect("SECRET_MAX_LENGTH must be set");
    env::var("CANARY").expect("CANARY must be set");
    let rate_limit_max_failed_attempts = env::var("RATE_LIMIT_MAX_FAILED_ATTEMPTS").expect("RATE_LIMIT_MAX_FAILED_ATTEMPTS must be set");

    let database_url = if cfg!(test) {
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set")
    } else {
        env::var("DATABASE_URL").expect("DATABASE_URL must be set")
    };

    let rate_limit_cooldown = match rate_limit_cooldown.parse::<i64>() {
        Ok(number) => number,
        Err(e) => {
            println!("Error: RATE_LIMIT_COOLDOWN must be a integer: {}", e);
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

    let rate_limit_max_failed_attempts = match rate_limit_max_failed_attempts.parse::<u8>() {
        Ok(number) => number,
        Err(e) => {
            println!("Error: RATE_LIMIT_MAX_FAILED_ATTEMPTS must be a u8: {}", e);
            std::process::exit(1);
        }
    };

    AppState {
        server_address: server_addr,
        database_url,
        rate_limit_cooldown: Duration::minutes(rate_limit_cooldown as i64),
        identifier_rate_limit: Arc::new(Mutex::new(HashMap::new())),
        secret_max_length,
        rate_limit_max_failed_attempts,
    }
}
