use chrono::Duration;
use dotenv::dotenv;
use std::{collections::HashMap, env, sync::Arc};
use tokio::sync::Mutex;

use crate::AppState;

pub fn init() -> AppState {
    dotenv().ok();

    let server_addr: String = env::var("SERVER_ADDRESS").expect("SERVER_ADDRESS must be set");
    let request_cooldown = env::var("REQUEST_COOLDOWN").expect("REQUEST_COOLDOWN must be set");
    let secret_max_length = env::var("SECRET_MAX_LENGTH").expect("SECRET_MAX_LENGTH must be set");
    env::var("CANARY").expect("CANARY must be set");
    let max_failed_attempts = env::var("MAX_FAILED_ATTEMPTS").expect("MAX_FAILED_ATTEMPTS must be set");

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

    let max_failed_attempts = match max_failed_attempts.parse::<u8>() {
        Ok(number) => number,
        Err(e) => {
            println!("Error: MAX_FAILED_ATTEMPTS must be a u8: {}", e);
            std::process::exit(1);
        }
    };

    AppState {
        server_address: server_addr,
        database_url,
        cooldown: Duration::minutes(cooldown),
        identifier_access_time: Arc::new(Mutex::new(HashMap::new())),
        secret_max_length,
        max_failed_attempts,
    }
}
