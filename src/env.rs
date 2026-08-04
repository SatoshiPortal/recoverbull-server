use chrono::Duration;
use dotenv::dotenv;
use std::{collections::HashMap, env, sync::Arc};
use tokio::sync::Mutex;

use crate::AppState;

/// Validates the security-critical configuration values.
///
/// A non-positive rate-limit cooldown would silently disable rate-limiting
/// entirely (the cooldown check would always be elapsed), and a zero
/// max_failed_attempts or secret_max_length makes the service unusable.
/// The server must refuse to start rather than run degraded.
pub fn validate_config(
    rate_limit_cooldown: i64,
    secret_max_length: usize,
    rate_limit_max_failed_attempts: u8,
) -> Result<(), String> {
    if rate_limit_cooldown <= 0 {
        return Err(format!(
            "RATE_LIMIT_COOLDOWN must be greater than 0, got {}",
            rate_limit_cooldown
        ));
    }
    // chrono::TimeDelta panics on out-of-range values; keep the cooldown
    // within a sane range (at most one year in minutes).
    if rate_limit_cooldown > 525_600 {
        return Err(format!(
            "RATE_LIMIT_COOLDOWN must be at most 525600 minutes (1 year), got {}",
            rate_limit_cooldown
        ));
    }
    if secret_max_length == 0 {
        return Err("SECRET_MAX_LENGTH must be greater than 0".to_string());
    }
    if rate_limit_max_failed_attempts == 0 {
        return Err("RATE_LIMIT_MAX_FAILED_ATTEMPTS must be at least 1".to_string());
    }
    Ok(())
}

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

    if let Err(e) = validate_config(
        rate_limit_cooldown,
        secret_max_length,
        rate_limit_max_failed_attempts,
    ) {
        println!("Error: {}", e);
        std::process::exit(1);
    }

    AppState {
        server_address: server_addr,
        database_url,
        rate_limit_cooldown: Duration::minutes(rate_limit_cooldown as i64),
        identifier_rate_limit: Arc::new(Mutex::new(HashMap::new())),
        secret_max_length,
        rate_limit_max_failed_attempts,
    }
}
