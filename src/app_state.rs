use chrono::Duration;
use dotenv::dotenv;
use std::{collections::HashMap, env, sync::Arc};
use tokio::sync::Mutex;

use crate::{
    utils::{get_secret_key_from_dotenv, get_test_server_public_key},
    AppState,
};

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
