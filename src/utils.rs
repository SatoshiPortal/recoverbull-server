use dotenv::dotenv;
use std::env;

pub fn is_sha256_hash(input: &str) -> bool {
    if input.len() != 64 || !input.chars().all(|c| c.is_digit(16)) {
        return false;
    }
    return true;
}

pub fn init() {
    dotenv().ok();
    env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    env::var("KEYCHAIN_ADDRESS").expect("KEYCHAIN_ADDRESS must be set");

    let request_cooldown = env::var("REQUEST_COOLDOWN").expect("REQUEST_COOLDOWN must be set");
    match request_cooldown.parse::<i64>() {
        Ok(number) => number,
        Err(e) => {
            println!("Error: REQUEST_COOLDOWN must be a integer: {}", e);
            std::process::exit(1);
        }
    };
}
