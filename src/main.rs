mod database;
mod handlers;
mod models;
mod router;
mod schema;
#[cfg(test)]
mod test;
mod utils;

use std::env;

#[tokio::main]
async fn main() {
    crate::utils::init();

    crate::database::init_db();

    let app = router::new();

    let keychain_address: String =
        env::var("KEYCHAIN_ADDRESS").expect("KEYCHAIN_ADDRESS must be set");

    let listener = tokio::net::TcpListener::bind(keychain_address)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
