use axum_test::TestServer;
use diesel::{RunQueryDsl, SqliteConnection};
use nostr::key::Keys;

use crate::utils::get_secret_key_from_dotenv;

#[cfg(test)]
pub async fn new_test_server() -> (TestServer, crate::AppState) {
    let app_state = crate::utils::init();

    crate::database::init_db(app_state.clone());

    let app = crate::router::new(app_state.clone());

    let mut connection = crate::database::establish_connection(app_state.clone().database_url);
    clear_table_secret(&mut connection).await;

    (TestServer::new(app).unwrap(), app_state)
}

pub fn get_test_server_public_key() -> String {
    let secret_key_from_dotenv = get_secret_key_from_dotenv();
    let keys = Keys::parse(&secret_key_from_dotenv).unwrap();
    keys.public_key().to_hex()
}

pub async fn clear_table_secret(connection: &mut SqliteConnection) {
    let _ = diesel::delete(crate::schema::secret::table).execute(connection);
}
