use axum_test::TestServer;
use diesel::{RunQueryDsl, SqliteConnection};
use std::time::Duration;

#[cfg(test)]
pub async fn new_test_server() -> (TestServer, crate::AppState) {
    new_test_server_with_delay(Duration::ZERO).await
}

pub async fn new_test_server_with_delay(response_delay: Duration) -> (TestServer, crate::AppState) {
    let app_state = crate::env::init();

    crate::database::init_db(app_state.clone());

    let app = crate::router::new_with_response_delay(app_state.clone(), response_delay);

    let mut connection = crate::database::establish_connection(app_state.clone().database_url);
    clear_table_secret(&mut connection).await;

    (TestServer::new(app).unwrap(), app_state)
}

pub async fn clear_table_secret(connection: &mut SqliteConnection) {
    let _ = diesel::delete(crate::schema::secret::table).execute(connection);
}
