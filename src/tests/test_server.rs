use axum_test::TestServer;
use diesel::{RunQueryDsl, SqliteConnection};

#[cfg(test)]
pub async fn new_test_server() -> (TestServer, crate::AppState) {
    let app_state = crate::app_state::init();

    crate::database::init_db(app_state.clone());

    let app = crate::router::new(app_state.clone());

    let mut connection = crate::database::establish_connection(app_state.clone().database_url);
    clear_table_secret(&mut connection).await;

    (TestServer::new(app).unwrap(), app_state)
}

pub async fn clear_table_secret(connection: &mut SqliteConnection) {
    let _ = diesel::delete(crate::schema::secret::table).execute(connection);
}
