use axum_test::TestServer;
use diesel::{RunQueryDsl, SqliteConnection};


#[cfg(test)]
pub async fn new_test_server() -> (TestServer,  diesel::SqliteConnection) {
    let app_state = crate::utils::init();

    crate::database::init_db(app_state.clone());

    let app = crate::router::new(app_state.clone());

    let mut connection = crate::database::establish_connection(app_state.database_url);
    clear_table_secret(&mut connection).await;

    return (TestServer::new(app).unwrap(),   connection);
}

    pub async fn clear_table_secret(connection: &mut SqliteConnection ) {
        let _ = diesel::delete(crate::schema::secret::table).execute(connection);
    }

