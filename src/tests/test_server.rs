// use axum_test::TestServer;
// use diesel::RunQueryDsl;

// #[cfg(test)]
// pub fn new_test_server() -> TestServer {
//     crate::utils::init();
//     crate::database::init_db();

//     let mut connection = crate::database::establish_connection();
//     let _ = diesel::delete(crate::schema::key::table).execute(&mut connection);

//     let app = crate::router::new();
//     return TestServer::new(app).unwrap();
// }
