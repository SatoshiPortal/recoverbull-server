#[test]
fn test_application_connection_enables_secure_delete() {
    use diesel::{QueryableByName, RunQueryDsl};

    #[derive(QueryableByName)]
    struct PragmaValue {
        #[diesel(sql_type = diesel::sql_types::Integer)]
        value: i32,
    }
    let state = crate::env::init();
    let mut connection = crate::database::establish_connection(state.database_url);
    let value = diesel::sql_query("SELECT secure_delete AS value FROM pragma_secure_delete")
        .get_result::<PragmaValue>(&mut connection)
        .unwrap();
    assert_eq!(value.value, 1);
}
