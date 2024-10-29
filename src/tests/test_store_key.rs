// use axum::http::StatusCode;

// use crate::tests::SHA256_123456;

// #[tokio::test]
// async fn test_success_created() {
//     let server = crate::tests::test_server::new_test_server();

//     let response = server
//         .post(&"/store_key")
//         .json(&crate::models::StoreKey {
//             backup_key: "a backup key".to_string(),
//             secret: SHA256_123456.to_string(),
//         })
//         .expect_success()
//         .await;

//     assert_eq!(response.status_code(), StatusCode::CREATED);
// }

// #[tokio::test]
// async fn test_failure_backup_key_duplicated() {
//     let server = crate::tests::test_server::new_test_server();

//     let key = &crate::models::StoreKey {
//         backup_key: "duplicate".to_string(),
//         secret: SHA256_123456.to_string(),
//     };

//     server.post(&"/store_key").json(key).expect_success().await;
//     let duplicate = server.post(&"/store_key").json(key).expect_failure().await;
//     assert_eq!(duplicate.status_code(), StatusCode::FORBIDDEN);
// }

// #[tokio::test]
// async fn test_failure_secret_not_64_letters() {
//     let server = crate::tests::test_server::new_test_server();

//     let response = server
//         .post(&"/store_key")
//         .json(&crate::models::StoreKey {
//             backup_key: "random".to_string(),
//             secret: "not-64-chars".to_string(),
//         })
//         .expect_failure()
//         .await;

//     assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
// }

// #[tokio::test]
// async fn test_failure_secret_not_base16_chars() {
//     let server = crate::tests::test_server::new_test_server();

//     let response = server
//         .post(&"/store_key")
//         .json(&crate::models::StoreKey {
//             backup_key: "random".to_string(),
//             secret: "zd969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c9z".to_string(),
//         })
//         .expect_failure()
//         .await;

//     assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
// }
