use crate::{
    env::get_test_server_public_key, models::{EncryptedRequest, FetchSecret, Payload, Secret, SignedResponse, StoreSecret}, nip44::{decrypt_body, encrypt_body}, schnorr::verify, tests::{
         BASE64_ENCRYPTED_SECRET, CLIENT_SECRET_KEY, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222, SHA256_CONCAT_111111_222222
    }
};
use axum::http::StatusCode;
use base64::{prelude::BASE64_STANDARD, Engine};
use nostr::key::Keys;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn test_fetch_success() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let client_keys = Keys::parse(CLIENT_SECRET_KEY).unwrap();
    let client_secret_key: [u8; 32] = client_keys.secret_key().to_secret_bytes();
    let server_public_key = get_test_server_public_key();

    let body = serde_json::to_string(&StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    })
    .unwrap();

    let encrypted_body: String =
        encrypt_body(&client_secret_key, &server_public_key, body).unwrap();

    server
        .post("/store")
        .json(&EncryptedRequest {
            public_key: client_keys.public_key().to_hex(),
            encrypted_body,
        })
        .expect_success()
        .await;

    let body = serde_json::to_string(&FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    })
    .unwrap();

    let encrypted_body = encrypt_body(&client_secret_key, &server_public_key, body).unwrap();

    let response = server
        .post("/fetch")
        .json(&EncryptedRequest {
            public_key: client_keys.public_key().to_hex(),
            encrypted_body,
        })
        .expect_success()
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let encrypted_response: String = response.json::<SignedResponse>().response;
    let body = decrypt_body(&client_secret_key, &server_public_key, encrypted_response).unwrap();
    let payload: Payload = serde_json::from_str(&body).unwrap();
    let secret: Secret = serde_json::from_str(&payload.data).unwrap();
    
    assert_eq!(secret.id, SHA256_CONCAT_111111_222222);
    assert_eq!(secret.encrypted_secret, BASE64_ENCRYPTED_SECRET);
}

#[tokio::test]
async fn test_fetch_key_failure_invalid_hash_for_format_identifier() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let client_keys = Keys::parse(CLIENT_SECRET_KEY).unwrap();
    let client_secret_key = client_keys.secret_key().to_secret_bytes();
    let server_public_key = get_test_server_public_key();

    let body = serde_json::to_string(&FetchSecret {
        identifier: "not_a_hash".to_string(),
        authentication_key: SHA256_111111.to_string(),
    })
    .unwrap();

    let encrypted_body = encrypt_body(&client_secret_key, &server_public_key, body).unwrap();

    let response = server
        .post("/fetch")
        .json(&EncryptedRequest {
            public_key: client_keys.public_key().to_hex(),
            encrypted_body,
        })
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_fetch_failure_invalid_hash_format_for_authentication_key() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let client_keys = Keys::parse(CLIENT_SECRET_KEY).unwrap();
    let client_secret_key = client_keys.secret_key().to_secret_bytes();
    let server_public_key = get_test_server_public_key();

    let body = serde_json::to_string(&FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: "not_a_hash".to_string(),
    })
    .unwrap();

    let encrypted_body = encrypt_body(&client_secret_key, &server_public_key, body).unwrap();

    let response = server
        .post("/fetch")
        .json(&EncryptedRequest {
            public_key: client_keys.public_key().to_hex(),
            encrypted_body,
        })
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_fetch_failure_too_many_attempts() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let client_keys = Keys::parse(CLIENT_SECRET_KEY).unwrap();
    let client_secret_key = client_keys.secret_key().to_secret_bytes();
    let server_public_key = get_test_server_public_key();

    let store = serde_json::to_string(&StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    })
    .unwrap();

    let encrypted_store: String =
        encrypt_body(&client_secret_key, &server_public_key, store).unwrap();
    server
        .post("/store")
        .json(&EncryptedRequest {
            public_key: client_keys.public_key().to_hex(),
            encrypted_body: encrypted_store,
        })
        .expect_success()
        .await;

    let fetch_wrong_authentication_key = serde_json::to_string(&FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: NOT_PASSWORD_HASH.to_string(), // this should make the fetchy fail
    })
    .unwrap();

    let encrypted_fetch = encrypt_body(
        &client_secret_key,
        &server_public_key,
        fetch_wrong_authentication_key,
    )
    .unwrap();

    // set the cooldown
    server
        .post("/fetch")
        .json(&EncryptedRequest {
            public_key: client_keys.public_key().to_hex(),
            encrypted_body: encrypted_fetch.clone(),
        })
        .expect_failure()
        .await;

    // trigger the cooldown
    let response = server
        .post("/fetch")
        .json(&EncryptedRequest {
            public_key: client_keys.public_key().to_hex(),
            encrypted_body: encrypted_fetch,
        })
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_fetch_signature() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let client_keys = Keys::parse(CLIENT_SECRET_KEY).unwrap();
    let client_secret_key = client_keys.secret_key().to_secret_bytes();
    let server_public_key = get_test_server_public_key();

    let body = serde_json::to_string(&StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    })
    .unwrap();

    let encrypted_body: String =
        encrypt_body(&client_secret_key, &server_public_key, body).unwrap();

    server
        .post("/store")
        .json(&EncryptedRequest {
            public_key: client_keys.public_key().to_hex(),
            encrypted_body,
        })
        .expect_success()
        .await;

    let body = serde_json::to_string(&FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    })
    .unwrap();

    let encrypted_body = encrypt_body(&client_secret_key, &server_public_key, body).unwrap();

    let response = server
        .post("/fetch")
        .json(&EncryptedRequest {
            public_key: client_keys.public_key().to_hex(),
            encrypted_body,
        })
        .expect_success()
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let encrypted_response:String = response.json::<SignedResponse>().response;
    let encrypted_response_signature:String = response.json::<SignedResponse>().signature;
    let encrypted_response_bytes = BASE64_STANDARD.decode(encrypted_response.clone()).unwrap();
    let hash_encryped_response: [u8; 32] = Sha256::digest(&encrypted_response_bytes).into();

    let is_valid = verify(&server_public_key, hash_encryped_response, &hex::decode(encrypted_response_signature).unwrap()).unwrap();
    assert_eq!(is_valid, true);
}
