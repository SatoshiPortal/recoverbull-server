use crate::{
    env::get_test_server_public_key, models::{EncryptedRequest, FetchSecret, SignedResponse, StoreSecret}, nip44::encrypt_body, schnorr::verify, tests::{
         BASE64_ENCRYPTED_SECRET, CLIENT_SECRET_KEY, SHA256_111111, SHA256_222222
    }
};
use axum::http::StatusCode;
use base64::{prelude::BASE64_STANDARD, Engine};
use nostr::key::Keys;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn test_trash_success_signature_refetch() {
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

    let encrypted_body = encrypt_body(&client_secret_key, &server_public_key, body.clone()).unwrap();

    let response = server
        .post("/trash")
        .json(&EncryptedRequest {
            public_key: client_keys.public_key().to_hex(),
            encrypted_body,
        })
        .expect_success()
        .await;

    assert_eq!(response.status_code(), StatusCode::ACCEPTED);

    let encrypted_response:String = response.json::<SignedResponse>().response;
    let encrypted_response_signature:String = response.json::<SignedResponse>().signature;
    let encrypted_response_bytes = BASE64_STANDARD.decode(encrypted_response.clone()).unwrap();
    let hash_encryped_response: [u8; 32] = Sha256::digest(&encrypted_response_bytes).into();

    let is_valid = verify(&server_public_key, hash_encryped_response, &hex::decode(encrypted_response_signature).unwrap()).unwrap();
    assert_eq!(is_valid, true);

    // re-attempt to /fetch this should fail
    let encrypted_body = encrypt_body(&client_secret_key, &server_public_key, body).unwrap();
     server
    .post("/fetch")
    .json(&EncryptedRequest {
        public_key: client_keys.public_key().to_hex(),
        encrypted_body,
    })
    .expect_failure()
    .await;
}
