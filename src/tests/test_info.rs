use axum::http::StatusCode;
use sha2::{Digest, Sha256};
use crate::{env::get_test_server_public_key, models::{Info, Payload, SignedResponse}, schnorr};

#[tokio::test]
async fn test_info_success_and_verify_signature() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let response = server.get("/info").expect_success().await;

    let signed_response: SignedResponse =
        serde_json::from_str(&response.text()).unwrap();
    let payload: Payload = serde_json::from_str(&signed_response.response).unwrap();
    let info: Info = serde_json::from_str(&payload.data).unwrap();
    
    let signature_bytes = hex::decode(signed_response.signature).unwrap();
    let server_public_key = get_test_server_public_key();

    let payload_hash: [u8; 32] = Sha256::digest(signed_response.response.as_bytes()).into();
    let is_valid = schnorr::verify(&server_public_key, payload_hash, &signature_bytes).unwrap();
   
    assert!(is_valid, "The signature must be valid");

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(info.cooldown, state.cooldown.num_minutes());
    assert_eq!(info.secret_max_length, state.secret_max_length);
    assert_eq!(info.canary, "🐦");
}
