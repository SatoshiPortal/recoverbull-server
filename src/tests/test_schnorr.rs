use nostr::secp256k1::{Keypair, Secp256k1};

use crate::schnorr;

#[tokio::test]
async fn test_sign() {
    let secret =
        hex::decode("5ee1c8000ab28edd64d74a7d951ac2dd559814887b1b9e1ac7c5f89e96125c12").unwrap();

    let mut message = [0u8; 32];
    message.copy_from_slice(&hex::decode("4b697394206581b03ca5222b37449a9cdca1741b122d78defc177444e2536f49").unwrap());

    let mut expected_signature = [0u8; 64];
    expected_signature.copy_from_slice(&hex::decode("797c47bef50eff748b8af0f38edcb390facf664b2367d72eb71c50b5f37bc83c4ae9cc9007e8489f5f63c66a66e101fd1515d0a846385953f5f837efb9afe885").unwrap());

    let secp = Secp256k1::new();
    let keys = Keypair::from_seckey_slice(&secp,&secret).unwrap();
    let public_key = keys.x_only_public_key().0.serialize();

    let is_valid = schnorr::verify(&public_key, message, &expected_signature).unwrap();
    assert!(is_valid);
}
