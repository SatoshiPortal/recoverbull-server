use std::error::Error;

use nostr::secp256k1::{schnorr::Signature, Keypair, Message, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

pub fn sign(secret_key: &[u8],message: [u8; 32]) -> Result<[u8; 64], Box<dyn Error>> {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(message);
    let keypair = Keypair::from_seckey_slice(&secp, secret_key)?;

    let signature = secp.sign_schnorr(&msg, &keypair);
    Ok(signature.serialize())
}


pub fn sha256_and_sign(secret_key: &[u8],payload: &[u8]) -> Result<[u8; 64], Box<dyn Error>> {
    let hash_payload: [u8; 32] = Sha256::digest(&payload).into();
    return sign(secret_key, hash_payload);
}

#[allow(dead_code)] // used for unit tests
pub fn verify(
    public_key: &[u8],
    message: [u8; 32],
    signature: &[u8]
) -> Result<bool, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(message);

    let xonly_pubkey = XOnlyPublicKey::from_slice(public_key)?;
    let signature = Signature::from_slice(signature)?;

    Ok(secp.verify_schnorr(&signature, &msg, &xonly_pubkey).is_ok())
}