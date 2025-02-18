use std::error::Error;

use nostr::secp256k1::{Keypair, Message, Secp256k1};

pub fn sign(secret_key: &[u8],message: [u8; 32]) -> Result<[u8; 64], Box<dyn Error>> {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(message);
    let keypair = Keypair::from_seckey_slice(&secp, secret_key)?;

    let signature = secp.sign_schnorr(&msg, &keypair);
    Ok(signature.serialize())
}