
use nostr::{
    key::{Keys, PublicKey, SecretKey},
    nips::nip44,
};
use std::error::Error;



pub fn decrypt_body(
    secret_key: &str,
    public_key: &str,
    ciphertext: String,
) -> Result<String, Box<dyn Error>> {
    let secret_key = SecretKey::parse(secret_key)?;
    let public_key = PublicKey::from_hex(public_key)?;
    let plaintext = nip44::decrypt(&secret_key, &public_key, ciphertext)?;
    Ok(plaintext)
}

pub fn encrypt_body(
    secret_key: &str,
    public_key: &str,
    plaintext: String,
) -> Result<String, Box<dyn Error>> {
    let keys = Keys::parse(secret_key)?;
    let public_key = PublicKey::from_hex(public_key)?;
    let ciphertext = nip44::encrypt(
        keys.secret_key(),
        &public_key,
        plaintext,
        nip44::Version::V2,
    )?;
    Ok(ciphertext)
}
