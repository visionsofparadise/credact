use crypto_box::aead::rand_core::RngCore;
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey};

pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 24;

pub fn generate_secret_key() -> SecretKey {
    SecretKey::generate(&mut OsRng)
}

pub fn random_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];

    OsRng.fill_bytes(&mut nonce);

    nonce
}

pub fn session_box_of(their_public_key: &[u8], secret_key: &SecretKey) -> Option<SalsaBox> {
    let public_key = PublicKey::from_slice(their_public_key).ok()?;

    Some(SalsaBox::new(&public_key, secret_key))
}

pub fn seal(
    session: &SalsaBox,
    nonce: &[u8; NONCE_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>, crypto_box::aead::Error> {
    session.encrypt(Nonce::from_slice(nonce), plaintext)
}

pub fn open(session: &SalsaBox, nonce: &[u8; NONCE_LENGTH], ciphertext: &[u8]) -> Option<Vec<u8>> {
    session.decrypt(Nonce::from_slice(nonce), ciphertext).ok()
}

pub fn increment_nonce(nonce: &[u8; NONCE_LENGTH]) -> [u8; NONCE_LENGTH] {
    let mut next = *nonce;

    for byte in next.iter_mut() {
        let (sum, overflowed) = byte.overflowing_add(1);

        *byte = sum;

        if !overflowed {
            break;
        }
    }

    next
}

#[cfg(test)]
#[path = "keepassxc_box.test.rs"]
mod tests;
