use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{AeadInPlace, OsRng, rand_core::RngCore},
};

use crate::error::{AppError, Result};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
const AAD: &[u8] = b"pass-manager:vault:v1";

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    buffer: &mut Vec<u8>,
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt_in_place(nonce, AAD, buffer)
        .map_err(|_| AppError::Crypto("vault encryption failed".into()))
}

pub fn decrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    buffer: &mut Vec<u8>,
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt_in_place(nonce, AAD, buffer)
        .map_err(|_| AppError::WrongMasterPassword)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroize;

    use super::{decrypt_in_place, encrypt_in_place, random_nonce};

    #[test]
    fn round_trips_ciphertext_in_place() {
        let key = [7u8; 32];
        let nonce = random_nonce();
        let mut payload = br#"{"site":"example.com","secret":"hunter2"}"#.to_vec();

        encrypt_in_place(&key, &nonce, &mut payload).expect("encrypt");
        assert_ne!(payload, br#"{"site":"example.com","secret":"hunter2"}"#);

        decrypt_in_place(&key, &nonce, &mut payload).expect("decrypt");
        assert_eq!(payload, br#"{"site":"example.com","secret":"hunter2"}"#);

        payload.zeroize();
    }
}
