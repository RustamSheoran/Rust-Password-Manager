use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m: 65_536,
            t: 3,
            p: 1,
        }
    }
}

pub fn derive_key(master: &SecretString, salt: &[u8], params: KdfParams) -> Result<[u8; KEY_LEN]> {
    let argon_params = Params::new(params.m, params.t, params.p, Some(KEY_LEN))
        .map_err(|error| AppError::Crypto(format!("invalid Argon2 parameters: {error}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = [0u8; KEY_LEN];

    argon
        .hash_password_into(master.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|error| AppError::Crypto(format!("failed to derive key: {error}")))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{KdfParams, derive_key};

    #[test]
    fn derives_stable_key_for_same_inputs() {
        let password = SecretString::new("correct horse battery staple".into());
        let salt = [42u8; 16];
        let params = KdfParams::default();

        let first = derive_key(&password, &salt, params).expect("derive first");
        let second = derive_key(&password, &salt, params).expect("derive second");

        assert_eq!(first, second);
    }

    #[test]
    fn changing_salt_changes_key() {
        let password = SecretString::new("correct horse battery staple".into());
        let params = KdfParams::default();

        let first = derive_key(&password, &[1u8; 16], params).expect("derive first");
        let second = derive_key(&password, &[2u8; 16], params).expect("derive second");

        assert_ne!(first, second);
    }
}
