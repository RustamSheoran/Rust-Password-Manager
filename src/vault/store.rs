use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use hex::{decode, encode};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use zeroize::Zeroize;

use crate::{
    crypto::{
        KdfParams, NONCE_LEN, SALT_LEN, decrypt_in_place, derive_key, encrypt_in_place,
        random_nonce, random_salt,
    },
    error::{AppError, Result},
    security::memory::{secret_from_string, wipe_bytes},
    vault::{Vault, VaultEntry},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultStatus {
    Missing,
    Sealed,
    PlaintextLegacy,
    UnsupportedLegacyEncrypted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadSource {
    Missing,
    Sealed,
    PlaintextLegacy,
}

#[derive(Debug)]
pub struct LoadedVault {
    pub vault: Vault,
    pub source: LoadSource,
}

impl LoadedVault {
    pub fn needs_persist(&self) -> bool {
        matches!(self.source, LoadSource::PlaintextLegacy)
    }
}

#[derive(Debug, Clone)]
pub struct VaultStore {
    path: PathBuf,
}

impl VaultStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn status(&self) -> Result<VaultStatus> {
        let Some(raw) = self.read_raw()? else {
            return Ok(VaultStatus::Missing);
        };

        if serde_json::from_str::<VaultBlob>(&raw).is_ok() {
            return Ok(VaultStatus::Sealed);
        }

        if serde_json::from_str::<LegacyEncryptedStore>(&raw).is_ok() {
            return Ok(VaultStatus::UnsupportedLegacyEncrypted);
        }

        if serde_json::from_str::<LegacyVault>(&raw).is_ok() {
            return Ok(VaultStatus::PlaintextLegacy);
        }

        Err(AppError::InvalidVault)
    }

    pub fn load(&self, master: Option<&SecretString>) -> Result<LoadedVault> {
        let Some(raw) = self.read_raw()? else {
            return Ok(LoadedVault {
                vault: Vault::default(),
                source: LoadSource::Missing,
            });
        };

        if let Ok(blob) = serde_json::from_str::<VaultBlob>(&raw) {
            let master = master.ok_or(AppError::VaultUninitialized)?;
            let vault = self.decrypt_blob(blob, master)?;
            debug!(path = %self.path.display(), "loaded encrypted vault");
            return Ok(LoadedVault {
                vault,
                source: LoadSource::Sealed,
            });
        }

        if serde_json::from_str::<LegacyEncryptedStore>(&raw).is_ok() {
            return Err(AppError::UnsupportedLegacy(
                "the previous custom-crypto format cannot be opened by this build".into(),
            ));
        }

        let legacy =
            serde_json::from_str::<LegacyVault>(&raw).map_err(|_| AppError::InvalidVault)?;
        let vault = self.convert_legacy(legacy);
        info!(path = %self.path.display(), "loaded plaintext legacy vault");

        Ok(LoadedVault {
            vault,
            source: LoadSource::PlaintextLegacy,
        })
    }

    pub fn save(&self, master: &SecretString, vault: &Vault) -> Result<()> {
        let kdf = KdfParams::default();
        let salt = random_salt();
        let nonce = random_nonce();
        let mut key = derive_key(master, &salt, kdf)?;
        let mut plaintext = serde_json::to_vec(vault)?;
        encrypt_in_place(&key, &nonce, &mut plaintext)?;
        key.zeroize();

        let blob = VaultBlob {
            version: 1,
            kdf,
            salt: encode(salt),
            nonce: encode(nonce),
            ciphertext: encode(&plaintext),
        };

        let serialized = serde_json::to_vec_pretty(&blob)?;
        self.write_secure(&serialized)?;
        info!(path = %self.path.display(), entries = vault.len(), "saved vault");

        Ok(())
    }

    fn decrypt_blob(&self, blob: VaultBlob, master: &SecretString) -> Result<Vault> {
        if blob.version != 1 {
            return Err(AppError::InvalidVault);
        }

        let salt = decode_fixed::<SALT_LEN>(&blob.salt)?;
        let nonce = decode_fixed::<NONCE_LEN>(&blob.nonce)?;
        let mut ciphertext = decode(blob.ciphertext)?;
        let mut key = derive_key(master, &salt, blob.kdf)?;
        let decrypted = decrypt_in_place(&key, &nonce, &mut ciphertext);
        key.zeroize();
        decrypted?;

        let parsed =
            serde_json::from_slice::<Vault>(&ciphertext).map_err(|_| AppError::InvalidVault);
        wipe_bytes(&mut ciphertext);
        parsed
    }

    fn convert_legacy(&self, legacy: LegacyVault) -> Vault {
        let mut vault = Vault::default();
        for (site, entry) in legacy {
            let created_at = entry.created_at.unwrap_or(0);
            let updated_at = entry.updated_at.unwrap_or(created_at);
            let entry = VaultEntry {
                username: entry.username,
                password: secret_from_string(entry.password),
                created_at,
                updated_at,
                last_accessed_at: entry.last_accessed_at,
            };
            vault.entries.insert(site, entry);
        }
        vault
    }

    fn read_raw(&self) -> Result<Option<String>> {
        match fs::read_to_string(&self.path) {
            Ok(raw) if raw.trim().is_empty() => Ok(None),
            Ok(raw) => Ok(Some(raw)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn write_secure(&self, bytes: &[u8]) -> Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);

        let mut file = options.open(&self.path)?;
        file.write_all(bytes)?;
        file.sync_all()?;

        #[cfg(unix)]
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;

        Ok(())
    }
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = decode(value)?;
    if bytes.len() != N {
        return Err(AppError::InvalidVault);
    }

    let mut fixed = [0u8; N];
    fixed.copy_from_slice(&bytes);
    Ok(fixed)
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultBlob {
    version: u32,
    kdf: KdfParams,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyEncryptedStore {
    salt: String,
    check: String,
    data: String,
}

type LegacyVault = std::collections::BTreeMap<String, LegacyEntry>;

#[derive(Debug, Serialize, Deserialize)]
struct LegacyEntry {
    username: String,
    password: String,
    #[serde(default)]
    created_at: Option<u64>,
    #[serde(default)]
    updated_at: Option<u64>,
    #[serde(default)]
    last_accessed_at: Option<u64>,
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use tempfile::tempdir;

    use super::{LoadSource, VaultStatus, VaultStore};
    use crate::vault::Vault;

    #[test]
    fn saves_and_loads_encrypted_vault() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("vault.json");
        let store = VaultStore::new(&path);
        let master = SecretString::new("correct horse battery staple".into());

        let mut vault = Vault::default();
        vault
            .add(
                "example.com".into(),
                "alice".into(),
                SecretString::new("hunter2".into()),
                false,
                100,
            )
            .expect("add entry");

        store.save(&master, &vault).expect("save vault");

        assert_eq!(store.status().expect("status"), VaultStatus::Sealed);

        let loaded = store.load(Some(&master)).expect("load vault");
        assert_eq!(loaded.source, LoadSource::Sealed);
        assert_eq!(loaded.vault.len(), 1);
        assert_eq!(
            loaded.vault.get("example.com").expect("entry").username,
            "alice"
        );
    }

    #[test]
    fn legacy_plaintext_is_detected_for_upgrade() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("vault.json");
        std::fs::write(
            &path,
            r#"{"example.com":{"username":"alice","password":"hunter2","created_at":12}}"#,
        )
        .expect("write legacy file");

        let store = VaultStore::new(&path);
        assert_eq!(
            store.status().expect("status"),
            VaultStatus::PlaintextLegacy
        );
        let loaded = store.load(None).expect("load legacy vault");
        assert_eq!(loaded.source, LoadSource::PlaintextLegacy);
        assert_eq!(
            loaded.vault.get("example.com").expect("entry").created_at,
            12
        );
    }

    #[test]
    fn wrong_master_password_is_rejected() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("vault.json");
        let store = VaultStore::new(&path);
        let master = SecretString::new("correct horse battery staple".into());

        let mut vault = Vault::default();
        vault
            .add(
                "example.com".into(),
                "alice".into(),
                SecretString::new("hunter2".into()),
                false,
                100,
            )
            .expect("add entry");

        store.save(&master, &vault).expect("save vault");

        let error = store
            .load(Some(&SecretString::new("totally wrong".into())))
            .expect_err("load should fail");
        assert!(matches!(error, crate::error::AppError::WrongMasterPassword));
    }

    #[test]
    fn legacy_custom_crypto_is_rejected() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("vault.json");
        std::fs::write(&path, r#"{"salt":"00","check":"11","data":"22"}"#)
            .expect("write legacy file");

        let store = VaultStore::new(&path);
        assert_eq!(
            store.status().expect("status"),
            VaultStatus::UnsupportedLegacyEncrypted
        );
        assert!(matches!(
            store.load(Some(&SecretString::new("master".into()))),
            Err(crate::error::AppError::UnsupportedLegacy(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("vault.json");
        let store = VaultStore::new(&path);
        let master = SecretString::new("correct horse battery staple".into());

        store.save(&master, &Vault::default()).expect("save vault");

        let permissions = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(permissions, 0o600);
    }
}
