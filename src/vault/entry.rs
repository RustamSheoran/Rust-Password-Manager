use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};

use crate::security::memory::secret_from_string;

#[derive(Debug)]
pub struct VaultEntry {
    pub username: String,
    pub password: SecretString,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_accessed_at: Option<u64>,
}

impl VaultEntry {
    pub fn new(username: String, password: SecretString, now: u64) -> Self {
        Self {
            username,
            password,
            created_at: now,
            updated_at: now,
            last_accessed_at: None,
        }
    }
}

impl Serialize for VaultEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("VaultEntry", 5)?;
        state.serialize_field("username", &self.username)?;
        state.serialize_field("password", self.password.expose_secret())?;
        state.serialize_field("created_at", &self.created_at)?;
        state.serialize_field("updated_at", &self.updated_at)?;
        state.serialize_field("last_accessed_at", &self.last_accessed_at)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for VaultEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireEntry {
            username: String,
            password: String,
            created_at: u64,
            updated_at: u64,
            #[serde(default)]
            last_accessed_at: Option<u64>,
        }

        let wire = WireEntry::deserialize(deserializer)?;
        Ok(Self {
            username: wire.username,
            password: secret_from_string(wire.password),
            created_at: wire.created_at,
            updated_at: wire.updated_at,
            last_accessed_at: wire.last_accessed_at,
        })
    }
}
