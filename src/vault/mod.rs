pub mod entry;
pub mod store;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

pub use entry::VaultEntry;
pub use store::{VaultStatus, VaultStore};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Vault {
    #[serde(default)]
    pub(crate) entries: BTreeMap<String, VaultEntry>,
}

impl Vault {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &VaultEntry)> {
        self.entries.iter()
    }

    pub fn get(&self, site: &str) -> Result<&VaultEntry> {
        self.entries
            .get(site)
            .ok_or_else(|| AppError::MissingEntry(site.to_owned()))
    }

    pub fn get_mut(&mut self, site: &str) -> Result<&mut VaultEntry> {
        self.entries
            .get_mut(site)
            .ok_or_else(|| AppError::MissingEntry(site.to_owned()))
    }

    pub fn add(
        &mut self,
        site: String,
        username: String,
        password: secrecy::SecretString,
        force: bool,
        now: u64,
    ) -> Result<()> {
        if site.trim().is_empty() {
            return Err(AppError::Input("site cannot be empty".into()));
        }

        if let Some(existing) = self.entries.get_mut(&site) {
            if !force {
                return Err(AppError::EntryExists(site));
            }

            existing.username = username;
            existing.password = password;
            existing.updated_at = now;
            return Ok(());
        }

        self.entries
            .insert(site, VaultEntry::new(username, password, now));
        Ok(())
    }

    pub fn delete(&mut self, site: &str) -> Result<()> {
        self.entries
            .remove(site)
            .map(|_| ())
            .ok_or_else(|| AppError::MissingEntry(site.to_owned()))
    }

    pub fn touch(&mut self, site: &str, now: u64) -> Result<()> {
        let entry = self.get_mut(site)?;
        entry.last_accessed_at = Some(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::Vault;

    #[test]
    fn add_requires_force_to_overwrite() {
        let mut vault = Vault::default();
        vault
            .add(
                "example.com".into(),
                "alice".into(),
                SecretString::new("one".into()),
                false,
                10,
            )
            .expect("add entry");

        let error = vault
            .add(
                "example.com".into(),
                "alice".into(),
                SecretString::new("two".into()),
                false,
                20,
            )
            .expect_err("overwrite should fail");

        assert!(matches!(error, crate::error::AppError::EntryExists(_)));
    }

    #[test]
    fn touch_updates_last_accessed_timestamp() {
        let mut vault = Vault::default();
        vault
            .add(
                "example.com".into(),
                "alice".into(),
                SecretString::new("one".into()),
                false,
                10,
            )
            .expect("add entry");

        vault.touch("example.com", 99).expect("touch entry");

        assert_eq!(
            vault.get("example.com").expect("entry").last_accessed_at,
            Some(99)
        );
    }

    #[test]
    fn delete_removes_entry() {
        let mut vault = Vault::default();
        vault
            .add(
                "example.com".into(),
                "alice".into(),
                SecretString::new("one".into()),
                false,
                10,
            )
            .expect("add entry");

        vault.delete("example.com").expect("delete entry");

        assert!(matches!(
            vault.get("example.com"),
            Err(crate::error::AppError::MissingEntry(_))
        ));
    }
}
