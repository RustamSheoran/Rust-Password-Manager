use secrecy::{ExposeSecret, SecretString};
use tempfile::tempdir;

use pass_manager::vault::{Vault, VaultStore, store::LoadSource};

#[test]
fn add_save_load_and_verify_roundtrip() {
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
            1_717_000_000,
        )
        .expect("add entry");

    store.save(&master, &vault).expect("save vault");

    let loaded = store.load(Some(&master)).expect("load vault");
    assert_eq!(loaded.source, LoadSource::Sealed);

    let entry = loaded.vault.get("example.com").expect("entry");
    assert_eq!(entry.username, "alice");
    assert_eq!(entry.password.expose_secret(), "hunter2");
    assert_eq!(entry.created_at, 1_717_000_000);
}
