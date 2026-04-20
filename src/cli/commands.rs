use std::{
    io::{self, Write},
    time::Duration,
};

use rand::{rngs::OsRng, seq::SliceRandom};
use secrecy::{ExposeSecret, SecretString};
use tracing::debug;

use crate::{
    cli::{AddArgs, Cli, Command, DeleteArgs, GenerateArgs, GetArgs},
    error::{AppError, Result},
    security::memory::secret_from_string,
    ui::tui::{TuiConfig, TuiOutcome, run as run_tui},
    vault::{Vault, VaultStatus, VaultStore},
};

pub fn execute(cli: Cli) -> Result<()> {
    let store = VaultStore::new(cli.vault);
    match cli.command.unwrap_or(Command::Tui) {
        Command::Add(args) => run_add(&store, args),
        Command::Get(args) => run_get(&store, args),
        Command::List => run_list(&store),
        Command::Delete(args) => run_delete(&store, args),
        Command::Generate(args) => run_generate(args),
        Command::Tui => run_tui_command(
            &store,
            TuiConfig {
                auto_lock_timeout: Duration::from_secs(cli.auto_lock_seconds.max(30)),
                reveal_timeout: Duration::from_secs(8),
                clipboard_timeout: Duration::from_secs(15),
                ctrl_c_grace_period: Duration::from_secs(3),
            },
        ),
    }
}

fn run_add(store: &VaultStore, args: AddArgs) -> Result<()> {
    let mut session = open_session(store, SessionMode::CreateIfMissing)?;
    let username = match args.username {
        Some(value) => value,
        None => prompt_line("Username: ")?,
    };
    let password = prompt_secret("Password: ")?;
    let now = unix_timestamp()?;

    session
        .vault
        .add(args.site, username, password, args.force, now)?;
    session.persist(store)?;
    Ok(())
}

fn run_get(store: &VaultStore, args: GetArgs) -> Result<()> {
    let mut session = open_session(store, SessionMode::ExistingOnly)?;
    let site = args.site;
    let now = unix_timestamp()?;

    session.vault.touch(&site, now)?;
    let entry = session.vault.get(&site)?;
    println!("site: {site}");
    println!("username: {}", entry.username);
    println!("password: {}", entry.password.expose_secret());

    if session.can_persist() {
        session.persist(store)?;
    }

    Ok(())
}

fn run_list(store: &VaultStore) -> Result<()> {
    let session = open_session(store, SessionMode::ExistingOnly)?;
    let mut sites = session
        .vault
        .iter()
        .map(|(site, _)| site.as_str())
        .collect::<Vec<_>>();
    sites.sort_unstable();
    for site in sites {
        println!("{site}");
    }
    Ok(())
}

fn run_delete(store: &VaultStore, args: DeleteArgs) -> Result<()> {
    let mut session = open_session(store, SessionMode::ExistingOnly)?;
    session.vault.delete(&args.site)?;
    session.persist(store)?;
    Ok(())
}

fn run_generate(args: GenerateArgs) -> Result<()> {
    let password = generate_password(args.length, !args.no_symbols)?;
    println!("{password}");
    Ok(())
}

fn run_tui_command(store: &VaultStore, config: TuiConfig) -> Result<()> {
    loop {
        let mut session = open_session(store, SessionMode::CreateIfMissing)?;
        if session.needs_persist {
            session.persist(store)?;
            session.needs_persist = false;
        }

        match run_tui(
            store,
            session.vault,
            session.master.expect("master required for tui"),
            config,
        )? {
            TuiOutcome::Quit => return Ok(()),
            TuiOutcome::Locked => debug!("vault auto-locked; restarting TUI session"),
        }
    }
}

fn open_session(store: &VaultStore, mode: SessionMode) -> Result<Session> {
    match store.status()? {
        VaultStatus::Missing => match mode {
            SessionMode::ExistingOnly => Ok(Session::empty()),
            SessionMode::CreateIfMissing => Ok(Session {
                vault: Vault::default(),
                master: Some(prompt_new_master()?),
                needs_persist: false,
            }),
        },
        VaultStatus::PlaintextLegacy => {
            let master = prompt_new_master()?;
            let loaded = store.load(Some(&master))?;
            let needs_persist = loaded.needs_persist();
            Ok(Session {
                vault: loaded.vault,
                master: Some(master),
                needs_persist,
            })
        }
        VaultStatus::Sealed => {
            let master = prompt_secret("Master password: ")?;
            let loaded = store.load(Some(&master))?;
            let needs_persist = loaded.needs_persist();
            Ok(Session {
                vault: loaded.vault,
                master: Some(master),
                needs_persist,
            })
        }
        VaultStatus::UnsupportedLegacyEncrypted => Err(AppError::UnsupportedLegacy(
            "legacy vault uses removed custom crypto; migrate it with the old build before upgrading".into(),
        )),
    }
}

fn prompt_new_master() -> Result<SecretString> {
    let master = prompt_secret("New master password: ")?;
    if master.expose_secret().is_empty() {
        return Err(AppError::Input("master password cannot be empty".into()));
    }

    let confirmation = prompt_secret("Confirm master password: ")?;
    if master.expose_secret() != confirmation.expose_secret() {
        return Err(AppError::Input("master passwords did not match".into()));
    }

    Ok(master)
}

fn prompt_secret(label: &str) -> Result<SecretString> {
    let value = rpassword::prompt_password(label)?;
    Ok(secret_from_string(value))
}

pub(crate) fn prompt_line(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;

    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;

    while matches!(buffer.as_bytes().last().copied(), Some(b'\n' | b'\r')) {
        buffer.pop();
    }

    Ok(buffer)
}

pub(crate) fn generate_password(length: usize, include_symbols: bool) -> Result<String> {
    if length < 12 {
        return Err(AppError::Input(
            "generated passwords must be at least 12 characters".into(),
        ));
    }

    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"23456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*-_=+?";

    let mut groups = vec![LOWER, UPPER, DIGITS];
    if include_symbols {
        groups.push(SYMBOLS);
    }

    if length < groups.len() {
        return Err(AppError::Input(
            "password length is too short for the selected policy".into(),
        ));
    }

    let mut rng = OsRng;
    let mut bytes = Vec::with_capacity(length);
    let charset = groups
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect::<Vec<_>>();

    for group in &groups {
        bytes.push(*group.choose(&mut rng).expect("group is not empty"));
    }

    while bytes.len() < length {
        bytes.push(*charset.choose(&mut rng).expect("charset is not empty"));
    }

    bytes.shuffle(&mut rng);
    Ok(bytes.into_iter().map(char::from).collect())
}

pub(crate) fn unix_timestamp() -> Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AppError::Input(format!("system clock error: {error}")))?
        .as_secs())
}

#[derive(Debug, Clone, Copy)]
enum SessionMode {
    ExistingOnly,
    CreateIfMissing,
}

struct Session {
    vault: Vault,
    master: Option<SecretString>,
    needs_persist: bool,
}

impl Session {
    fn empty() -> Self {
        Self {
            vault: Vault::default(),
            master: None,
            needs_persist: false,
        }
    }

    fn can_persist(&self) -> bool {
        self.master.is_some()
    }

    fn persist(&mut self, store: &VaultStore) -> Result<()> {
        let master = self.master.as_ref().ok_or(AppError::VaultUninitialized)?;
        store.save(master, &self.vault)?;
        self.needs_persist = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::AppError;

    use super::generate_password;

    #[test]
    fn generated_password_contains_mixed_charsets() {
        let password = generate_password(24, true).expect("generate password");

        assert!(password.chars().any(|ch| ch.is_ascii_lowercase()));
        assert!(password.chars().any(|ch| ch.is_ascii_uppercase()));
        assert!(password.chars().any(|ch| ch.is_ascii_digit()));
        assert!(password.chars().any(|ch| !ch.is_ascii_alphanumeric()));
    }

    #[test]
    fn generated_password_can_exclude_symbols() {
        let password = generate_password(24, false).expect("generate password");

        assert!(password.chars().all(|ch| ch.is_ascii_alphanumeric()));
    }

    #[test]
    fn generated_password_rejects_too_short_lengths() {
        let error = generate_password(8, true).expect_err("generation should fail");
        assert!(matches!(error, AppError::Input(_)));
    }
}
