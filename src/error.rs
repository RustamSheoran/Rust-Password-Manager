use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error("wrong master password or corrupted vault")]
    WrongMasterPassword,
    #[error("invalid vault format")]
    InvalidVault,
    #[error("vault is not initialized")]
    VaultUninitialized,
    #[error("entry not found: {0}")]
    MissingEntry(String),
    #[error("entry already exists: {0}")]
    EntryExists(String),
    #[error("input error: {0}")]
    Input(String),
    #[error("unsupported legacy vault format: {0}")]
    UnsupportedLegacy(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}
