//! Error types for the Veyra cryptographic core.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum VeyraError {
    #[error("master secret or public parameters are missing or corrupted")]
    MissingMasterMaterial,

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("access denied: the recipient's attributes do not satisfy the policy")]
    AccessDenied,

    #[error("decryption failed (wrong key, tampered object, or policy mismatch)")]
    DecryptionFailed,

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("attribute `{0}` is not allowed")]
    UnknownAttribute(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, VeyraError>;

impl From<bincode::Error> for VeyraError {
    fn from(e: bincode::Error) -> Self {
        VeyraError::Serialization(e.to_string())
    }
}

impl From<serde_json::Error> for VeyraError {
    fn from(e: serde_json::Error) -> Self {
        VeyraError::Serialization(e.to_string())
    }
}
