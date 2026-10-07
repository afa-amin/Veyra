//! Veyra cryptographic core: hybrid AES-256-GCM payload encryption with a
//! CP-ABE protected data-encryption key.

pub mod crypto;
pub mod error;

pub use crypto::{
    decrypt_reader, default_universe, effective_attributes, encrypt_reader, expand_clearance,
    keygen, normalize_attribute, parse_policy, public_for_policy, public_from_master,
    publish_attributes, setup, AccessNode, Attribute, MasterSecretKey, PublicKey,
    StreamDecryptor, StreamPackageHeader, UserSecretKey, DEFAULT_CHUNK_SIZE, PACKAGE_VERSION,
};
pub use error::{Result, VeyraError};
