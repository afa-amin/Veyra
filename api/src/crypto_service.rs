//! Protected storage of the master secret key.
//!
//! `master.v2.enc` holds `MasterSecretKey` encrypted with AES-256-GCM under a
//! key derived from the operator-supplied secret with Argon2id (random salt
//! stored in the file). The file is written atomically with mode 0600.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use veyra_core::{default_universe, public_from_master, setup, MasterSecretKey, PublicKey};
use zeroize::Zeroizing;

const MASTER_FILE: &str = "master.v2.enc";
const LEGACY_MASTER_FILE: &str = "master.enc";
const AAD: &[u8] = b"veyra-master-v2";
const FORMAT_VERSION: u32 = 2;

#[derive(Serialize, Deserialize)]
struct ProtectedMaster {
    version: u32,
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

pub fn master_file_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MASTER_FILE)
}

pub fn legacy_master_exists(data_dir: &Path) -> bool {
    data_dir.join(LEGACY_MASTER_FILE).exists()
}

fn derive_key(secret: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    // 64 MiB, 3 passes: runs once at startup.
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(secret.as_bytes(), salt, &mut key[..])
        .map_err(|e| anyhow!("argon2 key derivation failed: {e}"))?;
    Ok(key)
}

#[cfg(unix)]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(path)
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut f = open_private(&tmp).with_context(|| format!("cannot create {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn seal(secret: &str, msk: &MasterSecretKey) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(secret, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| anyhow!("{e}"))?;
    let plain = msk.to_bytes();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain[..], aad: AAD })
        .map_err(|_| anyhow!("master key encryption failed"))?;
    Ok(bincode::serialize(&ProtectedMaster {
        version: FORMAT_VERSION,
        salt,
        nonce,
        ciphertext,
    })?)
}

fn unseal(secret: &str, bytes: &[u8]) -> Result<MasterSecretKey> {
    let protected: ProtectedMaster =
        bincode::deserialize(bytes).context("master key file is corrupted")?;
    if protected.version != FORMAT_VERSION {
        bail!("unsupported master key file version");
    }
    let key = derive_key(secret, &protected.salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| anyhow!("{e}"))?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&protected.nonce),
                Payload { msg: &protected.ciphertext, aad: AAD },
            )
            .map_err(|_| {
                anyhow!("cannot decrypt the master key file: VEYRA_MASTER_ENCRYPTION_KEY is wrong or the file is corrupted")
            })?,
    );
    Ok(MasterSecretKey::from_bytes(&plain[..])?)
}

/// Load the protected master key, or create a new one when `allow_create` is set.
pub fn load_or_create(
    data_dir: &Path,
    secret: &str,
    allow_create: bool,
) -> Result<(PublicKey, MasterSecretKey)> {
    std::fs::create_dir_all(data_dir)?;
    let path = master_file_path(data_dir);
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        let msk = unseal(secret, &bytes)?;
        return Ok((public_from_master(&msk), msk));
    }
    if !allow_create {
        bail!(
            "{} is missing but encrypted data already exists. Restore the file from backup. \
             Generating a new master key would make all existing transfers permanently unreadable \
             (set VEYRA_ALLOW_NEW_MASTER=true only if that is intended)",
            path.display()
        );
    }
    let mut rng = OsRng;
    let (pk, msk) = setup(&default_universe(), &mut rng);
    write_private_atomic(&path, &seal(secret, &msk)?)?;
    tracing::warn!(
        "created a new master key at {}. Back this file up together with VEYRA_MASTER_ENCRYPTION_KEY: \
         without both, stored transfers cannot be decrypted",
        path.display()
    );
    Ok((pk, msk))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "unit-test-secret-with-at-least-32-characters!";

    #[test]
    fn seal_and_unseal_round_trip() {
        let (_, msk) = setup(&[], &mut OsRng);
        let bytes = seal(SECRET, &msk).unwrap();
        let restored = unseal(SECRET, &bytes).unwrap();
        assert_eq!(restored.to_bytes()[..], msk.to_bytes()[..]);
    }

    #[test]
    fn wrong_secret_and_tampering_fail() {
        let (_, msk) = setup(&[], &mut OsRng);
        let mut bytes = seal(SECRET, &msk).unwrap();
        assert!(unseal("another-secret-with-at-least-32-chars!!", &bytes).is_err());
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(unseal(SECRET, &bytes).is_err());
    }
}
