use anyhow::{Context, Result};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use veyra_core::{public_from_master, setup, MasterSecretKey, PublicKey};

#[derive(Serialize, Deserialize)]
struct ProtectedMaster { version: u32, nonce: [u8;12], ciphertext: Vec<u8> }

fn key_bytes(raw: &str) -> Result<[u8;32]> {
    if let Ok(bytes) = STANDARD.decode(raw) { if bytes.len()==32 { return Ok(bytes.try_into().unwrap()); } }
    let mut h=Sha256::new(); h.update(raw.as_bytes()); Ok(h.finalize().into())
}

pub fn load_or_create(data_dir: &Path, encryption_key: &str) -> Result<(PublicKey, MasterSecretKey)> {
    fs::create_dir_all(data_dir)?;
    let path = data_dir.join("master.enc");
    if path.exists() {
        let bytes=fs::read(path)?; let protected:ProtectedMaster=bincode::deserialize(&bytes)?;
        let key=key_bytes(encryption_key)?; let cipher=Aes256Gcm::new_from_slice(&key)?;
        let plain=cipher.decrypt(Nonce::from_slice(&protected.nonce), protected.ciphertext.as_ref()).map_err(|_| anyhow::anyhow!("invalid master encryption key"))?;
        let vals: ([u8;32],[u8;32])=bincode::deserialize(&plain)?;
        let alpha=bls12_381::Scalar::from_bytes(&vals.0).into_option().context("invalid alpha")?;
        let beta=bls12_381::Scalar::from_bytes(&vals.1).into_option().context("invalid beta")?;
        let msk=MasterSecretKey{alpha,beta}; let pk=public_from_master(&msk); return Ok((pk,msk));
    }
    let (pk,msk)=setup(&[],&mut OsRng);
    let plain=bincode::serialize(&(msk.alpha.to_bytes(),msk.beta.to_bytes()))?;
    let key=key_bytes(encryption_key)?; let cipher=Aes256Gcm::new_from_slice(&key)?; let mut nonce=[0u8;12]; OsRng.fill_bytes(&mut nonce);
    let ciphertext=cipher.encrypt(Nonce::from_slice(&nonce),plain.as_ref()).map_err(|_| anyhow::anyhow!("master encryption failed"))?;
    fs::write(path,bincode::serialize(&ProtectedMaster{version:1,nonce,ciphertext})?)?;
    Ok((pk,msk))
}
