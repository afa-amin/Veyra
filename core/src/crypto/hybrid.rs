//! Hybrid encryption primitives used by Veyra.
//! Payload encryption is AES-256-GCM; the random DEK is protected by CP-ABE.

use crate::crypto::keys::{AbeCiphertext, PublicKey, UserSecretKey};
use crate::crypto::scheme::{decrypt_keying_material, encrypt_keying_material};
use crate::error::{Result, SecureDropError};
use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use zeroize::Zeroize;

const NONCE_LEN: usize = 12;
pub const PACKAGE_VERSION: u32 = 1;
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredLeaf { pub attr: String, pub c_y: Vec<u8>, pub c_y_prime: Vec<u8> }

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredAbe {
    pub policy: String,
    pub c_prime: Vec<u8>,
    pub leaves: Vec<StoredLeaf>,
    pub wrapped_dek: [u8; 32],
    pub dek_hash: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecurePackage {
    pub version: u32,
    pub created_at: i64,
    pub original_filename: String,
    pub mime_type: String,
    pub plaintext_size: u64,
    pub policy: String,
    pub abe_ct: StoredAbe,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StreamPackageHeader {
    pub version: u32,
    pub created_at: i64,
    pub original_filename: String,
    pub mime_type: String,
    pub plaintext_size: u64,
    pub policy: String,
    pub abe_ct: StoredAbe,
    pub nonce: [u8; NONCE_LEN],
    pub chunk_size: u32,
}

fn g1_to_bytes(p: &bls12_381::G1Projective) -> Vec<u8> { bls12_381::G1Affine::from(*p).to_compressed().to_vec() }
fn g1_from_bytes(b: &[u8]) -> Result<bls12_381::G1Projective> {
    let arr: [u8; 48] = b.try_into().map_err(|_| SecureDropError::Serialization("bad G1 length".into()))?;
    let aff = bls12_381::G1Affine::from_compressed(&arr).into_option().ok_or_else(|| SecureDropError::Serialization("invalid G1".into()))?;
    Ok(bls12_381::G1Projective::from(aff))
}

fn store_abe(abe: AbeCiphertext) -> StoredAbe {
    let leaves = abe.leaf_components.into_iter().map(|(attr, (c_y, c_y_prime))| StoredLeaf { attr, c_y: g1_to_bytes(&c_y), c_y_prime: g1_to_bytes(&c_y_prime) }).collect();
    StoredAbe { policy: abe.policy, c_prime: g1_to_bytes(&abe.c_prime), leaves, wrapped_dek: abe.wrapped_dek, dek_hash: abe.dek_hash }
}

fn load_abe(stored: &StoredAbe) -> Result<AbeCiphertext> {
    let mut leaf_components = std::collections::HashMap::new();
    for leaf in &stored.leaves {
        if leaf_components.insert(leaf.attr.clone(), (g1_from_bytes(&leaf.c_y)?, g1_from_bytes(&leaf.c_y_prime)?)).is_some() {
            return Err(SecureDropError::Serialization("duplicate ABE leaf".into()));
        }
    }
    Ok(AbeCiphertext { policy: stored.policy.clone(), c_prime: g1_from_bytes(&stored.c_prime)?, leaf_components, wrapped_dek: stored.wrapped_dek, dek_hash: stored.dek_hash })
}

impl SecurePackage {
    pub fn into_abe(&self) -> Result<AbeCiphertext> { load_abe(&self.abe_ct) }
}

fn aad(header: &StreamPackageHeader) -> Result<Vec<u8>> {
    let mut copy = header.clone();
    copy.nonce = [0u8; NONCE_LEN];
    bincode::serialize(&copy).map_err(Into::into)
}

fn chunk_nonce(base: &[u8; NONCE_LEN], index: u64) -> [u8; NONCE_LEN] {
    let mut n = *base;
    let idx = index.to_be_bytes();
    for i in 0..8 { n[4 + i] ^= idx[i]; }
    n
}

/// Stream-encrypt a plaintext reader into a Veyra object writer without loading the file into RAM.
pub fn encrypt_reader<R: Read, W: Write>(
    pk: &PublicKey, policy: &str, original_filename: &str, mime_type: &str,
    plaintext_size: u64, mut reader: R, mut writer: W, chunk_size: usize, rng: &mut impl RngCore,
) -> Result<()> {
    if chunk_size == 0 || chunk_size > 16 * 1024 * 1024 { return Err(SecureDropError::Other("invalid chunk size".into())); }
    let (abe, mut dek) = encrypt_keying_material(pk, policy, rng)?;
    let mut nonce = [0u8; NONCE_LEN]; rng.fill_bytes(&mut nonce);
    let header = StreamPackageHeader { version: PACKAGE_VERSION, created_at: chrono::Utc::now().timestamp(), original_filename: original_filename.to_string(), mime_type: mime_type.to_string(), plaintext_size, policy: policy.to_string(), abe_ct: store_abe(abe), nonce, chunk_size: chunk_size as u32 };
    let header_bytes = bincode::serialize(&header)?;
    let aad = aad(&header)?;
    writer.write_all(b"VEYRAOBJ")?;
    writer.write_all(&(header_bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&header_bytes)?;
    let cipher = Aes256Gcm::new_from_slice(&dek).map_err(|e| SecureDropError::Crypto(e.to_string()))?;
    let mut buf = vec![0u8; chunk_size];
    let mut index = 0u64;
    let mut remaining = plaintext_size;
    while remaining > 0 {
        let want = remaining.min(chunk_size as u64) as usize;
        reader.read_exact(&mut buf[..want])?;
        let nonce_i = chunk_nonce(&nonce, index);
        let encrypted = cipher.encrypt(Nonce::from_slice(&nonce_i), Payload { msg: &buf[..want], aad: &aad }).map_err(|_| SecureDropError::Crypto("AES-GCM encryption failed".into()))?;
        writer.write_all(&(encrypted.len() as u32).to_be_bytes())?;
        writer.write_all(&encrypted)?;
        remaining -= want as u64;
        index += 1;
    }
    dek.zeroize();
    writer.flush()?;
    Ok(())
}

/// Stream-decrypt a Veyra object after the caller has already authorized the transfer.
pub fn decrypt_reader<R: Read, W: Write>(
    pk: &PublicKey, sk: &UserSecretKey, mut reader: R, mut writer: W,
) -> Result<StreamPackageHeader> {
    let mut magic = [0u8; 8]; reader.read_exact(&mut magic)?;
    if &magic != b"VEYRAOBJ" { return Err(SecureDropError::Serialization("invalid Veyra object".into())); }
    let mut len = [0u8; 4]; reader.read_exact(&mut len)?;
    let header_len = u32::from_be_bytes(len) as usize;
    if header_len == 0 || header_len > 8 * 1024 * 1024 { return Err(SecureDropError::Serialization("invalid object header length".into())); }
    let mut header_bytes = vec![0u8; header_len]; reader.read_exact(&mut header_bytes)?;
    let header: StreamPackageHeader = bincode::deserialize(&header_bytes)?;
    if header.version != PACKAGE_VERSION { return Err(SecureDropError::Serialization("unsupported package version".into())); }
    let abe = load_abe(&header.abe_ct)?;
    let mut dek = decrypt_keying_material(pk, sk, &abe)?;
    let cipher = Aes256Gcm::new_from_slice(&dek).map_err(|e| SecureDropError::Crypto(e.to_string()))?;
    let aad = aad(&header)?;
    let mut remaining = header.plaintext_size;
    let mut index = 0u64;
    while remaining > 0 {
        let mut len = [0u8; 4]; reader.read_exact(&mut len)?;
        let encrypted_len = u32::from_be_bytes(len) as usize;
        if encrypted_len < 16 || encrypted_len > header.chunk_size as usize + 16 { return Err(SecureDropError::Serialization("invalid encrypted chunk length".into())); }
        let mut encrypted = vec![0u8; encrypted_len]; reader.read_exact(&mut encrypted)?;
        let nonce_i = chunk_nonce(&header.nonce, index);
        let plain = cipher.decrypt(Nonce::from_slice(&nonce_i), Payload { msg: &encrypted, aad: &aad }).map_err(|_| SecureDropError::DecryptionFailed)?;
        if plain.len() as u64 > remaining || plain.len() > header.chunk_size as usize { return Err(SecureDropError::DecryptionFailed); }
        writer.write_all(&plain)?;
        remaining -= plain.len() as u64;
        index += 1;
    }
    dek.zeroize();
    Ok(header)
}

pub fn encrypt_file(pk: &PublicKey, policy: &str, plaintext: &[u8], original_filename: &str, rng: &mut impl RngCore) -> Result<SecurePackage> {
    let (abe, mut dek) = encrypt_keying_material(pk, policy, rng)?;
    let cipher = Aes256Gcm::new_from_slice(&dek).map_err(|e| SecureDropError::Crypto(e.to_string()))?;
    let mut nonce = [0u8; NONCE_LEN]; rng.fill_bytes(&mut nonce);
    let aad = policy.as_bytes();
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad }).map_err(|_| SecureDropError::Crypto("AES-GCM encryption failed".into()))?;
    dek.zeroize();
    Ok(SecurePackage { version: PACKAGE_VERSION, created_at: chrono::Utc::now().timestamp(), original_filename: original_filename.to_string(), mime_type: "application/octet-stream".into(), plaintext_size: plaintext.len() as u64, policy: policy.to_string(), abe_ct: store_abe(abe), nonce, ciphertext })
}

pub fn decrypt_file(pk: &PublicKey, sk: &UserSecretKey, package: &SecurePackage) -> Result<Vec<u8>> {
    let abe = package.into_abe()?;
    let mut dek = decrypt_keying_material(pk, sk, &abe)?;
    let cipher = Aes256Gcm::new_from_slice(&dek).map_err(|e| SecureDropError::Crypto(e.to_string()))?;
    let plaintext = cipher.decrypt(Nonce::from_slice(&package.nonce), Payload { msg: &package.ciphertext, aad: package.policy.as_bytes() }).map_err(|_| SecureDropError::DecryptionFailed)?;
    dek.zeroize();
    Ok(plaintext)
}
