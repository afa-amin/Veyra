//! Hybrid encryption primitives used by Veyra.
//!
//! Payload encryption is AES-256-GCM in fixed-size chunks; the random 256-bit
//! DEK is protected by CP-ABE. Object layout:
//!
//! ```text
//! "VEYRAOBJ" | u32 header_len (BE) | header (bincode) | { u32 chunk_len (BE) | AES-GCM chunk }*
//! ```
//!
//! Integrity properties:
//! * The magic and the complete header (version, filename, MIME type, size,
//!   policy, ABE ciphertext, chunk size) are authenticated as AAD of every chunk.
//! * Each chunk uses a unique nonce (random base nonce XOR chunk index), and a
//!   fresh DEK is generated for every object.
//! * `plaintext_size` is authenticated, so truncation, extension and chunk
//!   reordering are all detected; trailing bytes after the last chunk are rejected.

use crate::crypto::keys::{AbeCiphertext, PublicKey, UserSecretKey};
use crate::crypto::policy::parse_policy;
use crate::crypto::scheme::{decrypt_keying_material, encrypt_keying_material};
use crate::error::{Result, VeyraError};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"VEYRAOBJ";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_HEADER_LEN: usize = 256 * 1024;
const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

pub const PACKAGE_VERSION: u32 = 2;
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredLeaf {
    pub attr: String,
    pub c_y: Vec<u8>,
    pub c_y_prime: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredAbe {
    pub policy: String,
    pub c_prime: Vec<u8>,
    pub leaves: Vec<StoredLeaf>,
    pub wrapped_dek: [u8; 32],
    pub dek_hash: [u8; 32],
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

fn g1_to_bytes(p: &bls12_381::G1Projective) -> Vec<u8> {
    bls12_381::G1Affine::from(*p).to_compressed().to_vec()
}

fn g1_from_bytes(b: &[u8]) -> Result<bls12_381::G1Projective> {
    let arr: [u8; 48] = b
        .try_into()
        .map_err(|_| VeyraError::Serialization("bad G1 length".into()))?;
    let aff = Option::<bls12_381::G1Affine>::from(bls12_381::G1Affine::from_compressed(&arr))
        .ok_or_else(|| VeyraError::Serialization("invalid G1 point".into()))?;
    Ok(bls12_381::G1Projective::from(aff))
}

fn store_abe(abe: AbeCiphertext) -> StoredAbe {
    let mut leaves: Vec<StoredLeaf> = abe
        .leaf_components
        .into_iter()
        .map(|(attr, (c_y, c_y_prime))| StoredLeaf {
            attr,
            c_y: g1_to_bytes(&c_y),
            c_y_prime: g1_to_bytes(&c_y_prime),
        })
        .collect();
    // Deterministic order makes the serialized header canonical.
    leaves.sort_by(|a, b| a.attr.cmp(&b.attr));
    StoredAbe {
        policy: abe.policy,
        c_prime: g1_to_bytes(&abe.c_prime),
        leaves,
        wrapped_dek: abe.wrapped_dek,
        dek_hash: abe.dek_hash,
    }
}

fn load_abe(stored: &StoredAbe) -> Result<AbeCiphertext> {
    let mut leaf_components = std::collections::HashMap::new();
    for leaf in &stored.leaves {
        let pair = (g1_from_bytes(&leaf.c_y)?, g1_from_bytes(&leaf.c_y_prime)?);
        if leaf_components.insert(leaf.attr.clone(), pair).is_some() {
            return Err(VeyraError::Serialization("duplicate ABE leaf".into()));
        }
    }
    Ok(AbeCiphertext {
        policy: stored.policy.clone(),
        c_prime: g1_from_bytes(&stored.c_prime)?,
        leaf_components,
        wrapped_dek: stored.wrapped_dek,
        dek_hash: stored.dek_hash,
    })
}

fn aad(header: &StreamPackageHeader) -> Result<Vec<u8>> {
    let mut copy = header.clone();
    // The base nonce cannot be part of its own AAD; it is bound implicitly
    // because every chunk nonce is derived from it.
    copy.nonce = [0u8; NONCE_LEN];
    let mut out = Vec::with_capacity(MAGIC.len() + 256);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&bincode::serialize(&copy)?);
    Ok(out)
}

fn chunk_nonce(base: &[u8; NONCE_LEN], index: u64) -> [u8; NONCE_LEN] {
    let mut n = *base;
    let idx = index.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= idx[i];
    }
    n
}

fn new_cipher(dek: &[u8; 32]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(dek.as_slice()).map_err(|e| VeyraError::Crypto(e.to_string()))
}

/// Stream-encrypt a plaintext reader into a Veyra object writer without
/// loading the file into RAM. `plaintext_size` must equal the exact number of
/// bytes the reader yields.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_reader<R: Read, W: Write>(
    pk: &PublicKey,
    policy: &str,
    original_filename: &str,
    mime_type: &str,
    plaintext_size: u64,
    mut reader: R,
    mut writer: W,
    chunk_size: usize,
    rng: &mut impl RngCore,
) -> Result<()> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(VeyraError::Other("invalid chunk size".into()));
    }
    // Canonicalize (and thereby validate) the policy before embedding it.
    let canonical = parse_policy(policy)?.to_string();

    let (abe, mut dek_raw) = encrypt_keying_material(pk, &canonical, rng)?;
    let dek = Zeroizing::new(dek_raw);
    dek_raw.zeroize();
    let cipher = new_cipher(&dek)?;

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let header = StreamPackageHeader {
        version: PACKAGE_VERSION,
        created_at: chrono::Utc::now().timestamp(),
        original_filename: original_filename.to_string(),
        mime_type: mime_type.to_string(),
        plaintext_size,
        policy: canonical,
        abe_ct: store_abe(abe),
        nonce,
        chunk_size: chunk_size as u32,
    };
    let header_bytes = bincode::serialize(&header)?;
    if header_bytes.len() > MAX_HEADER_LEN {
        return Err(VeyraError::Other("object header is too large".into()));
    }
    let aad = aad(&header)?;

    writer.write_all(MAGIC)?;
    writer.write_all(&(header_bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&header_bytes)?;

    let mut buf = Zeroizing::new(vec![0u8; chunk_size]);
    let mut index = 0u64;
    let mut remaining = plaintext_size;
    while remaining > 0 {
        let want = remaining.min(chunk_size as u64) as usize;
        reader.read_exact(&mut buf[..want])?;
        let nonce_i = chunk_nonce(&nonce, index);
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce_i),
                Payload { msg: &buf[..want], aad: &aad },
            )
            .map_err(|_| VeyraError::Crypto("AES-GCM encryption failed".into()))?;
        writer.write_all(&(encrypted.len() as u32).to_be_bytes())?;
        writer.write_all(&encrypted)?;
        remaining -= want as u64;
        index += 1;
    }

    // The reader must not contain more data than was declared.
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => break,
            Ok(_) => {
                return Err(VeyraError::Other(
                    "input is longer than the declared plaintext size".into(),
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    writer.flush()?;
    Ok(())
}

/// Two-phase streaming decryptor.
///
/// `new` parses the header and recovers the DEK through CP-ABE, which is where
/// authorization failures surface. Callers can therefore return a proper error
/// before any plaintext is produced. `decrypt_to` then streams and
/// authenticates the chunks.
pub struct StreamDecryptor<R: Read> {
    reader: R,
    header: StreamPackageHeader,
    cipher: Aes256Gcm,
    aad: Vec<u8>,
}

impl<R: Read> StreamDecryptor<R> {
    pub fn new(pk: &PublicKey, sk: &UserSecretKey, mut reader: R) -> Result<Self> {
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(VeyraError::Serialization("invalid Veyra object".into()));
        }
        let mut len = [0u8; 4];
        reader.read_exact(&mut len)?;
        let header_len = u32::from_be_bytes(len) as usize;
        if header_len == 0 || header_len > MAX_HEADER_LEN {
            return Err(VeyraError::Serialization("invalid object header length".into()));
        }
        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;
        let header: StreamPackageHeader = bincode::deserialize(&header_bytes)?;
        // Reject non-canonical encodings and trailing bytes inside the header.
        if bincode::serialize(&header)? != header_bytes {
            return Err(VeyraError::Serialization("non-canonical object header".into()));
        }
        if header.version != PACKAGE_VERSION {
            return Err(VeyraError::Serialization("unsupported package version".into()));
        }
        let chunk_size = header.chunk_size as usize;
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err(VeyraError::Serialization("invalid chunk size".into()));
        }
        if header.policy != header.abe_ct.policy {
            return Err(VeyraError::Serialization("policy mismatch in object header".into()));
        }

        let abe = load_abe(&header.abe_ct)?;
        let mut dek_raw = decrypt_keying_material(pk, sk, &abe)?;
        let dek = Zeroizing::new(dek_raw);
        dek_raw.zeroize();
        let cipher = new_cipher(&dek)?;
        let aad = aad(&header)?;
        Ok(Self { reader, header, cipher, aad })
    }

    pub fn header(&self) -> &StreamPackageHeader {
        &self.header
    }

    /// Decrypt all chunks into `writer`. Every chunk is authenticated before it
    /// is written, and the object must end exactly after the declared size.
    pub fn decrypt_to<W: Write>(mut self, mut writer: W) -> Result<StreamPackageHeader> {
        let chunk_size = self.header.chunk_size as u64;
        let mut remaining = self.header.plaintext_size;
        let mut index = 0u64;
        while remaining > 0 {
            let want = remaining.min(chunk_size) as usize;
            let mut len = [0u8; 4];
            self.reader.read_exact(&mut len)?;
            let encrypted_len = u32::from_be_bytes(len) as usize;
            if encrypted_len != want + TAG_LEN {
                return Err(VeyraError::Serialization("invalid encrypted chunk length".into()));
            }
            let mut encrypted = vec![0u8; encrypted_len];
            self.reader.read_exact(&mut encrypted)?;
            let nonce_i = chunk_nonce(&self.header.nonce, index);
            let plain = Zeroizing::new(
                self.cipher
                    .decrypt(
                        Nonce::from_slice(&nonce_i),
                        Payload { msg: &encrypted, aad: &self.aad },
                    )
                    .map_err(|_| VeyraError::DecryptionFailed)?,
            );
            if plain.len() != want {
                return Err(VeyraError::DecryptionFailed);
            }
            writer.write_all(&plain)?;
            remaining -= want as u64;
            index += 1;
        }

        let mut probe = [0u8; 1];
        loop {
            match self.reader.read(&mut probe) {
                Ok(0) => break,
                Ok(_) => {
                    return Err(VeyraError::Serialization(
                        "unexpected trailing data after last chunk".into(),
                    ))
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        writer.flush()?;
        Ok(self.header)
    }
}

/// Stream-decrypt a Veyra object after the caller has already authorized the transfer.
pub fn decrypt_reader<R: Read, W: Write>(
    pk: &PublicKey,
    sk: &UserSecretKey,
    reader: R,
    writer: W,
) -> Result<StreamPackageHeader> {
    StreamDecryptor::new(pk, sk, reader)?.decrypt_to(writer)
}
