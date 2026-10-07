//! Key material types for the CP-ABE scheme.

use crate::error::{Result, VeyraError};
use bls12_381::{G1Projective, G2Projective, Gt, Scalar};
use ff::Field;
use std::collections::HashMap;
use zeroize::{Zeroize, Zeroizing};

/// Best-effort overwrite of a scalar that the optimizer cannot elide.
pub(crate) fn wipe_scalar(s: &mut Scalar) {
    // SAFETY: `s` is a valid, aligned, exclusive reference to a `Scalar`.
    unsafe { core::ptr::write_volatile(s, Scalar::zero()) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Master secret key. It must only ever live in the authority process and be
/// persisted exclusively in encrypted form.
///
/// `attr_seed` is a secret PRF key. Every attribute exponent `h_attr` is
/// derived from it and is never revealed to users: if users could compute
/// `h_attr` they could strip the per-attribute blinding from their key
/// components and decrypt ciphertexts regardless of the policy.
#[derive(Clone)]
pub struct MasterSecretKey {
    pub alpha: Scalar,
    pub beta: Scalar,
    pub attr_seed: [u8; 32],
}

impl MasterSecretKey {
    pub const SERIALIZED_LEN: usize = 96;

    /// Serialize as `alpha || beta || attr_seed`. The result is zeroized on drop.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 96]> {
        let mut out = Zeroizing::new([0u8; 96]);
        out[..32].copy_from_slice(&self.alpha.to_bytes());
        out[32..64].copy_from_slice(&self.beta.to_bytes());
        out[64..].copy_from_slice(&self.attr_seed);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return Err(VeyraError::MissingMasterMaterial);
        }
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut seed = [0u8; 32];
        a.copy_from_slice(&bytes[..32]);
        b.copy_from_slice(&bytes[32..64]);
        seed.copy_from_slice(&bytes[64..]);
        let alpha = Option::<Scalar>::from(Scalar::from_bytes(&a))
            .ok_or(VeyraError::MissingMasterMaterial)?;
        let beta = Option::<Scalar>::from(Scalar::from_bytes(&b))
            .ok_or(VeyraError::MissingMasterMaterial)?;
        a.zeroize();
        b.zeroize();
        if bool::from(beta.is_zero()) {
            return Err(VeyraError::MissingMasterMaterial);
        }
        Ok(Self { alpha, beta, attr_seed: seed })
    }
}

impl Drop for MasterSecretKey {
    fn drop(&mut self) {
        wipe_scalar(&mut self.alpha);
        wipe_scalar(&mut self.beta);
        self.attr_seed.zeroize();
    }
}

/// Public parameters. `attr_pubs` maps an attribute id to `g^{h_attr}`.
#[derive(Clone)]
pub struct PublicKey {
    pub g: G1Projective,
    pub h: G1Projective,
    pub e_gg_alpha: Gt,
    pub attr_pubs: HashMap<String, G1Projective>,
}

/// A user's secret key. Bound with a fresh random `r` for collusion resistance.
#[derive(Clone)]
pub struct UserSecretKey {
    pub user_id: String,
    pub d: G2Projective,
    pub components: HashMap<String, (G2Projective, G2Projective)>,
    pub attributes: Vec<String>,
}

impl Drop for UserSecretKey {
    fn drop(&mut self) {
        self.components.clear();
        self.attributes.clear();
        self.user_id.clear();
        self.d = G2Projective::identity();
    }
}

/// Ciphertext components for the ABE keying material.
/// The recoverable value is `e(g,g)^{alpha s}`. The actual DEK is random and wrapped.
#[derive(Clone)]
pub struct AbeCiphertext {
    pub policy: String,
    pub c_prime: G1Projective, // h^s = g^{beta s}
    pub leaf_components: HashMap<String, (G1Projective, G1Projective)>,
    /// DEK XOR HKDF(e(g,g)^{alpha s}), 32 bytes.
    pub wrapped_dek: [u8; 32],
    /// SHA-256(DEK), used as a key-confirmation check after unwrapping.
    pub dek_hash: [u8; 32],
}
