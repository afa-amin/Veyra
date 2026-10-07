//! Small-universe style CP-ABE (BSW07 adapted for Type-3 pairings on BLS12-381).
//!
//! ## Why attribute exponents are secret
//!
//! BSW07 needs a "hash" `H(attr)` that is available in both source groups with
//! the *same* exponent: `H1(attr) = g1^h` for ciphertexts and `H2(attr) = g2^h`
//! for keys. On a Type-3 pairing there is no isomorphism between G1 and G2, so
//! the exponent `h` must be known to the party that issues keys. If `h` were
//! publicly computable (for example `h = SHA-256(attr)`), any key holder could
//! compute `D_i - h * D_i' = g2^r` from a single key component and then decrypt
//! every ciphertext regardless of its policy. Veyra therefore derives
//! `h_attr = HKDF(attr_seed, attr)` from a secret seed held only by the key
//! authority. Users only ever see `D_i = g2^(r + h*r_i)` and `D_i' = g2^(r_i)`;
//! the encryptor only needs the public values `g1^h` (`PublicKey::attr_pubs`).
//!
//! ## Key schedule
//!
//! * `R = e(g,g)^(alpha*s)` is mapped to a 32-byte wrapping key with HKDF-SHA256.
//! * The random 256-bit DEK is wrapped as `DEK xor wrap_key` and confirmed with
//!   `SHA-256(DEK)` after unwrapping.

use crate::crypto::keys::{wipe_scalar, AbeCiphertext, MasterSecretKey, PublicKey, UserSecretKey};
use crate::crypto::policy::{normalize_attribute, parse_policy, AccessNode};
use crate::error::{Result, VeyraError};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Domain separation for the Gt -> IKM transcript.
const GT_TRANSCRIPT_DST: &[u8] = b"Veyra-Gt-Transcript-v1";
/// HKDF salt (extract stage) for the DEK wrapping key.
const HKDF_SALT: &[u8] = b"Veyra-Wrap-Salt-v1";
/// HKDF info (expand stage) for the DEK wrapping key.
const HKDF_INFO: &[u8] = b"Veyra-CPABE-WrapKey-v1";
/// HKDF salt / info for the secret per-attribute exponents.
const ATTR_SALT: &[u8] = b"Veyra-Attr-Salt-v2";
const ATTR_INFO: &[u8] = b"Veyra-CPABE-AttrExponent-v2";

pub fn default_universe() -> Vec<String> {
    let mut attrs = Vec::new();
    for i in 1..=10 {
        attrs.push(format!("clearance>={}", i));
    }
    for d in &[
        "intelligence",
        "operations",
        "engineering",
        "finance",
        "hr",
        "legal",
        "executive",
        "general",
    ] {
        attrs.push(format!("department={}", d));
    }
    for r in &["analyst", "operator", "admin", "auditor", "contractor", "member"] {
        attrs.push(format!("role={}", r));
    }
    attrs
}

/// Derive the secret exponent `h_attr` for an attribute id.
fn attr_exponent(msk: &MasterSecretKey, attr: &str) -> Scalar {
    let hk = Hkdf::<Sha256>::new(Some(ATTR_SALT), &msk.attr_seed);
    let mut counter: u8 = 0;
    loop {
        let mut info = Vec::with_capacity(ATTR_INFO.len() + 1 + attr.len());
        info.extend_from_slice(ATTR_INFO);
        info.push(counter);
        info.extend_from_slice(attr.as_bytes());
        let mut okm = [0u8; 64];
        hk.expand(&info, &mut okm)
            .expect("64 bytes is a valid HKDF-SHA256 output length");
        let s = Scalar::from_bytes_wide(&okm);
        okm.zeroize();
        if !bool::from(s.is_zero()) {
            return s;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Make the public values `g1^{h_attr}` available for the given attributes.
pub fn publish_attributes(pk: &mut PublicKey, msk: &MasterSecretKey, attrs: &[String]) {
    for a in attrs {
        if !pk.attr_pubs.contains_key(a) {
            let mut h = attr_exponent(msk, a);
            let public = pk.g * h;
            wipe_scalar(&mut h);
            pk.attr_pubs.insert(a.clone(), public);
        }
    }
}

/// Return a copy of `pk` that can encrypt under `policy`, publishing any
/// attribute of the policy that is not yet in the public key.
pub fn public_for_policy(pk: &PublicKey, msk: &MasterSecretKey, policy: &str) -> Result<PublicKey> {
    let tree = parse_policy(policy)?;
    let ids: Vec<String> = tree.collect_attributes().into_iter().map(|a| a.id()).collect();
    let mut out = pk.clone();
    publish_attributes(&mut out, msk, &ids);
    Ok(out)
}

pub fn setup(universe: &[String], rng: &mut impl RngCore) -> (PublicKey, MasterSecretKey) {
    let alpha = Scalar::random(&mut *rng);
    let mut beta = Scalar::random(&mut *rng);
    while bool::from(beta.is_zero()) {
        beta = Scalar::random(&mut *rng);
    }
    let mut attr_seed = [0u8; 32];
    rng.fill_bytes(&mut attr_seed);

    let msk = MasterSecretKey { alpha, beta, attr_seed };
    attr_seed.zeroize();
    let mut pk = public_from_master(&msk);
    publish_attributes(&mut pk, &msk, universe);
    (pk, msk)
}

pub fn public_from_master(msk: &MasterSecretKey) -> PublicKey {
    let g = G1Projective::generator();
    let g2 = G2Projective::generator();
    let h = g * msk.beta;
    let e_gg_alpha = bls12_381::pairing(&G1Affine::from(g), &G2Affine::from(g2 * msk.alpha));
    let mut pk = PublicKey { g, h, e_gg_alpha, attr_pubs: HashMap::new() };
    publish_attributes(&mut pk, msk, &default_universe());
    pk
}

pub fn keygen(
    _pk: &PublicKey,
    msk: &MasterSecretKey,
    user_id: &str,
    attributes: &[String],
    rng: &mut impl RngCore,
) -> Result<UserSecretKey> {
    let g2 = G2Projective::generator();
    let mut beta_inv = Option::<Scalar>::from(msk.beta.invert())
        .ok_or(VeyraError::MissingMasterMaterial)?;
    let mut r = Scalar::random(&mut *rng);

    let mut components = HashMap::new();
    for raw in attributes {
        let id = normalize_attribute(raw)?;
        if components.contains_key(&id) {
            continue;
        }
        let mut r_i = Scalar::random(&mut *rng);
        let mut h = attr_exponent(msk, &id);
        // D_i = g2^(r + h*r_i), D_i' = g2^(r_i)
        let d_i = g2 * (r + h * r_i);
        let d_i_prime = g2 * r_i;
        wipe_scalar(&mut h);
        wipe_scalar(&mut r_i);
        components.insert(id, (d_i, d_i_prime));
    }

    let d = g2 * ((msk.alpha + r) * beta_inv);
    wipe_scalar(&mut r);
    wipe_scalar(&mut beta_inv);

    let mut attrs: Vec<String> = components.keys().cloned().collect();
    attrs.sort();
    Ok(UserSecretKey {
        user_id: user_id.to_string(),
        d,
        components,
        attributes: attrs,
    })
}

fn share_secret(
    node: &AccessNode,
    secret: Scalar,
    pk: &PublicKey,
    out: &mut HashMap<String, (G1Projective, G1Projective)>,
    rng: &mut impl RngCore,
) -> Result<()> {
    match node {
        AccessNode::Leaf(attr) => {
            let attr_id = attr.id();
            let h1 = pk
                .attr_pubs
                .get(&attr_id)
                .ok_or_else(|| VeyraError::UnknownAttribute(attr_id.clone()))?;
            let c_y = pk.g * secret;
            let c_y_prime = *h1 * secret;
            out.insert(attr_id, (c_y, c_y_prime));
            Ok(())
        }
        AccessNode::Threshold { threshold, children } => {
            let t = *threshold;
            if t == 0 || t > children.len() {
                return Err(VeyraError::InvalidPolicy("invalid threshold".into()));
            }
            let mut coeffs = vec![secret];
            for _ in 1..t {
                coeffs.push(Scalar::random(&mut *rng));
            }
            for (i, child) in children.iter().enumerate() {
                let x = Scalar::from((i + 1) as u64);
                let mut share = Scalar::zero();
                let mut x_pow = Scalar::one();
                for c in &coeffs {
                    share += *c * x_pow;
                    x_pow *= x;
                }
                share_secret(child, share, pk, out, rng)?;
            }
            for c in coeffs.iter_mut() {
                wipe_scalar(c);
            }
            Ok(())
        }
    }
}

/// Build IKM bytes from a Gt element.
///
/// bls12_381 0.8 does not expose a public byte encoding for Gt, so the
/// canonical `Debug` rendering of the (canonically reduced) field element is
/// hashed into fixed-length IKM. The crate version is pinned exactly in
/// `Cargo.toml` because this encoding must stay stable for stored objects.
fn gt_to_ikm(gt: &Gt) -> [u8; 64] {
    let repr = format!("{:?}", gt);
    let mut hasher = Sha256::new();
    hasher.update(GT_TRANSCRIPT_DST);
    hasher.update((repr.len() as u64).to_le_bytes());
    hasher.update(repr.as_bytes());
    let block1 = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(GT_TRANSCRIPT_DST);
    hasher2.update(b"block2");
    hasher2.update(&block1);
    hasher2.update(repr.as_bytes());
    let block2 = hasher2.finalize();

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&block1);
    ikm[32..].copy_from_slice(&block2);
    ikm
}

/// HKDF-Extract + HKDF-Expand -> 32-byte wrapping key from the Gt shared secret.
pub(crate) fn wrapping_key_from_gt(gt: &Gt) -> Result<[u8; 32]> {
    let mut ikm = gt_to_ikm(gt);
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    ikm.zeroize();
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|e| VeyraError::Crypto(format!("HKDF expand failed: {}", e)))?;
    Ok(okm)
}

pub(crate) fn sha256_32(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Encrypt: random DEK, wrap it with HKDF(e(g,g)^{alpha s}), return ABE CT + DEK.
pub fn encrypt_keying_material(
    pk: &PublicKey,
    policy_str: &str,
    rng: &mut impl RngCore,
) -> Result<(AbeCiphertext, [u8; 32])> {
    let tree = parse_policy(policy_str)?;
    let mut s = Scalar::random(&mut *rng);

    // Random DEK (never derived directly from Gt).
    let mut dek = [0u8; 32];
    rng.fill_bytes(&mut dek);
    let dek_hash = sha256_32(&dek);

    // R = e(g,g)^{alpha s}
    let e_gg_alpha_s = pk.e_gg_alpha * s;
    let mut wrap_key = wrapping_key_from_gt(&e_gg_alpha_s)?;

    let mut wrapped_dek = [0u8; 32];
    for i in 0..32 {
        wrapped_dek[i] = dek[i] ^ wrap_key[i];
    }
    wrap_key.zeroize();

    // C' = h^s = g^{beta s}
    let c_prime = pk.h * s;
    let mut leaf_components = HashMap::new();
    let shared = share_secret(&tree, s, pk, &mut leaf_components, rng);
    wipe_scalar(&mut s);
    if let Err(e) = shared {
        dek.zeroize();
        return Err(e);
    }

    let ct = AbeCiphertext {
        policy: policy_str.to_string(),
        c_prime,
        leaf_components,
        wrapped_dek,
        dek_hash,
    };
    Ok((ct, dek))
}

pub fn decrypt_keying_material(
    _pk: &PublicKey,
    sk: &UserSecretKey,
    ct: &AbeCiphertext,
) -> Result<[u8; 32]> {
    let tree = parse_policy(&ct.policy)?;
    let user_attrs: HashSet<String> = sk.attributes.iter().cloned().collect();
    if !tree.satisfied_by(&user_attrs) {
        return Err(VeyraError::AccessDenied);
    }

    let result = decrypt_node(&tree, sk, ct, &user_attrs)?;

    let e_c_d = bls12_381::pairing(&G1Affine::from(ct.c_prime), &G2Affine::from(sk.d));

    // e(g,g)^{alpha s} = e(C', D) / e(g,g)^{r s}
    let e_gg_alpha_s = e_c_d - result;
    let mut wrap_key = wrapping_key_from_gt(&e_gg_alpha_s)?;

    let mut dek = [0u8; 32];
    for i in 0..32 {
        dek[i] = ct.wrapped_dek[i] ^ wrap_key[i];
    }
    wrap_key.zeroize();

    // Key confirmation in constant time: a wrong recovery yields a hash mismatch.
    let got_hash = sha256_32(&dek);
    let matches: bool = got_hash[..].ct_eq(&ct.dek_hash[..]).into();
    if !matches {
        dek.zeroize();
        return Err(VeyraError::DecryptionFailed);
    }

    Ok(dek)
}

fn decrypt_node(
    node: &AccessNode,
    sk: &UserSecretKey,
    ct: &AbeCiphertext,
    user_attrs: &HashSet<String>,
) -> Result<Gt> {
    match node {
        AccessNode::Leaf(attr) => {
            let attr_id = attr.id();
            if !user_attrs.contains(&attr_id) {
                return Err(VeyraError::AccessDenied);
            }
            let (d_i, d_i_prime) = sk
                .components
                .get(&attr_id)
                .ok_or(VeyraError::AccessDenied)?;
            let (c_y, c_y_prime) = ct
                .leaf_components
                .get(&attr_id)
                .ok_or(VeyraError::DecryptionFailed)?;

            let e1 = bls12_381::pairing(&G1Affine::from(*c_y), &G2Affine::from(*d_i));
            let e2 = bls12_381::pairing(&G1Affine::from(*c_y_prime), &G2Affine::from(*d_i_prime));
            Ok(e1 - e2)
        }
        AccessNode::Threshold { threshold, children } => {
            let mut satisfied = Vec::new();
            for (i, child) in children.iter().enumerate() {
                if let Ok(val) = decrypt_node(child, sk, ct, user_attrs) {
                    satisfied.push((i + 1, val));
                    if satisfied.len() >= *threshold {
                        break;
                    }
                }
            }
            if satisfied.len() < *threshold {
                return Err(VeyraError::AccessDenied);
            }

            let mut result = Gt::identity();
            for (i, (x_i, val_i)) in satisfied.iter().enumerate() {
                let mut lambda = Scalar::one();
                for (j, (x_j, _)) in satisfied.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    let num = Scalar::from(*x_j as u64);
                    let den = Scalar::from(*x_j as u64) - Scalar::from(*x_i as u64);
                    let den_inv = Option::<Scalar>::from(den.invert())
                        .ok_or(VeyraError::DecryptionFailed)?;
                    lambda *= num * den_inv;
                }
                result += *val_i * lambda;
            }
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    fn attrs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn basic_encrypt_decrypt() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&default_universe(), &mut rng);
        let sk = keygen(
            &pk,
            &msk,
            "alice",
            &attrs(&["clearance>=1", "clearance>=4", "department=intelligence"]),
            &mut rng,
        )
        .unwrap();
        let policy = "clearance>=4 AND department=intelligence";
        let (ct, dek) = encrypt_keying_material(&pk, policy, &mut rng).unwrap();
        let recovered = decrypt_keying_material(&pk, &sk, &ct).unwrap();
        assert_eq!(dek, recovered);
    }

    #[test]
    fn or_and_nested_policies_decrypt_via_each_branch() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&default_universe(), &mut rng);
        let policy = "(clearance>=3 OR role=admin) AND department=operations";
        let (ct, dek) = encrypt_keying_material(&pk, policy, &mut rng).unwrap();

        let by_clearance =
            keygen(&pk, &msk, "a", &attrs(&["clearance>=3", "department=operations"]), &mut rng).unwrap();
        assert_eq!(decrypt_keying_material(&pk, &by_clearance, &ct).unwrap(), dek);

        let by_role =
            keygen(&pk, &msk, "b", &attrs(&["role=admin", "department=operations"]), &mut rng).unwrap();
        assert_eq!(decrypt_keying_material(&pk, &by_role, &ct).unwrap(), dek);
    }

    #[test]
    fn unsatisfied_policy_is_denied() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&default_universe(), &mut rng);
        let (ct, _) = encrypt_keying_material(&pk, "clearance>=4 AND department=finance", &mut rng).unwrap();
        let sk = keygen(&pk, &msk, "eve", &attrs(&["clearance>=4", "department=hr"]), &mut rng).unwrap();
        assert!(matches!(
            decrypt_keying_material(&pk, &sk, &ct),
            Err(VeyraError::AccessDenied)
        ));
    }

    #[test]
    fn collusion_by_splicing_key_components_fails() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&default_universe(), &mut rng);
        let (ct, _) = encrypt_keying_material(&pk, "clearance>=4 AND department=finance", &mut rng).unwrap();
        let u1 = keygen(&pk, &msk, "u1", &attrs(&["clearance>=4"]), &mut rng).unwrap();
        let u2 = keygen(&pk, &msk, "u2", &attrs(&["department=finance"]), &mut rng).unwrap();

        let mut components = u1.components.clone();
        components.extend(u2.components.clone());
        let mut attributes = u1.attributes.clone();
        attributes.extend(u2.attributes.clone());
        let spliced = UserSecretKey {
            user_id: "colluders".into(),
            d: u1.d,
            components,
            attributes,
        };
        assert!(decrypt_keying_material(&pk, &spliced, &ct).is_err());
    }

    /// Regression test for the original construction, where `H(attr)` had a
    /// publicly known exponent. An attacker holding ONE attribute used the
    /// public hash to recover `g2^r` from a key component and decrypt policies
    /// requiring attributes they do not have.
    #[test]
    fn public_hash_attack_on_single_component_does_not_work() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&default_universe(), &mut rng);
        let sk = keygen(&pk, &msk, "mallory", &attrs(&["clearance>=1"]), &mut rng).unwrap();
        let policy = "clearance>=1 AND department=intelligence";
        let (ct, dek) = encrypt_keying_material(&pk, policy, &mut rng).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"Veyra-H-attr-v1");
        hasher.update("clearance>=1".as_bytes());
        let hash = hasher.finalize();
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&hash);
        let h_old = Scalar::from_bytes_wide(&wide);

        let (d_i, d_i_prime) = sk.components["clearance>=1"];
        let g2r_guess = d_i - d_i_prime * h_old;

        let leaf = |attr: &str| {
            bls12_381::pairing(
                &G1Affine::from(ct.leaf_components[attr].0),
                &G2Affine::from(g2r_guess),
            )
        };
        // AND of two children: Lagrange coefficients at x=1,2 are 2 and -1.
        let result = leaf("clearance>=1") * Scalar::from(2u64) - leaf("department=intelligence");
        let e_c_d = bls12_381::pairing(&G1Affine::from(ct.c_prime), &G2Affine::from(sk.d));
        let wrap = wrapping_key_from_gt(&(e_c_d - result)).unwrap();
        let mut guess = [0u8; 32];
        for i in 0..32 {
            guess[i] = ct.wrapped_dek[i] ^ wrap[i];
        }
        assert_ne!(guess, dek);
        assert_ne!(sha256_32(&guess), ct.dek_hash);
    }

    #[test]
    fn keys_from_a_different_authority_do_not_decrypt() {
        let mut rng = thread_rng();
        let (pk1, _msk1) = setup(&default_universe(), &mut rng);
        let (pk2, msk2) = setup(&default_universe(), &mut rng);
        let (ct, _) = encrypt_keying_material(&pk1, "clearance>=1", &mut rng).unwrap();
        let sk = keygen(&pk2, &msk2, "x", &attrs(&["clearance>=1"]), &mut rng).unwrap();
        assert!(decrypt_keying_material(&pk1, &sk, &ct).is_err());
    }

    #[test]
    fn unknown_attribute_requires_publication() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&[], &mut rng);
        let policy = "project=apollo";
        assert!(matches!(
            encrypt_keying_material(&pk, policy, &mut rng),
            Err(VeyraError::UnknownAttribute(_))
        ));
        let pk2 = public_for_policy(&pk, &msk, policy).unwrap();
        let (ct, dek) = encrypt_keying_material(&pk2, policy, &mut rng).unwrap();
        let sk = keygen(&pk2, &msk, "u", &attrs(&["project=apollo"]), &mut rng).unwrap();
        assert_eq!(decrypt_keying_material(&pk2, &sk, &ct).unwrap(), dek);
    }

    #[test]
    fn master_key_serialization_round_trips() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&default_universe(), &mut rng);
        let restored = MasterSecretKey::from_bytes(&msk.to_bytes()[..]).unwrap();
        let (ct, dek) = encrypt_keying_material(&pk, "clearance>=2", &mut rng).unwrap();
        let sk = keygen(&pk, &restored, "u", &attrs(&["clearance>=2"]), &mut rng).unwrap();
        assert_eq!(decrypt_keying_material(&pk, &sk, &ct).unwrap(), dek);
        assert!(MasterSecretKey::from_bytes(&[0u8; 95]).is_err());
    }

    #[test]
    fn keygen_rejects_invalid_attributes() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&default_universe(), &mut rng);
        assert!(keygen(&pk, &msk, "u", &attrs(&["not-an-attribute"]), &mut rng).is_err());
    }
}
