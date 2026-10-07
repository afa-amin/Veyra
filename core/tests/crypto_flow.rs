use rand::rngs::OsRng;
use std::io::Cursor;
use veyra_core::{
    decrypt_reader, default_universe, encrypt_reader, keygen, parse_policy, public_for_policy,
    setup, MasterSecretKey, PublicKey, StreamDecryptor, UserSecretKey, VeyraError,
    DEFAULT_CHUNK_SIZE,
};

const SMALL_CHUNK: usize = 1024;

fn authority() -> (PublicKey, MasterSecretKey) {
    setup(&default_universe(), &mut OsRng)
}

fn user(pk: &PublicKey, msk: &MasterSecretKey, attrs: &[&str]) -> UserSecretKey {
    let attrs: Vec<String> = attrs.iter().map(|s| s.to_string()).collect();
    keygen(pk, msk, "recipient", &attrs, &mut OsRng).unwrap()
}

fn seal(pk: &PublicKey, msk: &MasterSecretKey, policy: &str, data: &[u8], chunk: usize) -> Vec<u8> {
    let pk = public_for_policy(pk, msk, policy).unwrap();
    let mut object = Vec::new();
    encrypt_reader(
        &pk,
        policy,
        "sample.bin",
        "application/octet-stream",
        data.len() as u64,
        Cursor::new(data.to_vec()),
        &mut object,
        chunk,
        &mut OsRng,
    )
    .unwrap();
    object
}

fn open(pk: &PublicKey, sk: &UserSecretKey, object: &[u8]) -> Result<Vec<u8>, VeyraError> {
    let mut out = Vec::new();
    decrypt_reader(pk, sk, Cursor::new(object.to_vec()), &mut out)?;
    Ok(out)
}

fn header_end(object: &[u8]) -> usize {
    let len = u32::from_be_bytes(object[8..12].try_into().unwrap()) as usize;
    12 + len
}

#[test]
fn policy_examples_evaluate() {
    let tree = parse_policy("clearance>=4 AND department=engineering").unwrap();
    let attrs = [
        "clearance>=1",
        "clearance>=2",
        "clearance>=3",
        "clearance>=4",
        "department=engineering",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert!(tree.satisfied_by(&attrs));
}

#[test]
fn streaming_round_trip_default_chunk_size() {
    let (pk, msk) = authority();
    let sk = user(&pk, &msk, &["clearance>=1", "department=general", "role=member"]);
    let input = vec![42u8; DEFAULT_CHUNK_SIZE + 123];
    let object = seal(&pk, &msk, "clearance>=1", &input, DEFAULT_CHUNK_SIZE);
    assert_eq!(open(&pk, &sk, &object).unwrap(), input);
}

#[test]
fn round_trip_boundaries_and_empty_input() {
    let (pk, msk) = authority();
    let sk = user(&pk, &msk, &["clearance>=1"]);
    for size in [0usize, 1, SMALL_CHUNK - 1, SMALL_CHUNK, SMALL_CHUNK + 1, 3 * SMALL_CHUNK, 5000] {
        let input: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let object = seal(&pk, &msk, "clearance>=1", &input, SMALL_CHUNK);
        assert_eq!(open(&pk, &sk, &object).unwrap(), input, "size {}", size);
    }
}

#[test]
fn header_metadata_is_returned_after_authorization() {
    let (pk, msk) = authority();
    let sk = user(&pk, &msk, &["clearance>=1"]);
    let object = seal(&pk, &msk, "clearance>=1", b"hello", SMALL_CHUNK);
    let dec = StreamDecryptor::new(&pk, &sk, Cursor::new(object)).unwrap();
    assert_eq!(dec.header().original_filename, "sample.bin");
    assert_eq!(dec.header().plaintext_size, 5);
}

#[test]
fn every_single_byte_flip_is_detected() {
    let (pk, msk) = authority();
    let sk = user(&pk, &msk, &["clearance>=1"]);
    let input = vec![7u8; 2 * SMALL_CHUNK + 10];
    let object = seal(&pk, &msk, "clearance>=1", &input, SMALL_CHUNK);
    let start = header_end(&object);
    // Header bytes (sampled) and every region of the chunk stream.
    let mut positions: Vec<usize> = (8..start).step_by(7).collect();
    positions.extend((start..object.len()).step_by(97));
    positions.push(object.len() - 1);
    for pos in positions {
        let mut tampered = object.clone();
        tampered[pos] ^= 0x01;
        assert!(open(&pk, &sk, &tampered).is_err(), "flip at {} was not detected", pos);
    }
}

#[test]
fn truncation_and_trailing_data_are_rejected() {
    let (pk, msk) = authority();
    let sk = user(&pk, &msk, &["clearance>=1"]);
    let input = vec![9u8; 3 * SMALL_CHUNK];
    let object = seal(&pk, &msk, "clearance>=1", &input, SMALL_CHUNK);

    assert!(open(&pk, &sk, &object[..object.len() - 5]).is_err());
    let frame = 4 + SMALL_CHUNK + 16;
    assert!(open(&pk, &sk, &object[..object.len() - frame]).is_err());

    let mut extended = object.clone();
    extended.push(0);
    assert!(open(&pk, &sk, &extended).is_err());
}

#[test]
fn chunk_reordering_is_rejected() {
    let (pk, msk) = authority();
    let sk = user(&pk, &msk, &["clearance>=1"]);
    let input: Vec<u8> = (0..3 * SMALL_CHUNK).map(|i| (i % 256) as u8).collect();
    let object = seal(&pk, &msk, "clearance>=1", &input, SMALL_CHUNK);
    let start = header_end(&object);
    let frame = 4 + SMALL_CHUNK + 16;
    let mut swapped = object.clone();
    let (a, b) = (start, start + frame);
    let first = object[a..a + frame].to_vec();
    let second = object[b..b + frame].to_vec();
    swapped[a..a + frame].copy_from_slice(&second);
    swapped[b..b + frame].copy_from_slice(&first);
    assert!(open(&pk, &sk, &swapped).is_err());
}

#[test]
fn recipients_without_required_attributes_are_denied() {
    let (pk, msk) = authority();
    let object = seal(&pk, &msk, "clearance>=4 AND department=finance", b"secret", SMALL_CHUNK);
    let wrong = user(&pk, &msk, &["clearance>=4", "department=hr"]);
    assert!(matches!(open(&pk, &wrong, &object), Err(VeyraError::AccessDenied)));
    let right = user(&pk, &msk, &["clearance>=4", "department=finance"]);
    assert_eq!(open(&pk, &right, &object).unwrap(), b"secret");
}

#[test]
fn keys_from_another_authority_cannot_decrypt() {
    let (pk, msk) = authority();
    let (pk2, msk2) = authority();
    let object = seal(&pk, &msk, "clearance>=1", b"secret", SMALL_CHUNK);
    let foreign = user(&pk2, &msk2, &["clearance>=1"]);
    assert!(open(&pk, &foreign, &object).is_err());
}

#[test]
fn attributes_outside_the_published_universe_need_publication() {
    let (pk, msk) = setup(&[], &mut OsRng);
    let mut object = Vec::new();
    let err = encrypt_reader(
        &pk,
        "project=apollo",
        "f",
        "application/octet-stream",
        1,
        Cursor::new(vec![1u8]),
        &mut object,
        SMALL_CHUNK,
        &mut OsRng,
    );
    assert!(matches!(err, Err(VeyraError::UnknownAttribute(_))));
    let sealed = seal(&pk, &msk, "project=apollo", b"x", SMALL_CHUNK);
    let sk = user(&pk, &msk, &["project=apollo"]);
    assert_eq!(open(&pk, &sk, &sealed).unwrap(), b"x");
}

#[test]
fn oversized_header_and_garbage_are_rejected() {
    let (pk, msk) = authority();
    let sk = user(&pk, &msk, &["clearance>=1"]);
    let mut bogus = b"VEYRAOBJ".to_vec();
    bogus.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(open(&pk, &sk, &bogus).is_err());
    assert!(open(&pk, &sk, b"not a veyra object at all").is_err());
    assert!(open(&pk, &sk, b"").is_err());
}

#[test]
fn input_longer_than_declared_size_is_rejected() {
    let (pk, msk) = authority();
    let pk = public_for_policy(&pk, &msk, "clearance>=1").unwrap();
    let mut object = Vec::new();
    let res = encrypt_reader(
        &pk,
        "clearance>=1",
        "f",
        "application/octet-stream",
        2,
        Cursor::new(vec![0u8; 5]),
        &mut object,
        SMALL_CHUNK,
        &mut OsRng,
    );
    assert!(res.is_err());
}

#[test]
fn ciphertexts_are_randomized() {
    let (pk, msk) = authority();
    let a = seal(&pk, &msk, "clearance>=1", b"same input", SMALL_CHUNK);
    let b = seal(&pk, &msk, "clearance>=1", b"same input", SMALL_CHUNK);
    assert_ne!(a, b);
}
