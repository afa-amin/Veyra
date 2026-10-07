# Cryptography

## Hybrid construction

```text
random 256-bit DEK
   ├─ AES-256-GCM, 1 MiB chunks  → encrypted payload
   └─ DEK xor HKDF(e(g,g)^(alpha·s)) → wrapped DEK, protected by CP-ABE (BLS12-381)
```

Object layout: `"VEYRAOBJ" | header_len | header | { chunk_len | chunk }*`.

- The magic and the whole header (version, filename, MIME type, plaintext size, policy, ABE ciphertext, chunk size) are AAD of every chunk.
- Chunk nonce = random 96-bit base nonce XOR chunk index. The DEK is fresh per object.
- The authenticated plaintext size gives truncation, extension and reordering detection. Trailing bytes are rejected, headers must be canonically encoded.
- A SHA-256 hash of the DEK confirms correct unwrapping (compared in constant time).
- Key material (`DEK`, wrapping key, chunk buffers) is wrapped in zeroizing containers or wiped explicitly.

## CP-ABE and secret attribute exponents

The scheme is BSW07 adapted to a Type-3 pairing. `H(attr)` must exist in G1 (ciphertext) and G2 (key) with the same exponent `h`. Version 0.1 derived `h = SHA-256(attr)` — publicly computable — so any key holder could compute `D_i − h·D_i' = g2^r` from one key component and decrypt every ciphertext regardless of policy. Version 0.2 derives `h_attr = HKDF(attr_seed, attr)` from a secret seed in the master secret key. Users never learn `h_attr`; encryptors use only `g1^{h_attr}` (`PublicKey::attr_pubs`, extended on demand for the attributes of a policy). This is exercised by a regression test.

Properties and limits:
- The key authority is also the encryptor and holds the master secret: Veyra is **not** end-to-end encrypted, and the server decides access. CP-ABE is defence in depth against object-store and database compromise, not against a compromised API host.
- Policies are limited to 32 distinct attributes, each attribute at most once.
- The construction has not been independently audited. Obtain a professional review before high-value use.
- The Gt element is turned into key material through its canonical `Debug` rendering because `bls12_381` 0.8 exposes no byte encoding. The crate is pinned to `=0.8.0` for that reason.

## Master key at rest

`master.v2.enc`: AES-256-GCM, key from Argon2id(64 MiB, 3 passes, random salt) over `VEYRA_MASTER_ENCRYPTION_KEY`, AAD `veyra-master-v2`, written atomically with mode 0600. Contents: `alpha || beta || attr_seed`.

## Verification codes and tokens

- Link, session and download tokens: 256-bit random, only SHA-256 hashes stored.
- One-time codes: 8 digits (unbiased), stored as HMAC-SHA256 keyed from the master secret and bound to transfer and recipient address. 5 attempts per code, 10 failed attempts per transfer per 24 hours, at most 5 codes per hour.
- Passwords: Argon2id; unknown accounts pay an equivalent verification (timing equalization).
