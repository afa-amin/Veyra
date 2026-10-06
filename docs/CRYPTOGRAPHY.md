# Cryptography

## Construction

Veyra uses a hybrid design:

1. Generate a random 256-bit data-encryption key (DEK).
2. Encrypt file chunks with AES-256-GCM.
3. Protect the DEK with the supplied CP-ABE construction.
4. Derive a wrapping key from the CP-ABE pairing result using HKDF-SHA-256.
5. Authenticate package metadata as AES-GCM AAD.

## Object format

```text
VEYRAOBJ
u32 header length
versioned serialized header
repeated:
  u32 ciphertext chunk length
  AES-GCM ciphertext chunk
```

The header includes filename, MIME type, plaintext size, policy, ABE ciphertext, base nonce, and chunk size. The nonce itself is excluded from the AAD transcript to avoid circular construction.

Each chunk derives its nonce by XORing the base nonce's final eight bytes with the big-endian chunk index.

## Key lifecycle

- DEK: generated per transfer, held only during encryption/decryption, zeroized after use.
- ABE master material: encrypted at rest; loaded into memory only by the API process.
- User ABE key: generated on demand for the recipient and never persisted by Veyra.
- Session/transfer/OTP tokens: only hashes are persisted.

## Review requirement

The supplied CP-ABE implementation is not independently audited. It should not be represented as a formally verified cryptosystem.
