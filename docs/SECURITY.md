# Security

## Implemented controls

- Argon2id-compatible password hashing through the Argon2 password-hash API.
- Random opaque session tokens stored only as SHA-256 hashes.
- SameSite session cookies and double-submit CSRF token for state-changing authenticated requests.
- Opaque random transfer tokens stored only as hashes.
- Short-lived, single-use OTP challenges with attempt limits.
- Expiration and revocation enforced in authorization queries.
- Download-limit reservation under a PostgreSQL row lock.
- Server-generated object keys.
- Filename sanitization and bounded filename length.
- Upload size limits.
- AES-256-GCM authenticated encryption.
- Versioned encrypted object format.
- No passwords, session tokens, OTPs, DEKs, or private ABE keys in audit records.
- Master material encrypted at rest using an externally supplied encryption key.

## Important limitations

The current CP-ABE implementation is an adapted research implementation and has not received an independent cryptographic audit. The current server architecture is also not E2EE because the server handles plaintext during upload/decryption.

Production deployments should add:

- TLS termination with HSTS.
- KMS/HSM-backed master key protection.
- SMTP provider with domain authentication.
- Centralized rate limiting at the edge.
- Malware/content scanning appropriate to the deployment.
- Independent penetration testing and cryptographic review.
