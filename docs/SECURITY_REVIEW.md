# Security Review — MVP

## Findings addressed during implementation

| Area | Finding | Action |
|---|---|---|
| Master secret | SecureDrop stored master material as plaintext local state | Veyra encrypts master material at rest with an externally supplied key |
| Payload memory | SecureDrop read the complete plaintext into RAM | Veyra provides chunked streaming encryption/decryption |
| Object storage | SecureDrop was package-file oriented | Veyra introduces an ObjectStore abstraction and server-generated object keys |
| Transfer identity | No web bearer-link lifecycle | Veyra uses high-entropy opaque transfer tokens stored only as hashes |
| Recipient verification | No recipient verification flow | Short-lived, single-use, rate-limited OTP challenges |
| Download limit | No concurrent web reservation | PostgreSQL row locking reserves the download slot |
| Revocation | Local key deletion did not revoke existing packages | Transfer authorization checks status before download |
| IDOR | Download access token could otherwise be reused against another URL | Download access session is explicitly bound to the transfer URL token |
| Filename attacks | Package storage was path based | Server-generated object keys; filename is metadata only |
| Policy input | CLI policy was directly exposed | UI builds policy expressions from controlled fields |
| Marketing accuracy | E2EE could be incorrectly claimed | Documentation explicitly states the current server-side trust model |

## Remaining production review items

- Independent cryptographic audit of the CP-ABE implementation.
- Independent penetration test of the HTTP application.
- KMS/HSM integration for master-key protection.
- Edge-level rate limiting and abuse controls.
- Formal SMTP/email security configuration.
- Malware scanning/content policy appropriate to the deployment.
- Full browser integration tests and concurrent-download load tests.
