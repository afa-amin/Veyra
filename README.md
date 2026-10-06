# Veyra — Secure File Transfer

**Send sensitive files. Stay in control.**

Veyra is a production-oriented secure file transfer service. It presents a simple SaaS workflow while keeping encryption, policy evaluation, expiring links, verification, revocation, and encrypted object storage behind the interface.

> **Security terminology:** the current server-side architecture encrypts files before persistent object storage and serves them over HTTPS. It is **not end-to-end encryption (E2EE)** because the Veyra server processes plaintext during upload and decrypts authorized objects during download. Do not market the current architecture as E2EE.

## Quick start

Requirements for local development:

- Docker Compose
- A browser

Run:

```bash
git clone <your-repository>
cd veyra
docker compose up
```

Open:

```text
http://localhost
```

The first registered account becomes the development administrator. The development OTP is written to the API structured logs instead of being delivered by email.

## Product flow

```text
Register → Login → Select file → Configure access → Create Secure Link
    → Recipient opens link → OTP verification → Authorized decryption → Download
```

Persistent object storage contains only Veyra encrypted objects (`.vobj`). Plaintext upload data exists only transiently on the API host while it is being encrypted.

## Architecture

```text
Browser
   │ HTTPS
   ▼
Nginx
   │
   ▼
Veyra API (Rust/Axum)
   ├── Authentication / sessions
   ├── Transfer lifecycle
   ├── Policy / authorization
   ├── OTP verification
   ├── Audit events
   └── Crypto core (Rust)
       ├── AES-256-GCM payload encryption
       └── CP-ABE DEK protection
   │
   ├── PostgreSQL metadata
   └── ObjectStore
       ├── Local filesystem
       └── S3-compatible storage
```

## Repository

```text
veyra/
├── core/                 # Rust cryptographic library
├── api/                  # Rust HTTP API and migrations
├── frontend/             # Vite + Vanilla JavaScript SPA
├── docker/               # Nginx configuration
├── docs/                 # Architecture and security documentation
├── docker-compose.yml
├── .env.example
└── Cargo.toml
```

## Security model

Veyra uses a hybrid construction:

```text
random 256-bit DEK
       │
       ├── AES-256-GCM → encrypted file chunks
       │
       └── CP-ABE → protected DEK
```

The streaming object format is versioned and authenticates the package header as AES-GCM additional authenticated data. Each chunk gets a unique derived nonce.

The CP-ABE implementation is adapted from the supplied SecureDrop research implementation. It has **not** been independently audited. Treat the cryptographic core as security-sensitive code requiring professional review before high-value production deployment.

## Configuration

See `docs/CONFIGURATION.md` and `.env.example`.

Production deployments should provide a strong `VEYRA_MASTER_ENCRYPTION_KEY` through an external secret manager. The local encrypted master file is an envelope-protection mechanism, not an HSM/KMS replacement.

## Testing

When Rust tooling is available:

```bash
cargo test --workspace
```

Frontend:

```bash
cd frontend
npm install
npm run build
```

Security test coverage is described in `docs/TESTING.md`.

## License

MIT. See `LICENSE`.
