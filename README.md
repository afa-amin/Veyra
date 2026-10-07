# Veyra — Secure File Transfer

**Send sensitive files. Stay in control.**

Veyra is a production-oriented secure file transfer service. It presents a simple SaaS workflow while keeping encryption, policy evaluation, expiring links, verification, revocation, and encrypted object storage behind the interface.

> **Security terminology:** the current server-side architecture encrypts files before persistent object storage and serves them over HTTPS. It is **not end-to-end encryption (E2EE)** because the Veyra server processes plaintext during upload and decrypts authorized objects during download. Do not market the current architecture as E2EE.

## Quick start

Requirements: Docker Compose and a browser.

```bash
git clone <your-repository>
cd Veyra
cp .env.docker.example .env     # set POSTGRES_PASSWORD and VEYRA_MASTER_ENCRYPTION_KEY
docker compose up --build
```

Open `http://localhost`.

With the example settings (`VEYRA_ENV=development`) and no SMTP server, the one-time verification code is printed to the API log (`docker compose logs api`). In production (`VEYRA_ENV=production`, the default) SMTP is mandatory and the process refuses to start without it.

The first registered account becomes the administrator. Set `VEYRA_ADMIN_EMAIL` so that only that address can claim the role. Administrators manage the attributes used by restricted transfers under **Admin** in the web UI.

## Product flow

```text
Register → Login → Select file → Configure access → Create Secure Link
    → Recipient opens link → OTP verification → Authorized decryption → Download
```

Persistent object storage contains only Veyra encrypted objects (`.vobj`). During upload the plaintext exists only in a private (mode 0600) temporary file that is deleted as soon as encryption finishes, including on every error path, and stale files are purged at startup. Downloads are decrypted in a streaming fashion and never written to disk as plaintext.

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
├── docker/               # API and Nginx images, Nginx configuration
├── installer/            # Bare-metal installer (systemd + Nginx)
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

Attribute exponents of the CP-ABE scheme are derived from a secret key held by the authority (see `docs/CRYPTOGRAPHY.md`). The cryptographic core has **not** been independently audited. Treat the cryptographic core as security-sensitive code requiring professional review before high-value production deployment.

## Configuration

See `docs/CONFIGURATION.md` and `.env.example`.

Production deployments should provide a strong `VEYRA_MASTER_ENCRYPTION_KEY` through an external secret manager. The local encrypted master file is an envelope-protection mechanism, not an HSM/KMS replacement.

## Testing

Commit the generated `Cargo.lock` after the first build. With Rust (1.88 or newer):

```bash
cargo test --workspace
```

Frontend:

```bash
cd frontend
npm ci
npm run build
```

Security test coverage is described in `docs/TESTING.md`.

## License

MIT. See `LICENSE`.
