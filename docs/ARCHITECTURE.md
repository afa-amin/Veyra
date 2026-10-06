# Architecture

Veyra is a modular monolith. Authentication, transfers, authorization, audit, crypto orchestration, and storage live behind one API process. This keeps the MVP operationally small while preserving clean boundaries for later extraction.

## Components

- `frontend`: Vite + Vanilla JavaScript SPA.
- `api`: Rust/Axum REST API.
- `core`: Rust cryptographic library adapted from SecureDrop.
- PostgreSQL: identity, transfer metadata, policies, sessions, OTP challenges, and audit events.
- ObjectStore: local filesystem or S3-compatible storage.
- Nginx: static frontend delivery and API reverse proxy.

## Why a modular monolith

The product does not need Kafka, a service mesh, Kubernetes, or independent microservices. The crypto boundary is already explicit, and storage is abstracted behind an interface. Operational simplicity is more valuable for the MVP.

## Trust boundaries

1. Browser ↔ Nginx/API: TLS is required in production.
2. API ↔ PostgreSQL: metadata and authorization state.
3. API ↔ object storage: ciphertext only for persistent objects.
4. API ↔ crypto core: plaintext exists only in the application process during upload/decryption.
5. Master secret: encrypted at rest and intended to be replaceable by KMS/HSM integration.
