# Release notes

## 0.2.0 — security hardening

Cryptography
- **Fixed:** CP-ABE attribute exponents were publicly computable, allowing any key holder to decrypt any object. Exponents are now secret per-attribute PRF outputs. *Objects created by 0.1 are not readable by 0.2.* Existing deployments must re-send transfers: stop 0.1, remove old objects, start 0.2 with `VEYRA_ALLOW_NEW_MASTER=true` once.
- New object format v2: canonical header, strict chunk lengths, trailing-data rejection, zeroized key material, constant-time key confirmation.
- Master key file is Argon2id-protected, written with mode 0600, and never silently regenerated.
- Policies are validated: allow-list of attributes, value charset, length/depth/leaf limits (no stack-overflow DoS), duplicate attributes rejected. `clearance>=N` now implies lower levels.

API
- Verification-code flow: HMAC storage, 8 digits, rate limits, per-transfer lockout, identical responses for wrong addresses, recipient address no longer exposed on the public link endpoint.
- Development OTP mailbox endpoint removed. Default environment is production; production requires SMTP and a non-placeholder master secret.
- Rate limiting on register/login/code endpoints; timing-equalized login; first-admin race fixed; CSRF + audit on admin actions; admin user list endpoint.
- Download authorization happens before a slot is consumed; failures release the slot; plaintext is streamed, never written to disk on download.
- Temp files are guarded and purged; periodic sweep deletes expired/revoked objects, sessions and codes; revoke deletes the object immediately.
- Upload body limit raised to `MAX_UPLOAD_BYTES` only on the upload route; encryption runs off the async runtime.
- SMTP TLS mode fixed (implicit TLS vs STARTTLS), versioned migrations.

Frontend / infra
- Download flow fixed (cookie-based streaming download, correct file name, 8-digit code); policy builder validates input; admin page for attributes.
- Dockerfile for the API, hardened nginx (headers, rate limits, token redaction), sandboxed systemd unit, optional TLS in the installer, corrected `.gitignore` (`node_modules` removed from the repository).

Not done / known limits
- Not end-to-end encrypted. No independent audit. Rate limiter is per instance. S3 uploads use a single PUT (4 GiB cap). Registration does not verify email addresses.

## Installer hotfix release

- Added missing `serde_json` dependency to `veyra-core`.
- Installer now installs/updates the Rust stable toolchain instead of accepting an arbitrary old system Cargo.
- API release build uses the stable toolchain explicitly.
- Installer continues to wait safely for apt/dpkg/unattended-upgrades and never deletes package-manager lock files.
- Production SMTP behavior remains explicit; `--dev-mode` is available for installations without SMTP.

## API compile hotfix

- Renamed the API request DTO from `Credentials` to `AuthCredentials` to avoid collision with Lettre's SMTP `Credentials` type.
- Aliased Lettre's SMTP credentials type as `SmtpCredentials`.
- Added the direct `bls12_381` API dependency required by `crypto_service.rs`.
- Fixed `recipient_key` to return `UserSecretKey` rather than a one-element tuple.
- Removed an unused `PathBuf` import and unused storage stream import.
- Replaced ineffective scalar assignments with `zeroize()` calls in the cryptographic setup path.

## V6 build fix

- Fixed an incompatible `zeroize()` call on `bls12_381::Scalar` when using bls12_381 0.8.0.
- Restored the crate-compatible scalar clearing assignment so the workspace can compile.
- No cryptographic API or dependency version was changed for this fix.

## V7 installer/runtime fix

- Stops only an existing `veyra-api.service` before an upgrade/reinstall.
- Selects a free local API port instead of blindly assuming TCP/4000 is available.
- Persists the selected API port in `VEYRA_BIND`.
- Uses the selected API port consistently in Nginx, health checks, and `veyractl`.
- Avoids killing unrelated processes that happen to use TCP/4000.
- Shows the resolved public host in the completion summary.

## V8 port-selection fix

- Scans listening TCP sockets before selecting Veyra ports.
- Selects two independent random free ports from 20000-59999.
- One port is reserved for Nginx/public traffic and one for the API.
- Public and API ports are guaranteed to differ.
- Ports 80 and 443 are excluded and explicitly rejected as Veyra public ports.
- Selection is rechecked immediately before configuration to reduce race conditions.
