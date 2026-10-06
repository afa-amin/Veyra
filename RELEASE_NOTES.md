# Veyra Installer Release Notes

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
