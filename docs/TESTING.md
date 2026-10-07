# Testing

```bash
cargo test --workspace          # core + API unit tests
cd frontend && npm ci && npm run build
```

## Automated coverage

Core (`core/src`, `core/tests`):
- Policy grammar, canonical form, limits (length, depth, leaves), duplicate and unknown attributes.
- CP-ABE correctness for AND / OR / nested policies, denial for unsatisfied attributes, key-splicing (collusion) rejection, foreign-authority keys, and a regression test for the original public-hash attack.
- Streaming format: chunk boundaries, empty input, single-byte tampering across header and chunks, truncation, trailing data, chunk reordering, oversized headers, over-long input.

API (`api/src`):
- Email, filename, MIME and Content-Disposition sanitizing, OTP generation, HMAC field binding, rate limiter windows, object-key path safety, master-key sealing, migration statement splitting.

## Manual / integration checklist (needs PostgreSQL and SMTP or development mode)

- Register, login, logout, CSRF rejection without header.
- Upload larger than 2 MiB and near `MAX_UPLOAD_BYTES`.
- Code request for a wrong address gives the same response as for the right one.
- More than 10 wrong codes in 24 hours locks verification.
- Restricted transfer: recipient without attributes gets 403 and the download counter is unchanged.
- Revoke deletes the object; expired transfers are swept within 5 minutes.
- Kill the API during an upload and confirm `data/tmp` is empty after restart.
- Delete `master.v2.enc` with existing transfers: the API must refuse to start.

Penetration testing and an independent cryptographic review are still recommended before high-value production use.
